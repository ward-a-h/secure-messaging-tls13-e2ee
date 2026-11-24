"""
bench_client.py

Measurement client used by the experiments. It runs inside the Client 1
namespace and prints one JSON object with the results of a single run.

Three things are measured:

1. Connection setup, repeated --handshakes times:
     tcp_ms   time for the TCP three-way handshake (connect() returning)
     tls_ms   time for the TLS 1.3 handshake on top of that connection
              (zero in plaintext mode)
     total_ms tcp_ms + tls_ms, the time before the first message can be sent

2. Message round-trip time, repeated --messages times:
     A message is sent to the echo bot in the Client 2 namespace through the
     relay server, and the time until the echo comes back is recorded. The
     path is Client 1 -> server -> Client 2 -> server -> Client 1, so every
     round trip crosses the impaired transit link twice. Both timestamps are
     taken in this process with the monotonic clock.

3. Bytes on the wire per message:
     The kernel's byte counters of this namespace's network interface are
     read before and after the message phase. The difference divided by the
     number of messages gives the bytes sent and received per round trip,
     including TCP/IP headers, TLS records, end-to-end encryption overhead,
     acknowledgements and any retransmissions.

Usage (inside the Client 1 namespace, with server and echo bot running):
    python src/bench_client.py --mode tls_e2e --handshakes 20 --messages 50
Modes: plain, tls, tls_e2e
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import statistics
import sys
import time
from pathlib import Path

from crypto_e2e import E2EIdentity
from protocol import DEFAULT_PORT, read_message, send_message
from tls_config import client_context

ECHO_NAME = "echo"
MODES = ("plain", "tls", "tls_e2e")

# A fixed 100 character message, so every run sends identical content.
PAYLOAD = ("Secure messaging benchmark payload. " * 3)[:100]


def network_interface() -> str:
    """The single non-loopback interface of the namespace this process runs in."""
    names = [name for name in os.listdir("/sys/class/net") if name != "lo"]
    if len(names) != 1:
        raise RuntimeError(f"expected one network interface in this namespace, found {names}")
    return names[0]


def read_byte_counters(interface: str) -> tuple[int, int]:
    base = Path("/sys/class/net") / interface / "statistics"
    return int((base / "tx_bytes").read_text()), int((base / "rx_bytes").read_text())


def measure_handshakes(args: argparse.Namespace, count: int) -> dict[str, list[float]]:
    tls = client_context(args.cert) if args.mode != "plain" else None
    results: dict[str, list[float]] = {"tcp_ms": [], "tls_ms": [], "total_ms": []}

    for _ in range(count):
        start = time.perf_counter_ns()
        raw_socket = socket.create_connection((args.server, args.port), timeout=args.timeout)
        tcp_done = time.perf_counter_ns()
        if tls is not None:
            # wrap_socket performs the complete TLS 1.3 handshake before returning.
            connection = tls.wrap_socket(raw_socket, server_hostname=args.server)
        else:
            connection = raw_socket
        tls_done = time.perf_counter_ns()
        connection.close()

        results["tcp_ms"].append((tcp_done - start) / 1e6)
        results["tls_ms"].append((tls_done - tcp_done) / 1e6)
        results["total_ms"].append((tls_done - start) / 1e6)
    return results


async def measure_messages(args: argparse.Namespace, count: int) -> dict:
    tls = client_context(args.cert) if args.mode != "plain" else None
    identity = E2EIdentity() if args.mode == "tls_e2e" else None

    reader, writer = await asyncio.wait_for(asyncio.open_connection(
        args.server, args.port, ssl=tls, server_hostname=args.server if tls else None), args.timeout)
    await send_message(writer, {"type": "hello", "name": "bench",
                                "public_key": identity.public_key_b64 if identity else None})

    # Wait until the echo bot is known, together with its public key.
    echo_key: str | None = None
    echo_online = False
    deadline = time.monotonic() + args.timeout
    while not echo_online:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("the echo bot did not appear on the server")
        message = await asyncio.wait_for(read_message(reader), remaining)
        if message is None:
            raise ConnectionError("server closed the connection")
        if message.get("type") == "welcome":
            for peer in message["peers"]:
                if peer["name"] == ECHO_NAME:
                    echo_online, echo_key = True, peer.get("public_key")
        elif message.get("type") == "peer_joined" and message["name"] == ECHO_NAME:
            echo_online, echo_key = True, message.get("public_key")
        elif message.get("type") == "error":
            raise ConnectionError(message.get("reason"))
    if identity is not None and echo_key is None:
        raise RuntimeError("echo bot has no end-to-end key, start it without --no-e2e")

    interface = network_interface()
    tx_before, rx_before = read_byte_counters(interface)
    rtts: list[float] = []

    for msg_id in range(1, count + 1):
        body = identity.encrypt(PAYLOAD, echo_key) if identity else PAYLOAD
        sent = time.perf_counter_ns()
        await send_message(writer, {"type": "send", "to": ECHO_NAME, "body": body,
                                    "encrypted": identity is not None, "msg_id": msg_id,
                                    "sent_ns": time.monotonic_ns()})
        while True:
            reply = await asyncio.wait_for(read_message(reader), args.timeout)
            if reply is None:
                raise ConnectionError("server closed the connection")
            if reply.get("type") == "deliver" and reply.get("msg_id") == msg_id:
                break
        if identity is not None:
            # Decrypting the echo is part of the cost the user experiences.
            identity.decrypt(reply["body"], echo_key)
        rtts.append((time.perf_counter_ns() - sent) / 1e6)

    # Give the final TCP acknowledgements time to arrive before reading the counters.
    await asyncio.sleep(0.2)
    tx_after, rx_after = read_byte_counters(interface)
    writer.close()

    return {
        "rtt_ms": rtts,
        "wire_bytes_per_message": (tx_after - tx_before + rx_after - rx_before) / count,
        "payload_bytes": len(PAYLOAD.encode("utf-8")),
    }


def summarise(values: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Measurement client for the experiments.")
    parser.add_argument("--mode", choices=MODES, required=True, help="security mode to measure")
    parser.add_argument("--server", default="10.0.2.10", help="relay server address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="relay server port")
    parser.add_argument("--cert", type=Path, default=Path("certs/server.crt"), help="trusted server certificate")
    parser.add_argument("--handshakes", type=int, default=20, help="connections to open for setup timing")
    parser.add_argument("--messages", type=int, default=50, help="messages to send for round-trip timing")
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for any single step")
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        handshakes = measure_handshakes(args, args.handshakes)
        messages = asyncio.run(measure_messages(args, args.messages))
    except (OSError, TimeoutError, RuntimeError, ConnectionError) as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1

    print(json.dumps({
        "mode": args.mode,
        "handshake": {name: summarise(values) for name, values in handshakes.items()},
        "message_rtt_ms": summarise(messages["rtt_ms"]),
        "wire_bytes_per_message": messages["wire_bytes_per_message"],
        "payload_bytes": messages["payload_bytes"],
        "samples": {"handshakes": args.handshakes, "messages": args.messages},
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
