"""
echo_bot.py

Automatic responder used by the experiments.

The echo bot connects to the relay server like a normal client and
registers under the name "echo". Every message it receives is sent straight
back to its sender. When end-to-end encryption is on, the bot decrypts the
message and encrypts the reply again for the sender, so each round trip
includes the full cost of end-to-end encryption on both sides.

Measuring round trips from a single sender avoids comparing clocks across
processes: the sender records when a message leaves and when its echo comes
back, both on the same clock.

Usage (inside the Client 2 namespace):
    python src/echo_bot.py                      # TLS 1.3 + end-to-end
    python src/echo_bot.py --no-e2e             # TLS 1.3 only
    python src/echo_bot.py --plain --no-e2e     # plaintext baseline
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import ssl
import sys
from pathlib import Path

from crypto_e2e import E2EError, E2EIdentity
from protocol import DEFAULT_PORT, ProtocolError, read_message, send_message
from tls_config import client_context

BOT_NAME = "echo"


async def run(args: argparse.Namespace) -> int:
    tls = None if args.plain else client_context(args.cert)
    identity = None if args.no_e2e else E2EIdentity()
    peers: dict[str, str | None] = {}

    reader, writer = await asyncio.open_connection(
        args.server, args.port, ssl=tls, server_hostname=args.server if tls else None)
    await send_message(writer, {"type": "hello", "name": BOT_NAME,
                                "public_key": identity.public_key_b64 if identity else None})
    welcome = await read_message(reader)
    if welcome is None or welcome.get("type") != "welcome":
        print(f"[echo] Registration failed: {(welcome or {}).get('reason', 'connection closed')}", file=sys.stderr)
        return 1
    for peer in welcome["peers"]:
        peers[peer["name"]] = peer.get("public_key")
    print(f"[echo] Ready as '{BOT_NAME}' ({'TLS 1.3' if tls else 'plaintext TCP'}, "
          f"end-to-end {'on' if identity else 'off'})", flush=True)

    while True:
        message = await read_message(reader)
        if message is None:
            return 0
        kind = message.get("type")
        if kind == "peer_joined":
            peers[message["name"]] = message.get("public_key")
        elif kind == "peer_left":
            peers.pop(message["name"], None)
        elif kind == "deliver":
            sender = message["from"]
            body = message.get("body", "")
            if message.get("encrypted"):
                sender_key = peers.get(sender)
                if identity is None or sender_key is None:
                    continue  # cannot decrypt, so cannot answer meaningfully
                try:
                    body = identity.encrypt(identity.decrypt(body, sender_key), sender_key)
                except E2EError:
                    continue
            await send_message(writer, {
                "type": "send",
                "to": sender,
                "body": body,
                "encrypted": bool(message.get("encrypted")),
                "msg_id": message.get("msg_id"),
                "sent_ns": message.get("sent_ns"),
            })


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Echo responder for the latency experiments.")
    parser.add_argument("--server", default="10.0.2.10", help="relay server address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="relay server port")
    parser.add_argument("--cert", type=Path, default=Path("certs/server.crt"), help="trusted server certificate")
    parser.add_argument("--plain", action="store_true", help="disable TLS")
    parser.add_argument("--no-e2e", action="store_true", help="disable end-to-end encryption")
    return parser.parse_args()


async def main() -> int:
    args = parse_arguments()
    task = asyncio.create_task(run(args))
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, task.cancel)
    try:
        return await task
    except asyncio.CancelledError:
        return 0
    except (OSError, ProtocolError, ssl.SSLError) as exc:
        print(f"[echo] Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
