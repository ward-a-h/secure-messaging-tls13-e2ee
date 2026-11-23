"""
client.py

Interactive chat client for the secure messaging system.

The client connects to the relay server over TLS 1.3, registers under a
name, and then sends and receives messages. Type a message and press Enter
to send it to the other client. If more than one peer is online, address a
specific peer with "@name message".

Commands:
    /peers   list the clients that are currently online
    /quit    disconnect and exit

Usage (inside a client namespace):
    python src/client.py --name client1 --server 10.0.2.10
    python src/client.py --name client1 --server 10.0.2.10 --plain   # plaintext baseline
"""

from __future__ import annotations

import argparse
import asyncio
import itertools
import ssl
import sys
import time
from pathlib import Path

from protocol import DEFAULT_PORT, ProtocolError, read_message, send_message
from tls_config import client_context


class ChatClient:
    def __init__(self, name: str) -> None:
        self.name = name
        self.peers: dict[str, str | None] = {}   # peer name -> public key
        self.message_ids = itertools.count(1)
        self.writer: asyncio.StreamWriter | None = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    async def connect(self, server: str, port: int, tls: ssl.SSLContext | None) -> asyncio.StreamReader:
        # server_hostname makes TLS check that the certificate is valid for
        # the exact address we are connecting to.
        reader, writer = await asyncio.open_connection(
            server, port, ssl=tls, server_hostname=server if tls else None)
        self.writer = writer

        tls_object = writer.get_extra_info("ssl_object")
        if tls_object is not None:
            print(f"[info] Connected to {server}:{port} using {tls_object.version()}, cipher {tls_object.cipher()[0]}")
        else:
            print(f"[info] Connected to {server}:{port} using plaintext TCP (no TLS)")

        await send_message(writer, {"type": "hello", "name": self.name, "public_key": None})
        welcome = await read_message(reader)
        if welcome is None or welcome.get("type") != "welcome":
            reason = (welcome or {}).get("reason", "server closed the connection")
            raise ProtocolError(f"registration failed: {reason}")

        for peer in welcome["peers"]:
            self.peers[peer["name"]] = peer.get("public_key")
        print(f"[info] Registered as '{self.name}'. Online peers: {self._peer_list()}")
        return reader

    # ------------------------------------------------------------------
    # Receiving
    # ------------------------------------------------------------------

    async def receive_loop(self, reader: asyncio.StreamReader) -> None:
        while True:
            message = await read_message(reader)
            if message is None:
                print("[info] Server closed the connection")
                return
            self._handle_incoming(message)

    def _handle_incoming(self, message: dict) -> None:
        kind = message.get("type")
        if kind == "deliver":
            latency_ms = None
            if isinstance(message.get("sent_ns"), int):
                latency_ms = (time.time_ns() - message["sent_ns"]) / 1_000_000
            timing = f" ({latency_ms:.2f} ms)" if latency_ms is not None else ""
            print(f"\n{message['from']}: {message['body']}{timing}")
        elif kind == "peer_joined":
            self.peers[message["name"]] = message.get("public_key")
            print(f"\n[info] {message['name']} joined")
        elif kind == "peer_left":
            self.peers.pop(message["name"], None)
            print(f"\n[info] {message['name']} left")
        elif kind == "error":
            print(f"\n[error] {message.get('reason')}")
        else:
            print(f"\n[warning] Ignored unknown message type '{kind}'")

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    async def input_loop(self) -> None:
        """
        Read lines typed by the user and send them.

        The keyboard is watched with add_reader(), so the event loop is told
        when a full line is ready and receiving continues while the user types.
        """
        loop = asyncio.get_running_loop()
        lines: asyncio.Queue[str] = asyncio.Queue()
        loop.add_reader(sys.stdin, lambda: lines.put_nowait(sys.stdin.readline()))
        try:
            while True:
                line = await lines.get()
                if not line:
                    return  # end of input (Ctrl+D)
                line = line.strip()
                if not line:
                    continue
                if line == "/quit":
                    return
                if line == "/peers":
                    print(f"[info] Online peers: {self._peer_list()}")
                    continue
                await self._send_chat(line)
        finally:
            loop.remove_reader(sys.stdin)

    async def _send_chat(self, line: str) -> None:
        recipient, text = self._resolve_recipient(line)
        if recipient is None:
            return
        await send_message(self.writer, {
            "type": "send",
            "to": recipient,
            "body": text,
            "encrypted": False,
            "msg_id": next(self.message_ids),
            "sent_ns": time.time_ns(),
        })

    def _resolve_recipient(self, line: str) -> tuple[str | None, str]:
        if line.startswith("@"):
            name, _, text = line[1:].partition(" ")
            if name not in self.peers:
                print(f"[error] No peer named '{name}'. Online peers: {self._peer_list()}")
                return None, ""
            return name, text
        if len(self.peers) == 1:
            return next(iter(self.peers)), line
        if not self.peers:
            print("[error] No other client is online yet")
        else:
            print(f"[error] Several peers online, use @name. Online peers: {self._peer_list()}")
        return None, ""

    def _peer_list(self) -> str:
        return ", ".join(sorted(self.peers)) or "none"

    async def close(self) -> None:
        if self.writer is not None:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Chat client for the TLS 1.3 relay server.")
    parser.add_argument("--name", required=True, help="name to register under, for example client1")
    parser.add_argument("--server", default="10.0.2.10", help="relay server address (default: 10.0.2.10)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"relay server port (default: {DEFAULT_PORT})")
    parser.add_argument("--cert", type=Path, default=Path("certs/server.crt"), help="trusted server certificate")
    parser.add_argument("--plain", action="store_true", help="disable TLS (plaintext baseline for experiments)")
    return parser.parse_args()


async def main() -> int:
    args = parse_arguments()
    tls = None if args.plain else client_context(args.cert)
    client = ChatClient(args.name)

    try:
        reader = await client.connect(args.server, args.port, tls)
    except ssl.SSLCertVerificationError as exc:
        print(f"[error] Server certificate rejected: {exc.verify_message}")
        return 1
    except (OSError, ProtocolError) as exc:
        print(f"[error] Could not connect: {exc}")
        return 1

    print("[info] Type a message and press Enter. Commands: /peers, /quit")
    receiver = asyncio.create_task(client.receive_loop(reader))
    sender = asyncio.create_task(client.input_loop())
    done, pending = await asyncio.wait({receiver, sender}, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await client.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
