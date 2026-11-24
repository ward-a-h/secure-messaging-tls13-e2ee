"""
server.py

Relay server for the secure messaging system.

The server accepts client connections over TLS 1.3, keeps a directory of
connected clients and their public keys, and forwards each message to its
recipient. It reads only the routing fields of a message. The message body
is copied to the recipient unchanged, so when clients use end-to-end
encryption the server forwards ciphertext it cannot decrypt.

Usage (inside the server namespace):
    python src/server.py                     # TLS 1.3 on 0.0.0.0:8443
    python src/server.py --plain             # plaintext TCP baseline
    python src/server.py --port 9000 --cert certs/server.crt --key certs/server.key
    python src/server.py --log-level WARNING  # quiet mode used by the experiments
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import ssl
from dataclasses import dataclass
from pathlib import Path

from protocol import DEFAULT_PORT, ProtocolError, read_message, send_message
from tls_config import server_context

log = logging.getLogger("server")


@dataclass
class ConnectedClient:
    name: str
    public_key: str | None
    writer: asyncio.StreamWriter


class RelayServer:
    def __init__(self) -> None:
        # Directory of connected clients, keyed by client name.
        self.clients: dict[str, ConnectedClient] = {}

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer_address = writer.get_extra_info("peername")
        tls_object = writer.get_extra_info("ssl_object")
        if tls_object is not None:
            log.info("TLS connection from %s:%s using %s, cipher %s",
                     peer_address[0], peer_address[1], tls_object.version(), tls_object.cipher()[0])
        else:
            log.info("Plain TCP connection from %s:%s", peer_address[0], peer_address[1])

        client: ConnectedClient | None = None
        try:
            client = await self._register(reader, writer)
            if client is None:
                return
            await self._relay_loop(client, reader)
        except ProtocolError as exc:
            log.warning("Protocol error from %s: %s", peer_address[0], exc)
            await self._try_send(writer, {"type": "error", "reason": str(exc)})
        except (ConnectionError, ssl.SSLError) as exc:
            log.warning("Connection with %s lost: %s", peer_address[0], exc)
        finally:
            if client is not None and self.clients.get(client.name) is client:
                del self.clients[client.name]
                log.info("%s disconnected", client.name)
                await self._broadcast({"type": "peer_left", "name": client.name}, exclude=client.name)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass

    async def _register(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> ConnectedClient | None:
        """The first message on every connection must be a hello."""
        hello = await read_message(reader)
        if hello is None:
            return None
        if hello.get("type") != "hello" or not isinstance(hello.get("name"), str) or not hello["name"]:
            raise ProtocolError("first message must be a hello with a non-empty name")

        name = hello["name"]
        if name in self.clients:
            await send_message(writer, {"type": "error", "reason": f"name '{name}' is already in use"})
            log.warning("Rejected duplicate name %s", name)
            return None

        client = ConnectedClient(name=name, public_key=hello.get("public_key"), writer=writer)
        peers = [{"name": c.name, "public_key": c.public_key} for c in self.clients.values()]
        self.clients[name] = client

        await send_message(writer, {"type": "welcome", "name": name, "peers": peers})
        await self._broadcast({"type": "peer_joined", "name": name, "public_key": client.public_key}, exclude=name)
        log.info("%s registered (public key %s), %d client(s) online",
                 name, "provided" if client.public_key else "not provided", len(self.clients))
        return client

    async def _relay_loop(self, sender: ConnectedClient, reader: asyncio.StreamReader) -> None:
        while True:
            message = await read_message(reader)
            if message is None:
                return
            if message.get("type") != "send":
                raise ProtocolError(f"unexpected message type '{message.get('type')}'")

            recipient_name = message.get("to")
            recipient = self.clients.get(recipient_name)
            if recipient is None:
                await send_message(sender.writer, {"type": "error", "reason": f"no client named '{recipient_name}'"})
                continue

            body = message.get("body", "")
            encrypted = bool(message.get("encrypted", False))
            await send_message(recipient.writer, {
                "type": "deliver",
                "from": sender.name,
                "body": body,
                "encrypted": encrypted,
                "msg_id": message.get("msg_id"),
                "sent_ns": message.get("sent_ns"),
            })

            # The log records what the server is able to see. With end-to-end
            # encryption on, the body is ciphertext, so only a short prefix is
            # shown to prove it is unreadable.
            preview = body[:24] + ("..." if len(body) > 24 else "")
            log.info("Relayed %s -> %s | %d bytes | encrypted=%s | body as seen by server: %r",
                     sender.name, recipient.name, len(body), encrypted, preview)

    def disconnect_all(self) -> None:
        """Close every client connection, used when the server shuts down."""
        for client in list(self.clients.values()):
            client.writer.close()

    async def _broadcast(self, message: dict, exclude: str | None = None) -> None:
        for client in list(self.clients.values()):
            if client.name != exclude:
                await self._try_send(client.writer, message)

    @staticmethod
    async def _try_send(writer: asyncio.StreamWriter, message: dict) -> None:
        try:
            await send_message(writer, message)
        except (ConnectionError, ssl.SSLError):
            pass


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TLS 1.3 relay server for end-to-end encrypted messaging.")
    parser.add_argument("--host", default="0.0.0.0", help="address to listen on (default: all interfaces)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"TCP port (default: {DEFAULT_PORT})")
    parser.add_argument("--cert", type=Path, default=Path("certs/server.crt"), help="server certificate file")
    parser.add_argument("--key", type=Path, default=Path("certs/server.key"), help="server private key file")
    parser.add_argument("--plain", action="store_true", help="disable TLS (plaintext baseline for experiments)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="WARNING turns off the per-message log lines, so logging does not add to measured latency")
    return parser.parse_args()


async def main() -> None:
    args = parse_arguments()
    logging.basicConfig(level=args.log_level, format="%(asctime)s [%(name)s] %(message)s", datefmt="%H:%M:%S")

    tls = None if args.plain else server_context(args.cert, args.key)
    relay = RelayServer()
    server = await asyncio.start_server(relay.handle_connection, args.host, args.port, ssl=tls)

    mode = "plaintext TCP (baseline)" if args.plain else "TLS 1.3"
    # Printed directly so it appears at every log level. The experiment
    # runner waits for this line before starting the clients.
    print(f"Relay server listening on {args.host}:{args.port} using {mode}", flush=True)

    # Stop cleanly on Ctrl+C or a termination signal.
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    async with server:
        await stop.wait()
        log.info("Shutting down, disconnecting %d client(s)", len(relay.clients))
        server.close()
        relay.disconnect_all()
    log.info("Relay server stopped")


if __name__ == "__main__":
    asyncio.run(main())
