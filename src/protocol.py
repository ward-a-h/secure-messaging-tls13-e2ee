"""
protocol.py

Message framing and message types shared by the relay server and the clients.

Wire format
-----------
TCP delivers a stream of bytes with no message boundaries, so every message
is sent as a frame:

    +----------------------+------------------------------+
    | length (4 bytes)     | body (length bytes)          |
    | unsigned, big-endian | UTF-8 encoded JSON object    |
    +----------------------+------------------------------+

The receiver first reads exactly 4 bytes to learn the body length, then
reads exactly that many bytes. This guarantees that one call to
read_message() always returns one complete message.

Message types (the "type" field of every JSON object)
-----------------------------------------------------
Client to server:
    hello    {"type": "hello", "name": str, "public_key": str | null}
    send     {"type": "send", "to": str, "body": str, "encrypted": bool,
              "msg_id": int, "sent_ns": int}

Server to client:
    welcome      {"type": "welcome", "name": str, "peers": [peer, ...]}
    peer_joined  {"type": "peer_joined", "name": str, "public_key": str | null}
    peer_left    {"type": "peer_left", "name": str}
    deliver      {"type": "deliver", "from": str, "body": str,
                  "encrypted": bool, "msg_id": int, "sent_ns": int}
    error        {"type": "error", "reason": str}

where peer is {"name": str, "public_key": str | null}.

The server only reads the routing fields ("type", "name", "to"). It copies
"body" to the recipient without inspecting it, so when "encrypted" is true
the server handles ciphertext it has no key for.
"""

from __future__ import annotations

import asyncio
import json
import struct
from typing import Any

# Default TCP port of the relay server, as listed in the addressing plan.
DEFAULT_PORT = 8443

# Frames larger than this are rejected, so a faulty or malicious peer
# cannot make the receiver allocate unlimited memory.
MAX_FRAME_BYTES = 64 * 1024

# "!I" means network byte order (big-endian), unsigned 32-bit integer.
_LENGTH_PREFIX = struct.Struct("!I")


class ProtocolError(Exception):
    """Raised when a peer sends data that does not follow the protocol."""


def encode_message(message: dict[str, Any]) -> bytes:
    """Serialise a message into one length-prefixed frame."""
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise ProtocolError(f"message of {len(body)} bytes exceeds the {MAX_FRAME_BYTES} byte limit")
    return _LENGTH_PREFIX.pack(len(body)) + body


async def send_message(writer: asyncio.StreamWriter, message: dict[str, Any]) -> None:
    """Write one framed message and wait until it has been handed to the OS."""
    writer.write(encode_message(message))
    await writer.drain()


async def read_message(reader: asyncio.StreamReader) -> dict[str, Any] | None:
    """
    Read one framed message.

    Returns the decoded message, or None if the peer closed the connection
    cleanly before a new frame started.
    """
    try:
        header = await reader.readexactly(_LENGTH_PREFIX.size)
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None  # clean close between frames
        raise ProtocolError("connection closed in the middle of a frame header") from exc

    (length,) = _LENGTH_PREFIX.unpack(header)
    if length > MAX_FRAME_BYTES:
        raise ProtocolError(f"incoming frame of {length} bytes exceeds the {MAX_FRAME_BYTES} byte limit")

    try:
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise ProtocolError("connection closed in the middle of a frame body") from exc

    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("frame body is not valid UTF-8 JSON") from exc

    if not isinstance(message, dict) or "type" not in message:
        raise ProtocolError("message must be a JSON object with a 'type' field")
    return message
