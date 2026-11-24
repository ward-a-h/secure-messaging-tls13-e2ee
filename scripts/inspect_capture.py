"""
inspect_capture.py

Prints the application messages found inside a capture, after the TLS layer
has been removed, so it is easy to see exactly what the relay server and an
on-path observer holding the TLS keys are able to read.

The capture must be one of the "<name>_with_keys.pcapng" files written by
capture.sh, or a plaintext baseline capture. tshark decrypts the TLS records
using the secrets embedded in the file, and this script then splits the
decrypted byte stream into the length-prefixed JSON frames defined in
src/protocol.py.

Usage:
    python scripts/inspect_capture.py captures/tls13_e2e_session_with_keys.pcapng
    python scripts/inspect_capture.py captures/plaintext_baseline.pcapng --full

Requires: tshark
"""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
import sys
from pathlib import Path

PORT = 8443
BODY_PREVIEW_CHARS = 40


def read_payloads(capture: Path) -> list[tuple[str, str, str, bytes]]:
    """
    Return (frame number, source, destination, payload bytes) for every packet
    that carries application bytes on the relay port, after TLS decryption.
    """
    command = [
        "tshark", "-r", str(capture),
        "-d", f"tcp.port=={PORT},data" if "with_keys" not in capture.name else f"tcp.port=={PORT},tls",
        "-Y", "data",
        "-T", "fields", "-E", "separator=\t",
        "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "data.data",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        sys.exit(f"tshark failed: {result.stderr.strip()}")

    payloads = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or not parts[3]:
            continue
        # A packet can contain several decrypted records; tshark joins their
        # data fields with commas.
        data = b"".join(bytes.fromhex(chunk) for chunk in parts[3].split(","))
        payloads.append((parts[0], parts[1], parts[2], data))
    return payloads


def split_frames(stream: bytes) -> tuple[list[dict], bytes]:
    """Split a byte stream into protocol frames. Returns the frames and any unfinished remainder."""
    frames = []
    while len(stream) >= 4:
        (length,) = struct.unpack("!I", stream[:4])
        if len(stream) < 4 + length:
            break
        body = stream[4:4 + length]
        stream = stream[4 + length:]
        try:
            frames.append(json.loads(body.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            frames.append({"type": "<not a protocol frame>"})
    return frames, stream


def describe(message: dict, full: bool) -> str:
    kind = message.get("type", "?")
    if kind == "hello":
        has_key = "with public key" if message.get("public_key") else "no public key"
        return f"hello        name={message.get('name')} ({has_key})"
    if kind in ("send", "deliver"):
        body = str(message.get("body", ""))
        if not full and len(body) > BODY_PREVIEW_CHARS:
            body = body[:BODY_PREVIEW_CHARS] + "..."
        route = f"to={message.get('to')}" if kind == "send" else f"from={message.get('from')}"
        return f"{kind:<12} {route} encrypted={message.get('encrypted')} body={body!r}"
    if kind == "welcome":
        peers = ", ".join(p.get("name", "?") for p in message.get("peers", [])) or "none"
        return f"welcome      name={message.get('name')} peers=[{peers}]"
    if kind in ("peer_joined", "peer_left"):
        return f"{kind:<12} name={message.get('name')}"
    return f"{kind:<12} {json.dumps(message)[:80]}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Show the protocol messages inside a capture.")
    parser.add_argument("capture", type=Path, help="pcapng file to inspect")
    parser.add_argument("--full", action="store_true", help="show complete message bodies")
    args = parser.parse_args()

    if not args.capture.is_file():
        sys.exit(f"File not found: {args.capture}")

    # Bytes are buffered per direction, because one protocol frame can span
    # several packets and one packet can hold several frames.
    buffers: dict[tuple[str, str], bytes] = {}
    found = 0
    print(f"{'Frame':>5}  {'Source':<10} -> {'Destination':<11}  Message")
    for frame_number, source, destination, data in read_payloads(args.capture):
        key = (source, destination)
        frames, buffers[key] = split_frames(buffers.get(key, b"") + data)
        for message in frames:
            found += 1
            print(f"{frame_number:>5}  {source:<10} -> {destination:<11}  {describe(message, args.full)}")

    if found == 0:
        print("No protocol messages found. If this is a TLS capture, use the *_with_keys.pcapng copy.")


if __name__ == "__main__":
    main()
