"""
gui_client.py

Desktop chat window for the secure messaging system.

This is a graphical front end for the same client used in the terminal.
It reuses ChatClient from client.py, so the TLS 1.3 connection, the
registration with the relay server and the end-to-end encryption are
exactly the same. Only the way messages are shown and typed is different.

The window shows:
    - the TLS version and cipher suite of the connection to the server
    - this client's end-to-end key fingerprint
    - the online peers and their key fingerprints
    - the conversation, with the delivery time of every received message

Design:
    tkinter must run in the main thread, and the network code runs on an
    asyncio event loop. The event loop therefore runs in a background
    thread. The two sides talk through a queue: the network thread puts
    events on it, and the window checks the queue every 50 ms and updates
    the display. Sending works the other way round: the window hands the
    message to the event loop with run_coroutine_threadsafe().

Commands typed in the message box:
    /keys    show the key fingerprints in the conversation
    /quit    disconnect and close the window
    @name    address a specific peer when more than one is online

Usage (inside a client namespace, same options as client.py):
    sudo ./scripts/run_in_ns.sh c1 .venv/bin/python src/gui_client.py --name client1
    sudo ./scripts/run_in_ns.sh c2 .venv/bin/python src/gui_client.py --name client2

Requirements:
    sudo apt install -y python3-tk
"""

from __future__ import annotations

import argparse
import asyncio
import os
import queue
import ssl
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import font as tkfont

from client import ChatClient
from crypto_e2e import E2EError, fingerprint
from protocol import DEFAULT_PORT, ProtocolError, send_message
from tls_config import client_context

# sudo removes DISPLAY from the environment. On WSL the desktop is always
# display :0, and its X11 socket file is reachable from every namespace.
os.environ.setdefault("DISPLAY", ":0")

# Colours used in the window (dark theme).
COLOUR_BACKGROUND = "#000000"
COLOUR_PANEL = "#0d0d0d"
COLOUR_CARD = "#1a1a1a"
COLOUR_BORDER = "#2a2a2a"
COLOUR_TEXT = "#f0f0f0"
COLOUR_MUTED = "#9a9a9a"
COLOUR_NAME = "#2f6fd1"          # peer names: bold dark blue
COLOUR_OWN_BUBBLE = "#2f6fd1"
COLOUR_PEER_BUBBLE = "#1e1e1e"
COLOUR_ERROR = "#f28b82"
STATUS_COLOURS = {
    "tls": ("#0f2e1a", "#7ddc95"),      # background, text
    "plain": ("#3a1210", "#f28b82"),
    "cipher": ("#1e1e1e", "#bbbbbb"),
    "e2e": ("#0f2340", "#8ab8f0"),
    "no_e2e": ("#3a2a05", "#f2c46b"),
}


class GuiChatClient(ChatClient):
    """
    ChatClient that reports to the window instead of printing.

    Every incoming message is turned into an event tuple and put on the
    queue. The window is the only place that reads the queue.
    """

    def __init__(self, name: str, use_e2e: bool, events: queue.Queue) -> None:
        super().__init__(name, use_e2e)
        self.events = events

    async def receive_loop(self, reader: asyncio.StreamReader) -> None:
        try:
            await super().receive_loop(reader)
        except (ConnectionError, ssl.SSLError, ProtocolError) as exc:
            self.events.put(("error", f"Connection lost: {exc}"))
        self.events.put(("closed",))

    def _handle_incoming(self, message: dict) -> None:
        kind = message.get("type")
        if kind == "deliver":
            self.events.put(("received", *self._decode_delivery(message)))
        elif kind == "peer_joined":
            self.peers[message["name"]] = message.get("public_key")
            self.events.put(("info", f"{message['name']} joined"))
            self.events.put(("peers",))
        elif kind == "peer_left":
            self.peers.pop(message["name"], None)
            self.events.put(("info", f"{message['name']} left"))
            self.events.put(("peers",))
        elif kind == "error":
            self.events.put(("error", message.get("reason", "unknown error from server")))
        else:
            self.events.put(("error", f"Ignored unknown message type '{kind}'"))

    def _decode_delivery(self, message: dict) -> tuple[str, str, bool, float | None]:
        """Return (sender, text, was_encrypted, latency_ms) for a delivered message."""
        sender = message.get("from", "?")
        body = message.get("body", "")
        encrypted = bool(message.get("encrypted"))

        if encrypted:
            sender_key = self.peers.get(sender)
            if self.identity is None:
                text = "<encrypted message, but end-to-end encryption is off on this client>"
            elif sender_key is None:
                text = f"<encrypted message, but no public key is known for {sender}>"
            else:
                try:
                    text = self.identity.decrypt(body, sender_key)
                except E2EError as exc:
                    text = f"<rejected: {exc}>"
        else:
            text = body

        # Same one-way latency measurement as the terminal client: both
        # namespaces share the monotonic clock of the machine.
        latency_ms = None
        if isinstance(message.get("sent_ns"), int):
            latency_ms = (time.monotonic_ns() - message["sent_ns"]) / 1_000_000
        return sender, text, encrypted, latency_ms

    async def send_text(self, line: str) -> None:
        """Encrypt (when end-to-end is on) and send one chat message."""
        recipient, text = self._pick_recipient(line)
        if recipient is None:
            return

        body, encrypted = text, False
        if self.identity is not None:
            recipient_key = self.peers.get(recipient)
            if recipient_key is None:
                self.events.put(("error", f"{recipient} has end-to-end encryption off. Message not sent."))
                return
            body, encrypted = self.identity.encrypt(text, recipient_key), True

        try:
            await send_message(self.writer, {
                "type": "send",
                "to": recipient,
                "body": body,
                "encrypted": encrypted,
                "msg_id": next(self.message_ids),
                "sent_ns": time.monotonic_ns(),
            })
        except (ConnectionError, ssl.SSLError) as exc:
            self.events.put(("error", f"Message not sent: {exc}"))
            return
        self.events.put(("sent", recipient, text, encrypted))

    def _pick_recipient(self, line: str) -> tuple[str | None, str]:
        """Same addressing rules as the terminal client, reported as events."""
        if line.startswith("@"):
            name, _, text = line[1:].partition(" ")
            if name not in self.peers:
                self.events.put(("error", f"No peer named '{name}'"))
                return None, ""
            return name, text
        if len(self.peers) == 1:
            return next(iter(self.peers)), line
        if not self.peers:
            self.events.put(("error", "No other client is online yet"))
        else:
            self.events.put(("error", "Several peers are online. Start the message with @name"))
        return None, ""


class NetworkThread(threading.Thread):
    """Runs the asyncio event loop that owns the TLS connection."""

    def __init__(self, client: GuiChatClient, args: argparse.Namespace) -> None:
        super().__init__(daemon=True)
        self.client = client
        self.args = args
        self.loop = asyncio.new_event_loop()
        self.stop_requested = asyncio.Event()

    def run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._session())

    async def _session(self) -> None:
        events = self.client.events
        try:
            tls = None if self.args.plain else client_context(self.args.cert)
            reader = await self.client.connect(self.args.server, self.args.port, tls)
        except ssl.SSLCertVerificationError as exc:
            events.put(("fatal", f"Server certificate rejected: {exc.verify_message}"))
            return
        except (OSError, ProtocolError, ssl.SSLError) as exc:
            events.put(("fatal", f"Could not connect: {exc}"))
            return

        tls_object = self.client.writer.get_extra_info("ssl_object")
        if tls_object is not None:
            events.put(("connected", tls_object.version(), tls_object.cipher()[0]))
        else:
            events.put(("connected", None, None))
        events.put(("peers",))

        receiver = asyncio.create_task(self.client.receive_loop(reader))
        stopper = asyncio.create_task(self.stop_requested.wait())
        _, pending = await asyncio.wait({receiver, stopper}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await self.client.close()

    def send(self, line: str) -> None:
        asyncio.run_coroutine_threadsafe(self.client.send_text(line), self.loop)

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.stop_requested.set)


class ChatWindow:
    """The tkinter window. Reads events from the queue and draws them."""

    POLL_MS = 50

    def __init__(self, root: tk.Tk, client: GuiChatClient, network: NetworkThread, args: argparse.Namespace) -> None:
        self.root = root
        self.client = client
        self.network = network
        self.args = args

        base = tkfont.nametofont("TkDefaultFont")
        base.configure(size=11)
        self.font = base
        self.font_bold = base.copy()
        self.font_bold.configure(weight="bold")
        self.font_small = base.copy()
        self.font_small.configure(size=9)
        self.font_mono = tkfont.nametofont("TkFixedFont").copy()
        self.font_mono.configure(size=9)

        root.title(f"Secure chat: {client.name}")
        root.geometry("820x520")
        root.minsize(640, 400)
        root.configure(bg=COLOUR_BACKGROUND)
        root.protocol("WM_DELETE_WINDOW", self.quit)

        self._build_status_bar()
        self._build_body()
        self._show_info(f"Connecting to {args.server}:{args.port} ...")
        root.after(self.POLL_MS, self._poll_events)

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_status_bar(self) -> None:
        # Two rows, so the fingerprint is not cut off in a half-screen window.
        top = tk.Frame(self.root, bg=COLOUR_BACKGROUND, padx=10, pady=8)
        top.pack(side=tk.TOP, fill=tk.X)
        row1 = tk.Frame(top, bg=COLOUR_BACKGROUND)
        row1.pack(side=tk.TOP, fill=tk.X)
        row2 = tk.Frame(top, bg=COLOUR_BACKGROUND)
        row2.pack(side=tk.TOP, fill=tk.X, pady=(6, 0))
        self.status_tls = self._pill(row1, "Connecting ...", "cipher")
        self.status_cipher = self._pill(row1, "", "cipher")
        self.status_e2e = self._pill(row2, "", "cipher")
        tk.Frame(self.root, bg=COLOUR_BORDER, height=1).pack(side=tk.TOP, fill=tk.X)

    def _pill(self, parent: tk.Widget, text: str, style: str) -> tk.Label:
        background, foreground = STATUS_COLOURS[style]
        label = tk.Label(parent, text=text, bg=background, fg=foreground, font=self.font_small, padx=8, pady=3)
        if text:
            label.pack(side=tk.LEFT, padx=(0, 6))
        return label

    def _set_pill(self, label: tk.Label, text: str, style: str) -> None:
        background, foreground = STATUS_COLOURS[style]
        label.configure(text=text, bg=background, fg=foreground)
        # Empty pills stay hidden until they have something to show.
        if text and not label.winfo_ismapped():
            label.pack(side=tk.LEFT, padx=(0, 6))

    def _build_body(self) -> None:
        body = tk.Frame(self.root, bg=COLOUR_BACKGROUND)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Left pane: online peers and their fingerprints.
        side = tk.Frame(body, bg=COLOUR_PANEL, width=200, padx=10, pady=10)
        side.pack(side=tk.LEFT, fill=tk.Y)
        side.pack_propagate(False)
        tk.Label(side, text="Online peers", bg=COLOUR_PANEL, fg=COLOUR_MUTED, font=self.font_small,
                 anchor="w").pack(fill=tk.X)
        self.peer_frame = tk.Frame(side, bg=COLOUR_PANEL)
        self.peer_frame.pack(fill=tk.X, pady=(6, 0))
        tk.Label(side, text="Compare fingerprints with your peer over another channel to rule out a key swap.",
                 bg=COLOUR_PANEL, fg=COLOUR_MUTED, font=self.font_small, justify=tk.LEFT, wraplength=175,
                 anchor="w").pack(side=tk.BOTTOM, fill=tk.X)
        tk.Frame(body, bg=COLOUR_BORDER, width=1).pack(side=tk.LEFT, fill=tk.Y)

        # Right pane: conversation and message box.
        chat = tk.Frame(body, bg=COLOUR_BACKGROUND, padx=10, pady=10)
        chat.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        entry_row = tk.Frame(chat, bg=COLOUR_BACKGROUND)
        entry_row.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 0))
        self.entry = tk.Entry(entry_row, font=self.font, relief=tk.FLAT, bd=0, bg=COLOUR_CARD, fg=COLOUR_TEXT,
                              insertbackground=COLOUR_TEXT, disabledbackground=COLOUR_PANEL,
                              highlightthickness=1, highlightbackground=COLOUR_BORDER, highlightcolor=COLOUR_NAME)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        self.entry.bind("<Return>", lambda _event: self._on_send())
        self.send_button = tk.Button(entry_row, text="Send", font=self.font_bold, command=self._on_send, padx=14,
                                     bg=COLOUR_OWN_BUBBLE, fg="#ffffff", activebackground="#2559a8",
                                     activeforeground="#ffffff", disabledforeground="#6f8fc0",
                                     relief=tk.FLAT, bd=0, highlightthickness=0)
        self.send_button.pack(side=tk.LEFT, padx=(8, 0))
        self.entry.configure(state=tk.DISABLED)
        self.send_button.configure(state=tk.DISABLED)

        scrollbar = tk.Scrollbar(chat, bg=COLOUR_CARD, troughcolor=COLOUR_BACKGROUND, activebackground=COLOUR_BORDER,
                                 highlightthickness=0, bd=0)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log = tk.Text(chat, wrap=tk.WORD, bg=COLOUR_BACKGROUND, fg=COLOUR_TEXT, font=self.font,
                           relief=tk.FLAT, padx=6, pady=6, yscrollcommand=scrollbar.set, cursor="arrow",
                           highlightthickness=0, insertbackground=COLOUR_TEXT)
        self.log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.configure(command=self.log.yview)

        self.log.tag_configure("info", justify=tk.CENTER, foreground=COLOUR_MUTED, font=self.font_small,
                               spacing1=4, spacing3=4)
        self.log.tag_configure("error", justify=tk.CENTER, foreground=COLOUR_ERROR, font=self.font_small,
                               spacing1=4, spacing3=4)
        # A right-aligned line takes its layout from "own_line". The bubble
        # colour sits on "own", which covers only the message text.
        self.log.tag_configure("own_line", justify=tk.RIGHT, rmargin=8, spacing1=8)
        self.log.tag_configure("own", background=COLOUR_OWN_BUBBLE, foreground="#ffffff")
        self.log.tag_configure("own_meta", justify=tk.RIGHT, foreground=COLOUR_MUTED, font=self.font_small,
                               rmargin=8, spacing3=4)
        self.log.tag_configure("peer", justify=tk.LEFT, background=COLOUR_PEER_BUBBLE, foreground=COLOUR_TEXT,
                               lmargin1=8, lmargin2=8, spacing1=8)
        self.log.tag_configure("peer_meta", justify=tk.LEFT, foreground=COLOUR_MUTED, font=self.font_small,
                               lmargin1=8, lmargin2=8, spacing3=4)
        self.log.tag_configure("keys", justify=tk.LEFT, foreground=COLOUR_TEXT, font=self.font_mono,
                               lmargin1=8, lmargin2=8)
        self.log.configure(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # Writing to the conversation
    # ------------------------------------------------------------------

    def _append(self, text: str, tag: str) -> None:
        self.log.configure(state=tk.NORMAL)
        # The newline is inserted without the tag, so a bubble's background
        # covers only its text instead of the whole line.
        self.log.insert(tk.END, text, tag)
        self.log.insert(tk.END, "\n")
        self.log.configure(state=tk.DISABLED)
        self.log.see(tk.END)

    def _show_info(self, text: str) -> None:
        self._append(text, "info")

    def _show_error(self, text: str) -> None:
        self._append(text, "error")

    def _show_own(self, recipient: str, text: str, encrypted: bool) -> None:
        self.log.configure(state=tk.NORMAL)
        # The hair space starts the line without the bubble colour, so the
        # colour does not stretch back to the left edge.
        self.log.insert(tk.END, "\u200a", "own_line")
        self.log.insert(tk.END, f"  {text}  ", ("own_line", "own"))
        self.log.insert(tk.END, "\n")
        self.log.configure(state=tk.DISABLED)
        how = "encrypted end-to-end" if encrypted else "not end-to-end encrypted"
        self._append(f"to {recipient}, {how}", "own_meta")

    def _show_peer(self, sender: str, text: str, encrypted: bool, latency_ms: float | None) -> None:
        self._append(f"  {text}  ", "peer")
        parts = [sender, "e2e" if encrypted else "plain"]
        if latency_ms is not None:
            parts.append(f"{latency_ms:.2f} ms")
        self._append(", ".join(parts), "peer_meta")

    def _show_keys(self) -> None:
        if self.client.identity is None:
            self._show_info("End-to-end encryption is off on this client")
            return
        lines = [f"{self.client.name} (you): {self.client.identity.fingerprint}"]
        for name in sorted(self.client.peers):
            key = self.client.peers[name]
            lines.append(f"{name}: {fingerprint(key) if key else 'no end-to-end key'}")
        self._append("\n".join(lines), "keys")

    def _refresh_peers(self) -> None:
        for widget in self.peer_frame.winfo_children():
            widget.destroy()
        if not self.client.peers:
            tk.Label(self.peer_frame, text="none yet", bg=COLOUR_PANEL, fg=COLOUR_MUTED,
                     font=self.font_small, anchor="w").pack(fill=tk.X)
            return
        for name in sorted(self.client.peers):
            key = self.client.peers[name]
            card = tk.Frame(self.peer_frame, bg=COLOUR_CARD, padx=8, pady=6)
            card.pack(fill=tk.X, pady=(0, 6))
            tk.Label(card, text=name, bg=COLOUR_CARD, fg=COLOUR_NAME, font=self.font_bold, anchor="w").pack(fill=tk.X)
            tk.Label(card, text=fingerprint(key) if key else "no end-to-end key", bg=COLOUR_CARD,
                     fg=COLOUR_MUTED, font=self.font_mono, anchor="w").pack(fill=tk.X)

    # ------------------------------------------------------------------
    # Events and input
    # ------------------------------------------------------------------

    def _poll_events(self) -> None:
        while True:
            try:
                event = self.client.events.get_nowait()
            except queue.Empty:
                break
            self._handle_event(event)
        self.root.after(self.POLL_MS, self._poll_events)

    def _handle_event(self, event: tuple) -> None:
        kind = event[0]
        if kind == "connected":
            self._on_connected(event[1], event[2])
        elif kind == "peers":
            self._refresh_peers()
        elif kind == "received":
            self._show_peer(*event[1:])
        elif kind == "sent":
            self._show_own(*event[1:])
        elif kind == "info":
            self._show_info(event[1])
        elif kind == "error":
            self._show_error(event[1])
        elif kind in ("fatal", "closed"):
            self._show_error(event[1] if kind == "fatal" else "Server closed the connection")
            self._set_pill(self.status_tls, "Disconnected", "plain")
            self.entry.configure(state=tk.DISABLED)
            self.send_button.configure(state=tk.DISABLED)

    def _on_connected(self, version: str | None, cipher: str | None) -> None:
        address = f"{self.args.server}:{self.args.port}"
        if version:
            self._set_pill(self.status_tls, f"{version} to {address}", "tls")
            self._set_pill(self.status_cipher, cipher, "cipher")
        else:
            self._set_pill(self.status_tls, f"Plaintext TCP to {address}", "plain")
            self._set_pill(self.status_cipher, "no TLS", "plain")
        if self.client.identity:
            self._set_pill(self.status_e2e, f"E2E on, you: {self.client.identity.fingerprint}", "e2e")
        else:
            self._set_pill(self.status_e2e, "E2E off, the server can read messages", "no_e2e")

        others = ", ".join(sorted(self.client.peers)) or "none"
        self._show_info(f"Registered as '{self.client.name}'. Online peers: {others}")
        self.entry.configure(state=tk.NORMAL)
        self.send_button.configure(state=tk.NORMAL)
        self.entry.focus_set()

    def _on_send(self) -> None:
        line = self.entry.get().strip()
        if not line:
            return
        self.entry.delete(0, tk.END)
        if line == "/quit":
            self.quit()
        elif line == "/keys":
            self._show_keys()
        elif line == "/peers":
            self._show_info(f"Online peers: {', '.join(sorted(self.client.peers)) or 'none'}")
        else:
            self.network.send(line)

    def quit(self) -> None:
        self.network.stop()
        # Give the event loop a moment to close the TLS connection cleanly.
        self.root.after(200, self.root.destroy)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Desktop chat window for the TLS 1.3 relay server.")
    parser.add_argument("--name", required=True, help="name to register under, for example client1")
    parser.add_argument("--server", default="10.0.2.10", help="relay server address (default: 10.0.2.10)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"relay server port (default: {DEFAULT_PORT})")
    parser.add_argument("--cert", type=Path, default=Path("certs/server.crt"), help="trusted server certificate")
    parser.add_argument("--plain", action="store_true", help="disable TLS (plaintext baseline)")
    parser.add_argument("--no-e2e", action="store_true", help="disable end-to-end encryption (TLS only)")
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"[error] Could not open a window: {exc}")
        print("[error] On WSL this needs Windows 11 (WSLg). Check that 'echo $DISPLAY' prints :0 in a normal tab.")
        return 1

    events: queue.Queue = queue.Queue()
    client = GuiChatClient(args.name, use_e2e=not args.no_e2e, events=events)
    network = NetworkThread(client, args)
    ChatWindow(root, client, network, args)
    network.start()
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
