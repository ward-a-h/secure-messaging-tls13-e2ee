"""
crypto_e2e.py

End-to-end encryption between clients, built on PyNaCl (libsodium).

Keys
----
Every client creates a fresh X25519 key pair when it starts. The public key
is shared with the other clients through the relay server in the hello
message. The private key never leaves the client, so the server is never
able to decrypt a message.

Encryption
----------
Messages are protected with NaCl's crypto_box construction:

    X25519 key agreement  ->  shared secret between sender and recipient
    XSalsa20 stream cipher ->  confidentiality
    Poly1305 MAC          ->  integrity and authenticity

The encrypted output is laid out as:

    +-----------------+-------------------------------------------+
    | nonce (24 B)    | Poly1305 tag (16 B) + encrypted message    |
    +-----------------+-------------------------------------------+

so each message grows by 40 bytes before Base64 encoding. A new random
nonce is generated for every message, so the same text never produces the
same ciphertext twice.

Because the box is built from the sender's private key and the recipient's
public key, a message that decrypts successfully is proven to come from the
holder of the sender's private key and to be unmodified.

Trust model
-----------
The relay server distributes public keys, so a malicious server could hand
out its own key instead of the real one (a man-in-the-middle attack). Each
client therefore displays short key fingerprints. Two users who compare
their fingerprints over another channel, for example in person, can detect
such a substitution. This is the same idea as the safety numbers used in
the Signal messenger.
"""

from __future__ import annotations

import base64
import hashlib

from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey

# Size added to every message by crypto_box: 24 byte nonce + 16 byte MAC.
E2E_OVERHEAD_BYTES = Box.NONCE_SIZE + 16


class E2EError(Exception):
    """Raised when a key is malformed or a message fails to decrypt."""


def _decode_public_key(public_key_b64: str) -> PublicKey:
    try:
        return PublicKey(base64.b64decode(public_key_b64, validate=True))
    except Exception as exc:  # malformed Base64 or wrong key length
        raise E2EError("peer public key is malformed") from exc


def fingerprint(public_key_b64: str) -> str:
    """
    Short, human-comparable fingerprint of a public key.

    The first 8 bytes of the SHA-256 hash of the raw key, shown as four
    groups of four hex characters, for example "3f2a 9c1d 77e0 b415".
    """
    raw_key = base64.b64decode(public_key_b64)
    digest = hashlib.sha256(raw_key).hexdigest()[:16]
    return " ".join(digest[i:i + 4] for i in range(0, 16, 4))


class E2EIdentity:
    """The key pair of one client and the encryption operations that use it."""

    def __init__(self) -> None:
        self._private_key = PrivateKey.generate()
        self.public_key_b64 = base64.b64encode(bytes(self._private_key.public_key)).decode("ascii")
        # A Box precomputes the shared secret, so one Box per peer key is
        # kept and reused instead of repeating the key agreement per message.
        self._boxes: dict[str, Box] = {}

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key_b64)

    def _box_for(self, peer_public_key_b64: str) -> Box:
        box = self._boxes.get(peer_public_key_b64)
        if box is None:
            box = Box(self._private_key, _decode_public_key(peer_public_key_b64))
            self._boxes[peer_public_key_b64] = box
        return box

    def encrypt(self, plaintext: str, recipient_public_key_b64: str) -> str:
        """Encrypt text for one recipient and return it as Base64."""
        encrypted = self._box_for(recipient_public_key_b64).encrypt(plaintext.encode("utf-8"))
        return base64.b64encode(bytes(encrypted)).decode("ascii")

    def decrypt(self, ciphertext_b64: str, sender_public_key_b64: str) -> str:
        """Decrypt a Base64 message from a sender. Raises E2EError if it was altered."""
        try:
            encrypted = base64.b64decode(ciphertext_b64, validate=True)
            plaintext = self._box_for(sender_public_key_b64).decrypt(encrypted)
        except (CryptoError, ValueError) as exc:
            raise E2EError("message failed authentication: it was altered or not encrypted for this client") from exc
        return plaintext.decode("utf-8")
