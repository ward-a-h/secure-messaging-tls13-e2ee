"""
tls_config.py

Builds the TLS contexts used by the server and the clients.

Both sides are restricted to TLS 1.3 only (RFC 8446). Older versions are
refused, so a connection either uses TLS 1.3 or does not happen at all.

Packet capture support
----------------------
If the environment variable SSLKEYLOGFILE is set, the TLS session secrets
are appended to that file in the standard NSS key log format. Wireshark can
use this file to decrypt the captured TLS traffic. This is used only to
produce evidence for the report: it shows that after the TLS layer is
removed, an end-to-end encrypted message body is still unreadable.
The key log file is a secret and is excluded from Git.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path


def _enable_key_logging(context: ssl.SSLContext) -> None:
    keylog_path = os.environ.get("SSLKEYLOGFILE")
    if keylog_path:
        context.keylog_filename = keylog_path


def server_context(cert_file: Path, key_file: Path) -> ssl.SSLContext:
    """TLS 1.3 server context that presents the relay server certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    _enable_key_logging(context)
    return context


def client_context(trusted_cert: Path) -> ssl.SSLContext:
    """
    TLS 1.3 client context that trusts only the relay server certificate.

    Certificate verification and hostname checking stay enabled. The client
    accepts the server only if it presents the exact certificate in
    trusted_cert and that certificate is valid for the address being
    connected to. This blocks a man-in-the-middle that presents any other
    certificate.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verifies by default
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=str(trusted_cert))
    _enable_key_logging(context)
    return context
