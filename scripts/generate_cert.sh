#!/usr/bin/env bash
#
# generate_cert.sh
#
# Creates a self-signed X.509 certificate and private key for the relay
# server. Clients trust this exact certificate (certificate pinning), so no
# public certificate authority is needed.
#
# The certificate is valid for the server's address in the topology
# (10.0.2.10) and for localhost, so the same files work for routed tests
# and for quick local tests.
#
# Key type: ECDSA on curve P-256 (prime256v1), a modern choice that keeps
# the TLS 1.3 handshake small.
#
# Output:   certs/server.crt  (public certificate, shared with clients)
#           certs/server.key  (private key, stays with the server only)
#
# Usage:    ./scripts/generate_cert.sh
# Requires: openssl

set -euo pipefail

readonly CERT_DIR="certs"
readonly CERT_FILE="${CERT_DIR}/server.crt"
readonly KEY_FILE="${CERT_DIR}/server.key"
readonly SERVER_IP="10.0.2.10"
readonly VALID_DAYS=365

log() { printf '[cert] %s\n' "$*"; }

mkdir -p "$CERT_DIR"

openssl req -x509 \
  -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes \
  -days "$VALID_DAYS" \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -subj "/CN=secure-relay-server" \
  -addext "subjectAltName=IP:${SERVER_IP},IP:127.0.0.1,DNS:localhost" \
  2> /dev/null

# The private key must only be readable by its owner.
chmod 600 "$KEY_FILE"

log "Created ${CERT_FILE} and ${KEY_FILE}"
log "Certificate details:"
openssl x509 -in "$CERT_FILE" -noout -subject -dates -ext subjectAltName
