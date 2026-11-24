#!/usr/bin/env bash
#
# capture.sh
#
# Records packets on one interface of the topology into a pcapng file
# until Ctrl+C is pressed.
#
# If the relay server was started with SSLKEYLOGFILE set to
# captures/sslkeys.log, a second copy of the capture is also written with
# the TLS session secrets embedded in it (<name>_with_keys.pcapng).
# Wireshark opens that copy with the TLS layer already decrypted, with no
# extra settings, so another group can inspect the inner messages directly.
# The embedded secrets belong only to the short demonstration sessions in
# that file and cannot decrypt any other traffic.
#
# Usage:    sudo ./scripts/capture.sh <name> [namespace] [interface] [filter]
# Defaults: namespace srv, interface srv-eth0, filter "tcp port 8443"
#
# Examples:
#   sudo ./scripts/capture.sh tls13_e2e_session
#   sudo ./scripts/capture.sh transit_link r1 r1-eth1
#   sudo ./scripts/capture.sh traceroute r1 r1-eth1 "icmp or udp"
#
# Requires: tshark and editcap (installed with the tshark package)

set -euo pipefail

readonly CAPTURE_DIR="captures"
readonly KEYLOG_FILE="${CAPTURE_DIR}/sslkeys.log"

log()  { printf '[capture] %s\n' "$*"; }
fail() { printf '[capture] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "This script must be run as root. Try: sudo $0 <name>"
[[ $# -ge 1 ]] || fail "Usage: sudo $0 <name> [namespace] [interface] [filter]"

readonly NAME="$1"
readonly NAMESPACE="${2:-srv}"
readonly INTERFACE="${3:-srv-eth0}"
readonly FILTER="${4:-tcp port 8443}"
readonly OWNER="${SUDO_USER:-root}"

[[ "$NAME" =~ ^[A-Za-z0-9_-]+$ ]] || fail "Use only letters, digits, '-' and '_' in the capture name"
ip netns list | grep -qw "$NAMESPACE" || fail "Namespace '${NAMESPACE}' not found. Run: sudo ./topology/setup.sh"
ip netns exec "$NAMESPACE" ip link show "$INTERFACE" > /dev/null 2>&1 \
  || fail "Interface '${INTERFACE}' not found in namespace '${NAMESPACE}'"

mkdir -p "$CAPTURE_DIR"
readonly OUTPUT="${CAPTURE_DIR}/${NAME}.pcapng"

# tshark gives up some root privileges while it captures, so it may not be
# allowed to write into the user's home folder. It therefore writes into a
# private temporary folder, and the finished file is moved afterwards.
# The folder has a random name and is deleted when the script exits.
readonly WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
chmod 777 "$WORK_DIR"
readonly TEMP_OUTPUT="${WORK_DIR}/${NAME}.pcapng"
readonly ERROR_LOG="${WORK_DIR}/tshark_errors.log"

log "Capturing on ${NAMESPACE}/${INTERFACE} with filter '${FILTER}'"
log "Writing to ${OUTPUT}. Press Ctrl+C to stop."

# Ctrl+C must stop tshark but not this script, so the steps after the
# capture still run. A handler that does nothing keeps the script alive,
# while tshark still receives the signal and closes its file cleanly.
trap 'true' INT
ip netns exec "$NAMESPACE" tshark -q -i "$INTERFACE" -f "$FILTER" -w "$TEMP_OUTPUT" 2> "$ERROR_LOG" || true
trap - INT

if [[ ! -s "$TEMP_OUTPUT" ]]; then
  # Show tshark's own explanation, without its routine warning about root.
  grep -v -e "Running as user" -e "^Capturing on" "$ERROR_LOG" >&2 || true
  fail "No capture file was written"
fi
mv "$TEMP_OUTPUT" "$OUTPUT"
chown "${OWNER}:" "$OUTPUT"
chmod 644 "$OUTPUT"
PACKETS=$(tshark -r "$OUTPUT" 2> /dev/null | wc -l)
log "Saved ${PACKETS} packets to ${OUTPUT}"

if [[ -s "$KEYLOG_FILE" ]]; then
  readonly KEYED_OUTPUT="${CAPTURE_DIR}/${NAME}_with_keys.pcapng"
  editcap --inject-secrets "tls,${KEYLOG_FILE}" "$OUTPUT" "$KEYED_OUTPUT"
  chown "${OWNER}:" "$KEYED_OUTPUT"
  chmod 644 "$KEYED_OUTPUT"
  log "Saved a decryptable copy with embedded TLS secrets to ${KEYED_OUTPUT}"
else
  log "No TLS key log at ${KEYLOG_FILE}, so no decryptable copy was made"
fi
