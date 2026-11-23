#!/usr/bin/env bash
#
# run_in_ns.sh
#
# Runs a command inside a network namespace as the normal (non-root) user.
# Entering a namespace requires root, but the programs themselves do not
# need root, so privileges are dropped before the command starts. Files the
# program creates, such as TLS key logs, are then owned by the user.
#
# The SSLKEYLOGFILE variable is passed through so TLS secrets can be logged
# for packet capture decryption.
#
# Usage:    sudo ./scripts/run_in_ns.sh <namespace> <command> [arguments...]
# Example:  sudo ./scripts/run_in_ns.sh srv .venv/bin/python src/server.py

set -euo pipefail

fail() { printf '[run_in_ns] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "Run with sudo: sudo $0 <namespace> <command>"
[[ $# -ge 2 ]] || fail "Usage: sudo $0 <namespace> <command> [arguments...]"

readonly NAMESPACE="$1"
shift
readonly TARGET_USER="${SUDO_USER:-}"
[[ -n "$TARGET_USER" ]] || fail "Could not detect the normal user. Run this script through sudo."

ip netns list | grep -qw "$NAMESPACE" || fail "Namespace '${NAMESPACE}' not found. Run: sudo ./topology/setup.sh"

exec ip netns exec "$NAMESPACE" sudo -u "$TARGET_USER" --preserve-env=SSLKEYLOGFILE -- "$@"
