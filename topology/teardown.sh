#!/usr/bin/env bash
#
# teardown.sh
#
# Removes everything created by setup.sh. Deleting a namespace also deletes
# the interfaces inside it, so the virtual links are removed along with
# their devices.
#
# Usage:  sudo ./topology/teardown.sh

set -euo pipefail

readonly NAMESPACES=(c1 r1 r2 srv c2)

log()  { printf '[teardown] %s\n' "$*"; }
fail() { printf '[teardown] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "This script must be run as root. Try: sudo $0"

for ns in "${NAMESPACES[@]}"; do
  if ip netns del "$ns" 2>/dev/null; then
    log "Removed namespace ${ns}"
  else
    log "Namespace ${ns} not present, skipped"
  fi
done

log "Topology removed"
