#!/usr/bin/env bash
#
# status.sh
#
# Prints the current state of the topology: interface addresses on every
# device, the routing tables of both routers, and a traceroute from
# Client 1 to Client 2 showing that traffic crosses both routers.
# The output is used as evidence of the routed baseline in the report.
#
# Usage:  sudo ./topology/status.sh
# Save:   sudo ./topology/status.sh | tee docs/topology_status.txt

set -euo pipefail

readonly NAMESPACES=(c1 r1 r2 srv c2)

fail() { printf '[status] ERROR: %s\n' "$*" >&2; exit 1; }
section() { printf '\n==== %s ====\n' "$*"; }

in_ns() {
  local ns="$1"
  shift
  ip netns exec "$ns" "$@"
}

[[ "${EUID}" -eq 0 ]] || fail "This script must be run as root. Try: sudo $0"
ip netns list | grep -qw c1 || fail "Topology not found. Run: sudo ./topology/setup.sh"

for ns in "${NAMESPACES[@]}"; do
  section "Interfaces on ${ns}"
  in_ns "$ns" ip -brief address show
done

for router in r1 r2; do
  section "Routing table on ${router}"
  in_ns "$router" ip route show
done

section "Traceroute from Client 1 (10.0.1.10) to Client 2 (10.0.3.10)"
in_ns c1 traceroute -n -q 1 -w 1 10.0.3.10
