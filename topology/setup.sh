#!/usr/bin/env bash
#
# setup.sh
#
# Builds the routed test topology for the project
# "Secure Messaging over TLS 1.3 with End-to-End Encryption".
#
# Each device below is a Linux network namespace, which behaves like a
# separate computer with its own interfaces, addresses and routing table.
#
#   Subnet A 10.0.1.0/24       Transit 10.0.12.0/30        Subnet B 10.0.2.0/24
#   [c1] ----------------- [r1] ------------------- [r2] ------------------ [srv]
#   10.0.1.10      10.0.1.1    10.0.12.1     10.0.12.2    10.0.2.1     10.0.2.10
#                                                  |
#                                                  | 10.0.3.1
#                                                  |
#                                                [c2] 10.0.3.10
#                                           Subnet C 10.0.3.0/24
#
# Interface names follow the pattern <device>-eth<port>.
# Example: r2-eth1 is port 1 on router r2.
#
# Usage:     sudo ./topology/setup.sh
# Undo:      sudo ./topology/teardown.sh
# Requires:  iproute2 (ip), iputils-ping, a Linux kernel with network namespaces

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

readonly NAMESPACES=(c1 r1 r2 srv c2)
readonly INTERFACES=(c1-eth0 r1-eth0 r1-eth1 r2-eth0 r2-eth1 r2-eth2 srv-eth0 c2-eth0)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

log()  { printf '[setup] %s\n' "$*"; }
fail() { printf '[setup] ERROR: %s\n' "$*" >&2; exit 1; }

# Runs a command inside a namespace.
# Usage: in_ns <namespace> <command> [arguments...]
in_ns() {
  local ns="$1"
  shift
  ip netns exec "$ns" "$@"
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || fail "This script must be run as root. Try: sudo $0"
}

# ---------------------------------------------------------------------------
# Step 1: Remove any previous copy of the topology
# ---------------------------------------------------------------------------
# Running the script twice must not fail with "already exists" errors,
# so old namespaces and any stray interfaces are removed first.

clean_previous() {
  log "Removing any previous topology"
  for ns in "${NAMESPACES[@]}"; do
    ip netns del "$ns" 2>/dev/null || true
  done
  for ifname in "${INTERFACES[@]}"; do
    ip link del "$ifname" 2>/dev/null || true
  done
}

# ---------------------------------------------------------------------------
# Step 2: Create the namespaces (the devices)
# ---------------------------------------------------------------------------

create_namespaces() {
  log "Creating namespaces: ${NAMESPACES[*]}"
  for ns in "${NAMESPACES[@]}"; do
    ip netns add "$ns"
    # The loopback interface is down by default inside a new namespace.
    # Some programs expect it, so it is switched on for every device.
    in_ns "$ns" ip link set lo up
  done
}

# ---------------------------------------------------------------------------
# Step 3: Create the links (the cables)
# ---------------------------------------------------------------------------

# Creates a veth pair, which acts as a virtual cable with two ends,
# and places each end inside its device.
# Usage: connect <namespace_a> <interface_a> <namespace_b> <interface_b>
connect() {
  local ns_a="$1" if_a="$2" ns_b="$3" if_b="$4"
  ip link add "$if_a" type veth peer name "$if_b"
  ip link set "$if_a" netns "$ns_a"
  ip link set "$if_b" netns "$ns_b"
}

create_links() {
  log "Creating virtual links"
  connect c1 c1-eth0  r1  r1-eth0    # Subnet A:  Client 1 <-> Router 1
  connect r1 r1-eth1  r2  r2-eth0    # Transit:   Router 1 <-> Router 2
  connect r2 r2-eth1  srv srv-eth0   # Subnet B:  Router 2 <-> Server
  connect r2 r2-eth2  c2  c2-eth0    # Subnet C:  Router 2 <-> Client 2
}

# ---------------------------------------------------------------------------
# Step 4: Assign IP addresses and bring interfaces up
# ---------------------------------------------------------------------------

# Usage: assign <namespace> <interface> <address/prefix>
assign() {
  local ns="$1" ifname="$2" address="$3"
  in_ns "$ns" ip addr add "$address" dev "$ifname"
  in_ns "$ns" ip link set "$ifname" up
}

assign_addresses() {
  log "Assigning IP addresses"
  assign c1  c1-eth0  10.0.1.10/24
  assign r1  r1-eth0  10.0.1.1/24
  assign r1  r1-eth1  10.0.12.1/30
  assign r2  r2-eth0  10.0.12.2/30
  assign r2  r2-eth1  10.0.2.1/24
  assign r2  r2-eth2  10.0.3.1/24
  assign srv srv-eth0 10.0.2.10/24
  assign c2  c2-eth0  10.0.3.10/24
}

# ---------------------------------------------------------------------------
# Step 5: Turn the routers into routers
# ---------------------------------------------------------------------------
# By default Linux drops packets that are not addressed to itself.
# Enabling IPv4 forwarding lets r1 and r2 pass packets between their ports.

enable_forwarding() {
  log "Enabling IPv4 forwarding on r1 and r2"
  for router in r1 r2; do
    in_ns "$router" sysctl -qw net.ipv4.ip_forward=1
  done
}

# ---------------------------------------------------------------------------
# Step 6: Static routes
# ---------------------------------------------------------------------------
# Every device already knows the subnets it is directly connected to.
# These routes tell each device where to send traffic for the other subnets.

configure_routes() {
  log "Configuring static routes"

  # Hosts send all traffic outside their own subnet to their router.
  in_ns c1  ip route add default via 10.0.1.1
  in_ns srv ip route add default via 10.0.2.1
  in_ns c2  ip route add default via 10.0.3.1

  # r1 reaches Subnets B and C through r2 over the transit link.
  in_ns r1 ip route add 10.0.2.0/24 via 10.0.12.2
  in_ns r1 ip route add 10.0.3.0/24 via 10.0.12.2

  # r2 reaches Subnet A through r1 over the transit link.
  in_ns r2 ip route add 10.0.1.0/24 via 10.0.12.1
}

# ---------------------------------------------------------------------------
# Step 7: Verify end-to-end reachability
# ---------------------------------------------------------------------------

# Sends one ping and reports PASS or FAIL.
# Usage: check_ping <source_namespace> <destination_ip> <description>
check_ping() {
  local ns="$1" destination="$2" description="$3"
  if in_ns "$ns" ping -c 1 -W 2 "$destination" > /dev/null 2>&1; then
    log "  PASS  ${description}"
  else
    log "  FAIL  ${description}"
    return 1
  fi
}

verify() {
  log "Verifying reachability"
  local failures=0
  check_ping c1  10.0.2.10 "Client 1 -> Server    (crosses r1 and r2)" || failures=$((failures + 1))
  check_ping c2  10.0.2.10 "Client 2 -> Server    (crosses r2)"        || failures=$((failures + 1))
  check_ping c1  10.0.3.10 "Client 1 -> Client 2  (crosses r1 and r2)" || failures=$((failures + 1))
  check_ping srv 10.0.1.10 "Server   -> Client 1  (return path)"       || failures=$((failures + 1))

  if [[ "$failures" -gt 0 ]]; then
    fail "${failures} reachability check(s) failed"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  require_root
  clean_previous
  create_namespaces
  create_links
  assign_addresses
  enable_forwarding
  configure_routes
  verify
  log "Topology is ready"
}

main "$@"
