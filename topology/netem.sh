#!/usr/bin/env bash
#
# netem.sh
#
# Applies, removes or shows controlled network impairment on the transit
# link between r1 and r2, using the Linux traffic control tool (tc) with the
# netem queueing discipline.
#
# The impairment is applied to both ends of the transit link, so it affects
# traffic in both directions:
#   r1-eth1  (r1 sending towards r2)
#   r2-eth0  (r2 sending towards r1)
#
# A delay of D milliseconds on each end adds 2 x D milliseconds to the round
# trip time (RTT) of every connection that crosses the transit link. For
# example, "--rtt 100" sets 50 ms on each end. Packet loss is applied
# independently on each end, so a message and its reply each face that loss.
#
# Usage:
#   sudo ./topology/netem.sh set --rtt 100            # add 100 ms to the RTT
#   sudo ./topology/netem.sh set --loss 2             # drop 2% of packets
#   sudo ./topology/netem.sh set --rtt 20 --loss 2    # both at once
#   sudo ./topology/netem.sh clear                    # remove all impairment
#   sudo ./topology/netem.sh show                     # print current settings
#
# Requires: iproute2 (tc), a kernel with the sch_netem module

set -euo pipefail

readonly LINK_ENDS=("r1 r1-eth1" "r2 r2-eth0")

log()  { printf '[netem] %s\n' "$*"; }
fail() { printf '[netem] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  printf 'Usage:\n'
  printf '  sudo %s set [--rtt <ms>] [--loss <percent>]\n' "$0"
  printf '  sudo %s clear\n' "$0"
  printf '  sudo %s show\n' "$0"
  exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "This script must be run as root. Try: sudo $0 $*"
[[ $# -ge 1 ]] || usage
ip netns list | grep -qw r1 || fail "Topology not found. Run: sudo ./topology/setup.sh"

clear_impairment() {
  for end in "${LINK_ENDS[@]}"; do
    read -r ns ifname <<< "$end"
    ip netns exec "$ns" tc qdisc del dev "$ifname" root 2> /dev/null || true
  done
}

show_impairment() {
  for end in "${LINK_ENDS[@]}"; do
    read -r ns ifname <<< "$end"
    printf '%-4s %-8s ' "$ns" "$ifname"
    ip netns exec "$ns" tc qdisc show dev "$ifname" | head -n 1
  done
}

set_impairment() {
  local rtt_ms=0 loss_percent=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --rtt)  rtt_ms="${2:?--rtt needs a value in milliseconds}"; shift 2 ;;
      --loss) loss_percent="${2:?--loss needs a percentage}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ "$rtt_ms" =~ ^[0-9]+$ ]] || fail "--rtt must be a whole number of milliseconds"
  [[ "$loss_percent" =~ ^[0-9]+([.][0-9]+)?$ ]] || fail "--loss must be a number, for example 2 or 0.5"

  # Half of the added round trip time is applied on each end of the link.
  local one_way_ms
  one_way_ms=$(awk "BEGIN { printf \"%.1f\", ${rtt_ms} / 2 }")

  clear_impairment
  for end in "${LINK_ENDS[@]}"; do
    read -r ns ifname <<< "$end"
    ip netns exec "$ns" tc qdisc add dev "$ifname" root netem \
      delay "${one_way_ms}ms" loss "${loss_percent}%" \
      || fail "tc could not add netem on ${ns}/${ifname}. Is the sch_netem kernel module available?"
  done
  log "Transit link impaired: +${rtt_ms} ms RTT (${one_way_ms} ms each way), ${loss_percent}% loss each way"
}

case "$1" in
  set)   shift; set_impairment "$@" ;;
  clear) clear_impairment; log "Impairment removed from the transit link" ;;
  show)  show_impairment ;;
  *)     usage ;;
esac
