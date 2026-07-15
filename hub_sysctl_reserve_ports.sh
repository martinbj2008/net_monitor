#!/usr/bin/env bash
# hub_sysctl_reserve_ports.sh — reserve a port range for vps_probe raw socket use
#
# Run on the HUB only (the machine that sends probes).
#
# Purpose:
#   Prevent the kernel from auto-allocating ports in our probe range to any
#   other process (both implicit bind(port=0) and connect() ephemeral source
#   port selection). Our probe program explicitly bind()s to ports inside this
#   range; reserving them here guarantees no collision with random apps
#   (curl, apt, ssh client, etc.).
#
# Note:
#   This does NOT stop the kernel from replying RST to unexpected SYN-ACK on
#   these ports. RST suppression is done by the XDP program (XDP_DROP on
#   ingress SYN-ACK), which consumes the packet before the IP stack ever
#   sees it. sysctl reservation and XDP interception are orthogonal.
#
# Range:
#   65400-65535 (last 136 ports of the ephemeral space) — kept reserved as
#   a headroom "black hole" so the kernel never auto-assigns anything here.
#   Rounded down to 65400 for a clean boundary with a bit of extra headroom.
#
#   CURRENT USAGE:
#     * :65535  — SYN-probe RTT measurement (fixed sport of the probe daemon;
#                 XDP matches inbound TCP dport==65535 and drops it).
#     * :65400..:65534 — reserved but IDLE. Not used by anything yet.
#
#   Do NOT shrink this range or release the idle ports back to the ephemeral
#   pool. They stay carved out so future probe experiments (extra sports,
#   parallel A/B ports, side-channel probes) can plug in without needing
#   another sysctl change / reboot.
#
# Idempotent: safe to re-run. `remove` reverses.

set -euo pipefail

CONF="/etc/sysctl.d/99-vps-probe.conf"
# Reserve the whole 136-port window even though only :65535 is in active use.
# See "Range:" note above before touching this.
PORT_RANGE="65400-65535"
KEY="net.ipv4.ip_local_reserved_ports"

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (try: sudo $0 $*)" >&2
    exit 1
  fi
}

apply() {
  need_root "$@"
  echo "Writing ${CONF} ..."
  cat > "${CONF}" <<EOF
# vps_probe: reserve ephemeral ports so nothing else grabs them.
# Managed by hub_sysctl_reserve_ports.sh — do not edit by hand.
${KEY} = ${PORT_RANGE}
EOF
  chmod 0644 "${CONF}"
  echo "Reloading sysctl ..."
  sysctl -p "${CONF}"
  echo
  echo "Current value:"
  sysctl "${KEY}"
}

remove() {
  need_root "$@"
  if [[ -f "${CONF}" ]]; then
    echo "Removing ${CONF} ..."
    rm -f "${CONF}"
  else
    echo "${CONF} not present, nothing to remove."
  fi
  echo "Clearing runtime value ..."
  sysctl -w "${KEY}=" || true
  echo
  echo "Current value:"
  sysctl "${KEY}"
}

show() {
  echo "Config file: ${CONF}"
  if [[ -f "${CONF}" ]]; then
    echo "--- content ---"
    cat "${CONF}"
    echo "---------------"
  else
    echo "(config file not present)"
  fi
  echo "Runtime value:"
  sysctl "${KEY}" 2>/dev/null || echo "(unavailable)"
}

case "${1:-apply}" in
  apply)          apply "$@" ;;
  remove|--remove) remove "$@" ;;
  show)           show ;;
  *)
    echo "Usage: $0 [apply|remove|show]"
    exit 1
    ;;
esac
