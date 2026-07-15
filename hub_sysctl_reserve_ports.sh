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
#   65408-65535 (last 128 ports of the ephemeral space)
#   Program actually uses 65408-65423 (first 16); rest is headroom.
#
# Idempotent: safe to re-run. `remove` reverses.

set -euo pipefail

CONF="/etc/sysctl.d/99-vps-probe.conf"
PORT_RANGE="65408-65535"
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
