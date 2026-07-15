#!/usr/bin/env bash
# hub_probe/verify_kernel_rst.sh
#
# Goal: distinguish "kernel did not emit RST" from "kernel emitted RST but the
# cloud vSwitch silently dropped it".
#
# Method: read /proc/net/netstat (TcpExtOutRsts) and /proc/net/snmp (Tcp:OutRsts)
# before/after firing N crafted SYNs and receiving their SA replies.
#
# If delta(OutRsts) >= N  -> kernel DID send RST (cloud dropped them on egress)
# If delta(OutRsts) == 0  -> kernel DID NOT send RST (something earlier suppressed it)
#
# Also captures rt_type / route lookup for sanity.

set -u

TARGET="${TARGET:-43.132.210.4}"
IFACE="${IFACE:-eth0}"
COUNT="${COUNT:-5}"
LOGDIR="${LOGDIR:-/tmp/verify_rst_$(date +%Y%m%d_%H%M%S)}"

mkdir -p "$LOGDIR"
cd "$(dirname "$0")"

echo "============================================================"
echo "Kernel RST emission verification"
echo "  target=$TARGET  iface=$IFACE  count=$COUNT"
echo "  logdir=$LOGDIR"
echo "============================================================"

# --- Safety: make sure XDP is NOT attached (we want kernel to try to send RST) ---
existing="$(ip -j link show dev "$IFACE" 2>/dev/null | grep -o '"xdp"' || true)"
if [[ -n "$existing" ]]; then
    echo "[warn] $IFACE has XDP attached — detaching to observe raw kernel behavior"
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
    ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
    sleep 0.5
fi

# --- Route sanity: how would hub route a packet destined to its own eth0 IP? ---
local_ip="$(ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -1)"
echo
echo "[info] $IFACE local IP: $local_ip"
echo "[info] route lookup for $local_ip (from $TARGET via $IFACE):"
ip route get "$local_ip" from "$TARGET" iif "$IFACE" 2>&1 | sed 's/^/  /' || true
echo "[info] route lookup for $TARGET (egress):"
ip route get "$TARGET" 2>&1 | sed 's/^/  /' || true

# --- Snapshot counters BEFORE ---
snapshot() {
    local tag="$1"
    {
        echo "=== $tag ==="
        date -Iseconds
        echo "--- /proc/net/snmp Tcp: ---"
        awk '/^Tcp:/{h=$0; getline v; print h; print v}' /proc/net/snmp
        echo "--- /proc/net/netstat TcpExt: ---"
        awk '/^TcpExt:/{h=$0; getline v; print h; print v}' /proc/net/netstat
        echo "--- nstat -a snapshot (relevant) ---"
        nstat -asz 2>/dev/null | grep -E 'Tcp.*(Rst|OutSegs|InSegs|OutRsts)' || true
    } > "$LOGDIR/counters_$tag.txt"
}

# extract OutRsts from a saved snapshot
extract_outrsts() {
    # snmp Tcp: OutRsts is column position — find it by header
    local f="$1"
    awk '
        /^--- \/proc\/net\/snmp Tcp: ---$/ {getline hdr; getline val;
            n = split(hdr, H, " "); split(val, V, " ");
            for (i=1;i<=n;i++) if (H[i]=="OutRsts") {print "snmp_OutRsts=" V[i]}}
        /^--- \/proc\/net\/netstat TcpExt: ---$/ {getline hdr; getline val;
            n = split(hdr, H, " "); split(val, V, " ");
            for (i=1;i<=n;i++) {
                if (H[i]=="TCPAbortOnData") print "ext_TCPAbortOnData=" V[i]
                if (H[i]=="TCPAbortOnClose") print "ext_TCPAbortOnClose=" V[i]
                if (H[i]=="TCPAbortOnMemory") print "ext_TCPAbortOnMemory=" V[i]
                if (H[i]=="TCPAbortOnTimeout") print "ext_TCPAbortOnTimeout=" V[i]
                if (H[i]=="TCPAbortOnLinger") print "ext_TCPAbortOnLinger=" V[i]
                if (H[i]=="TCPAbortFailed") print "ext_TCPAbortFailed=" V[i]
            }
        }' "$f"
}

echo
echo "[info] taking BEFORE snapshot ..."
snapshot before

# --- Fire probe (no XDP) ---
echo
echo "[info] firing $COUNT SYNs -> $TARGET ..."
python3 step3_probe.py --target "$TARGET" --iface "$IFACE" --count "$COUNT" \
    2>&1 | tee "$LOGDIR/probe.log"
probe_rc=${PIPESTATUS[0]}
echo "[info] probe exit=$probe_rc"

# Small settle so any deferred RSTs get counted
sleep 1.0

echo
echo "[info] taking AFTER snapshot ..."
snapshot after

# --- Diff ---
echo
echo "============================================================"
echo "COUNTER DIFF"
echo "============================================================"
before_outrsts=$(extract_outrsts "$LOGDIR/counters_before.txt" | grep snmp_OutRsts | cut -d= -f2)
after_outrsts=$(extract_outrsts  "$LOGDIR/counters_after.txt"  | grep snmp_OutRsts | cut -d= -f2)
delta=$(( after_outrsts - before_outrsts ))
echo "snmp Tcp:OutRsts   before=$before_outrsts  after=$after_outrsts  delta=$delta"

echo
echo "TcpExt abort counters (for reference):"
diff <(extract_outrsts "$LOGDIR/counters_before.txt" | grep ext_) \
     <(extract_outrsts "$LOGDIR/counters_after.txt"  | grep ext_) || true

echo
echo "============================================================"
echo "VERDICT"
echo "============================================================"
if (( delta >= COUNT )); then
    echo "→ Kernel DID emit >= $COUNT RSTs (delta=$delta)."
    echo "→ The zero tx_rst seen by sniffer means those RSTs were DROPPED on"
    echo "  the way out — most likely by the cloud provider's vSwitch or"
    echo "  a stateful firewall. NOT reserved_ports, NOT the kernel."
elif (( delta > 0 )); then
    echo "→ Kernel emitted $delta RSTs, less than the $COUNT SAs received."
    echo "→ Partial suppression somewhere; inspect route/rt_type or nf hooks."
else
    echo "→ Kernel emitted ZERO RSTs despite receiving $COUNT+ SYN-ACKs."
    echo "→ Something in the ingress path suppressed the send_reset call."
    echo "  Candidates: rt_type != RTN_LOCAL, netfilter drop, or a code path"
    echo "  we haven't identified. Check dmesg and iptables -L -v -n -t raw/filter."
fi
echo
echo "Logs: $LOGDIR"
