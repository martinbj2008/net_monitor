#!/usr/bin/env bash
# hub_probe/verify_rst_dropper.sh
#
# Goal: pin down WHERE the kernel-emitted RSTs are dropped.
#   Candidates:
#     (1) host-side iptables/nftables OUTPUT/POSTROUTING
#     (2) host-side conntrack marking RST as INVALID
#     (3) cloud vSwitch (external, not visible on host)
#
# Method: snapshot rule/table counters + conntrack stats before/after firing
#   the probe. Any counter that increments = suspect. If nothing on-host moves
#   while Tcp:OutRsts jumps, the drop is off-host (vSwitch).

set -u

TARGET="${TARGET:-43.132.210.4}"
IFACE="${IFACE:-eth0}"
COUNT="${COUNT:-5}"
LOGDIR="${LOGDIR:-/tmp/verify_dropper_$(date +%Y%m%d_%H%M%S)}"

mkdir -p "$LOGDIR"
cd "$(dirname "$0")"

echo "============================================================"
echo "RST dropper localization"
echo "  target=$TARGET  iface=$IFACE  count=$COUNT"
echo "  logdir=$LOGDIR"
echo "============================================================"

# Make sure XDP is off so kernel really tries to send RST
if ip -j link show dev "$IFACE" 2>/dev/null | grep -q '"xdp"'; then
    echo "[warn] detaching XDP from $IFACE"
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
    ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
    sleep 0.3
fi

snapshot() {
    local tag="$1"
    {
        echo "=== $tag  $(date -Iseconds) ==="

        echo "----- iptables -L -v -n (filter) -----"
        iptables -L -v -n 2>&1 || echo "(iptables not available)"

        echo "----- iptables -L -v -n -t raw -----"
        iptables -L -v -n -t raw 2>&1 || true

        echo "----- iptables -L -v -n -t mangle -----"
        iptables -L -v -n -t mangle 2>&1 || true

        echo "----- iptables -L -v -n -t nat -----"
        iptables -L -v -n -t nat 2>&1 || true

        echo "----- nft list ruleset -----"
        nft list ruleset 2>&1 || echo "(nft not available)"

        echo "----- conntrack -S (per-cpu stats) -----"
        conntrack -S 2>&1 || echo "(conntrack tool not available)"

        echo "----- /proc/net/stat/nf_conntrack -----"
        cat /proc/net/stat/nf_conntrack 2>&1 || true

        echo "----- Tcp: OutRsts / OutSegs -----"
        awk '/^Tcp:/{h=$0; getline v; print h; print v}' /proc/net/snmp

        echo "----- ip -s link show $IFACE -----"
        ip -s link show "$IFACE" 2>&1 || true
    } > "$LOGDIR/snap_$tag.txt"
}

echo "[info] BEFORE snapshot ..."
snapshot before

echo "[info] firing $COUNT SYN ..."
python3 step3_probe.py --target "$TARGET" --iface "$IFACE" --count "$COUNT" \
    2>&1 | tee "$LOGDIR/probe.log" | tail -20

sleep 1.5

echo "[info] AFTER snapshot ..."
snapshot after

echo
echo "============================================================"
echo "DIFF (only non-zero-delta lines shown)"
echo "============================================================"

# Show diff of the two snapshot files
diff -u "$LOGDIR/snap_before.txt" "$LOGDIR/snap_after.txt" > "$LOGDIR/diff.txt" || true

# Extract key deltas
echo
echo "--- Tcp:OutRsts delta ---"
b=$(awk '/^Tcp:/{getline; for(i=1;i<=NF;i++) if(h[i]=="OutRsts") print $i; next} /^Tcp:/{for(i=1;i<=NF;i++) h[i]=$i}' /proc/net/snmp <<<"$(cat "$LOGDIR/snap_before.txt" | awk '/^----- Tcp:/{found=1; next} found && /^Tcp:/{print; getline; print; exit}')" 2>/dev/null || echo "?")
# Simpler: just grep the Tcp: lines
grep -A1 '^Tcp:' "$LOGDIR/snap_before.txt" | tail -2 > /tmp/_tb.$$
grep -A1 '^Tcp:' "$LOGDIR/snap_after.txt"  | tail -2 > /tmp/_ta.$$
python3 - <<'PYEOF'
def parse(p):
    lines=[l.rstrip() for l in open(p)]
    hdr=lines[0].split(); val=lines[1].split()
    return dict(zip(hdr,val))
import sys
b=parse("/tmp/_tb.%d"%__import__("os").getpid())
a=parse("/tmp/_ta.%d"%__import__("os").getpid())
for k in ("OutRsts","OutSegs","InSegs","AttemptFails","EstabResets"):
    if k in b and k in a:
        try: print(f"  {k:15s}  before={b[k]:>10s}  after={a[k]:>10s}  delta={int(a[k])-int(b[k])}")
        except: pass
PYEOF
rm -f /tmp/_tb.$$ /tmp/_ta.$$

echo
echo "--- iptables filter chain packet counter deltas (non-zero) ---"
# Diff iptables filter table
awk '
    /^----- iptables -L -v -n \(filter\) -----$/ {in_sec=1; next}
    /^----- / {in_sec=0}
    in_sec {print}
' "$LOGDIR/snap_before.txt" > "$LOGDIR/ipt_before.txt"
awk '
    /^----- iptables -L -v -n \(filter\) -----$/ {in_sec=1; next}
    /^----- / {in_sec=0}
    in_sec {print}
' "$LOGDIR/snap_after.txt" > "$LOGDIR/ipt_after.txt"
if diff -q "$LOGDIR/ipt_before.txt" "$LOGDIR/ipt_after.txt" >/dev/null 2>&1; then
    echo "  (iptables filter table unchanged — no host-side iptables drop)"
else
    diff -u "$LOGDIR/ipt_before.txt" "$LOGDIR/ipt_after.txt" | grep -E '^[+-][^+-]' | head -40
fi

echo
echo "--- nftables ruleset diff ---"
awk '
    /^----- nft list ruleset -----$/ {in_sec=1; next}
    /^----- / {in_sec=0}
    in_sec {print}
' "$LOGDIR/snap_before.txt" > "$LOGDIR/nft_before.txt"
awk '
    /^----- nft list ruleset -----$/ {in_sec=1; next}
    /^----- / {in_sec=0}
    in_sec {print}
' "$LOGDIR/snap_after.txt" > "$LOGDIR/nft_after.txt"
if diff -q "$LOGDIR/nft_before.txt" "$LOGDIR/nft_after.txt" >/dev/null 2>&1; then
    echo "  (nftables ruleset unchanged — no host-side nft drop)"
else
    diff -u "$LOGDIR/nft_before.txt" "$LOGDIR/nft_after.txt" | grep -E '^[+-][^+-]' | head -40
fi

echo
echo "--- conntrack -S deltas ---"
awk '
    /^----- conntrack -S/ {in_sec=1; next}
    /^----- / {in_sec=0}
    in_sec {print}
' "$LOGDIR/snap_before.txt" > "$LOGDIR/ct_before.txt"
awk '
    /^----- conntrack -S/ {in_sec=1; next}
    /^----- / {in_sec=0}
    in_sec {print}
' "$LOGDIR/snap_after.txt" > "$LOGDIR/ct_after.txt"
if diff -q "$LOGDIR/ct_before.txt" "$LOGDIR/ct_after.txt" >/dev/null 2>&1; then
    echo "  (conntrack stats unchanged — conntrack not in play, or module unloaded)"
else
    diff -u "$LOGDIR/ct_before.txt" "$LOGDIR/ct_after.txt" | grep -E '^[+-][^+-]' | head -60
fi

echo
echo "--- interface tx counter delta ---"
awk '
    /^----- ip -s link show/ {in_sec=1; next}
    /^----- / {in_sec=0}
    in_sec {print}
' "$LOGDIR/snap_before.txt" > "$LOGDIR/link_before.txt"
awk '
    /^----- ip -s link show/ {in_sec=1; next}
    /^----- / {in_sec=0}
    in_sec {print}
' "$LOGDIR/snap_after.txt" > "$LOGDIR/link_after.txt"
diff -u "$LOGDIR/link_before.txt" "$LOGDIR/link_after.txt" | grep -E '^[+-][^+-]' | head -20

echo
echo "============================================================"
echo "VERDICT (auto)"
echo "============================================================"
ipt_changed=1
diff -q "$LOGDIR/ipt_before.txt" "$LOGDIR/ipt_after.txt" >/dev/null 2>&1 && ipt_changed=0
nft_changed=1
diff -q "$LOGDIR/nft_before.txt" "$LOGDIR/nft_after.txt" >/dev/null 2>&1 && nft_changed=0
ct_changed=1
diff -q "$LOGDIR/ct_before.txt" "$LOGDIR/ct_after.txt" >/dev/null 2>&1 && ct_changed=0

if [[ $ipt_changed -eq 0 && $nft_changed -eq 0 ]]; then
    echo "→ No host firewall counters moved."
    if [[ $ct_changed -eq 0 ]]; then
        echo "→ conntrack didn't move either."
        echo "→ CONCLUSION: RSTs left the host (or died between IP-out and driver)."
        echo "  Given Tcp:OutRsts +15 and sniffer tx_rst=0, the most likely drop"
        echo "  point is the CLOUD vSWITCH filtering RST-from-unknown-flow egress."
    else
        echo "→ conntrack counters moved — inspect diff above; RST may be INVALID-dropped."
    fi
else
    echo "→ Host firewall counters changed. Inspect diff above to identify the chain/rule."
fi
echo
echo "Full logs: $LOGDIR"
