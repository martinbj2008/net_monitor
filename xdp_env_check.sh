#!/usr/bin/env bash
# xdp_env_check.sh — verify XDP prerequisites on the hub (bangkok)
# Usage:
#   scp xdp_env_check.sh bangkok:/tmp/
#   ssh bangkok "sudo bash /tmp/xdp_env_check.sh"
#
# Exit code: 0 = ready, 1 = blocking issue found

set -u
PASS=0; WARN=0; FAIL=0
say() { printf "%-6s %s\n" "$1" "$2"; case "$1" in PASS) PASS=$((PASS+1));; WARN) WARN=$((WARN+1));; FAIL) FAIL=$((FAIL+1));; esac; }

echo "=== XDP environment check on $(hostname) @ $(date -Is) ==="
echo

# ---- B1: kernel version ----
KV=$(uname -r)
KMAJ=$(echo "$KV" | cut -d. -f1)
KMIN=$(echo "$KV" | cut -d. -f2)
if [ "$KMAJ" -gt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -ge 10 ]; }; then
  say PASS "B1 kernel $KV (>=5.10)"
else
  say FAIL "B1 kernel $KV (<5.10, XDP CO-RE may not work)"
fi

# ---- B2: BTF ----
if [ -f /sys/kernel/btf/vmlinux ]; then
  say PASS "B2 BTF /sys/kernel/btf/vmlinux present"
else
  say FAIL "B2 BTF vmlinux missing (CO-RE unavailable)"
fi

# ---- B3: BPF features via bpftool ----
if command -v bpftool >/dev/null 2>&1; then
  BPFV=$(bpftool version 2>/dev/null | head -1)
  say PASS "B3 bpftool: $BPFV"
  # rough probe
  if bpftool feature probe kernel 2>/dev/null | grep -q "bpf() syscall.*is available"; then
    say PASS "B3 bpf() syscall available"
  else
    say WARN "B3 bpftool feature probe inconclusive (check manually)"
  fi
else
  say FAIL "B3 bpftool not installed (apt install linux-tools-common linux-tools-generic)"
fi

# ---- B8: figure out default egress interface ----
IFACE=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
if [ -n "$IFACE" ]; then
  IP4=$(ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | head -1)
  say PASS "B8 default egress iface: $IFACE ($IP4)"
else
  say FAIL "B8 no default route found"
  IFACE=eth0
fi

# ---- B4: driver ----
if command -v ethtool >/dev/null 2>&1; then
  DRV=$(ethtool -i "$IFACE" 2>/dev/null | awk -F': ' '/^driver:/{print $2}')
  say PASS "B4 $IFACE driver: ${DRV:-unknown}"
else
  say WARN "B4 ethtool missing (apt install ethtool)"
  DRV=unknown
fi

# ---- B6: clang / libbpf ----
if command -v clang >/dev/null 2>&1; then
  CLV=$(clang --version | head -1)
  say PASS "B6 clang: $CLV"
else
  say FAIL "B6 clang not installed (apt install clang llvm)"
fi

if ldconfig -p 2>/dev/null | grep -q libbpf; then
  LBV=$(dpkg -l 2>/dev/null | awk '/libbpf/{print $2" "$3}' | head -1)
  say PASS "B6 libbpf present: ${LBV:-detected via ldconfig}"
else
  say WARN "B6 libbpf not detected (apt install libbpf-dev)"
fi

# ---- B9: existing XDP program ----
XDPINFO=$(ip -details link show "$IFACE" | grep -oE 'xdp[a-z]*' | head -1 || true)
if [ -z "$XDPINFO" ]; then
  say PASS "B9 no existing XDP program on $IFACE"
else
  say WARN "B9 existing XDP attachment on $IFACE: $XDPINFO (will conflict)"
fi

# ---- B10: rx queues ----
if command -v ethtool >/dev/null 2>&1; then
  RXQ=$(ethtool -l "$IFACE" 2>/dev/null | awk '/^Combined:/{print $2; exit}')
  say PASS "B10 $IFACE combined queues: ${RXQ:-n/a}"
fi

# ---- B11: GRO ----
GRO=$(ethtool -k "$IFACE" 2>/dev/null | awk '/generic-receive-offload/{print $2}')
if [ "$GRO" = "on" ]; then
  say WARN "B11 GRO on (XDP sees pre-GRO frames anyway, but note it)"
else
  say PASS "B11 GRO $GRO"
fi

# ---- B12: rp_filter ----
RPA=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)
RPI=$(sysctl -n "net.ipv4.conf.${IFACE}.rp_filter" 2>/dev/null)
if [ "$RPA" -le 1 ] && [ "$RPI" -le 1 ] 2>/dev/null; then
  say PASS "B12 rp_filter all=$RPA $IFACE=$RPI (loose/off)"
else
  say WARN "B12 rp_filter strict (all=$RPA $IFACE=$RPI); may drop asymmetric returns"
fi

# ---- B.3: smoke XDP attach ----
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
cat > "$TMPDIR/smoke.bpf.c" <<'BPFEOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
SEC("xdp") int smoke(struct xdp_md *ctx) { return XDP_PASS; }
char _license[] SEC("license") = "GPL";
BPFEOF

ARCH_INC=$(ls -d /usr/include/*-linux-gnu 2>/dev/null | head -1)
if command -v clang >/dev/null 2>&1; then
  if clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      ${ARCH_INC:+-I"$ARCH_INC"} \
      -c "$TMPDIR/smoke.bpf.c" -o "$TMPDIR/smoke.o" 2>"$TMPDIR/clang.err"; then
    say PASS "B.3 compile smoke.bpf.c ok"
    ATTACHED=""
    if ip link set dev "$IFACE" xdp obj "$TMPDIR/smoke.o" sec xdp 2>"$TMPDIR/attach.err"; then
      say PASS "B.3 XDP native attach ok on $IFACE"
      ATTACHED=native
    elif ip link set dev "$IFACE" xdpgeneric obj "$TMPDIR/smoke.o" sec xdp 2>>"$TMPDIR/attach.err"; then
      say WARN "B.3 XDP native failed, generic attach ok (slower but usable)"
      ATTACHED=generic
    else
      say FAIL "B.3 XDP attach failed (see below)"
      sed 's/^/       /' "$TMPDIR/attach.err"
    fi
    if [ -n "$ATTACHED" ]; then
      sleep 1
      ip link set dev "$IFACE" "${ATTACHED/native/xdp}" off 2>/dev/null || true
      ip link set dev "$IFACE" xdp off 2>/dev/null || true
      ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
      say PASS "B.3 XDP detach ok"
    fi
  else
    say FAIL "B.3 compile failed:"
    sed 's/^/       /' "$TMPDIR/clang.err"
  fi
fi

echo
echo "=== Summary: PASS=$PASS WARN=$WARN FAIL=$FAIL ==="
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT: READY FOR XDP DEVELOPMENT"
  exit 0
else
  echo "RESULT: BLOCKING ISSUES — fix FAIL items before proceeding"
  exit 1
fi
