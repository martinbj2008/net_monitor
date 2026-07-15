#!/usr/bin/env bash
# hub_probe/step3_run.sh — one-shot Step 3 verification runner on hub.
#
# Runs two rounds back-to-back and prints a summary:
#   Round 1: NO XDP attached  -> expect tx_rst=5 (control)
#   Round 2: WITH XDP attached -> expect tx_rst=0, and loader logs 5 events
#
# Assumes:
#   - Called from ~/git/net_monitor/hub_probe on the hub
#   - probe_xdp.bpf.o already built (../bpf/probe_xdp.bpf.o exists)
#   - Running as root

set -u

TARGET="${TARGET:-43.132.210.4}"
IFACE="${IFACE:-eth0}"
COUNT="${COUNT:-5}"
MODE="${MODE:-generic}"
LOGDIR="${LOGDIR:-/tmp/step3_$(date +%Y%m%d_%H%M%S)}"

mkdir -p "$LOGDIR"
cd "$(dirname "$0")"

echo "============================================================"
echo "Step 3 verification"
echo "  target=$TARGET  iface=$IFACE  count=$COUNT  mode=$MODE"
echo "  logdir=$LOGDIR"
echo "============================================================"

# --- Sanity: BPF object exists ---
if [[ ! -f ../bpf/probe_xdp.bpf.o ]]; then
    echo "[FAIL] ../bpf/probe_xdp.bpf.o missing. Run: cd ../bpf && make" >&2
    exit 1
fi

# --- Sanity: no leftover XDP program on iface ---
existing="$(ip -j link show dev "$IFACE" 2>/dev/null | grep -o '"xdp"' || true)"
if [[ -n "$existing" ]]; then
    echo "[warn] $IFACE already has an XDP program attached. Detaching..."
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
    ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
    sleep 0.5
fi

# =====================================================================
# Round 1: control (no XDP)
# =====================================================================
echo
echo "----- Round 1: control (no XDP) -----"
python3 step3_probe.py --target "$TARGET" --iface "$IFACE" --count "$COUNT" \
    2>&1 | tee "$LOGDIR/round1_probe.log"
r1_rc=${PIPESTATUS[0]}
echo "[info] round1 exit=$r1_rc"

if [[ $r1_rc -ne 0 ]]; then
    echo "[FAIL] Round 1 probe exited $r1_rc — aborting before touching XDP." >&2
    exit 2
fi

# =====================================================================
# Round 2: with XDP attached
# =====================================================================
echo
echo "----- Round 2: with XDP attached (mode=$MODE) -----"

# Start loader in background; it registers SIGTERM handler for clean detach.
nohup python3 -u test_loader.py --iface "$IFACE" --mode "$MODE" --count 0 \
    > "$LOGDIR/round2_loader.log" 2>&1 &
LOADER_PID=$!
echo "[info] loader pid=$LOADER_PID (log: $LOGDIR/round2_loader.log)"

# Wait for loader to finish attach; poll the log until we see "[info] polling"
attached=0
for i in $(seq 1 30); do
    if grep -q "polling ringbuf" "$LOGDIR/round2_loader.log" 2>/dev/null; then
        attached=1; break
    fi
    if ! kill -0 "$LOADER_PID" 2>/dev/null; then
        echo "[FAIL] loader died during attach:" >&2
        cat "$LOGDIR/round2_loader.log" >&2
        exit 3
    fi
    sleep 0.2
done
if [[ $attached -eq 0 ]]; then
    echo "[FAIL] loader didn't reach ringbuf poll within 6s:" >&2
    cat "$LOGDIR/round2_loader.log" >&2
    kill "$LOADER_PID" 2>/dev/null || true
    exit 4
fi
echo "[info] loader attached, XDP live on $IFACE"

# Give the driver a beat to settle
sleep 0.5

# Fire probes
python3 step3_probe.py --target "$TARGET" --iface "$IFACE" --count "$COUNT" \
    2>&1 | tee "$LOGDIR/round2_probe.log"
r2_rc=${PIPESTATUS[0]}
echo "[info] round2 probe exit=$r2_rc"

# Let loader drain the ringbuf
sleep 1.0

# Stop loader (SIGTERM -> its signal handler triggers detach + close)
echo "[info] stopping loader (SIGTERM pid=$LOADER_PID)"
kill -TERM "$LOADER_PID" 2>/dev/null || true
for i in $(seq 1 20); do
    if ! kill -0 "$LOADER_PID" 2>/dev/null; then break; fi
    sleep 0.2
done
if kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "[warn] loader still alive, SIGKILL"
    kill -KILL "$LOADER_PID" 2>/dev/null || true
    # emergency detach
    ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
fi

# Final safety: ensure nothing is left attached
leftover="$(ip -j link show dev "$IFACE" 2>/dev/null | grep -o '"xdp"' || true)"
if [[ -n "$leftover" ]]; then
    echo "[warn] XDP still present after loader exit; forcing detach"
    ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
fi

# =====================================================================
# Summary
# =====================================================================
echo
echo "============================================================"
echo "SUMMARY"
echo "============================================================"

r1_line="$(grep -E '^result: ' "$LOGDIR/round1_probe.log" | tail -1)"
r2_line="$(grep -E '^result: ' "$LOGDIR/round2_probe.log" | tail -1)"
loader_events="$(grep -cE '^\[[0-9]+\] ts=' "$LOGDIR/round2_loader.log" || echo 0)"

echo "Round 1 (no  XDP): $r1_line"
echo "Round 2 (with XDP): $r2_line"
echo "Round 2 loader events observed: $loader_events"
echo
echo "Loader log tail:"
tail -8 "$LOGDIR/round2_loader.log" | sed 's/^/  /'
echo
echo "All logs: $LOGDIR"
