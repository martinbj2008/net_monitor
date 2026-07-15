#!/usr/bin/env bash
# hub_probe/step4_run.sh — one-shot Step 4 runner.
#
# What it does on the hub:
#   1. sanity: xdp not stuck, kernel reserved ports set, obj built
#   2. kill any leftover probe_daemon.py
#   3. start probe_daemon.py for --duration-s (default 30s), 1 target
#      (hongkong) at 1 Hz, CSV -> /tmp/rtt_step4.csv
#   4. after finishing, summarize CSV: total / matched / timeout / rtt stats
#
# Usage on hub:
#   sudo bash step4_run.sh                       # default 30s hongkong probe
#   sudo bash step4_run.sh --duration 60
#   sudo bash step4_run.sh --target virginia=170.106.106.161

set -euo pipefail

IFACE="eth0"
DURATION=30
INTERVAL_MS=1000
TIMEOUT_MS=3000
CSV="/tmp/rtt_step4.csv"
TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)    IFACE="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --interval) INTERVAL_MS="$2"; shift 2 ;;
    --timeout)  TIMEOUT_MS="$2"; shift 2 ;;
    --csv)      CSV="$2"; shift 2 ;;
    --target)   TARGETS+=("$2"); shift 2 ;;
    -h|--help)  sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown: $1" >&2; exit 2 ;;
  esac
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("hongkong=43.132.210.4")
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OBJ="${REPO_DIR}/bpf/probe_xdp.bpf.o"

echo "=========== step4_run.sh ==========="
echo "iface       = $IFACE"
echo "targets     = ${TARGETS[*]}"
echo "duration    = ${DURATION}s"
echo "interval    = ${INTERVAL_MS}ms"
echo "timeout     = ${TIMEOUT_MS}ms"
echo "csv         = $CSV"
echo "obj         = $OBJ"

# --- 1. sanity checks ---
if [[ $EUID -ne 0 ]]; then
  echo "must run as root" >&2; exit 1
fi
if [[ ! -f "$OBJ" ]]; then
  echo "[fail] $OBJ missing — run 'cd $REPO_DIR/bpf && make' first" >&2
  exit 1
fi
cur_xdp=$(ip -d link show "$IFACE" 2>/dev/null | grep -o 'prog/xdp' || true)
if [[ -n "$cur_xdp" ]]; then
  echo "[warn] $IFACE already has an XDP prog — detaching first"
  ip link set dev "$IFACE" xdp off || true
  sleep 0.5
fi

# --- 2. kill leftovers ---
if pgrep -f "probe_daemon.py" >/dev/null; then
  echo "[info] killing existing probe_daemon.py ..."
  pkill -f "probe_daemon.py" || true
  sleep 1
fi

# fresh CSV
rm -f "$CSV" "${CSV}.chk"

# --- 3. run daemon ---
TARGET_ARGS=()
for t in "${TARGETS[@]}"; do
  TARGET_ARGS+=(--target "$t")
done

echo "[info] launching probe_daemon.py ..."
python3 "$SCRIPT_DIR/probe_daemon.py" \
  --iface "$IFACE" \
  --obj "$OBJ" \
  --mode generic \
  "${TARGET_ARGS[@]}" \
  --interval-ms "$INTERVAL_MS" \
  --timeout-ms "$TIMEOUT_MS" \
  --duration-s "$DURATION" \
  --csv "$CSV" \
  --verbose

# --- 4. summarize ---
echo
echo "=========== CSV summary ==========="
if [[ ! -s "$CSV" ]]; then
  echo "[fail] CSV empty: $CSV"; exit 3
fi

python3 - <<PYEOF
import csv, statistics
rows = []
with open("$CSV") as f:
    r = csv.DictReader(f)
    for x in r:
        rows.append(x)
by_dst = {}
for x in rows:
    by_dst.setdefault(x["dst"], []).append(x)

for dst, xs in by_dst.items():
    total = len(xs)
    ok = [x for x in xs if x["ok"].lower() == "true"]
    to = total - len(ok)
    rtts = [int(x["rtt_ms"]) for x in ok if x["rtt_ms"]]
    if rtts:
        mn, avg, mx = min(rtts), statistics.mean(rtts), max(rtts)
        line = f"  {dst:<12} total={total:>3} ok={len(ok):>3} timeout={to:>3} " \
               f"rtt min/avg/max = {mn}/{avg:.1f}/{mx} ms"
    else:
        line = f"  {dst:<12} total={total:>3} ok=0 timeout={to:>3} rtt=n/a"
    print(line)
PYEOF

echo
echo "[done] csv preserved at $CSV"
