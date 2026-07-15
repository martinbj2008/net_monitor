#!/usr/bin/env bash
# hub_probe/step4_run.sh — one-shot Step 4 runner (PG sink).
#
# What it does on the hub:
#   1. sanity: not-running-as-non-root, obj built, xdp free, PG reachable
#   2. kill any leftover probe_daemon.py
#   3. record baseline row count for this batch_ts window (start-of-run wall
#      time), then start probe_daemon.py for --duration-s (default 30s)
#   4. after finishing, query PG for the rows just inserted and summarize
#
# The DSN is composed from docker/.env — no plaintext password in this script.
#
# Usage on hub:
#   sudo bash step4_run.sh                     # default 30s hongkong probe
#   sudo bash step4_run.sh --duration 60
#   sudo bash step4_run.sh --target virginia=170.106.106.161

set -euo pipefail

IFACE="eth0"
DURATION=30
INTERVAL_MS=1000
TIMEOUT_MS=3000
BATCH_SIZE=1000
BATCH_INTERVAL=300
TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)          IFACE="$2"; shift 2 ;;
    --duration)       DURATION="$2"; shift 2 ;;
    --interval)       INTERVAL_MS="$2"; shift 2 ;;
    --timeout)        TIMEOUT_MS="$2"; shift 2 ;;
    --batch-size)     BATCH_SIZE="$2"; shift 2 ;;
    --batch-interval) BATCH_INTERVAL="$2"; shift 2 ;;
    --target)         TARGETS+=("$2"); shift 2 ;;
    -h|--help)        sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown: $1" >&2; exit 2 ;;
  esac
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("hongkong=43.132.210.4")
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OBJ="${REPO_DIR}/bpf/probe_xdp.bpf.o"

# Where to find docker/.env for the PG credentials. Priority:
#   1. $PROBE_PG_DSN already exported -> use it directly, skip env-file lookup
#   2. $PROBE_ENV_FILE if the caller sets it
#   3. sibling docker/ in the same repo (dev/mac workspace layout)
#   4. /root/vps_probe/docker/.env  (hub deployment layout)
ENV_FILE=""
if [[ -z "${PROBE_PG_DSN:-}" ]]; then
  for cand in \
      "${PROBE_ENV_FILE:-}" \
      "${REPO_DIR}/docker/.env" \
      "/root/vps_probe/docker/.env"; do
    if [[ -n "$cand" && -f "$cand" ]]; then
      ENV_FILE="$cand"; break
    fi
  done
fi

echo "=========== step4_run.sh ==========="
echo "iface       = $IFACE"
echo "targets     = ${TARGETS[*]}"
echo "duration    = ${DURATION}s"
echo "interval    = ${INTERVAL_MS}ms"
echo "timeout     = ${TIMEOUT_MS}ms"
echo "batch_size  = $BATCH_SIZE"
echo "batch_intvl = ${BATCH_INTERVAL}s"
echo "obj         = $OBJ"
if [[ -n "${PROBE_PG_DSN:-}" ]]; then
  echo "pg_dsn      = <from env>"
else
  echo "env_file    = $ENV_FILE"
fi

# --- 1. sanity ---
if [[ $EUID -ne 0 ]]; then
  echo "must run as root" >&2; exit 1
fi
if [[ ! -f "$OBJ" ]]; then
  echo "[fail] $OBJ missing — run 'cd $REPO_DIR/bpf && make' first" >&2
  exit 1
fi
if [[ -z "${PROBE_PG_DSN:-}" ]]; then
  if [[ -z "$ENV_FILE" || ! -f "$ENV_FILE" ]]; then
    echo "[fail] neither \$PROBE_PG_DSN set nor docker/.env found; " \
         "tried \$PROBE_ENV_FILE, $REPO_DIR/docker/.env, " \
         "/root/vps_probe/docker/.env" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a
  PG_HOST_PORT="${PG_BIND:-127.0.0.1:25432}"
  PROBE_PG_DSN="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${PG_HOST_PORT}/${POSTGRES_DB}"
fi
export PROBE_PG_DSN

# poke PG once so we fail fast if unreachable / creds wrong
python3 - <<'PYEOF' || { echo "[fail] cannot reach PG" >&2; exit 1; }
import os, sys, psycopg2
dsn = os.environ["PROBE_PG_DSN"]
conn = psycopg2.connect(dsn, connect_timeout=3)
cur  = conn.cursor(); cur.execute("SELECT 1"); cur.fetchone(); conn.close()
print("[pg] reachable")
PYEOF

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

# --- 3. run daemon ---
TARGET_ARGS=()
for t in "${TARGETS[@]}"; do
  TARGET_ARGS+=(--target "$t")
done

RUN_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[info] run_start_utc=$RUN_START_ISO"
echo "[info] launching probe_daemon.py ..."

python3 "$SCRIPT_DIR/probe_daemon.py" \
  --iface "$IFACE" \
  --obj "$OBJ" \
  --mode generic \
  "${TARGET_ARGS[@]}" \
  --interval-ms "$INTERVAL_MS" \
  --timeout-ms "$TIMEOUT_MS" \
  --duration-s "$DURATION" \
  --sink pg \
  --batch-size "$BATCH_SIZE" \
  --batch-interval-s "$BATCH_INTERVAL" \
  --verbose

# --- 4. summarize by querying PG ---
echo
echo "=========== PG summary (rows since $RUN_START_ISO) ==========="
python3 - "$RUN_START_ISO" <<'PYEOF'
import os, sys, psycopg2, statistics
run_start = sys.argv[1]
conn = psycopg2.connect(os.environ["PROBE_PG_DSN"])
cur  = conn.cursor()
cur.execute("""
    SELECT dst, ok, rtt_ms FROM probe_sample
     WHERE batch_ts >= %s
       AND proto = 'tcp_synack'
""", (run_start,))
rows = cur.fetchall()
conn.close()
if not rows:
    print("[fail] no rows in PG for this run — daemon didn't insert?")
    sys.exit(3)
by_dst = {}
for dst, ok, rtt in rows:
    by_dst.setdefault(dst, []).append((ok, rtt))
for dst, xs in sorted(by_dst.items()):
    total = len(xs)
    ok_xs = [r for o, r in xs if o and r is not None]
    to    = sum(1 for o, _ in xs if not o)
    if ok_xs:
        mn, avg, mx = min(ok_xs), statistics.mean(ok_xs), max(ok_xs)
        print(f"  {dst:<12} total={total:>4} ok={len(ok_xs):>4} "
              f"timeout={to:>4} rtt min/avg/max = {mn}/{avg:.1f}/{mx} ms")
    else:
        print(f"  {dst:<12} total={total:>4} ok=0 timeout={to:>4} rtt=n/a")
PYEOF

echo "[done]"
