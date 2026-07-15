#!/usr/bin/env bash
# hub_probe/run_forever.sh — long-running launcher for probe_daemon.py on the HUB.
#
# Runs the unified XDP-assisted TCP SYN/SYN-ACK RTT probe against a fixed set
# of remote VPS peers, forever (--duration-s 0), in the background via
# nohup + disown. Survives the launching SSH session going away; does NOT
# survive a reboot (by design — after reboot re-run this script).
#
# Everything the daemon needs is baked in here on purpose:
#   * PG DSN (read straight out of the probe_pg container env at deploy time)
#   * XDP object path
#   * target list (dst_name=IP)
#   * iface, timeouts, batch settings
#
# Why not use docker/.env like step4_run.sh? Because on this HUB we run only
# ONE authoritative probe daemon against a known peer list, and we want the
# start command to be self-contained: `bash run_forever.sh start` and done.
#
# Usage:
#   sudo bash run_forever.sh start        # launch (kills any previous instance)
#   sudo bash run_forever.sh stop         # kill running instance
#   sudo bash run_forever.sh status       # is it alive? tail last log line
#   sudo bash run_forever.sh tail         # tail -f the log
#
# Sysctl reservation is a one-shot operational step handled by
# hub_sysctl_reserve_ports.sh — this script does NOT touch sysctl. Ensure
# net.ipv4.ip_local_reserved_ports covers 65400-65535 before starting.

set -euo pipefail

# ---------- config: EDIT HERE if peer list / creds change ----------
IFACE="eth0"
INTERVAL_MS=1000
TIMEOUT_MS=3000
BATCH_SIZE=1000
BATCH_INTERVAL_S=300

# Business label for this HUB, written to probe_sample.src.
# Do NOT rely on hostname (the box is named VM-0-15-ubuntu which is meaningless).
SRC_NAME="bangkok"

# Fixed peer list. Names are free-form labels stored in probe_sample.dst_name.
# Each entry is `name=ip4[,ip6]`; if v6 present, daemon rounds-robins both
# families AND both protocols and writes independent rows:
#   proto=tcp_synack (via XDP-caught SA)  ip_ver=4|6
#   proto=icmp       (v4 raw echo)         ip_ver=4
#   proto=icmpv6     (v6 raw echo)         ip_ver=6
# v6 addresses are the real public v6s from vps.yaml — verified reachable
# from this hub (ping6 + scapy SYN test confirmed SA returns via eth0).
TARGETS=(
  "hongkong=43.132.210.4,240d:c000:f005:fc00:8446:a124:f20a:0"
  "virginia=43.165.69.64,240d:c000:f030:1000:8446:a124:f20a:0"
  "beijing=81.70.84.208,2402:4e00:c054:cc00:8446:a124:f20a:0"
)

# PG DSN. Password sourced from `docker inspect probe_pg` on this HUB.
# probe_pg listens on 127.0.0.1:25432 (localhost only after wg retirement).
PROBE_PG_DSN="postgresql://probe:jPPErRzPbz0cMo2r8TfM1MD4@127.0.0.1:25432/probe"

LOG_FILE="/var/log/probe_daemon.log"
PID_FILE="/var/run/probe_daemon.pid"
# -------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OBJ="${REPO_DIR}/bpf/probe_xdp.bpf.o"

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "must run as root (try: sudo $0 $*)" >&2
    exit 1
  fi
}

is_alive() {
  # returns 0 if a matching probe_daemon.py is running
  pgrep -f "probe_daemon\\.py" >/dev/null 2>&1
}

do_start() {
  need_root "$@"

  if [[ ! -f "$OBJ" ]]; then
    echo "[fail] $OBJ missing — run 'cd $REPO_DIR/bpf && make' first" >&2
    exit 1
  fi

  # kill any prior instance so we always end up with exactly one
  if is_alive; then
    echo "[info] existing probe_daemon.py running, killing it first ..."
    pkill -f "probe_daemon\\.py" || true
    sleep 1
  fi

  # detach any leftover XDP prog on the iface so probe_daemon can re-attach
  if ip -d link show "$IFACE" 2>/dev/null | grep -q 'prog/xdp'; then
    echo "[warn] $IFACE already has an XDP prog attached — detaching"
    ip link set dev "$IFACE" xdp off || true
    sleep 0.5
  fi

  # sanity-check PG reachability up front (fail fast, don't background a
  # doomed daemon)
  if ! PROBE_PG_DSN="$PROBE_PG_DSN" python3 - <<'PYEOF'
import os, sys, psycopg2
conn = psycopg2.connect(os.environ["PROBE_PG_DSN"], connect_timeout=3)
cur  = conn.cursor(); cur.execute("SELECT 1"); cur.fetchone(); conn.close()
print("[pg] reachable")
PYEOF
  then
    echo "[fail] cannot reach PG — aborting" >&2
    exit 1
  fi

  TARGET_ARGS=()
  for t in "${TARGETS[@]}"; do
    TARGET_ARGS+=(--target "$t")
  done

  echo "=========== run_forever.sh start ==========="
  echo "src_name    = $SRC_NAME"
  echo "iface       = $IFACE"
  echo "targets     = ${TARGETS[*]}"
  echo "interval    = ${INTERVAL_MS}ms"
  echo "timeout     = ${TIMEOUT_MS}ms"
  echo "batch_size  = $BATCH_SIZE  batch_intvl=${BATCH_INTERVAL_S}s"
  echo "obj         = $OBJ"
  echo "log_file    = $LOG_FILE"
  echo "pid_file    = $PID_FILE"

  # append a session banner to the log so restarts are visible
  {
    echo
    echo "===== $(date -u +%Y-%m-%dT%H:%M:%SZ) run_forever.sh start ====="
  } >>"$LOG_FILE"

  # Launch: nohup + disown so it survives ssh session close.
  # We use setsid to fully detach from the controlling terminal.
  PROBE_PG_DSN="$PROBE_PG_DSN" \
  nohup setsid python3 -u "$SCRIPT_DIR/probe_daemon.py" \
      --iface "$IFACE" \
      --obj "$OBJ" \
      --mode generic \
      --src-name "$SRC_NAME" \
      "${TARGET_ARGS[@]}" \
      --interval-ms "$INTERVAL_MS" \
      --timeout-ms "$TIMEOUT_MS" \
      --duration-s 0 \
      --sink pg \
      --batch-size "$BATCH_SIZE" \
      --batch-interval-s "$BATCH_INTERVAL_S" \
      --verbose \
      >>"$LOG_FILE" 2>&1 &

  pid=$!
  disown "$pid" 2>/dev/null || true
  echo "$pid" >"$PID_FILE"
  sleep 2

  if kill -0 "$pid" 2>/dev/null; then
    echo "[ok] started pid=$pid"
    echo "     tail -f $LOG_FILE"
  else
    echo "[fail] daemon died within 2s — check $LOG_FILE"
    tail -n 40 "$LOG_FILE" || true
    exit 1
  fi
}

do_stop() {
  need_root "$@"
  if is_alive; then
    echo "[info] killing probe_daemon.py ..."
    pkill -f "probe_daemon\\.py" || true
    sleep 1
    if is_alive; then
      echo "[warn] still alive, sending SIGKILL"
      pkill -9 -f "probe_daemon\\.py" || true
    fi
    echo "[ok] stopped"
  else
    echo "[info] not running"
  fi
  rm -f "$PID_FILE"

  # optional: detach XDP so the iface isn't left in a weird state
  if ip -d link show "$IFACE" 2>/dev/null | grep -q 'prog/xdp'; then
    echo "[info] detaching XDP from $IFACE"
    ip link set dev "$IFACE" xdp off || true
  fi
}

do_status() {
  if is_alive; then
    pids=$(pgrep -f "probe_daemon\\.py" | tr '\n' ' ')
    echo "[ok] running  pid(s)=${pids}"
    if [[ -f "$LOG_FILE" ]]; then
      echo "--- last 5 log lines ---"
      tail -n 5 "$LOG_FILE"
    fi
  else
    echo "[info] not running"
    exit 1
  fi
}

do_tail() {
  exec tail -F "$LOG_FILE"
}

case "${1:-status}" in
  start)  do_start "$@" ;;
  stop)   do_stop  "$@" ;;
  status) do_status ;;
  tail)   do_tail ;;
  *)
    echo "Usage: $0 {start|stop|status|tail}" >&2
    exit 2
    ;;
esac
