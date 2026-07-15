#!/usr/bin/env bash
# verify_synack.sh — v3 (scapy backend)
#
# Run on HUB (bangkok). Verify that sending TCP SYN to leaf VPS :22 (sshd)
# from sport in reserved range [65408, 65423] works end-to-end AFTER hub-side
# port reservation is in place, WITHOUT disturbing real ssh clients.
#
# Backend: python3 + scapy (raw socket). Prior hping3 backend proved
# unreliable due to sport-based reply mixing with unrelated flows.
#
# Prerequisites on this hub (run once):
#   sudo bash hub_sysctl_reserve_ports.sh apply
#   apt-get install -y python3-scapy   # or: pip3 install scapy
#
# Prerequisites on leaf VPS:
#   - reachable via ssh from hub as root (key auth already set up)
#   - sshd on public IP :22
#   - `ss`, `nstat` available (iproute2, standard)
#
# What this script does per target:
#   1. Snapshot VPS baseline (ss + nstat).
#   2. Run verify_synack_scapy.py from hub -> leaf :port.
#      - COUNT SYNs, one per INTERVAL_MS.
#      - sport rotates across [SPORT_LO..SPORT_HI].
#      - each reply is strictly matched by 5-tuple; classified as
#        SA / RA / R / FA / A / other / mismatch / timeout.
#   3. During sending, sample VPS listen queue every 500ms; log peaks.
#   4. Snapshot VPS end state, diff counters.
#   5. Aggregate JSON summary from scapy script; write report per target.
#
# Usage:
#   bash verify_synack.sh [--port 22] [--count 60] [--interval-ms 1000] \
#       [--targets "beijing:81.70.84.208,hongkong:43.132.210.4,virginia:43.165.69.64"]
#
# All output goes under ./verify_report/<name>_port<port>_<ts>/.

set -u
set -o pipefail

# ---------------- defaults ----------------
PORT=22
COUNT=60
INTERVAL_MS=1000
TARGETS_ARG=""

# sport reservation range actually used by the probe program
SPORT_LO=65408
SPORT_HI=65423   # 16 ports: 65408..65423

SSH_USER=root
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5)

# ---------------- argparse ----------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)        PORT="$2"; shift 2 ;;
    --count)       COUNT="$2"; shift 2 ;;
    --interval-ms) INTERVAL_MS="$2"; shift 2 ;;
    --targets)     TARGETS_ARG="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,40p' "$0"
      exit 0 ;;
    *)
      echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ---------------- targets ----------------
declare -a TARGETS
if [[ -n "$TARGETS_ARG" ]]; then
  IFS=',' read -r -a _tmp <<< "$TARGETS_ARG"
  for t in "${_tmp[@]}"; do
    TARGETS+=("$t")
  done
else
  # Default targets: stable network points only.
  # NOTE: beijing (81.70.84.208) excluded — the hub->beijing path is currently
  # flaky (~350ms RTT with ~20% packet loss on plain ICMP), which pollutes
  # SYN/SYN-ACK stats. Add it back manually via --targets once network is fixed.
  TARGETS=(
    "hongkong:43.132.210.4"
    "virginia:43.165.69.64"
  )
fi

# ---------------- preflight ----------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found." >&2
  exit 1
fi
if ! python3 -c 'import scapy' >/dev/null 2>&1; then
  echo "ERROR: python3 scapy not available. Install: apt-get install -y python3-scapy" >&2
  exit 1
fi
SCAPY_SCRIPT="$(dirname "$(readlink -f "$0")")/verify_synack_scapy.py"
if [[ ! -f "$SCAPY_SCRIPT" ]]; then
  echo "ERROR: $SCAPY_SCRIPT not found." >&2
  exit 1
fi

RESERVED=$(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || echo "")
echo "[preflight] hub ip_local_reserved_ports = '${RESERVED}'"
if ! echo "$RESERVED" | grep -qE '(65408|6540[89]|654[0-9][0-9]|655[0-2][0-9]|6553[0-5])'; then
  echo "WARN: reserved range does not appear to cover ${SPORT_LO}-${SPORT_HI}."
  echo "      run: sudo bash hub_sysctl_reserve_ports.sh apply"
fi

TS=$(date +%Y%m%d_%H%M%S)
OUTROOT="./verify_report/run_${TS}"
mkdir -p "$OUTROOT"
echo "[info] output root = $OUTROOT"

# ---------------- helpers ----------------
# snapshot vps listen state + counters
vps_snapshot() {
  local host="$1" tag="$2" outdir="$3"
  ssh "${SSH_OPTS[@]}" "${SSH_USER}@${host}" \
    "ss -H -ntl 'sport = :${PORT}' 2>/dev/null; echo '---NSTAT---'; \
     nstat -az 2>/dev/null | grep -E 'ListenDrops|ListenOverflows|TcpExtTCPReqQFullDrop|TcpExtTCPReqQFullDoCookies|TcpExtSyncookiesSent|TcpExtSyncookiesRecv|TcpExtSyncookiesFailed|TcpAttemptFails|TcpPassiveOpens' || true" \
    > "${outdir}/vps_${tag}.txt" 2>"${outdir}/vps_${tag}.err" || {
      echo "WARN: ssh snapshot to ${host} (${tag}) failed" >&2
    }
}

# background sampler: every 500ms, one line: <ts> <Recv-Q> <Send-Q>
vps_sampler_start() {
  local host="$1" outfile="$2" pidfile="$3"
  # Use a single ssh session running a short loop for ~ (COUNT*INTERVAL_MS/1000 + 5) seconds.
  local dur=$(( COUNT * INTERVAL_MS / 1000 + 5 ))
  # remote inline loop; runs at 2Hz
  ssh "${SSH_OPTS[@]}" "${SSH_USER}@${host}" \
    "end=\$(( \$(date +%s) + ${dur} )); \
     while [ \$(date +%s) -lt \$end ]; do \
       ts=\$(date +%s.%N); \
       line=\$(ss -H -ntl 'sport = :${PORT}' 2>/dev/null | head -1); \
       rq=\$(echo \"\$line\" | awk '{print \$2}'); \
       sq=\$(echo \"\$line\" | awk '{print \$3}'); \
       echo \"\$ts \${rq:-NA} \${sq:-NA}\"; \
       sleep 0.5; \
     done" \
    > "$outfile" 2>/dev/null &
  echo $! > "$pidfile"
}

vps_sampler_stop() {
  local pidfile="$1"
  if [[ -f "$pidfile" ]]; then
    local pid
    pid=$(cat "$pidfile")
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$pidfile"
  fi
}

# run scapy prober; produce stderr trace + stdout JSON
run_scapy_probe() {
  local ip="$1" outdir="$2"
  local jsonfile="${outdir}/scapy.json"
  local tracefile="${outdir}/scapy.trace"
  # Root required for raw socket
  python3 "$SCAPY_SCRIPT" \
    --dst "$ip" --dport "$PORT" \
    --count "$COUNT" --interval-ms "$INTERVAL_MS" \
    --sport-lo "$SPORT_LO" --sport-hi "$SPORT_HI" \
    --timeout-ms 2000 \
    >"$jsonfile" 2>"$tracefile" || {
      echo "WARN: scapy prober exited non-zero (see $tracefile)" >&2
    }
}

# parse scapy JSON -> one-line human summary
parse_scapy() {
  local jsonfile="$1"
  python3 - "$jsonfile" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"parse_error: {e}")
    sys.exit(0)
rtt = d.get("rtt_ms") or {}
def g(k): return rtt.get(k, "NA")
print(
    f"sent={d.get('sent',0)} SA={d.get('sa',0)} RA={d.get('ra',0)} "
    f"R={d.get('r',0)} FA={d.get('fa',0)} A={d.get('a_only',0)} "
    f"other={d.get('other',0)} mismatch={d.get('mismatch',0)} "
    f"timeout={d.get('timeout',0)} "
    f"rtt_ms={g('min')}/{g('avg')}/{g('max')} "
    f"p50={g('p50')} p95={g('p95')} rtt_n={g('count')}"
)
PY
}

# ---------------- main loop ----------------
for row in "${TARGETS[@]}"; do
  name="${row%%:*}"
  ip="${row#*:}"
  tgt_dir="${OUTROOT}/${name}_port${PORT}"
  mkdir -p "$tgt_dir"

  echo
  echo "======================================================================"
  echo "[$name] $ip :$PORT   count=$COUNT interval=${INTERVAL_MS}ms  sports=${SPORT_LO}..${SPORT_HI}"
  echo "======================================================================"

  # 1) baseline snapshot
  vps_snapshot "$ip" "before" "$tgt_dir"

  # 2) start background sampler
  vps_sampler_start "$ip" "${tgt_dir}/vps_sampler.txt" "${tgt_dir}/.sampler.pid"

  # 3) send via scapy
  run_scapy_probe "$ip" "$tgt_dir"

  # 4) stop sampler & take end snapshot
  vps_sampler_stop "${tgt_dir}/.sampler.pid"
  vps_snapshot "$ip" "after" "$tgt_dir"

  # 5) summary
  summary=$(parse_scapy "${tgt_dir}/scapy.json")
  # peak Send-Q from sampler
  peak_sq=$(awk 'NF>=3 && $3 ~ /^[0-9]+$/ {if($3>m)m=$3} END{print m+0}' "${tgt_dir}/vps_sampler.txt" 2>/dev/null || echo "NA")
  peak_rq=$(awk 'NF>=3 && $2 ~ /^[0-9]+$/ {if($2>m)m=$2} END{print m+0}' "${tgt_dir}/vps_sampler.txt" 2>/dev/null || echo "NA")

  {
    echo "==== target: $name ($ip) port $PORT ===="
    echo "hub scapy summary: $summary"
    echo "vps listen-q peak during test: Recv-Q_max=${peak_rq}  Send-Q_max=${peak_sq}"
    echo
    echo "---- vps counters BEFORE ----"
    awk '/---NSTAT---/{p=1;next} p' "${tgt_dir}/vps_before.txt" 2>/dev/null || true
    echo "---- vps counters AFTER ----"
    awk '/---NSTAT---/{p=1;next} p' "${tgt_dir}/vps_after.txt" 2>/dev/null || true
    echo "---- vps listen socket BEFORE ----"
    awk '/---NSTAT---/{exit} {print}' "${tgt_dir}/vps_before.txt" 2>/dev/null || true
    echo "---- vps listen socket AFTER ----"
    awk '/---NSTAT---/{exit} {print}' "${tgt_dir}/vps_after.txt" 2>/dev/null || true
  } | tee "${tgt_dir}/report.txt"

done

echo
echo "===== ALL DONE ====="
echo "reports under: $OUTROOT"
