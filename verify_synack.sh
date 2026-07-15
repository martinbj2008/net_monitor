#!/usr/bin/env bash
# verify_synack.sh — v2
#
# Run on HUB (bangkok). Verify that sending TCP SYN to leaf VPS :22 (sshd)
# from sport in reserved range [65408, 65423] works end-to-end AFTER hub-side
# port reservation is in place, WITHOUT disturbing real ssh clients.
#
# Prerequisites on this hub (run once):
#   sudo bash hub_sysctl_reserve_ports.sh apply
#   # ensures net.ipv4.ip_local_reserved_ports contains 65408-65535
#
# Prerequisites on leaf VPS:
#   - reachable via ssh from hub as root (key auth already set up)
#   - sshd on public IP :22
#   - `ss`, `nstat` available (iproute2, standard)
#
# What this script does per target:
#   1. Snapshot VPS baseline:
#        - ss -H -ntl 'sport = :22'  -> listen socket Recv-Q/Send-Q
#        - nstat -az | grep -E 'ListenDrops|ListenOverflows|TCPReqQFullDrop|TCPReqQFullDoCookies|TcpExtSyncookies'
#   2. hping3 from hub public IP -> leaf public IP :22
#        - -S (SYN), -c $COUNT, -i u$IV_US, -p 22
#        - --keep -s $SPORT to fix source port (rotated across [65408..65423])
#          NOTE: hping3 --keep locks sport to the given value; to rotate we
#          split COUNT into batches, one sport per batch.
#   3. During sending, sample VPS listen queue every 500ms via ssh in
#      background; log peak Send-Q.
#   4. Snapshot VPS end state, diff counters.
#   5. Aggregate hub-side hping3 stats (SA / RA / timeout counts, min/avg/max
#      RTT) and write a report file per target.
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
  TARGETS=(
    "beijing:81.70.84.208"
    "hongkong:43.132.210.4"
    "virginia:43.165.69.64"
  )
fi

# ---------------- preflight ----------------
if ! command -v hping3 >/dev/null 2>&1; then
  echo "ERROR: hping3 not found. Install: apt-get install -y hping3" >&2
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

IV_US=$(( INTERVAL_MS * 1000 ))
NUM_SPORTS=$(( SPORT_HI - SPORT_LO + 1 ))

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

# hub-side hping3 for one sport batch
hping_batch() {
  local ip="$1" sport="$2" batch_count="$3" outfile="$4"
  # -S SYN, -c count, -i u<us>, -p dport, -s sport, --keep keep sport fixed
  hping3 -S -c "$batch_count" -i "u${IV_US}" -p "$PORT" \
    -s "$sport" --keep "$ip" \
    >> "$outfile" 2>&1 || true
}

# parse hping3 output block, produce summary counts
parse_hping() {
  local infile="$1"
  local sa ra other sent recv rttmin rttavg rttmax
  sa=$(grep -Eo 'flags=SA' "$infile" | wc -l | tr -d ' ')
  ra=$(grep -Eo 'flags=RA' "$infile" | wc -l | tr -d ' ')
  # replies that aren't SA/RA (rare: R, FA...)
  other=$(grep -Eo 'flags=[A-Z]+' "$infile" | grep -Ev 'flags=(SA|RA)$' | wc -l | tr -d ' ')
  sent=$(grep -Eo '[0-9]+ packets transmitted' "$infile" | awk '{s+=$1} END{print s+0}')
  recv=$(grep -Eo '[0-9]+ packets received' "$infile" | awk '{s+=$1} END{print s+0}')
  # rtt lines: "round-trip min/avg/max = 1.2/3.4/5.6 ms"
  local rttline
  rttline=$(grep -E 'round-trip min/avg/max' "$infile" | tail -1)
  rttmin=$(echo "$rttline" | sed -nE 's|.*= *([0-9.]+)/([0-9.]+)/([0-9.]+).*|\1|p')
  rttavg=$(echo "$rttline" | sed -nE 's|.*= *([0-9.]+)/([0-9.]+)/([0-9.]+).*|\2|p')
  rttmax=$(echo "$rttline" | sed -nE 's|.*= *([0-9.]+)/([0-9.]+)/([0-9.]+).*|\3|p')
  echo "SA=${sa} RA=${ra} OTHER=${other} sent=${sent} recv=${recv} rtt_ms=${rttmin:-NA}/${rttavg:-NA}/${rttmax:-NA}"
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

  # 3) send in batches, rotating sport
  hping_out="${tgt_dir}/hping.out"
  : > "$hping_out"
  # split COUNT across sports as evenly as possible
  per=$(( COUNT / NUM_SPORTS ))
  rem=$(( COUNT % NUM_SPORTS ))
  sp="$SPORT_LO"
  batch_idx=0
  while [[ $sp -le $SPORT_HI ]]; do
    n=$per
    if [[ $batch_idx -lt $rem ]]; then n=$(( n + 1 )); fi
    if [[ $n -gt 0 ]]; then
      echo "--- batch sport=$sp count=$n ---" >> "$hping_out"
      hping_batch "$ip" "$sp" "$n" "$hping_out"
    fi
    sp=$(( sp + 1 ))
    batch_idx=$(( batch_idx + 1 ))
  done

  # 4) stop sampler & take end snapshot
  vps_sampler_stop "${tgt_dir}/.sampler.pid"
  vps_snapshot "$ip" "after" "$tgt_dir"

  # 5) summary
  summary=$(parse_hping "$hping_out")
  # peak Send-Q from sampler
  peak_sq=$(awk 'NF>=3 && $3 ~ /^[0-9]+$/ {if($3>m)m=$3} END{print m+0}' "${tgt_dir}/vps_sampler.txt" 2>/dev/null || echo "NA")
  peak_rq=$(awk 'NF>=3 && $2 ~ /^[0-9]+$/ {if($2>m)m=$2} END{print m+0}' "${tgt_dir}/vps_sampler.txt" 2>/dev/null || echo "NA")

  # counter diff (before vs after) — simple line-oriented diff on the ---NSTAT--- block
  {
    echo "==== target: $name ($ip) port $PORT ===="
    echo "hub hping3 summary: $summary"
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
