#!/bin/bash
# 手动 TCP 探测诊断脚本：验证下线 TCP 探测的根因是否为内核资源打满
# 用法：scp 到目标节点后 nohup 后台跑
set -u
LOG=/tmp/tcp_probe_test.log
STAT=/tmp/tcp_probe_stat.log
TARGET=${1:-43.132.210.4}
PORT=${2:-9999}
DURATION=${3:-180}

: > "$LOG"
: > "$STAT"

echo "=== START $(date -u +%FT%TZ) target=$TARGET:$PORT duration=${DURATION}s ===" | tee -a "$STAT"
echo "kernel: $(uname -r)" | tee -a "$STAT"
echo "conntrack_max: $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)" | tee -a "$STAT"
echo "tcp_max_orphans: $(cat /proc/sys/net/ipv4/tcp_max_orphans)" | tee -a "$STAT"
echo "ip_local_port_range: $(cat /proc/sys/net/ipv4/ip_local_port_range)" | tee -a "$STAT"
echo "---" | tee -a "$STAT"

# 采样器：每 5 秒记录一次
(
  n=$((DURATION / 5 + 4))
  for i in $(seq 1 $n); do
    ts=$(date -u +%FT%TZ)
    cc=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
    tw=$(ss -tan state time-wait 2>/dev/null | wc -l)
    est=$(ss -tan state established 2>/dev/null | wc -l)
    orph=$(awk '/^TCP:/{print $7}' /proc/net/sockstat 2>/dev/null)
    outrst=$(awk '/OutRsts/{print $2}' /proc/net/snmp 2>/dev/null | head -1)
    echo "[$ts] conntrack=$cc tw=$tw est=$est orphan=$orph OutRsts=$outrst" >> "$STAT"
    sleep 5
  done
) &

# SSH 反向可达性观测
(
  n=$((DURATION / 30))
  for i in $(seq 1 $n); do
    sleep 30
    ts=$(date -u +%FT%TZ)
    if timeout 5 bash -c "echo > /dev/tcp/$TARGET/22" 2>/dev/null; then
      r=OK
    else
      r=FAIL
    fi
    echo "[$ts] ssh_probe_to_${TARGET}_22=$r" >> "$STAT"
  done
) &

# 主探测：TCP connect 1pps
nping --tcp-connect -p "$PORT" -c "$DURATION" --delay 1s "$TARGET" >> "$LOG" 2>&1
echo "=== NPING DONE $(date -u +%FT%TZ) ===" | tee -a "$STAT"

wait 2>/dev/null
echo "=== END $(date -u +%FT%TZ) ===" | tee -a "$STAT"
