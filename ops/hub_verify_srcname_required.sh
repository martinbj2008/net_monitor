#!/usr/bin/env bash
# hub_verify_srcname_required.sh
#
# One-shot HUB-side script:
#   1. git pull the latest mirror repo
#   2. NEGATIVE TEST: run probe_daemon.py without --src-name; expect argparse
#      to reject it (exit != 0). This proves the new required=True is live.
#   3. Stop the current daemon and restart it via run_forever.sh (which
#      supplies SRC_NAME=bangkok), so we are running the new code.
#   4. Print the "daemon started" banner from the log.
#
# Intended to be scp'd to the HUB and executed as:
#   bash /root/hub_verify_srcname_required.sh
set -u

REPO=/root/git/net_monitor
OBJ="$REPO/bpf/probe_xdp.bpf.o"
LOG=/var/log/probe_daemon.log

echo "=== [1] git pull ==="
cd "$REPO" || { echo "no repo at $REPO"; exit 2; }
git pull --ff-only 2>&1 | tail -n 5

echo
echo "=== [2] negative test: probe_daemon.py without --src-name (expect FAIL) ==="
set +e
python3 "$REPO/hub_probe/probe_daemon.py" \
    --iface eth0 --obj "$OBJ" --target x=1.2.3.4 --duration-s 1 --sink stdout 2>&1 \
    | tail -n 5
rc=${PIPESTATUS[0]}
set -e
if [[ "$rc" -eq 0 ]]; then
    echo "[FAIL] daemon accepted missing --src-name (rc=0); required=True not effective"
    exit 3
else
    echo "[ok] daemon refused to start without --src-name (rc=$rc)"
fi

echo
echo "=== [3] restart via run_forever.sh (SRC_NAME=bangkok) ==="
bash "$REPO/hub_probe/run_forever.sh" stop  2>&1 | tail -n 3
bash "$REPO/hub_probe/run_forever.sh" start 2>&1 | tail -n 8

echo
echo "=== [4] daemon banner ==="
sleep 3
grep "daemon started" "$LOG" | tail -n 1

echo
echo "[done]"
