#!/usr/bin/env bash
# ops/cleanup_legacy_vps_probe.sh
# Run this on every host (HUB + all leaves) to clean up the legacy vps_probe.
# Idempotent: safe to run multiple times.
#
# It removes exactly these three things and NOTHING else:
#   1) root crontab line matching the trailing marker "# vps_probe"
#      (the actual line is:
#         */15 * * * * /root/vps_probe/probe.sh >> /var/log/vps_probe.log 2>&1 # vps_probe
#       we anchor on the "# vps_probe" marker so we don't touch stargate /
#       mytesla / yunjing / anything else.)
#   2) /root/vps_probe/            (the whole legacy dir)
#   3) /var/log/vps_probe.log      (the noisy log)
#
# It DOES NOT touch:
#   * /root/git/*        (net_monitor / mytesla / hexo_blog / etc.)
#   * any stargate / sgagenttask / yunjing / sysstat cron entries
#   * any systemd unit
set -euo pipefail

HOST="$(hostname)"
echo "== cleanup on ${HOST} =="

# ---- 1) crontab ----
if crontab -l >/dev/null 2>&1; then
    before="$(crontab -l | wc -l)"
    # Drop only lines whose comment tail is exactly "# vps_probe".
    # grep -v is safe: if there's no match, we just rewrite the same content.
    new_cron="$(crontab -l | grep -vE '# *vps_probe *$' || true)"
    printf '%s\n' "$new_cron" | crontab -
    after="$(crontab -l | wc -l)"
    echo "  crontab lines: ${before} -> ${after}"
else
    echo "  crontab: (none for root)"
fi

# ---- 2) /root/vps_probe/ ----
if [ -e /root/vps_probe ]; then
    du -sh /root/vps_probe 2>/dev/null | sed 's/^/  removing: /'
    rm -rf /root/vps_probe
    echo "  /root/vps_probe removed"
else
    echo "  /root/vps_probe: already absent"
fi

# ---- 3) /var/log/vps_probe.log ----
if [ -e /var/log/vps_probe.log ]; then
    ls -la /var/log/vps_probe.log | sed 's/^/  removing: /'
    rm -f /var/log/vps_probe.log
    echo "  /var/log/vps_probe.log removed"
else
    echo "  /var/log/vps_probe.log: already absent"
fi

echo "== ${HOST} done =="
