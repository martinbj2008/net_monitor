#!/usr/bin/env bash
# pull_from_workspace.sh
#
# This directory (net_monitor/) is a TRANSFER-ONLY mirror on GitHub, not a
# real code home. The real workspace lives one level up:
#     /Users/martinzhang/git/vps_probe/
#
# This script copies a whitelisted set of scripts from the parent workspace
# into this repo, then commits & pushes. The hub (bangkok) later does:
#     cd ~/git/net_monitor && git pull
# to receive the update.
#
# Usage:
#   bash pull_from_workspace.sh                # copy + commit + push
#   bash pull_from_workspace.sh --no-push      # copy + commit only
#   bash pull_from_workspace.sh --dry-run      # show what would change
#
# Add new files to sync by appending to FILES=() below.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --- whitelist: files (relative to SRC_DIR) to mirror into this repo ---
# NOTE: legacy VPS-side scripts, step3/step4 one-shot runners, XDP verifiers
# and same-sport experiments have all been retired. Current production stack
# on the HUB is just: XDP RST-dropper + probe_daemon.py + run_forever.sh, all
# writing directly to local Postgres.
FILES=(
  # --- XDP RST dropper (loaded by probe_daemon on startup) ---
  "bpf/probe_xdp.h"
  "bpf/probe_xdp.bpf.c"
  "bpf/Makefile"
  # --- unified probe daemon (direct PG sink) ---
  "hub_probe/probe_daemon.py"
  "hub_probe/run_forever.sh"
  # --- ops / one-off cleanup + verification scripts ---
  "ops/cleanup_legacy_vps_probe.sh"
  "ops/hub_verify_srcname_required.sh"
)

# --- whitelist: whole directories (mirrored with rsync-like semantics) ---
# Anything under these dirs is mirrored 1:1; files removed in workspace are
# also removed in this repo (via --delete on rsync).
DIRS=(
  # --- Postgres + Grafana docker stack (compose, .env, provisioning, dashboards) ---
  "docker"
)

PUSH=1
DRY=0
for a in "$@"; do
  case "$a" in
    --no-push) PUSH=0 ;;
    --dry-run) DRY=1 ;;
    -h|--help)
      sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

cd "$SCRIPT_DIR"

echo "[info] src workspace: $SRC_DIR"
echo "[info] mirror repo  : $SCRIPT_DIR"

changed=0
missing=0
for f in "${FILES[@]}"; do
  src="${SRC_DIR}/${f}"
  dst="${SCRIPT_DIR}/${f}"
  if [[ ! -f "$src" ]]; then
    echo "  MISS  $f  (not in workspace)"
    missing=$(( missing + 1 ))
    continue
  fi
  mkdir -p "$(dirname "$dst")"
  if [[ ! -f "$dst" ]] || ! cmp -s "$src" "$dst"; then
    if [[ $DRY -eq 1 ]]; then
      echo "  DIFF  $f"
    else
      cp -p "$src" "$dst"
      echo "  COPY  $f"
    fi
    changed=$(( changed + 1 ))
  else
    echo "  same  $f"
  fi
done

# --- mirror whole directories via rsync (delete removed files too) ---
for d in "${DIRS[@]}"; do
  src="${SRC_DIR}/${d}/"
  dst="${SCRIPT_DIR}/${d}/"
  if [[ ! -d "${SRC_DIR}/${d}" ]]; then
    echo "  MISS  ${d}/  (not in workspace)"
    missing=$(( missing + 1 ))
    continue
  fi
  mkdir -p "$dst"
  if [[ $DRY -eq 1 ]]; then
    rsync_out=$(rsync -rlpt --delete --itemize-changes --dry-run "$src" "$dst" 2>&1 | grep -v '^\.[df]\.\.\.\.\.' || true)
    if [[ -n "$rsync_out" ]]; then
      echo "  DIFF  ${d}/"
      echo "$rsync_out" | sed 's/^/        /'
      changed=$(( changed + 1 ))
    else
      echo "  same  ${d}/"
    fi
  else
    rsync_out=$(rsync -rlpt --delete --itemize-changes "$src" "$dst" 2>&1 | grep -v '^\.[df]\.\.\.\.\.' || true)
    if [[ -n "$rsync_out" ]]; then
      echo "  SYNC  ${d}/"
      echo "$rsync_out" | sed 's/^/        /'
      changed=$(( changed + 1 ))
    else
      echo "  same  ${d}/"
    fi
  fi
done

echo "[info] changed=$changed missing=$missing"

if [[ $DRY -eq 1 ]]; then
  echo "[dry-run] no git actions taken."
  exit 0
fi

if [[ $changed -eq 0 ]]; then
  echo "[info] nothing to commit."
  exit 0
fi

git add -A
ts=$(date +%Y-%m-%d_%H:%M:%S)
git commit -m "sync from workspace @ ${ts}"

if [[ $PUSH -eq 1 ]]; then
  echo "[info] git push ..."
  git push
else
  echo "[info] --no-push: skipping git push."
fi

echo "[done]"
