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
FILES=(
  "verify_synack.sh"
  "verify_synack_scapy.py"
  "hub_sysctl_reserve_ports.sh"
  "xdp_env_check.sh"
  "tcp_probe_diag.sh"
  # --- XDP Step 2 scaffold ---
  "bpf/probe_xdp.h"
  "bpf/probe_xdp.bpf.c"
  "bpf/Makefile"
  "hub_probe/test_loader.py"
  # --- XDP Step 3 verification probe ---
  "hub_probe/step3_probe.py"
  "hub_probe/step3_run.sh"
  "hub_probe/verify_kernel_rst.sh"
  "hub_probe/verify_rst_dropper.sh"
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
