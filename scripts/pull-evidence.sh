#!/usr/bin/env bash
# pull-evidence.sh — copy an Atomic Red Team run's evidence off the DC (dc01)
# into evidence/<RunId>/ (markers, execlog, transcript).
#
# Usage:   scripts/pull-evidence.sh <RunId> [ssh-target]
# Example: scripts/pull-evidence.sh run-ec-1
#
# Run from the repo root on the libvirt host — the machine that runs vagrant and
# already has SSH to the DC (the same channel used to launch the runs:
# `ssh Administrator@10.77.77.20 ...`). Transport is scp over that SSH; the DC
# has no synced folder, and SSH is the path the harness already relies on.
set -euo pipefail

RUNID="${1:?usage: scripts/pull-evidence.sh <RunId> [ssh-target]}"
DC="${2:-Administrator@10.77.77.20}"
SRC="C:/AtomicRedTeam/results/${RUNID}"
DEST="evidence/${RUNID}"

if [ -e "$DEST" ]; then
  echo "[!] ${DEST} already exists — refusing to overwrite. Move it aside first." >&2
  exit 1
fi

mkdir -p evidence
echo "[*] copying ${DC}:${SRC} -> evidence/"
scp -r -o StrictHostKeyChecking=no "${DC}:${SRC}" evidence/

if [ ! -d "$DEST" ]; then
  echo "[!] nothing copied — check the run id and that dc01 is up" >&2
  exit 1
fi

echo "[+] evidence in ${DEST}/"
ls -la "$DEST"

MK="${DEST}/${RUNID}-markers.txt"
if [ -f "$MK" ]; then
  echo
  echo "----- ${RUNID}-markers.txt -----"
  cat "$MK"
fi
