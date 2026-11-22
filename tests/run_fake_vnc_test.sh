#!/usr/bin/env bash
# language: bash, target: Linux
# run_fake_vnc_test.sh - drive a fake VNC session at vnc-watch on your machine.
#
# Safety: the real vnc-watch daemon auto-applies "close + wipe" 60 s after a
# detection when VNC_WATCH_POPUP_AUTO is unset. This script stops that daemon
# for the duration and runs a foreground detector with AUTO=0, so nothing is
# erased. It restores the daemon on exit.
#
#   tests/run_fake_vnc_test.sh [port] [hold_seconds]
#
# Exercises the tiers reachable without root: a new listener on a watched port
# and an established socket. The log-derived CONFIRMED/PROBABLE tiers need
# /var/log/x11vnc.log, which is root-owned, so they are not covered here.

set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${1:-5900}"
HOLD="${2:-8}"
OUT="$(mktemp -d)"
DET=""

cleanup() {
    [ -n "$DET" ] && kill "$DET" 2>/dev/null || true
    pkill -f '[f]ake_vnc.py' 2>/dev/null || true
    wait 2>/dev/null || true
    systemctl --user start vnc-watch 2>/dev/null || true
    echo "artifacts in $OUT"
}
trap cleanup EXIT

echo "[*] stopping the auto-wiping daemon"
systemctl --user stop vnc-watch 2>/dev/null || true
sleep 1

echo "[*] starting foreground detector (AUTO=0, no destructive action)"
VNC_WATCH_POPUP_AUTO=0 VNC_WATCH_POPUP_TIMEOUT=25 \
    python3 -u vnc-watch.py watch >"$OUT/detector.out" 2>&1 &
DET=$!
sleep 2.5

echo "[*] fake RFB server on :$PORT"
python3 -u tests/fake_vnc.py --port "$PORT" --hold "$HOLD" >"$OUT/server.out" 2>&1 &
sleep 1

echo "[*] fake RFB viewer attaching"
python3 -u tests/fake_vnc.py --client --port "$PORT" --hold "$((HOLD - 2))" \
    >"$OUT/client.out" 2>&1 &

sleep 5
echo "================ DETECTOR ================"
cat "$OUT/detector.out"
echo "================ SERVER ================"
cat "$OUT/server.out"
echo "================ VIEWER ================"
cat "$OUT/client.out"

echo "[*] waiting for the session to end"
sleep "$((HOLD))"
