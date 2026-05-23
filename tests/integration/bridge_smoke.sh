#!/usr/bin/env bash
# Integration smoke test: start brightnexus-bridge and probe HEARTBEAT / GET_PUBLIC_KEY.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
export HOME="$TMP"
export BRIGHTNEXUS_SOCKET="$TMP/brightnexus.sock"

cd "$ROOT"
if ! cargo build --release -p brightnexus-bridge >/dev/null 2>&1; then
  echo "cargo build --release -p brightnexus-bridge failed" >&2
  exit 1
fi
BIN="$ROOT/target/release/brightnexus-bridge"
if [[ ! -x "$BIN" ]]; then
  # Fallback when CARGO_TARGET_DIR is redirected (CI/sandbox).
  BIN="$(find "$ROOT" -path '*/release/brightnexus-bridge' -perm -111 2>/dev/null | head -1)"
fi
[[ -x "$BIN" ]] || { echo "brightnexus-bridge binary not found"; exit 1; }

"$BIN" &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; rm -rf "$TMP"' EXIT

for _ in $(seq 1 50); do
  [[ -S "$BRIGHTNEXUS_SOCKET" ]] && break
  sleep 0.1
done
[[ -S "$BRIGHTNEXUS_SOCKET" ]] || { echo "socket not ready"; exit 1; }

hb="$(printf '%s' '{"cmd":"HEARTBEAT"}' | nc -U "$BRIGHTNEXUS_SOCKET" | head -1)"
echo "$hb" | grep -q '"ok":true' || { echo "HEARTBEAT failed: $hb"; exit 1; }

pk="$(printf '%s' '{"cmd":"GET_PUBLIC_KEY"}' | nc -U "$BRIGHTNEXUS_SOCKET" | head -1)"
echo "$pk" | grep -q '"publicKey"' || { echo "GET_PUBLIC_KEY failed: $pk"; exit 1; }

echo "OK: bridge HEARTBEAT + GET_PUBLIC_KEY"
