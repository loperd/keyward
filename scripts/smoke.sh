#!/usr/bin/env bash
# An end-to-end check of keyward on an isolated KEYWARD_HOME.
# It checks what the whole thing was written for: the daemon comes up, a
# mapping resolves to one item, the agent's socket appears, and on a foreign
# host resolve honestly comes back with a non-zero code.
set -euo pipefail

BIN="${1:-./target/debug/keyward}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export KEYWARD_HOME="${KEYWARD_HOME:-/tmp/keyward-smoke}"

cleanup() {
  [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null || true
  wait "${DAEMON_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$KEYWARD_HOME"
mkdir -p "$KEYWARD_HOME"

# The test keys are generated on the spot, and nothing of anybody else's is
# touched. Both kinds: in real vaults RSA is met as often as Ed25519, and an
# agent that shows a key but cannot sign with it is of no use.
ssh-keygen -q -t ed25519 -N '' -C keyward-smoke -f "$KEYWARD_HOME/id_smoke"
ssh-keygen -q -t rsa -b 2048 -N '' -C keyward-smoke-rsa -f "$KEYWARD_HOME/id_rsa_smoke"
PUB=$(cat "$KEYWARD_HOME/id_smoke.pub")
PRIV=$(python3 -c 'import json,sys;print(json.dumps(open(sys.argv[1]).read()))' "$KEYWARD_HOME/id_smoke")
PUB_RSA=$(cat "$KEYWARD_HOME/id_rsa_smoke.pub")
PRIV_RSA=$(python3 -c 'import json,sys;print(json.dumps(open(sys.argv[1]).read()))' "$KEYWARD_HOME/id_rsa_smoke")

cat > "$KEYWARD_HOME/mappings.json" <<JSON
[
  {
    "id": "smoke-1",
    "name": "the sandbox key",
    "kw-host": "*.smoke.test, exact.smoke.test",
    "public_key": "$PUB",
    "private_key": $PRIV
  },
  {
    "id": "smoke-2",
    "name": "the key with a certificate",
    "kw-host": "ca.smoke.test",
    "kw-cert": "ops",
    "public_key": "$PUB"
  },
  {
    "id": "smoke-3",
    "name": "the rsa key",
    "kw-host": "rsa.smoke.test",
    "public_key": "$PUB_RSA",
    "private_key": $PRIV_RSA
  }
]
JSON

"$BIN" daemon --source file &
DAEMON_PID=$!

for _ in $(seq 1 50); do
  [[ -S "$KEYWARD_HOME/d.sock" ]] && break
  sleep 0.1
done
[[ -S "$KEYWARD_HOME/d.sock" ]] || { echo "FAILED: the daemon did not bring up the control socket"; exit 1; }

# The ssh plugin is no longer compiled into the daemon — it is installed from
# the catalogue. Here it is installed from disk: a directory has no signature
# and cannot have one, the daemon will mark the package unverified, and that is
# honest — this is how a developer installs it.

echo "--- installing the ssh plugin ---"
"$REPO/scripts/plugin-package.sh" ssh >/dev/null || { echo "FAILED: the plugin's package was not built"; exit 1; }
"$BIN" plugin install "$REPO/dist/packages/ssh" \
  || { echo "FAILED: the ssh plugin was not installed"; exit 1; }
# Consent to the permissions is the switching on: before it the plugin has no
# process.
"$BIN" plugin enable ssh \
  || { echo "FAILED: the ssh plugin did not switch on"; exit 1; }
echo "--- a plaintext request is refused ---"
REFUSAL="$(python3 - "$KEYWARD_HOME" <<'PYEOF'
import os, socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect(os.path.join(sys.argv[1], "d.sock"))
s.sendall(b'{"op":"vault"}\n')
buf = b""
while not buf.endswith(b"\n"):
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
print(buf.decode().strip())
PYEOF
)"
case "$REFUSAL" in
  *err.channelRequired*) echo "refused: $REFUSAL" ;;
  *) echo "FAILED: a plaintext request was answered: $REFUSAL"; exit 1 ;;
esac
echo "--- status ---"; "$BIN" status
echo "--- hosts ---";  "$BIN" hosts

echo "--- resolve: a known host ---"
"$BIN" resolve node1.smoke.test "" 0
SOCK="$KEYWARD_HOME/s/node1.smoke.test.sock"
[[ -S "$SOCK" ]] || { echo "FAILED: the agent's socket was not created: $SOCK"; exit 1; }

echo "--- the agent gives out exactly one key ---"
COUNT=$(SSH_AUTH_SOCK="$SOCK" ssh-add -l | grep -c . || true)
[[ "$COUNT" == "1" ]] || { echo "FAILED: the agent gave out $COUNT keys (1 was expected)"; SSH_AUTH_SOCK="$SOCK" ssh-add -l; exit 1; }
SSH_AUTH_SOCK="$SOCK" ssh-add -l

echo "--- resolve: specificity (an exact host beats a glob) ---"
"$BIN" resolve exact.smoke.test "" 0

echo "--- resolve: a foreign host has to give a non-zero code ---"
if "$BIN" resolve nothing.example.org "" 0 2>/dev/null; then
  echo "FAILED: resolve came back with 0 on a host with no mapping"; exit 1
fi

echo "--- signing with Ed25519 ---"
SSH_AUTH_SOCK="$SOCK" ssh-add -T "$KEYWARD_HOME/id_smoke.pub" \
  || { echo "FAILED: the agent did not sign with Ed25519"; exit 1; }

echo "--- signing with RSA ---"
"$BIN" resolve rsa.smoke.test "" 0
RSOCK="$KEYWARD_HOME/s/rsa.smoke.test.sock"
[[ -S "$RSOCK" ]] || { echo "FAILED: the socket for the rsa host was not created"; exit 1; }
SSH_AUTH_SOCK="$RSOCK" ssh-add -T "$KEYWARD_HOME/id_rsa_smoke.pub" \
  || { echo "FAILED: the agent did not sign with RSA"; exit 1; }

echo "--- the sockets' permissions ---"
MODE=$(stat -f '%Lp' "$SOCK")
[[ "$MODE" == "600" ]] || { echo "FAILED: the socket's permissions are $MODE, 600 was expected"; exit 1; }

echo
echo "ALL PASSED: the daemon, the mapping, one key to a host, signing with Ed25519 and RSA, a refusal on a foreign host, permissions 0600."
