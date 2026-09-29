#!/usr/bin/env bash
# A stable signature for local builds.
#
# A Tauri build is signed ad hoc, and every new build has a different
# signature. macOS keeps permissions — Accessibility, notifications — by the
# signature, so after every rebuild the right had to be granted again, and the
# switch in the settings glowed for an application that no longer existed.
#
# A self-signed certificate in the keychain gives the application a permanent
# identity: the bundle's identifier plus one and the same certificate. The
# builds change, the permissions stay. This is not Apple's signature — no
# notarisation and no Gatekeeper for other people's machines — but for one's
# own Mac it is enough.
set -euo pipefail

IDENTITY="${KEYWARD_SIGN_IDENTITY:-keyward-dev}"

# Whether the keychain already holds such an identity.
have_identity() {
  security find-identity -v -p codesigning 2>/dev/null | grep -q "\"$IDENTITY\""
}

ensure_identity() {
  if have_identity; then return 0; fi
  printf '\033[1m%s\033[0m\n' "The signing certificate ${IDENTITY} — creating it"
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  cat > "$tmp/ext.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $IDENTITY
O = keyward
[ext]
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
basicConstraints = critical, CA:false
subjectKeyIdentifier = hash
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$tmp/key.pem" -out "$tmp/cert.pem" -config "$tmp/ext.cnf" >/dev/null 2>&1
  # Into the keychain as one identity (the key plus the certificate).
  # codesign is given the right to use the key at once, or every signing brings
  # up a dialogue. The container's algorithms are old on purpose: the modern
  # PKCS12 from OpenSSL 3 the macOS keychain cannot read ("MAC verification
  # failed").
  openssl pkcs12 -export -inkey "$tmp/key.pem" -in "$tmp/cert.pem" \
    -macalg sha1 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES \
    -out "$tmp/id.p12" -passout pass:keyward -name "${IDENTITY}" >/dev/null 2>&1
  local kc="$HOME/Library/Keychains/login.keychain-db"
  security import "$tmp/id.p12" -k "$kc" -P keyward -T /usr/bin/codesign -T /usr/bin/security >/dev/null
  # Trust for code signing in the user's domain. It may ask for the user's
  # password in a system dialogue — once.
  security add-trusted-cert -r trustRoot -p codeSign -k "$kc" "$tmp/cert.pem" 2>/dev/null || true
  have_identity
}

# Sign the application with the stable identity. The identifier is the
# bundle's rather than a random hash from the linker: it is what macOS knows
# the application by.
sign_app() {
  local app="$1"
  ensure_identity || { echo "  signing skipped: the identity ${IDENTITY} is out of reach"; return 0; }
  # The hardened runtime: no injected libraries, no DYLD_ variables, no
  # debugger's task port — the window types and shows passwords.
  codesign --force --deep --sign "${IDENTITY}" --identifier me.loper \
    --options runtime --timestamp=none "$app" 2>&1 | grep -v "replacing existing signature" || true
  codesign --verify --deep --strict "$app" 2>/dev/null && printf '  signature: %s\n' "${IDENTITY}"
}

# Sign the CLI with the same identity.
#
# The daemon is the same binary run with `daemon`, and it needs the signature
# not for permissions but for the lock on the socket: the daemon builds a
# requirement out of its own signature and decides by it whom to give passwords
# to. With no signature there is nothing to build the requirement from — then
# passwords go out on biometrics alone, and the log says so plainly.
#
# The identifier is its own, `me.loper.cli`: the application and the
# CLI are different binaries, and one identifier for the two of them is an
# invitation to confusion over permissions. The identity (and so the root the
# daemon checks) is one.
sign_cli() {
  local bin="$1"
  ensure_identity || { echo "  signing skipped: the identity ${IDENTITY} is out of reach"; return 0; }
  # The hardened runtime: the daemon holds the vault's keys.
  codesign --force --sign "${IDENTITY}" --identifier me.loper.cli \
    --options runtime --timestamp=none "$bin" 2>&1 | grep -v "replacing existing signature" || true
  codesign --verify --strict "$bin" 2>/dev/null && printf '  signature: %s\n' "${IDENTITY}"
}

# Sign the passkey bridge (`keyward-passkey-host`) with the same identity and
# an identifier of its own. The daemon tells it apart by exactly that pair —
# our root plus `me.loper.passkey-host` — and gives it passkeys and
# nothing else: not a password, not a lock, not a deletion.
sign_host() {
  local bin="$1"
  ensure_identity || { echo "  signing skipped: the identity ${IDENTITY} is out of reach"; return 0; }
  codesign --force --sign "${IDENTITY}" --identifier me.loper.passkey-host \
    --options runtime --timestamp=none "$bin" 2>&1 | grep -v "replacing existing signature" || true
  codesign --verify --strict "$bin" 2>/dev/null && printf '  signature: %s\n' "${IDENTITY}"
}

case "${1:-}" in
  ensure) ensure_identity ;;
  sign) sign_app "${2:?path to the .app}" ;;
  sign-cli) sign_cli "${2:?path to the binary}" ;;
  sign-host) sign_host "${2:?path to the binary}" ;;
  *) echo "usage: $0 ensure | sign <app> | sign-cli <bin> | sign-host <bin>"; exit 2 ;;
esac
