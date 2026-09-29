#!/usr/bin/env bash
# Publishing a plugin to the catalogue.
#
# A catalogue is one `index.json` in an R2 bucket and the packages beside it:
#
#   index.json
#   hello/1.0.0/hello-1.0.0.tar.gz
#
# The script does exactly what a person would do by hand: packs the directory,
# counts the digest, puts the package into the bucket and writes the version
# into `index.json`. The digest is not decoration: without a match the daemon
# refuses to install, and a package published past this script cannot be
# installed from the window.
#
# Wrangler is not on the system and there is no point demanding it be
# installed: everything goes through `npx wrangler`. With no token the script
# says what is missing and leaves with a non-zero code. Nothing can be
# "published" silently.
#
#   scripts/plugin-publish.sh examples/plugins/hello --dry-run
#   scripts/plugin-publish.sh examples/plugins/hello --bucket keyward-plugins
#
# `--dry-run` puts the catalogue into `dist/registry/` — it can be fed to the
# daemon at once as the source `file://…/dist/registry/index.json`.
set -euo pipefail

BUCKET="${KEYWARD_R2_BUCKET:-keyward-plugins}"
DRY=0
SRC=""
PLATFORM=""
NEW_KEY=""
PUBLISHER="${KEYWARD_PUBLISHER:-keyward-dev}"
KEYFILE="${KEYWARD_PUBLISHER_KEY:-}"

die() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }
say() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

usage() {
  cat >&2 <<'TXT'
Publishing a plugin to the keyward catalogue.

  scripts/plugin-publish.sh <plugin-directory> [--bucket NAME] [--platform TRIPLE] [--dry-run]
  scripts/plugin-publish.sh --new-key <file> [--publisher NAME]

  --bucket NAME      the R2 bucket (or KEYWARD_R2_BUCKET), by default
                     keyward-plugins
  --platform TRIPLE  whom the package is for: any (the default) or, say,
                     aarch64-apple-darwin; it can also be given by the
                     "platform" field in plugin.json
  --publisher NAME   the publisher's name in the catalogue (or
                     KEYWARD_PUBLISHER)
  --new-key FILE     create a publisher's key and print its public half with
                     the five words of the fingerprint — those are what goes
                     into publishers.json
  --dry-run          upload nothing, put it all into dist/registry/

The signing key comes from KEYWARD_PUBLISHER_KEY (the path to a file with the
private key). Without a key the script does not publish: the daemon will not
install an unsigned package.
TXT
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bucket) BUCKET="${2:-}"; [[ -n "$BUCKET" ]] || usage; shift 2 ;;
    --platform) PLATFORM="${2:-}"; [[ -n "$PLATFORM" ]] || usage; shift 2 ;;
    --publisher) PUBLISHER="${2:-}"; [[ -n "$PUBLISHER" ]] || usage; shift 2 ;;
    --new-key) NEW_KEY="${2:-}"; [[ -n "$NEW_KEY" ]] || usage; shift 2 ;;
    --key) KEYFILE="${2:-}"; [[ -n "$KEYFILE" ]] || usage; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage ;;
    -*) die "unknown flag ${1}" ;;
    *) [[ -z "$SRC" ]] || die "the plugin's directory is already given: ${SRC}"; SRC="$1"; shift ;;
  esac
done


REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v python3 >/dev/null || die "no python3 — without it the package cannot be signed nor plugin.json read"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ── The signature ───────────────────────────────────────────────────────
# Ed25519 and the five words of the fingerprint in plain python. Not out of a
# love of reinvention: /usr/bin/openssl on macOS is LibreSSL, and it cannot do
# Ed25519 in `pkeyutl`, and publishing must not depend on whose openssl is in
# PATH.
cat > "$WORK/kwsign.py" <<'PYLIB'
import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _sha512(b):
    return hashlib.sha512(b).digest()


def _inv(x):
    return pow(x, P - 2, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * I % P
    if (x * x - xx) % P != 0:
        return None
    if x % 2 != sign:
        x = P - x
    return x


BY = 4 * _inv(5) % P
BX = _recover_x(BY, 0)
B = (BX, BY, 1, BX * BY % P)


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    Bb = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * D % P
    Dd = 2 * a[2] * b[2] % P
    E, F, G, H = Bb - A, Dd - C, Dd + C, Bb + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _compress(pt):
    x, y, z = pt[0], pt[1], pt[2]
    zi = _inv(z)
    x, y = x * zi % P, y * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _secret_scalar(seed):
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    a, _ = _secret_scalar(seed)
    return _compress(_mul(a, B))


def sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _secret_scalar(seed)
    pub = _compress(_mul(a, B))
    r = int.from_bytes(_sha512(prefix + msg), "little") % L
    Rs = _compress(_mul(r, B))
    k = int.from_bytes(_sha512(Rs + pub + msg), "little") % L
    s = (r + k * a) % L
    return Rs + int.to_bytes(s, 32, "little")


import base64, hashlib, hmac, os, sys


def words_of(publisher: str, pub: bytes, wordlist_path: str):
    """The five words of the fingerprint — the same algorithm as an account's:
    HKDF-Expand(prk = sha256(key), info = the publisher's name), then the
    number written out in base 7776."""
    words = []
    for line in open(wordlist_path, encoding="utf-8"):
        parts = line.split("\t")
        if len(parts) > 1 and parts[1].strip():
            words.append(parts[1].strip())
    if len(words) != 7776:
        sys.exit("the word list is damaged")
    prk = hashlib.sha256(pub).digest()
    material = hmac.new(prk, publisher.encode("utf-8") + b"\x01", hashlib.sha256).digest()
    number = int.from_bytes(material, "big")
    out = []
    for _ in range(5):
        number, rem = divmod(number, 7776)
        out.append(words[rem])
    return out


def read_seed(path):
    raw = open(path, encoding="utf-8").read().strip()
    try:
        seed = base64.b64decode(raw, validate=True)
    except Exception:
        sys.exit(f"the key in {path} is not base64")
    if len(seed) != 32:
        sys.exit(f"the key in {path} is not 32 bytes")
    return seed


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "new":
        path, publisher, wordlist = sys.argv[2], sys.argv[3], sys.argv[4]
        if os.path.exists(path):
            sys.exit(f"{path} already exists — we do not risk a key of your own")
        seed = os.urandom(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(seed).decode() + "\n")
        pub = public_key(seed)
        print(base64.b64encode(pub).decode())
        print(" ".join(words_of(publisher, pub, wordlist)))
    elif cmd == "sign":
        seed = read_seed(sys.argv[2])
        body = open(sys.argv[3], "rb").read()
        print(base64.b64encode(sign(seed, body)).decode())
    elif cmd == "words":
        seed = read_seed(sys.argv[2])
        pub = public_key(seed)
        print(base64.b64encode(pub).decode())
        print(" ".join(words_of(sys.argv[3], pub, sys.argv[4])))
PYLIB

WORDLIST="$REPO/crates/vault/src/eff_large_wordlist.txt"

if [[ -n "$NEW_KEY" ]]; then
  say "Creating the publisher key ${PUBLISHER}"
  OUT="$(python3 "$WORK/kwsign.py" new "$NEW_KEY" "$PUBLISHER" "$WORDLIST")" || die "$OUT"
  PUBKEY="$(printf '%s\n' "$OUT" | sed -n 1p)"
  WORDS="$(printf '%s\n' "$OUT" | sed -n 2p)"
  note "the private half: $NEW_KEY (permissions 0600, show it to nobody)"
  printf '\n%s\n' "Into ~/.keyward/plugins/publishers.json:"
  printf '  [{"id": "%s", "key": "%s"}]\n' "$PUBLISHER" "$PUBKEY"
  printf '\n%s\n' "The five words of the fingerprint — they are what a person checks, not the key:"
  printf '  \033[1m%s\033[0m\n' "$WORDS"
  printf '\n%s\n' "To sign: export KEYWARD_PUBLISHER_KEY=$NEW_KEY KEYWARD_PUBLISHER=$PUBLISHER"
  exit 0
fi

[[ -n "$SRC" ]] || usage
[[ -d "$SRC" ]] || die "${SRC} is not a directory"
[[ -f "$SRC/plugin.json" ]] || die "${SRC} has no plugin.json — this is not a plugin package"
SRC="$(cd "$SRC" && pwd)"

# The key is compulsory: the daemon will not install an unsigned package from
# the catalogue, and publishing one means publishing what nobody can
# install.
if [[ -z "$KEYFILE" ]]; then
  printf '\033[31m%s\033[0m\n' "There is nothing to sign the package with." >&2
  printf '%s\n' "  • KEYWARD_PUBLISHER_KEY — the path to a file with the publisher's private key" >&2
  printf '%s\n' "To create a key: scripts/plugin-publish.sh --new-key ~/.keyward/publisher.key" >&2
  exit 1
fi
[[ -f "$KEYFILE" ]] || die "there is no publisher key: $KEYFILE"

# ── The manifest ────────────────────────────────────────────────────────
# The fields are read by python3 rather than by grep: json with line breaks
# inside a string grep reads wrongly exactly when it costs most.
read_manifest() {
  python3 - "$SRC/plugin.json" <<'PY'
import json, re, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
def need(key):
    v = m.get(key)
    if not isinstance(v, str) or not v.strip():
        sys.exit(f"plugin.json has no {key} field")
    return v.strip()
pid = need("id")
if not re.fullmatch(r"[a-z0-9][a-z0-9-]*[a-z0-9]|[a-z0-9]", pid):
    sys.exit(f"the identifier {pid} is not lower-case latin, digits and hyphens")
ver = need("version")
if not re.fullmatch(r"[0-9]+(\.[0-9]+)*([.-][0-9A-Za-z.-]+)?", ver):
    sys.exit(f"the version {ver} does not look like a version")
out = {
    "id": pid,
    "version": ver,
    "title": m.get("title") or pid,
    "description": m.get("description", ""),
    "icon": m.get("icon", ""),
    "homepage": m.get("homepage", ""),
    "platform": m.get("platform", "any"),
    "permissions": m.get("permissions", []),
}
for k in ("id", "version", "title", "description", "icon", "homepage", "platform"):
    print(f"{k}\t{out[k]}")
print("permissions\t" + json.dumps(out["permissions"], ensure_ascii=False))
PY
}

MANIFEST="$(read_manifest)" || die "$MANIFEST"
get() { printf '%s\n' "$MANIFEST" | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }

ID="$(get id)"
VERSION="$(get version)"
TITLE="$(get title)"
DESCRIPTION="$(get description)"
ICON="$(get icon)"
HOMEPAGE="$(get homepage)"
PERMISSIONS="$(get permissions)"
[[ -n "$PLATFORM" ]] || PLATFORM="$(get platform)"

EXEC="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8")).get("exec",""))' "$SRC/plugin.json")"
[[ -n "$EXEC" ]] || die "plugin.json has no exec field — the daemon will not know what to run the plugin with"
[[ -x "$SRC/$EXEC" ]] || die "the file ${EXEC} is not executable — chmod +x, or the daemon will refuse to install the package"

say "The plugin $ID $VERSION ($PLATFORM)"

# ── The package ─────────────────────────────────────────────────────────
# Inside the archive is a directory named after the plugin: the daemon unpacks
# the package and looks in it for the one directory with a plugin.json.
FILE="$ID-$VERSION.tar.gz"
mkdir -p "$WORK/$ID"
# macOS resource forks (`._file`) are not wanted in the archive — an unpacker
# on another machine would turn them into rubbish beside the program.
export COPYFILE_DISABLE=1
tar -czf "$WORK/$FILE" -C "$(dirname "$SRC")" \
  --exclude '.git' --exclude '.git/*' \
  --exclude '__pycache__' --exclude '*/__pycache__' \
  --exclude '.DS_Store' --exclude '*.pyc' \
  "$(basename "$SRC")" \
  --transform "s,^$(basename "$SRC"),$ID," 2>/dev/null \
  || {
    # BSD tar does not know --transform: we pack from a copy named as it
    # should be.
    rm -f "$WORK/$FILE"
    cp -R "$SRC/." "$WORK/$ID/"
    find "$WORK/$ID" \( -name '__pycache__' -o -name '.git' \) -prune -exec rm -rf {} + 2>/dev/null || true
    find "$WORK/$ID" \( -name '.DS_Store' -o -name '*.pyc' \) -delete 2>/dev/null || true
    tar -czf "$WORK/$FILE" -C "$WORK" "$ID"
  }

SHA="$(shasum -a 256 "$WORK/$FILE" | awk '{print $1}')"
SIZE="$(wc -c < "$WORK/$FILE" | tr -d ' ')"
SIGNATURE="$(python3 "$WORK/kwsign.py" sign "$KEYFILE" "$WORK/$FILE")" || die "$SIGNATURE"
KEYINFO="$(python3 "$WORK/kwsign.py" words "$KEYFILE" "$PUBLISHER" "$WORDLIST")" || die "$KEYINFO"
note "the package $FILE, $SIZE bytes"
note "sha256 $SHA"
PUBKEY="$(printf '%s\n' "$KEYINFO" | sed -n 1p)"
note "publisher $PUBLISHER: $(printf '%s\n' "$KEYINFO" | sed -n 2p)"

KEY="$ID/$VERSION/$FILE"

# ── Where to put it ─────────────────────────────────────────────────────
if [[ "$DRY" == 1 ]]; then
  OUT="$REPO/dist/registry"
  mkdir -p "$OUT/$ID/$VERSION"
  cp "$WORK/$FILE" "$OUT/$KEY"
  INDEX_IN="$OUT/index.json"
  [[ -f "$INDEX_IN" ]] || printf '{"version":1,"plugins":[]}\n' > "$INDEX_IN"
else
  command -v npx >/dev/null || die "no npx (it comes with node) — wrangler cannot be called without it"
  MISSING=()
  [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]] || MISSING+=("CLOUDFLARE_API_TOKEN — an R2 token with the right to write")
  [[ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ]] || MISSING+=("CLOUDFLARE_ACCOUNT_ID — the Cloudflare account's identifier")
  if [[ ${#MISSING[@]} -gt 0 ]]; then
    printf '\033[31m%s\033[0m\n' "Publishing is impossible, what is missing:" >&2
    for m in "${MISSING[@]}"; do printf '  • %s\n' "$m" >&2; done
    printf '%s\n' "First: export CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=…" >&2
    printf '%s\n' "To see what comes out, with no network: --dry-run" >&2
    exit 1
  fi
  INDEX_IN="$WORK/index.json"
  say "Fetching the current index.json of the bucket $BUCKET"
  if ! npx --yes wrangler r2 object get "$BUCKET/index.json" --file "$INDEX_IN" --remote >/dev/null 2>"$WORK/get.err"; then
    note "there is no catalogue in the bucket yet — creating a new one"
    note "$(tail -n 2 "$WORK/get.err" | tr '\n' ' ')"
    printf '{"version":1,"plugins":[]}\n' > "$INDEX_IN"
  fi
fi

# ── Writing the version into index.json ─────────────────────────────────
INDEX_OUT="$WORK/index.new.json"
python3 - "$INDEX_IN" "$INDEX_OUT" <<PY || die "index.json was not built"
import json, sys

src, dst = sys.argv[1], sys.argv[2]
try:
    index = json.load(open(src, encoding="utf-8"))
except Exception:
    index = {}
if not isinstance(index, dict) or index.get("version") != 1:
    index = {"version": 1, "plugins": []}
plugins = index.setdefault("plugins", [])

entry = next((p for p in plugins if p.get("id") == "$ID"), None)
if entry is None:
    entry = {"id": "$ID", "versions": []}
    plugins.append(entry)
# The publisher's key is declared in the catalogue itself: the interface shows
# the five words of the fingerprint from it, and "trust" puts the key into
# publishers.json.
known = [p for p in index.setdefault("publishers", []) if p.get("id") != "$PUBLISHER"]
known.append({"id": "$PUBLISHER", "key": "$PUBKEY"})
known.sort(key=lambda p: p.get("id", ""))
index["publishers"] = known

entry["title"] = """$TITLE"""
entry["description"] = """$DESCRIPTION"""
entry["icon"] = """$ICON"""
entry["homepage"] = """$HOMEPAGE"""

version = {
    "version": "$VERSION",
    "platform": "$PLATFORM",
    # The address is relative: the catalogue has to travel together with the
    # directory it lies in — both in the bucket and in dist/registry.
    "url": "$KEY",
    "sha256": "$SHA",
    "permissions": json.loads(r'''$PERMISSIONS'''),
    "size": $SIZE,
    "publisher": "$PUBLISHER",
    "signature": "$SIGNATURE",
}
versions = [v for v in entry.get("versions", [])
            if not (v.get("version") == "$VERSION" and v.get("platform", "any") == "$PLATFORM")]
versions.append(version)

def key(v):
    parts = []
    for p in str(v.get("version", "")).replace("-", ".").split("."):
        digits = "".join(c for c in p if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return parts

# Descending: the daemon sorts by itself anyway, but the catalogue is read by
# eye as well.
versions.sort(key=key, reverse=True)
entry["versions"] = versions
plugins.sort(key=lambda p: p.get("id", ""))

json.dump(index, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
open(dst, "a", encoding="utf-8").write("\n")
PY

# ── Uploading ───────────────────────────────────────────────────────────
if [[ "$DRY" == 1 ]]; then
  cp "$INDEX_OUT" "$REPO/dist/registry/index.json"
  say "Done, nothing was uploaded"
  note "the catalogue: $REPO/dist/registry/index.json"
  note "the package:   $REPO/dist/registry/$KEY"
  printf '\n%s\n' "To feed it to the daemon:"
  printf '  keyward plugin-sources file://%s/dist/registry/index.json\n' "$REPO"
else
  say "Putting the package into $BUCKET/$KEY"
  npx --yes wrangler r2 object put "$BUCKET/$KEY" \
    --file "$WORK/$FILE" --content-type application/gzip --remote \
    || die "the package was not uploaded — the catalogue is left alone"
  say "Updating $BUCKET/index.json"
  npx --yes wrangler r2 object put "$BUCKET/index.json" \
    --file "$INDEX_OUT" --content-type application/json --remote \
    || die "the package is uploaded and the catalogue is not; publish again"
  say "Published: $ID $VERSION"
  note "remember that the bucket has to be readable over https"
fi
