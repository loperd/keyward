#!/usr/bin/env bash
# The Chrome Web Store upload: extension/chromium as a zip, ready to submit.
#
# What differs from the unpacked extension is exactly one thing: the manifest
# loses its `key`. The key pins the unpacked extension's identifier for local
# use; the store gives the item an identifier of its own and refuses a package
# that carries one. Everything else ships as it is, and is checked first —
# a package that would be rejected, or that carries something it should not,
# fails here rather than in review.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/extension/chromium"
OUT="$ROOT/dist/extension"

fail() { printf 'extension-package: %s\n' "$*" >&2; exit 1; }

command -v node >/dev/null || fail "node is needed to check the scripts"
command -v zip >/dev/null || fail "zip is needed"

VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$SRC/manifest.json")"
[[ "$VERSION" =~ ^[0-9]+(\.[0-9]+){0,3}$ ]] || fail "the version $VERSION is not what the store takes"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Only what the extension is made of: no dot-files, no editor leftovers.
rsync -a --exclude='.*' --exclude='*~' --exclude='*.swp' "$SRC/" "$WORK/pkg/"

python3 - "$WORK/pkg/manifest.json" <<'PYEOF'
import json, os, sys
path = sys.argv[1]
m = json.load(open(path))
m.pop("key", None)
problems = []
if m.get("manifest_version") != 3:
    problems.append("manifest_version is not 3")
for size in ("16", "48", "128"):
    icon = m.get("icons", {}).get(size)
    if not icon or not os.path.exists(os.path.join(os.path.dirname(path), icon)):
        problems.append(f"no {size}px icon")
if m.get("web_accessible_resources"):
    problems.append("web_accessible_resources would let pages load the chooser")
csp = m.get("content_security_policy", {}).get("extension_pages", "")
if "unsafe-eval" in csp or "unsafe-inline" in csp or "http" in csp:
    problems.append("the extension pages' CSP allows remote or inline code")
root = os.path.dirname(path)
for key in ("name", "description"):
    value = m.get(key, "")
    if value.startswith("__MSG_"):
        msg = value[6:-2]
        for lang in os.listdir(os.path.join(root, "_locales")):
            text = json.load(open(os.path.join(root, "_locales", lang, "messages.json")))[msg]["message"]
            if key == "description" and len(text) > 132:
                problems.append(f"{lang}: the description is over 132 characters")
if problems:
    sys.exit("extension-package: " + "; ".join(problems))
json.dump(m, open(path, "w"), ensure_ascii=False, indent=2)
open(path, "a").write("\n")
PYEOF

grep -q '"key"' "$WORK/pkg/manifest.json" && fail "the key is still in the manifest"
for f in "$WORK"/pkg/*.js; do
  node --check "$f" 2>/dev/null || node --input-type=module --check < "$f" || fail "$(basename "$f") does not parse"
done
# No remote code and no eval in what ships.
if grep -nE '\beval\(|new Function\(|https?://[^"'"'"' ]+\.js' "$WORK"/pkg/*.js; then
  fail "remote code or eval in the scripts"
fi

mkdir -p "$OUT"
ZIP="$OUT/keyward-$VERSION.zip"
rm -f "$ZIP"
( cd "$WORK/pkg" && zip -X -q -r "$ZIP" . )
printf '%s\n' "$ZIP"
printf '  %s bytes, sha256 %s\n' "$(stat -f %z "$ZIP")" "$(shasum -a 256 "$ZIP" | cut -d' ' -f1)"
unzip -Z1 "$ZIP" | sed 's/^/  /'
