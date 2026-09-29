#!/usr/bin/env bash
# Building a package of one's own plugin.
#
# A package is a directory with a `plugin.json` and the program beside it:
# exactly what the daemon unpacks into `~/.keyward/plugins/<id>`. Here is where
# it is built: the version is taken from `Cargo.toml`, and the triple from
# whatever it was built with rather than "any" — there is machine code inside,
# and on another platform it will not run.
#
#   scripts/plugin-package.sh ssh
#   scripts/plugin-package.sh hashicorp --target aarch64-apple-darwin
#
# Two things come out of it:
#
#   dist/packages/<id>/                      — the package's directory (what is
#                                              published)
#   dist/packages/<id>-<version>-<triple>.tar.gz — the same as an archive, to
#                                              hand over by hand
#
# Publishing is `scripts/plugin-publish.sh dist/packages/<id>`; it packs and
# signs by itself. The debug symbols are not cut: `strip` on macOS breaks the
# signature, and the package travels compressed anyway.
set -euo pipefail

die() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }
say() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

usage() {
  cat >&2 <<'TXT'
Building a keyward plugin's package.

  scripts/plugin-package.sh <id> [--target TRIPLE]

  <id>              ssh or hashicorp — the directory crates/plugins/<id>
  --target TRIPLE   whom to build for; by default this machine's triple
TXT
  exit 2
}

ID=""
TARGET=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:-}"; [[ -n "$TARGET" ]] || usage; shift 2 ;;
    -h|--help) usage ;;
    -*) die "unknown flag ${1}" ;;
    *) [[ -z "$ID" ]] || die "the plugin is already given: ${ID}"; ID="$1"; shift ;;
  esac
done
[[ -n "$ID" ]] || usage

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE="$REPO/crates/plugins/$ID"
[[ -d "$CRATE" ]] || die "there is no crate crates/plugins/$ID"
[[ -f "$CRATE/plugin.json" ]] || die "crates/plugins/$ID has no plugin.json"
command -v python3 >/dev/null || die "no python3 — the package's plugin.json cannot be built without it"

# This machine's triple comes from the compiler itself: there is no point
# guessing by uname.
[[ -n "$TARGET" ]] || TARGET="$(rustc -vV | awk '/^host:/{print $2}')"
[[ -n "$TARGET" ]] || die "this machine's triple cannot be made out — give --target"

BIN="keyward-plugin-$ID"
# The version comes from the crate's Cargo.toml (the same as the
# application's). It is deliberately absent from the repository's plugin.json:
# one source of truth, and it belongs to the build.
VERSION="$(
  cargo metadata --no-deps --format-version 1 --manifest-path "$CRATE/Cargo.toml" \
  | python3 -c 'import json,sys;m=json.load(sys.stdin);print(next(p["version"] for p in m["packages"] if p["name"]=="'"keyward-plugin-$ID"'"))'
)" || die "the plugin's version cannot be found out"

say "Building $ID $VERSION for $TARGET"
cargo build --release --bin "$BIN" --target "$TARGET" --manifest-path "$CRATE/Cargo.toml" >&2 \
  || die "the build failed"

EXE="$REPO/target/$TARGET/release/$BIN"
[[ -x "$EXE" ]] || die "the built program is not there: $EXE"

OUT="$REPO/dist/packages/$ID"
rm -rf "$OUT"
mkdir -p "$OUT"
cp "$EXE" "$OUT/$BIN"
chmod 0755 "$OUT/$BIN"
# `if` rather than `&&`: under `set -e` a failed check would cut the script
# short.
if [[ -f "$REPO/LICENSE" ]]; then cp "$REPO/LICENSE" "$OUT/LICENSE"; fi

# The plugin's words travel with the plugin: the core has none of them compiled
# in, and the daemon and the window read them out of the installed package.
if [[ -d "$CRATE/i18n" ]]; then
  mkdir -p "$OUT/i18n"
  cp "$CRATE"/i18n/*.json "$OUT/i18n/"
  note "words:     $(ls "$CRATE/i18n" | tr '\n' ' ')"
fi

# The package's manifest is the crate's, plus the version and the triple. The
# triple has to be the real one: the catalogue decides by it whether to show the
# package to this machine, and "any" would mean "it suits anybody" — untrue.
python3 - "$CRATE/plugin.json" "$OUT/plugin.json" "$VERSION" "$TARGET" "$BIN" <<'PY' || die "the package's plugin.json was not built"
import json, sys

src, dst, version, target, exe = sys.argv[1:6]
m = json.load(open(src, encoding="utf-8"))
m["version"] = version
m["platform"] = target
m["exec"] = exe
json.dump(m, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
open(dst, "a", encoding="utf-8").write("\n")
PY

ARCHIVE="$REPO/dist/packages/$ID-$VERSION-$TARGET.tar.gz"
# macOS resource forks (`._file`) are not wanted in the archive.
export COPYFILE_DISABLE=1
tar -czf "$ARCHIVE" -C "$REPO/dist/packages" "$ID"

SIZE="$(wc -c < "$ARCHIVE" | tr -d ' ')"
note "directory: dist/packages/$ID"
note "archive:   dist/packages/$(basename "$ARCHIVE") ($SIZE bytes)"
note "publish:   scripts/plugin-publish.sh dist/packages/$ID --platform $TARGET"
