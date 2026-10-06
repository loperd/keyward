#!/usr/bin/env bash
# Installing keyward: the application, the CLI and the daemon under a
# LaunchAgent.
#
# It does nothing silently: before every step it prints where it writes, and it
# does not touch ~/.ssh/config at all — it only shows the lines that have to be
# added. An ssh configuration is too dear to be edited behind somebody's
# back.
set -euo pipefail

LABEL="me.loper"
BIN_DIR="${KEYWARD_BIN_DIR:-$HOME/.local/bin}"
APP_SRC="target/release/bundle/macos/keyward.app"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_DIR="$HOME/.keyward"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

app_dir() {
  if [ -w /Applications ]; then echo /Applications; else echo "$HOME/Applications"; fi
}

# The code's fingerprint rather than the file's.
#
# The binary's `shasum` can no longer be compared: a signature carries the time
# of signing, and one and the same code signed twice gives different files. The
# CDHash is counted from the code itself and does not change when the signature
# is redone — it is what shows whether the binary really has become another.
# Empty (nothing there, or unsigned) counts as changed: restarting the daemon is
# cheaper than leaving the old one.
cdhash() {
  [ -e "$1" ] || return 0
  codesign -d --verbose=4 "$1" 2>&1 | sed -n 's/^CDHash=//p' | head -1
}

do_build() {
  # tauri build builds only the GUI, so the CLI is built separately: without it
  # there is neither an ssh agent nor a daemon.
  say "Building the CLI"
  cargo build --release -p keyward-cli -p keyward-passkey-host
  say "Building the application"
  ( cd gui && npm run tauri build )
}


# The plugins from this very code.
#
# The daemon was brought up to date here and the plugins were not: they stayed
# the build of the day they were first put in, and the day the daemon's rules
# moved on without them, the Vault section said "not connected". Each plugin
# is packed from the working tree and put in through the daemon — files
# swapped by hand are caught and the plugin switched off, rightly. The daemon
# installs a local package only fresh, so an installed one is removed first;
# its settings and whatever files of its own it keeps are put back, and it is
# switched on again if it was on. A plugin whose program has not changed is
# left alone.
do_plugins() {
  say "The plugins"
  local dir="$HOME/.keyward/plugins"
  # Every plugin in the tree unless told otherwise: a directory under
  # crates/plugins with a plugin.json. A new plugin is picked up without a list
  # to edit.
  local all
  all="$(for f in crates/plugins/*/plugin.json; do basename "$(dirname "$f")"; done)"
  for id in ${PLUGINS:-$all}; do
    ./scripts/plugin-package.sh "$id" >/dev/null 2>&1 || { note "$id: the package would not build — scripts/plugin-package.sh $id says why"; exit 1; }
    local pkg="dist/packages/$id" archive
    archive="$(ls -t dist/packages/"$id"-*.tar.gz | head -1)"
    local exe
    exe="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["exec"])' "$pkg/plugin.json")"
    # PLUGINS_FORCE=1 puts it in again anyway.
    if [ "${PLUGINS_FORCE:-0}" != "1" ] && [ -f "$dir/$id/$exe" ] && cmp -s "$pkg/$exe" "$dir/$id/$exe"; then
      note "$id: up to date"
      continue
    fi
    local was_on keep
    # Through the CLI: the daemon speaks only over its encrypted channel.
    was_on="$("$BIN_DIR/keyward" plugin state "$id")" || { note "$id: the daemon did not answer"; exit 1; }
    keep="$(mktemp -d)"
    [ -f "$dir/$id.json" ] && cp -p "$dir/$id.json" "$keep/settings.json"
    [ -d "$dir/$id" ] && cp -Rp "$dir/$id" "$keep/own"
    if [ "$was_on" != "absent" ]; then
      "$BIN_DIR/keyward" plugin remove "$id" || { note "$id: it would not be removed; the old files are kept in $keep"; exit 1; }
    fi
    local answer
    if ! answer="$("$BIN_DIR/keyward" plugin install "$PWD/$archive" 2>&1)"; then
      note "$id: $answer"; note "the old files are kept in $keep"; exit 1
    fi
    [ -f "$keep/settings.json" ] && cp -p "$keep/settings.json" "$dir/$id.json"
    # The plugin's own files — state it keeps next to its program — come back;
    # the package's own files are the new ones.
    [ -d "$keep/own" ] && rsync -a --ignore-existing "$keep/own/" "$dir/$id/"
    if [ "$was_on" = "on" ]; then
      "$BIN_DIR/keyward" plugin enable "$id" || { note "$id: it would not switch on"; exit 1; }
      note "$id: updated, on"
    else
      note "$id: updated, $( [ "$was_on" = absent ] && echo 'installed — switch it on in Settings → Plugins' || echo 'off, as it was' )"
    fi
    rm -rf "$keep"
  done
}

# What follows the daemon either way: the plugins, then the window.
do_after() {
  do_plugins

  # A running window is the old build until it is started again: it is
  # restarted so that what was just installed is what is on the screen.
  if pgrep -f "keyward.app/Contents/MacOS/keyward-gui" >/dev/null 2>&1; then
    say "The window"
    pkill -f "keyward.app/Contents/MacOS/keyward-gui" || true
    for _ in $(seq 1 20); do pgrep -f "keyward.app/Contents/MacOS/keyward-gui" >/dev/null 2>&1 || break; sleep 0.25; done
    # Launch Services can answer -600 for a moment after the old window went:
    # it has not let go of the process yet. A few tries, then a plain failure.
    local tries=0
    until open -a "$(app_dir)/keyward.app" 2>/dev/null; do
      tries=$((tries + 1))
      [ "$tries" -lt 5 ] || { echo "the window did not start: open -a $(app_dir)/keyward.app"; return 1; }
      sleep 1
    done
    note "restarted"
  fi
}

# The browsers whose native messaging hosts we register: the Chromium family,
# each in its own profile directory. Only those actually installed get a
# manifest — no directories are made for a browser that is not there.
HOST_NAME="me.loper"
# The extensions allowed to start the bridge: the unpacked one (its id comes
# from the `key` in its manifest) and, once published, the store's. The host
# checks the same list itself (`ALLOWED` in crates/passkey-host/src/main.rs).
EXTENSION_ORIGINS=(
  "chrome-extension://cblgcmdaededmmnlihjkalbkhdeegehl/"
  "chrome-extension://codlckblccbcnadacdnoieimkmdieajg/"
)
browser_dirs() {
  local base="$HOME/Library/Application Support"
  for d in "Google/Chrome" "Google/Chrome Beta" "Google/Chrome Canary" "Chromium" \
           "Arc/User Data" "BraveSoftware/Brave-Browser" "Microsoft Edge" "Vivaldi"; do
    [ -d "$base/$d" ] && printf '%s\n' "$base/$d/NativeMessagingHosts"
  done
}

# The passkey bridge: the binary, its signature, and a manifest per browser
# that lets exactly keyward's extension start it. The manifest is the only
# thing a browser reads; the host checks the extension's origin itself too.
do_passkey_host() {
  say "The passkey bridge for browsers"
  install -m 0755 target/release/keyward-passkey-host "$BIN_DIR/keyward-passkey-host"
  "$(dirname "$0")/signing.sh" sign-host "$BIN_DIR/keyward-passkey-host"
  note "$BIN_DIR/keyward-passkey-host"
  local dir any=0
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    any=1
    mkdir -p "$dir"
    cat > "$dir/$HOST_NAME.json" <<HOSTEOF
{
  "name": "$HOST_NAME",
  "description": "keyward: passkeys from your vault",
  "path": "$BIN_DIR/keyward-passkey-host",
  "type": "stdio",
  "allowed_origins": [$(printf '"%s",' "${EXTENSION_ORIGINS[@]}" | sed 's/,$//')]
}
HOSTEOF
    chmod 0644 "$dir/$HOST_NAME.json"
    note "$dir/$HOST_NAME.json"
  done < <(browser_dirs)
  [ "$any" = 1 ] || note "no Chromium browser found — the bridge is installed but no browser knows of it"
  # The extension itself is loaded by a person: a browser takes an extension
  # from outside its store only by hand, in developer mode, and that is as it
  # should be.
  note "the extension: chrome://extensions (arc://extensions) → Developer mode → Load unpacked →"
  note "  $(cd "$(dirname "$0")/.." && pwd)/extension/chromium"
}

do_install() {
  [ "${1:-}" = "--no-build" ] || do_build

  local dest; dest="$(app_dir)"
  [ -d "$APP_SRC" ] || { echo "there is no $APP_SRC — build it first"; exit 1; }

  say "The application"
  rm -rf "$dest/keyward.app"
  cp -R "$APP_SRC" "$dest/"
  note "$dest/keyward.app"
  # A stable signature: otherwise every build is a new application to macOS,
  # and the Accessibility permission falls off after every update.
  "$(dirname "$0")/signing.sh" sign "$dest/keyward.app"

  say "CLI"
  mkdir -p "$BIN_DIR"
  # The daemon has to be restarted only when the binary itself has changed:
  # otherwise every rebuild of the window locks the vault and tears the sockets
  # for no reason.
  local before after
  before="$(cdhash "$BIN_DIR/keyward")"
  install -m 0755 target/release/keyward "$BIN_DIR/keyward"
  # The daemon is this same binary with the `daemon` argument, and it is signed
  # for the sake of the lock on the socket: passwords are given out only to
  # whoever is signed with the same identity.
  "$(dirname "$0")/signing.sh" sign-cli "$BIN_DIR/keyward"
  after="$(cdhash "$BIN_DIR/keyward")"
  note "$BIN_DIR/keyward"
  do_passkey_host
  if [ -n "$after" ] && [ "$before" = "$after" ]; then
    RESTART_DAEMON=0
    note "the binary has not changed — the daemon is left alone and the vault stays open"
  else
    RESTART_DAEMON=1
  fi

  if [ "${RESTART_DAEMON:-1}" = "0" ] && launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
    say "The daemon"
    note "it is running, no restart is needed"
    "$BIN_DIR/keyward" status || true
    do_after
    say "The lines for ~/.ssh/config"
    "$BIN_DIR/keyward" ssh-config | sed 's/^/  /'
    return 0
  fi

  say "The daemon under a LaunchAgent"
  mkdir -p "$HOME/Library/LaunchAgents" "$LOG_DIR"
  # Whatever is already running is stopped: both the agent and a run from the
  # build directory. bootout comes back before the job really disappears, so we
  # wait — otherwise the next bootstrap falls over with "Input/output error".
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  # The agent under its old label, from before the label changed: left loaded,
  # it starts a second daemon that takes the socket from this one.
  for old in net.0x2c.keyward; do
    if [ -e "$HOME/Library/LaunchAgents/$old.plist" ] || launchctl print "gui/$(id -u)/$old" >/dev/null 2>&1; then
      launchctl bootout "gui/$(id -u)/$old" 2>/dev/null || true
      mkdir -p "$LOG_DIR/backup"
      [ -e "$HOME/Library/LaunchAgents/$old.plist" ] && mv "$HOME/Library/LaunchAgents/$old.plist" "$LOG_DIR/backup/"
      note "the old agent $old was unloaded; its plist is in $LOG_DIR/backup"
    fi
  done
  for _ in $(seq 1 20); do
    launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || break
    sleep 0.25
  done
  pkill -f 'keyward daemon' 2>/dev/null || true

  cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN_DIR/keyward</string>
    <string>daemon</string>
    <string>--source</string>
    <string>vault</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG_DIR/daemon.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/daemon.log</string>
</dict>
</plist>
PLISTEOF

  # If the job has stayed registered after all, bootstrap will grumble — no
  # matter, kickstart decides everything after that.
  launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null || true
  launchctl kickstart -k "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
  note "$PLIST"
  note "log: $LOG_DIR/daemon.log"

  # The daemon is given time to come up before anything is claimed to be well.
  # Fifteen seconds: a cold start after a build is noticeably slower than a warm
  # one.
  for _ in $(seq 1 60); do
    [ -S "$HOME/.keyward/d.sock" ] && "$BIN_DIR/keyward" status >/dev/null 2>&1 && break
    sleep 0.25
  done

  say "The check"
  if "$BIN_DIR/keyward" status; then :; else
    echo "the daemon does not answer — see $LOG_DIR/daemon.log"; exit 1
  fi

  do_after

  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) say "Take note"; note "$BIN_DIR is not in PATH — add it, or the keyward command will not be found";;
  esac

  say "What is left is to add this to ~/.ssh/config"
  "$BIN_DIR/keyward" ssh-config | sed 's/^/  /'
  note ""
  note "The path is absolute on purpose: Match exec goes through /bin/sh, where PATH is another."
}

do_uninstall() {
  say "Stopping the daemon"
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  say "Deleting the files"
  rm -rf "$(app_dir)/keyward.app" "$HOME/Applications/keyward.app"
  rm -f "$BIN_DIR/keyward" "$BIN_DIR/keyward-passkey-host"
  local dir
  while IFS= read -r dir; do
    [ -n "$dir" ] && rm -f "$dir/$HOST_NAME.json"
  done < <(browser_dirs)
  note "the data in ~/.keyward and the accounts in the Keychain are left — they can be removed by hand"
}

do_status() {
  say "The state"
  note "application: $( [ -d "$(app_dir)/keyward.app" ] && echo "$(app_dir)/keyward.app" || echo 'not installed' )"
  note "CLI:         $( [ -x "$BIN_DIR/keyward" ] && echo "$BIN_DIR/keyward" || echo 'not installed' )"
  # The CLI's signature is the daemon's too: without it the daemon cannot tell
  # the application from any other process and will give passwords out on
  # biometrics alone.
  local who; who="$(codesign -d --verbose=4 "$BIN_DIR/keyward" 2>&1 | sed -n 's/^Authority=//p' | head -1)"
  note "signature:   ${who:-none — the daemon will not tell the application from a foreign process and will give passwords out on biometrics alone}"
  local hw; hw="$(codesign -d --verbose=4 "$BIN_DIR/keyward-passkey-host" 2>&1 | sed -n 's/^Identifier=//p' | head -1)"
  note "passkeys:    $( [ -x "$BIN_DIR/keyward-passkey-host" ] && echo "${hw:-unsigned — the daemon will not know it as the bridge}" || echo 'not installed' )"
  local dir
  while IFS= read -r dir; do
    [ -n "$dir" ] && [ -f "$dir/$HOST_NAME.json" ] && note "             $dir/$HOST_NAME.json"
  done < <(browser_dirs)
  note "LaunchAgent: $( launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 && echo 'loaded' || echo 'not loaded' )"
  [ -x "$BIN_DIR/keyward" ] && "$BIN_DIR/keyward" status 2>&1 | sed 's/^/  /' || true
}

case "${1:-install}" in
  install) shift || true; do_install "${1:-}";;
  uninstall) do_uninstall;;
  status) do_status;;
  *) echo "usage: $0 [install [--no-build] | uninstall | status]"; exit 1;;
esac
