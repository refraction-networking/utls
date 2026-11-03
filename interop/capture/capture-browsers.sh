#!/bin/sh
# Capture fresh-profile ClientHellos from locally installed browsers over
# loopback only. Run on a host (not inside a restrictive sandbox) from the
# repository root. Uses throwaway profiles; never touches your own.
#   interop/capture/capture-browsers.sh OUTDIR
set -eu
OUT=${1:?usage: capture-browsers.sh OUTDIR}
mkdir -p "$OUT"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
go build -o "$WORK/capture" ./interop/capture
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
FIREFOX=${FIREFOX:-"/Applications/Firefox.app/Contents/MacOS/firefox"}

run() { # name port cmd...
  name=$1 port=$2; shift 2
  "$WORK/capture" "$port" "$OUT/$name" & cap=$!
  sleep 1
  "$@" >"$WORK/$name.log" 2>&1 & b=$!
  sleep 20; kill $b 2>/dev/null || true; wait $cap || true
}

if [ -x "$CHROME" ]; then
  v=$("$CHROME" --version | awk '{print $3}')
  run "chrome$v" 47621 "$CHROME" --headless=new --user-data-dir="$WORK/chrome" \
    --no-first-run --no-default-browser-check --disable-quic \
    --disable-background-networking --disable-component-update --disable-sync \
    --host-resolver-rules="MAP utls-capture.test 127.0.0.1" https://utls-capture.test:47621/
fi
if [ -x "$FIREFOX" ]; then
  v=$("$FIREFOX" --version | awk '{print $3}')
  mkdir -p "$WORK/ff"
  cat >"$WORK/ff/user.js" <<'PREFS'
user_pref("network.dns.localDomains", "utls-capture.test");
user_pref("network.trr.mode", 5);
user_pref("app.update.enabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
PREFS
  run "firefox$v" 47622 "$FIREFOX" --headless --no-remote -profile "$WORK/ff" https://utls-capture.test:47622/
fi
ls -l "$OUT"
