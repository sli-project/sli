#!/usr/bin/env bash
# Isolated dispatch fixtures; no Git, SSH, Docker or running services.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
export TZ=Etc/GMT-7
export WATCHDOG_UPDATE_HOME="$TMP/update"
export WATCHDOG_UPDATE_SCRIPT="$WATCHDOG_UPDATE_HOME/update.sh"
export WATCHDOG_STAND_CONFIG="$WATCHDOG_UPDATE_HOME/config.json"
mkdir -p "$WATCHDOG_UPDATE_HOME"
printf '{}\n' > "$WATCHDOG_STAND_CONFIG"
cat > "$TMP/python" <<'SH'
#!/usr/bin/env bash
printf 'check\n' >> "$WATCHDOG_UPDATE_HOME/checks"
printf '%s\r\n' "${VERSION_STATUS:-update_available}"
exit "${CHECK_EXIT:-0}"
SH
cat > "$WATCHDOG_UPDATE_SCRIPT" <<'SH'
#!/usr/bin/env bash
printf 'apply:%s\n' "${SLI_STAND_NOW:-0}" >> "$WATCHDOG_UPDATE_HOME/actions"
SH
chmod +x "$TMP/python"
PYTHON="$TMP/python"
DRY=0
ROOT_ORIGINAL=$ROOT
HOME_DIR=$TMP
cygpath() { printf '%s\n' "${@: -1}"; }
note() { printf '%s\n' "$*"; }
source "$ROOT/deployment.sh"
run_at() {
  NOW=$(date -d "$1" +%s)
  watchdog_stand_update > "$TMP/status"
  wait
}
count_actions() { if [[ -f "$UPDATE_HOME/actions" ]]; then wc -l < "$UPDATE_HOME/actions"; else echo 0; fi; }
run_at '2026-10-18 02:59:59'
[[ $(count_actions) == 0 ]]
grep -q '2026-10-18 03:00 +0700' "$TMP/status"
run_at '2026-10-18 03:00:00'
[[ $(count_actions) == 1 && -d "$UPDATE_HOME/stand-windows/2026-10-18" ]]
run_at '2026-10-18 03:10:00'
[[ $(count_actions) == 1 ]]
grep -q '2026-10-19 03:00 +0700' "$TMP/status"
run_at '2026-10-19 03:29:59'
[[ $(count_actions) == 2 ]]
run_at '2026-10-20 03:30:00'
[[ $(count_actions) == 2 ]]
export VERSION_STATUS=current
run_at '2026-10-21 03:00:00'
[[ $(count_actions) == 2 && ! -d "$UPDATE_HOME/stand-windows/2026-10-21" ]]
export VERSION_STATUS=update_available CHECK_EXIT=1
run_at '2026-10-21 03:10:00'
[[ $(count_actions) == 2 && ! -d "$UPDATE_HOME/stand-windows/2026-10-21" ]]
unset CHECK_EXIT
export SLI_STAND_NOW=1
run_at '2026-10-21 12:00:00'
[[ $(count_actions) == 3 ]]
grep -q 'apply:1' "$UPDATE_HOME/actions"
DRY=1
before=$(wc -l < "$UPDATE_HOME/checks")
run_at '2026-10-22 03:00:00'
[[ $(count_actions) == 3 && $(wc -l < "$UPDATE_HOME/checks") == "$before" ]]
[[ ! -d "$UPDATE_HOME/stand-windows/2026-10-22" ]]
WATCHDOG_PYTHON="$PYTHON" bash "$ROOT_ORIGINAL/deployment.sh" --stand-now -n > "$TMP/manual-dry"
grep -q 'DRY-RUN' "$TMP/manual-dry"
[[ $(count_actions) == 3 ]]
unset SLI_STAND_NOW
DRY=0
NOW=$(date -d '2026-10-23 03:00:00' +%s)
dispatch_and_wait() { watchdog_stand_update; wait; }
dispatch_and_wait > "$TMP/concurrent-a" &
dispatch_and_wait > "$TMP/concurrent-b" &
wait
[[ $(count_actions) == 4 ]]
echo 'PASS daily local window, once per date, version-only polling, CRLF, failure, manual and dry-run'
