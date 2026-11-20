#!/usr/bin/env bash
# External CLIs are fixtures; the real watchdog, file state and workers are exercised.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rc=$?; if (( rc == 0 )); then rm -rf "$TMP"; else echo "Test evidence kept at $TMP"; fi' EXIT
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *'pr list'* ]]; then
  [[ ${OFFLINE:-0} == 0 ]] || exit 1
  if [[ "$*" == *'--head'* ]]; then echo 88; else cat "$FIXTURE/prs"; fi
elif [[ "$*" == *'pr merge'* ]]; then
  printf '%s\n' "$*" >> "$FIXTURE/actions"
else exit 1; fi
EOF
cat > "$TMP/bin/docker" <<'EOF'
#!/usr/bin/env bash
cat "$FIXTURE/containers"
EOF
cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
if [[ -n ${FAILED_HOST:-} && "$*" == *"$FAILED_HOST"* ]]; then exit 1; fi
printf '%s' "${READY:-200}"
EOF
cat > "$TMP/bin/ps" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == '-W' ]]; then
  [[ ${PS_FAIL:-0} == 0 ]] || exit 1
  for ((i=0;i<${CODEX_COUNT:-4};i++)); do
    echo '1 0 0 999 ? 1 now /Programs/codex/bin/codex'
  done
elif [[ "$1" == '-p' ]]; then
  # Emulate Git Bash's PID/PPID/PGID/WINPID columns on the Linux test host.
  printf '%s 1 1 999999\n' "$2"
else /usr/bin/ps "$@"; fi
EOF
cat > "$TMP/bin/powershell.exe" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *'-Mode inventory'*) [[ "$*" == *'-CiScript '* && "$*" == *'-ConflictScript '* ]] || exit 1; cat "$FIXTURE/processes";;
  *'-Mode identity'*) echo '999999 123456789';;
  *'-Mode repair-kill'*) [[ "$*" == *'-CiScript '* && "$*" == *'-ConflictScript '* ]] || exit 1; echo kill >> "$FIXTURE/actions";;
  *'-Mode kill'*) echo kill >> "$FIXTURE/actions";;
  *) exit 1;;
esac
EOF
cat > "$TMP/bin/cygpath" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${@: -1}"
EOF
cat > "$TMP/bin/watchdog-python" <<'EOF'
#!/usr/bin/env bash
# Process cleanup/publication are covered separately with fake inventories.
if [[ "$*" == *' janitor '* ]]; then printf 'janitor\n' > "$FIXTURE/janitor-ran"; fi
exit 0
EOF
chmod +x "$TMP/bin/"*
export PATH="$TMP/bin:$PATH"
export WATCHDOG_REPO="$ROOT" CODEX_COUNT=4
export WATCHDOG_UPDATE_SCRIPT="$TMP/disabled-update.sh"
export WATCHDOG_PYTHON="$TMP/bin/watchdog-python" WATCHDOG_HEAVY_DIR="$TMP/heavy"
new_case() {
  FIXTURE="$TMP/$1"; export FIXTURE WATCHDOG_HOME="$TMP/$1"
  mkdir -p "$FIXTURE"
  : > "$FIXTURE/prs"; : > "$FIXTURE/containers"; : > "$FIXTURE/processes"
  unset OFFLINE READY PS_FAIL FAILED_HOST
}
run() { bash "$ROOT/watchdog.sh" "$@"; }
contains() { grep -q -- "$2" "$1" || { echo "FAIL: $1 missing $2"; exit 1; }; }
absent() { [[ ! -e "$1" ]] || { echo "FAIL: unexpected $1"; exit 1; }; }

[[ -f "$ROOT/watchdog.sh" ]] || { echo 'FAIL: watchdog.sh is missing (required executable behavior)'; exit 1; }

new_case dry
printf '%s\n' $'11\tconsolidation/codex-green\tMERGEABLE\tCLEAN\t2026-10-10\t1\ttrue\ttrue\tfalse' $'12\tconsolidation/codex-conflict\tCONFLICTING\tDIRTY\t2026-10-10\t1\ttrue\ttrue\tfalse' $'13\tconsolidation/codex-fail\tMERGEABLE\tBLOCKED\t2026-10-10\t1\ttrue\tfalse\ttrue' $'14\tconsolidation/codex-pending\tMERGEABLE\tBLOCKED\t2026-10-10\t2\tfalse\tfalse\ttrue' $'15\tconsolidation/codex-empty\tMERGEABLE\tCLEAN\t2026-10-10\t0\ttrue\ttrue\tfalse' > "$FIXTURE/prs"
printf 'keep|Title||task.md\r\n' > "$FIXTURE/queue.txt"
cp "$FIXTURE/queue.txt" "$FIXTURE/queue.before"
run -n
contains "$FIXTURE/STATUS.md" 'gh pr merge --merge'
contains "$FIXTURE/STATUS.md" 'conflict_fix'
contains "$FIXTURE/STATUS.md" 'ci_fix'
contains "$FIXTURE/STATUS.md" 'CI ещё выполняется'
contains "$FIXTURE/STATUS.md" 'нет проверок'
cmp "$FIXTURE/queue.txt" "$FIXTURE/queue.before"
absent "$FIXTURE/state.tsv"; absent "$FIXTURE/actions"; absent "$FIXTURE/watchdog.lock"
echo 'PASS dry-run decisions and immutability'

new_case offline
export OFFLINE=1
printf '99\told\tci_fix\t123\t999999\t123456789\t1\ttoken\n' > "$FIXTURE/state.tsv"
cp "$FIXTURE/state.tsv" "$FIXTURE/state.before"
if run; then echo 'FAIL: offline pass must return nonzero'; exit 1; fi
cmp "$FIXTURE/state.tsv" "$FIXTURE/state.before"; absent "$FIXTURE/actions"
contains "$FIXTURE/STATUS.md" 'GitHub недоступен'
echo 'PASS offline no mutations'

new_case alerts
export READY=503
printf 'sli-core\tUp 3 minutes (unhealthy)\nsli-worker\tRestarting (1)\n' > "$FIXTURE/containers"
run -n
contains "$FIXTURE/STATUS.md" 'ALERT.*sli-core'
contains "$FIXTURE/STATUS.md" 'ALERT.*sli-worker'
contains "$FIXTURE/STATUS.md" '503'
echo 'PASS health alerts'

new_case merge
printf '%s\n' $'21\tconsolidation/codex-ready\tMERGEABLE\tCLEAN\t2026-10-10\t1\ttrue\ttrue\tfalse' > "$FIXTURE/prs"
run
contains "$FIXTURE/actions" 'pr merge 21 --merge'
echo 'PASS green PR merge'

new_case limit
printf '%s\n' $'22\tconsolidation/codex-bad\tCONFLICTING\tDIRTY\t2026-10-10\t1\ttrue\tfalse\ttrue' > "$FIXTURE/prs"
printf '22\t3\n' > "$FIXTURE/attempts.tsv"
run
contains "$FIXTURE/STATUS.md" 'нужен человек'
absent "$FIXTURE/actions"
echo 'PASS repair attempt limit'

new_case external
printf '%s\n' $'23\tconsolidation/codex-busy\tCONFLICTING\tDIRTY\t2026-10-10\t1\ttrue\tfalse\ttrue' > "$FIXTURE/prs"
printf 'conflict_fix\t23\t777\t123456789\n' > "$FIXTURE/processes"
run
contains "$FIXTURE/STATUS.md" 'уже выполняется'
absent "$FIXTURE/attempts.tsv"
echo 'PASS external repair deduplication'

new_case lock
mkdir "$FIXTURE/watchdog.lock.guard"
printf '%s\t%s\tbusy\n' "$$" "$(date +%s)" > "$FIXTURE/watchdog.lock"
run -n
contains "$FIXTURE/watchdog.lock" busy
absent "$FIXTURE/STATUS.md"
echo 'PASS live lock blocks duplicate pass'

new_case old_live_lock
mkdir "$FIXTURE/watchdog.lock.guard"
printf '%s\t1\tbusy\n' "$$" > "$FIXTURE/watchdog.lock"
run
contains "$FIXTURE/watchdog.lock" busy
absent "$FIXTURE/STATUS.md"
echo 'PASS old live lock is never reclaimed'

new_case stale_dry_lock
mkdir "$FIXTURE/watchdog.lock.guard"
printf '99999999\t1\tstale\n' > "$FIXTURE/watchdog.lock"
run -n
contains "$FIXTURE/watchdog.lock" stale
[[ -d "$FIXTURE/watchdog.lock.guard" ]] || exit 1
echo 'PASS dry pass preserves stale lock'

for host in github.com api.openai.com; do
  new_case "network_$host"
  export FAILED_HOST="$host"
  printf '%s\n' $'41\tconsolidation/codex-ready\tMERGEABLE\tCLEAN\t2026-10-10\t1\ttrue\ttrue\tfalse' > "$FIXTURE/prs"
  printf 'first|Title||task.md\n' > "$FIXTURE/queue.txt"
  cp "$FIXTURE/queue.txt" "$FIXTURE/queue.before"
  if run; then echo 'FAIL: network failure must block the pass'; exit 1; fi
  contains "$FIXTURE/STATUS.md" 'Сеть: нет ответа (перезапустите VPN)'
  contains "$FIXTURE/janitor-ran" janitor
  cmp "$FIXTURE/queue.txt" "$FIXTURE/queue.before"
  absent "$FIXTURE/actions"; absent "$FIXTURE/state.tsv"
done
echo 'PASS either endpoint failure blocks dispatch but runs janitor'

new_case malformed
printf 'broken output\n' > "$FIXTURE/prs"
if run; then echo 'FAIL: malformed PR response must fail'; exit 1; fi
absent "$FIXTURE/actions"
echo 'PASS malformed discovery blocks actions'

new_case process_failure
export PS_FAIL=1 CODEX_COUNT=0
printf '%s\n' $'31\tconsolidation/codex-ready\tMERGEABLE\tCLEAN\t2026-10-10\t1\ttrue\ttrue\tfalse' > "$FIXTURE/prs"
if run; then echo 'FAIL: missing process count must block actions'; exit 1; fi
absent "$FIXTURE/actions"
echo 'PASS failed process discovery blocks actions'

new_case repair_launch
export CODEX_COUNT=0 WATCHDOG_CI_SCRIPT="$FIXTURE/fix.sh"
printf '#!/usr/bin/env bash\nprintf "%%s %%s\\n" "$1" "$2" > "$WATCHDOG_HOME/fix.args"\n' > "$FIXTURE/fix.sh"
printf '%s\n' $'32\tconsolidation/codex-red\tMERGEABLE\tBLOCKED\t2026-10-10\t1\ttrue\tfalse\ttrue' > "$FIXTURE/prs"
run
for ((i=0;i<60;i++)); do [[ ! -f "$FIXTURE/fix.args" ]] || break; sleep .1; done
contains "$FIXTURE/fix.args" '^32 red$'
contains "$FIXTURE/attempts.tsv" $'^32\t1$'
contains "$FIXTURE/state.tsv" $'^32\tred\tci_fix\t'
echo 'PASS background repair and persistent attempt'

new_case parallel_pr_identity
export CODEX_COUNT=0 WATCHDOG_CI_SCRIPT="$FIXTURE/fix.sh" WATCHDOG_CONFLICT_SCRIPT="$FIXTURE/fix.sh"
cat > "$FIXTURE/fix.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\t%s\n' "$1" "$2" > "$WATCHDOG_HOME/fix-$1.args"
for ((i=0;i<300;i++)); do
  [[ ! -f "$WATCHDOG_HOME/release" ]] || exit 0
  sleep .1
done
exit 1
EOF
# Counters, an active queue worker, and a completed repair coexist with two launches.
printf '549\t1\n552\t1\n543\t1\n' > "$FIXTURE/attempts.tsv"
mkdir -p "$FIXTURE/jobs/active-token" "$FIXTURE/jobs/completed-token"
printf '553\n' > "$FIXTURE/jobs/active-token/pr"
printf 'ok\n' > "$FIXTURE/jobs/completed-token/result"
printf 'queue:adpub\tadpub\tqueue\t%s\t999999\t123456789\t%s\tactive-token\n555\tcompleted\tci_fix\t%s\t999999\t123456789\t%s\tcompleted-token\n' "$$" "$(date +%s)" "$$" "$(date +%s)" > "$FIXTURE/state.tsv"
printf '%s\n' $'552\tconsolidation/codex-fsui\tCONFLICTING\tDIRTY\t2026-10-10\t4\ttrue\tfalse\ttrue' $'549\tconsolidation/codex-l01wire\tMERGEABLE\tBLOCKED\t2026-10-10\t4\ttrue\tfalse\ttrue' $'553\tconsolidation/codex-adpub\tMERGEABLE\tCLEAN\t2026-10-10\t4\ttrue\ttrue\tfalse' > "$FIXTURE/prs"
run
for ((i=0;i<100;i++)); do
  [[ ! -f "$FIXTURE/fix-552.args" || ! -f "$FIXTURE/fix-549.args" ]] || break
  sleep .1
done
# Release both fixtures before assertions, including on the unfixed implementation.
touch "$FIXTURE/release"
contains "$FIXTURE/fix-552.args" $'^552\tfsui$'
contains "$FIXTURE/fix-549.args" $'^549\tl01wire$'
contains "$FIXTURE/state.tsv" $'^552\tfsui\tconflict_fix\t'
contains "$FIXTURE/state.tsv" $'^549\tl01wire\tci_fix\t'
contains "$FIXTURE/state.tsv" $'^queue:adpub\tadpub\tqueue\t'
[[ $(wc -l < "$FIXTURE/state.tsv") == 3 ]] || { echo 'FAIL: parallel jobs lost or miskeyed'; exit 1; }
contains "$FIXTURE/attempts.tsv" $'^552\t2$'
contains "$FIXTURE/attempts.tsv" $'^549\t2$'
contains "$FIXTURE/attempts.tsv" $'^543\t1$'
contains "$FIXTURE/STATUS.md" '^| #552 | consolidation/codex-fsui |.*запущен conflict_fix, попытка 2/3'
contains "$FIXTURE/STATUS.md" '^| #549 | consolidation/codex-l01wire |.*запущен ci_fix, попытка 2/3'
contains "$FIXTURE/STATUS.md" '^| #553 | consolidation/codex-adpub |.*уже выполняется'
contains "$FIXTURE/STATUS.md" 'резерв фоновых работ 3'
absent "$FIXTURE/actions"
for repair_pr in 552 549; do
  repair_token=$(awk -F '\t' -v pr="$repair_pr" '$1==pr {print $8}' "$FIXTURE/state.tsv")
  repair_name=fsui; repair_kind=conflict_fix
  if [[ "$repair_pr" == 549 ]]; then repair_name=l01wire; repair_kind=ci_fix; fi
  contains "$FIXTURE/jobs/$repair_token/identity.tsv" "$(printf '^%s\t%s\t%s$' "$repair_pr" "$repair_name" "$repair_kind")"
  contains "$FIXTURE/logs/$repair_token.log" "^dispatch: key=$repair_pr name=$repair_name kind=$repair_kind$"
  for ((i=0;i<100;i++)); do [[ ! -f "$FIXTURE/jobs/$repair_token/result" ]] || break; sleep .1; done
  contains "$FIXTURE/jobs/$repair_token/result" '^ok$'
done
echo 'PASS simultaneous PR repairs preserve arguments, counters, state, logs and status'

new_case queue_launch
export CODEX_COUNT=0 WATCHDOG_QUEUE_SCRIPT="$FIXTURE/q_main.sh" WATCHDOG_AUTO_SCRIPT="$FIXTURE/auto.sh"
printf '#!/usr/bin/env bash\ncat "$1" > "$WATCHDOG_HOME/dispatched"\necho "12:00 first rc=0"\n' > "$FIXTURE/q_main.sh"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$1" > "$WATCHDOG_HOME/auto.args"\n' > "$FIXTURE/auto.sh"
touch "$FIXTURE/task_first.md" "$FIXTURE/task_second.md"
printf '\r\nfirst|First title||task_first.md\r\nsecond|Second title||task_second.md\r\n' > "$FIXTURE/queue.txt"
run
for ((i=0;i<100;i++)); do [[ ! -f "$FIXTURE/auto.args" ]] || break; sleep .1; done
contains "$FIXTURE/dispatched" '^first|First title||task_first.md$'
contains "$FIXTURE/queue.txt" '^second|Second title||task_second.md'
contains "$FIXTURE/auto.args" '^88:first$'
contains "$FIXTURE/attempts.tsv" $'^88\t1$'
contains "$FIXTURE/STATUS.md" 'резерв фоновых работ 1'
[[ $(wc -l < "$FIXTURE/queue.txt") == 1 ]] || { echo 'FAIL: queue must consume one task'; exit 1; }
echo 'PASS FIFO CRLF queue and deferred auto_merge'

new_case reserved_slot
export CODEX_COUNT=3
printf 'queue:busy\tbusy\tqueue\t%s\t999999\t123456789\t%s\tbusy-token\n' "$$" "$(date +%s)" > "$FIXTURE/state.tsv"
printf 'first|Title||task_first.md\n' > "$FIXTURE/queue.txt"
cp "$FIXTURE/queue.txt" "$FIXTURE/queue.before"
run
cmp "$FIXTURE/queue.txt" "$FIXTURE/queue.before"
contains "$FIXTURE/STATUS.md" 'ожидает слот'
echo 'PASS reserved slot prevents premature queue launch'

new_case timeout
export CODEX_COUNT=4
printf '35\told\tci_fix\t%s\t999999\t123456789\t1\told-token\n' "$$" > "$FIXTURE/state.tsv"
run
contains "$FIXTURE/actions" kill
[[ ! -s "$FIXTURE/state.tsv" ]] || { echo 'FAIL: expired job must allow retry'; exit 1; }
echo 'PASS expired owned job tree termination'

new_case dry_timeout
printf '35\told\tci_fix\t%s\t999999\t123456789\t1\told-token\n' "$$" > "$FIXTURE/state.tsv"
cp "$FIXTURE/state.tsv" "$FIXTURE/state.before"
run -n
cmp "$FIXTURE/state.tsv" "$FIXTURE/state.before"
absent "$FIXTURE/actions"
contains "$FIXTURE/STATUS.md" 'старше 2 часов'
echo 'PASS dry-run preserves expired jobs'

new_case invalid_queue
export CODEX_COUNT=0
printf 'bad|Title|API_KEY=do-not-execute|task.md\n' > "$FIXTURE/queue.txt"
cp "$FIXTURE/queue.txt" "$FIXTURE/queue.before"
run
cmp "$FIXTURE/queue.txt" "$FIXTURE/queue.before"
contains "$FIXTURE/STATUS.md" 'некорректна'
absent "$FIXTURE/actions"
echo 'PASS malformed queue stays unconsumed'

new_case queue_pr_busy
export CODEX_COUNT=0
mkdir -p "$FIXTURE/jobs/auto-token"
printf '33\n' > "$FIXTURE/jobs/auto-token/pr"
printf 'queue:busy\tbusy\tqueue\t%s\t999999\t123456789\t%s\tauto-token\n' "$$" "$(date +%s)" > "$FIXTURE/state.tsv"
printf '%s\n' $'33\tconsolidation/codex-busy\tMERGEABLE\tBLOCKED\t2026-10-10\t1\ttrue\tfalse\ttrue' > "$FIXTURE/prs"
run
contains "$FIXTURE/STATUS.md" 'уже выполняется'
absent "$FIXTURE/attempts.tsv"
echo 'PASS queue auto_merge owns its PR until completion'

new_case queue_pr_before_metadata
export CODEX_COUNT=0
printf 'queue:busy\tbusy\tqueue\t%s\t999999\t123456789\t%s\tearly-token\n' "$$" "$(date +%s)" > "$FIXTURE/state.tsv"
printf '%s\n' $'36\tconsolidation/codex-busy\tMERGEABLE\tCLEAN\t2026-10-10\t1\ttrue\ttrue\tfalse' > "$FIXTURE/prs"
run
absent "$FIXTURE/actions"
contains "$FIXTURE/STATUS.md" 'уже выполняется'
echo 'PASS queue owns branch before PR metadata publication'

new_case external_timeout
export CODEX_COUNT=4
printf 'conflict_fix\t34\t999999\t123456789\t1\n' > "$FIXTURE/processes"
printf '%s\n' $'34\tconsolidation/codex-old\tCONFLICTING\tDIRTY\t2026-10-10\t1\ttrue\tfalse\ttrue' > "$FIXTURE/prs"
run
contains "$FIXTURE/actions" kill
contains "$FIXTURE/STATUS.md" 'внешняя работа.*старше 2 часов'
if grep -q 'уже выполняется' "$FIXTURE/STATUS.md"; then echo 'FAIL: expired external process still blocks retry'; exit 1; fi
echo 'PASS external repair timeout allows retry'

new_case auto_limit
export CODEX_COUNT=0 WATCHDOG_QUEUE_SCRIPT="$FIXTURE/q_main.sh" WATCHDOG_AUTO_SCRIPT="$FIXTURE/auto.sh"
printf '#!/usr/bin/env bash\necho "12:00 first rc=0"\n' > "$FIXTURE/q_main.sh"
printf '#!/usr/bin/env bash\necho bad > "$WATCHDOG_HOME/auto.args"\n' > "$FIXTURE/auto.sh"
touch "$FIXTURE/task_first.md"
printf '88\t3\n' > "$FIXTURE/attempts.tsv"
printf 'first|Title||task_first.md\n' > "$FIXTURE/queue.txt"
run
for ((i=0;i<100;i++)); do [[ -z $(find "$FIXTURE/jobs" -name result -print -quit) ]] || break; sleep .1; done
absent "$FIXTURE/auto.args"
contains "$FIXTURE/attempts.tsv" $'^88\t3$'
echo 'PASS exhausted budget blocks implicit auto_merge repair'

echo 'ALL TESTS PASSED'
