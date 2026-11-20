#!/usr/bin/env bash
# Git Bash on Windows. -n writes status/dashboard only; no dispatch or merge.
set -uo pipefail
umask 077
ROOT=$(cd "$(dirname "$0")" && pwd)
HOME_DIR=${WATCHDOG_HOME:-$ROOT}
REPO=${WATCHDOG_REPO:-/d/SLI_docker/workspace/sli-platform}
LOCAL_DATA=$(cygpath -u "${LOCALAPPDATA:-$HOME/AppData/Local}")
QUEUE_SCRIPT=${WATCHDOG_QUEUE_SCRIPT:-$LOCAL_DATA/Temp/claude/D--II-project-SLI-platform/6d92231a-f40a-4e7a-99af-716c3946f78c/scratchpad/q_main_v3.sh}
QUEUE_DIR=$(dirname "$QUEUE_SCRIPT")
CI_SCRIPT=${WATCHDOG_CI_SCRIPT:-/d/SLI_docker/ci_fix.sh}
CONFLICT_SCRIPT=${WATCHDOG_CONFLICT_SCRIPT:-/d/SLI_docker/conflict_fix.sh}
AUTO_SCRIPT=${WATCHDOG_AUTO_SCRIPT:-/d/SLI_docker/auto_merge.sh}
DRY=0
case "${1:-}" in -n) DRY=1;; '') :;; *) echo 'Usage: watchdog.sh [-n]' >&2; exit 2;; esac
[[ $# -le 1 ]] || exit 2
mkdir -p "$HOME_DIR/logs" || exit 1
NOW=$(date +%s)
STAMP=$(date '+%Y-%m-%d %H:%M:%S %z')
TOKEN="$NOW-$$-$RANDOM"
LOCK="$HOME_DIR/watchdog.lock"
GUARD="$LOCK.guard"
OWN_LOCK=0
WORK=''
cleanup() {
  [[ -z "$WORK" ]] || rm -rf -- "$WORK"
  if (( OWN_LOCK )) && [[ -f "$LOCK" ]] && [[ $(cut -f3 "$LOCK") == "$TOKEN" ]]; then
    rm -f -- "$LOCK"; rmdir "$GUARD" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
if (( DRY )); then
  # A dry pass never claims/reclaims a lock owned by the live pipeline.
  owner=0; born=0
  if [[ -f "$LOCK" ]]; then IFS=$'\t' read -r owner born _ < "$LOCK" || true; fi
  if [[ "$owner" =~ ^[1-9][0-9]*$ ]] && kill -0 "$owner" 2>/dev/null; then exit 0; fi
elif ! mkdir "$GUARD" 2>/dev/null; then
  # Serialize stale-lock reclamation separately from the running owner.
  mkdir "$HOME_DIR/.lock-reclaim" 2>/dev/null || exit 0
  owner=0; born=0
  if [[ -f "$LOCK" ]]; then IFS=$'\t' read -r owner born _ < "$LOCK" || true; fi
  [[ "$born" =~ ^[0-9]+$ ]] || born=0
  if (( born == 0 )); then born=$(stat -c %Y "$GUARD" 2>/dev/null || echo "$NOW"); fi
  if (( NOW-born <= 1800 )) || { [[ "$owner" =~ ^[1-9][0-9]*$ ]] && kill -0 "$owner" 2>/dev/null; }; then
    rmdir "$HOME_DIR/.lock-reclaim"; exit 0
  fi
  rm -f -- "$LOCK"
  rmdir "$GUARD" 2>/dev/null || { rmdir "$HOME_DIR/.lock-reclaim"; exit 1; }
  mkdir "$GUARD" 2>/dev/null || { rmdir "$HOME_DIR/.lock-reclaim"; exit 0; }
  rmdir "$HOME_DIR/.lock-reclaim"
fi
if (( !DRY )); then
  printf '%s\t%s\t%s\n' "$$" "$NOW" "$TOKEN" > "$LOCK" || exit 1
  OWN_LOCK=1
fi
WORK=$(mktemp -d "$HOME_DIR/.pass.XXXXXX") || exit 1
REPORT="$WORK/status"
printf '# SLI Watchdog\n\nВремя: %s\n\nРежим: %s\n\n' "$STAMP" "$([[ $DRY == 1 ]] && echo 'DRY-RUN (без действий)' || echo 'рабочий')" > "$REPORT"
EVENTS=0
note() { printf '%s\n' "$*" >> "$REPORT"; EVENTS=$((EVENTS+1)); }
finish() {
  mv -f -- "$REPORT" "$HOME_DIR/STATUS.md" || exit 1
  printf '%s mode=%s result=%s events=%s codex=%s reserved=%s\n' "$STAMP" "$DRY" "$1" "$EVENTS" "${CODEX:-unknown}" "${RESERVED:-unknown}" >> "$HOME_DIR/logs/history.log"
  watchdog_dashboard "$1"
}
health() {
  local ready containers name status
  ready=$(timeout -k 5 20 curl --silent --insecure --output /dev/null --write-out '%{http_code}' --connect-timeout 5 --max-time 12 https://localhost:8443/api/health/ready 2>/dev/null); ready=${ready:0:3}; [[ "$ready" =~ ^[0-9]{3}$ ]] || ready=000
  if [[ "$ready" == 200 ]]; then note 'SLI ready: HTTP 200.'; else note "ALERT: SLI ready HTTP $ready (ожидался 200)."; fi
  if containers=$(timeout -k 5 15 docker ps -a --filter 'name=sli-' --format '{{.Names}}\t{{.Status}}' 2>/dev/null); then
    [[ -n "$containers" ]] || note 'ALERT: контейнеры sli-* не найдены.'
    while IFS=$'\t' read -r name status; do
      [[ "$name" == sli-* ]] || continue
      case "$status" in *Restarting*|*unhealthy*) note "ALERT: $name — $status.";; esac
    done <<< "$containers"
  else note 'ALERT: Docker недоступен; состояние sli-* неизвестно.'; fi
}
source "$ROOT/deployment.sh"
source "$ROOT/dashboard.sh"
source "$ROOT/network.sh"
HEAVY_DIR=${WATCHDOG_HEAVY_DIR:-$LOCAL_DATA/Temp/claude/D--II-project-SLI-platform/77c6b75b-e27a-4256-8ca4-ff2eacb0ccf8/scratchpad}
PYTHON=${WATCHDOG_PYTHON:-$UPDATE_HOME/venv/Scripts/python.exe}
janitor_args=()
(( !DRY )) || janitor_args=(--dry)
if ! timeout -k 5 120 "$PYTHON" "$ROOT/watchdog_pipeline.py" janitor \
    --home "$(cygpath -w "$HOME_DIR")" --root "$(cygpath -w "$ROOT")" \
    --bash "$(cygpath -w "$BASH")" --heavy "$(cygpath -w "$HEAVY_DIR")" \
    --update "$(cygpath -w "$UPDATE_HOME")" "${janitor_args[@]}" > "$WORK/janitor" 2>/dev/null; then
  note 'ERROR: уборщик не завершён; запуск новых задач заблокирован.'
  NETWORK=offline; finish process_error; exit 1
fi
while IFS= read -r line; do note "$line"; done < "$WORK/janitor"
if [[ -f "$HOME_DIR/guard-notice.txt" ]]; then
  while IFS= read -r line; do note "$line"; done < "$HOME_DIR/guard-notice.txt"
fi
if ! watchdog_network; then finish network_error; exit 1; fi
watchdog_update_status
JQ=' .[] | [ .number, .headRefName, .mergeable, .mergeStateStatus, .updatedAt,
  (.statusCheckRollup | length),
  ([.statusCheckRollup[] | if .__typename == "CheckRun" then .status == "COMPLETED" else (.state == "SUCCESS" or .state == "FAILURE" or .state == "ERROR") end] | all),
  ([.statusCheckRollup[] | if .__typename == "CheckRun" then (.conclusion == "SUCCESS" or .conclusion == "NEUTRAL" or .conclusion == "SKIPPED") else .state == "SUCCESS" end] | all),
  ([.statusCheckRollup[] | if .__typename == "CheckRun" then (.conclusion == "FAILURE" or .conclusion == "TIMED_OUT" or .conclusion == "CANCELLED" or .conclusion == "ACTION_REQUIRED" or .conclusion == "STARTUP_FAILURE" or .conclusion == "STALE") else (.state == "FAILURE" or .state == "ERROR") end] | any)
] | @tsv'
cd "$REPO" 2>/dev/null || { note 'ERROR: репозиторий недоступен; действия отменены.'; finish error; exit 1; }
# PR discovery precedes dispatch/merge; local janitor recovery is independent of GitHub.
if ! timeout -k 5 45 gh pr list --state open --limit 1000 --json number,headRefName,mergeable,mergeStateStatus,statusCheckRollup,updatedAt --jq "$JQ" > "$WORK/prs" 2>/dev/null; then
  note 'ERROR: GitHub недоступен (gh завершился с ошибкой или timeout); никаких действий.'
  health; finish github_error; exit 1
fi
VALID=1; PR_COUNT=0
while IFS=$'\t' read -r pr branch mergeable merge_state updated checks complete green red extra; do
  [[ -n "$pr" ]] || continue
  PR_COUNT=$((PR_COUNT+1))
  if [[ ! "$pr" =~ ^[1-9][0-9]*$ || -z "$branch" || ! "$checks" =~ ^[0-9]+$ || ! "$complete" =~ ^(true|false)$ || ! "$green" =~ ^(true|false)$ || ! "$red" =~ ^(true|false)$ || -n "$extra" ]]; then VALID=0; fi
done < "$WORK/prs"
if (( !VALID || PR_COUNT >= 1000 )); then
  note 'ERROR: неполный или некорректный ответ gh; действия отменены.'
  health; finish github_error; exit 1
fi
watchdog_update
if ! CODEX=$(ps -W 2>/dev/null | awk '/[Pp]rograms[/\\]codex[/\\]bin[/\\]codex(\.exe)?$/ {n++} END {print n+0}'); then
  note 'ERROR: число процессов Codex неизвестно; действия отменены.'
  health; finish process_error; exit 1
fi
# CIM supplies command lines for external Windows/Git Bash fix processes.
if ! timeout -k 5 25 powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(cygpath -w "$ROOT/processes.ps1")" -Mode inventory -CiScript "$(cygpath -w "$CI_SCRIPT")" -ConflictScript "$(cygpath -w "$CONFLICT_SCRIPT")" > "$WORK/processes" 2>/dev/null; then
  note 'ERROR: список Windows-процессов недоступен; действия отменены.'
  health; finish process_error; exit 1
fi
sed -i 's/\r$//' "$WORK/processes"
declare -A ATTEMPTS=() JOBS=() OPEN=() NAMES=() ACTIVE_PR=()
if [[ -f "$HOME_DIR/attempts.tsv" ]]; then
  while IFS=$'\t' read -r pr count; do
    [[ "$pr" =~ ^[1-9][0-9]*$ && "$count" =~ ^[0-9]+$ ]] || { note 'ERROR: повреждён attempts.tsv; действия отменены.'; health; finish state_error; exit 1; }
    ATTEMPTS[$pr]=$count
  done < "$HOME_DIR/attempts.tsv"
fi
RESERVED=0
if [[ -f "$HOME_DIR/state.tsv" ]]; then
  while IFS=$'\t' read -r key name kind pid winpid ticks started token; do
    [[ -n "$key" ]] || continue
    if [[ ! "$pid" =~ ^[1-9][0-9]*$ || ! "$winpid" =~ ^[1-9][0-9]*$ || ! "$ticks" =~ ^[0-9]+$ || ! "$started" =~ ^[0-9]+$ || ! "$token" =~ ^[a-zA-Z0-9_-]+$ || ! "$name" =~ ^[a-zA-Z0-9_-]+$ || ! "$kind" =~ ^(ci_fix|conflict_fix|queue)$ ]]; then
      note 'ERROR: повреждён state.tsv; действия отменены.'; health; finish state_error; exit 1
    fi
    JOBS[$key]="$key"$'\t'"$name"$'\t'"$kind"$'\t'"$pid"$'\t'"$winpid"$'\t'"$ticks"$'\t'"$started"$'\t'"$token"
  done < "$HOME_DIR/state.tsv"
fi
save_jobs() {
  local key
  : > "$WORK/state"
  for key in "${!JOBS[@]}"; do printf '%s\n' "${JOBS[$key]}" >> "$WORK/state"; done
  mv -f -- "$WORK/state" "$HOME_DIR/state.tsv"
}
save_attempts() {
  # Bash loop variables are global unless local: never overwrite the PR being handled.
  local pr
  : > "$WORK/attempts"
  for pr in "${!ATTEMPTS[@]}"; do printf '%s\t%s\n' "$pr" "${ATTEMPTS[$pr]}" >> "$WORK/attempts"; done
  mv -f -- "$WORK/attempts" "$HOME_DIR/attempts.tsv"
}
for key in "${!JOBS[@]}"; do
  IFS=$'\t' read -r _ name kind pid winpid ticks started token <<< "${JOBS[$key]}"
  jobdir="$HOME_DIR/jobs/$token"
  if [[ -f "$jobdir/result" ]]; then
    result=$(cat "$jobdir/result")
    if [[ "$result" == ok ]]; then note "Работа $key ($kind) завершена."; else note "нужен человек: работа $key ($kind) завершилась ошибкой; см. logs/$token.log."; fi
    if (( !DRY )); then unset 'JOBS[$key]'; fi
  elif (( NOW-started > 7200 )); then
    if (( DRY )); then
      note "DRY-RUN: работа $key ($kind) старше 2 часов; завершить дерево PID $winpid."
    elif timeout -k 5 25 powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(cygpath -w "$ROOT/processes.ps1")" -Mode kill -WinPid "$winpid" -StartTicks "$ticks" >/dev/null 2>&1; then
      note "Работа $key ($kind) старше 2 часов: дерево завершено/уже отсутствует; разрешён повтор."
      unset 'JOBS[$key]'; save_jobs
    else note "нужен человек: не удалось завершить дерево работы $key; повтор заблокирован."; fi
  elif ! kill -0 "$pid" 2>/dev/null; then
    note "нужен человек: работа $key ($kind) исчезла без результата; разрешён повтор."
    if (( !DRY )); then unset 'JOBS[$key]'; fi
  fi
  [[ ! -v JOBS[$key] ]] || RESERVED=$((RESERVED+1))
done
(( DRY )) || { [[ ! -f "$HOME_DIR/state.tsv" ]] || save_jobs; }
# Apply the same verified-identity timeout to pre-existing external repairs.
: > "$WORK/processes.live"
while IFS=$'\t' read -r kind pr winpid ticks started; do
  [[ -n "$kind" ]] || continue
  if [[ "$started" =~ ^[0-9]+$ && "$winpid" =~ ^[1-9][0-9]*$ && "$ticks" =~ ^[0-9]+$ ]] && (( NOW-started > 7200 )); then
    if (( DRY )); then note "DRY-RUN: внешняя работа #$pr ($kind) старше 2 часов; завершить дерево PID $winpid."
    elif timeout -k 5 25 powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(cygpath -w "$ROOT/processes.ps1")" -Mode repair-kill -CiScript "$(cygpath -w "$CI_SCRIPT")" -ConflictScript "$(cygpath -w "$CONFLICT_SCRIPT")" -WinPid "$winpid" -StartTicks "$ticks" >/dev/null 2>&1; then
      note "внешняя работа #$pr ($kind) старше 2 часов: дерево завершено/отсутствует; разрешён повтор."
      continue
    else note "нужен человек: не удалось завершить внешнюю работу #$pr ($kind); повтор заблокирован."; fi
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$pr" "$winpid" "$ticks" "$started" >> "$WORK/processes.live"
done < "$WORK/processes"
mv -f "$WORK/processes.live" "$WORK/processes"
for key in "${!JOBS[@]}"; do
  IFS=$'\t' read -r _ name kind pid winpid ticks started token <<< "${JOBS[$key]}"
  if [[ "$kind" == queue && -f "$HOME_DIR/jobs/$token/pr" ]]; then
    auto_pr=$(cat "$HOME_DIR/jobs/$token/pr")
    [[ ! "$auto_pr" =~ ^[1-9][0-9]*$ ]] || ACTIVE_PR[$auto_pr]=1
  fi
done
active_fix() { awk -F '\t' -v pr="$1" '$2==pr && ($1=="ci_fix" || $1=="conflict_fix") {found=1} END {exit !found}' "$WORK/processes"; }
start_job() {
  local kind=$1 key=$2 name=$3 input=${4:-} token pid winpid identity ticks jobdir
  token="$NOW-$$-$RANDOM"; jobdir="$HOME_DIR/jobs/$token"
  mkdir -p "$jobdir" || return 1
  # Persist the dispatch identity even when the external script produces no output.
  printf '%s\t%s\t%s\n' "$key" "$name" "$kind" > "$jobdir/identity.tsv" || return 1
  if [[ -n "$input" ]]; then printf '%s\n' "$input" > "$jobdir/queue.txt" || return 1; fi
  export WATCHDOG_HOME="$HOME_DIR" WATCHDOG_REPO="$REPO" WATCHDOG_QUEUE_SCRIPT="$QUEUE_SCRIPT" WATCHDOG_CI_SCRIPT="$CI_SCRIPT" WATCHDOG_CONFLICT_SCRIPT="$CONFLICT_SCRIPT" WATCHDOG_AUTO_SCRIPT="$AUTO_SCRIPT"
  printf 'dispatch: key=%s name=%s kind=%s\n' "$key" "$name" "$kind" > "$HOME_DIR/logs/$token.log" || return 1
  nohup bash "$ROOT/worker.sh" "$kind" "$key" "$name" "$jobdir" >> "$HOME_DIR/logs/$token.log" 2>&1 < /dev/null &
  pid=$!
  winpid=$(ps -p "$pid" 2>/dev/null | awk -v pid="$pid" '$1 == pid {print $4}')
  if [[ "$winpid" =~ ^[1-9][0-9]*$ ]]; then
    identity=$(timeout -k 5 15 powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(cygpath -w "$ROOT/processes.ps1")" -Mode identity -WinPid "$winpid" 2>/dev/null | tr -d '\r') || identity=''
  else identity=''; fi
  read -r winpid ticks <<< "$identity"
  if [[ ! "$winpid" =~ ^[1-9][0-9]*$ || ! "$ticks" =~ ^[0-9]+$ ]]; then
    kill "$pid" 2>/dev/null || true; note "ERROR: не получена идентичность фоновой работы $key; запуск отменён."; return 1
  fi
  JOBS[$key]="$key"$'\t'"$name"$'\t'"$kind"$'\t'"$pid"$'\t'"$winpid"$'\t'"$ticks"$'\t'"$NOW"$'\t'"$token"
  save_jobs || return 1
  LAST_JOB_DIR="$jobdir"
  RESERVED=$((RESERVED+1))
}
note ''; note '| PR | Ветка | CI / слияние | Действие |'; note '| --- | --- | --- | --- |'
while IFS=$'\t' read -r pr branch mergeable merge_state updated checks complete green red _; do
  [[ -n "$pr" ]] || continue
  OPEN[$pr]=1
  name=${branch#consolidation/codex-}; NAMES[$name]=1
  action='наблюдение'
  count=${ATTEMPTS[$pr]:-0}
  if [[ -v JOBS[$pr] || -v ACTIVE_PR[$pr] ]] || { [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] && [[ -v JOBS[queue:$name] ]]; } || active_fix "$pr"; then action='исправление/auto_merge уже выполняется'
  elif [[ "$mergeable" == MERGEABLE && "$merge_state" == CLEAN && "$complete" == true && "$green" == true ]] && (( checks > 0 )); then
    if (( DRY )); then action='DRY-RUN: gh pr merge --merge'
    elif { timeout -k 5 30 gh pr ready "$pr" >/dev/null 2>&1 || true; timeout -k 5 45 gh pr merge "$pr" --merge >/dev/null 2>&1; }; then action='слит: gh pr merge --merge'
    else action='ERROR: gh pr merge не выполнен'; fi
  elif [[ "$mergeable" == CONFLICTING || ( "$complete" == true && "$red" == true ) ]]; then
    if (( count >= 3 )); then action='нужен человек: исчерпаны 3 исправления'
    elif [[ "$branch" != consolidation/codex-* || ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then action='нужен человек: ветка не поддерживается скриптами исправления'
    else
      kind=ci_fix; script="$CI_SCRIPT"
      if [[ "$mergeable" == CONFLICTING ]]; then kind=conflict_fix; script="$CONFLICT_SCRIPT"; fi
      if (( DRY )); then action="DRY-RUN: $kind, попытка $((count+1))/3"
      elif (( CODEX+RESERVED >= 4 )); then action="$kind ожидает свободный слот"
      elif [[ ! -f "$script" ]]; then action="нужен человек: отсутствует $kind.sh"
      else
        ATTEMPTS[$pr]=$((count+1)); save_attempts || exit 1
        if start_job "$kind" "$pr" "$name"; then
          touch "$LAST_JOB_DIR/start"; action="запущен $kind, попытка $((count+1))/3"
        else action="ERROR: $kind не запущен, попытка учтена"; fi
      fi
    fi
  elif [[ "$complete" == false ]]; then action='CI ещё выполняется'
  elif (( checks == 0 )); then action='ожидание: нет проверок CI'
  elif [[ "$mergeable" == UNKNOWN ]]; then action='GitHub ещё вычисляет mergeable'
  fi
  # Branches are JSON data, never executed. Escape table separators/backticks.
  display=${branch//|/\\|}; display=${display//\`/}
  note "| #$pr | $display | $checks проверок; $mergeable/$merge_state; обновлён $updated | $action |"
done < "$WORK/prs"
(( PR_COUNT )) || note 'Открытых PR нет.'
note ''
if [[ -s "$HOME_DIR/queue.txt" ]]; then
  line=''; index=0
  while IFS= read -r candidate || [[ -n "$candidate" ]]; do
    index=$((index+1)); candidate=${candidate%$'\r'}
    [[ -n "$candidate" ]] || continue
    line=$candidate; break
  done < "$HOME_DIR/queue.txt"
  if [[ -n "$line" ]]; then
    IFS='|' read -r name title extra tf rest <<< "$line"
    pipes=${line//[^|]/}
    if [[ ${#pipes} != 3 || ! "$name" =~ ^[a-zA-Z0-9_-]+$ || -z "$title" || -n "$extra" || -z "$tf" || "$tf" == /* || "$tf" == *:* || "$tf" == *\\* || "$tf" == '..' || "$tf" == ../* || "$tf" == */../* || "$tf" == */.. ]]; then
      note 'нужен человек: первая непустая строка queue.txt некорректна; очередь сохранена.'
    elif [[ -v NAMES[$name] || -v JOBS[queue:$name] ]]; then note "Очередь: $name уже имеет PR/фоновую работу; строка сохранена."
    elif (( CODEX+RESERVED >= 4 )); then note "Очередь: $name ожидает слот."
    elif [[ ! -f "$QUEUE_SCRIPT" || ! -f "$AUTO_SCRIPT" || ! -f "$QUEUE_DIR/$tf" ]]; then
      note "нужен человек: для очереди $name отсутствует скрипт или файл задания; строка сохранена."
    elif (( DRY )); then note "DRY-RUN: снять первую строку ($name), запустить q_main_v3, затем auto_merge созданного PR."
    elif start_job queue "queue:$name" "$name" "$line"; then
      tail -n "+$((index+1))" "$HOME_DIR/queue.txt" > "$WORK/queue"
      if mv -f -- "$WORK/queue" "$HOME_DIR/queue.txt"; then
        touch "$LAST_JOB_DIR/start"; note "Очередь: запущен $name; после успеха — auto_merge созданного PR."
      else note "ERROR: не удалось снять строку $name; worker не разрешён."; fi
    fi
  else note 'Очередь пуста.'; fi
else note 'Очередь пуста.'; fi
note "Слоты: Codex $CODEX/4; резерв фоновых работ $RESERVED; свободно $(( CODEX+RESERVED < 4 ? 4-CODEX-RESERVED : 0 ))."
note ''; health
finish ok
