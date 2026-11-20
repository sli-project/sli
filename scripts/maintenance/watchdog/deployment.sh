#!/usr/bin/env bash
# Sourced by watchdog; deployed checkout is independent of the development queue.
UPDATE_SCRIPT=${WATCHDOG_UPDATE_SCRIPT:-/d/SLI_docker/update/update.sh}
UPDATE_HOME=${WATCHDOG_UPDATE_HOME:-$(dirname "$UPDATE_SCRIPT")}
UPDATE_REPO=${WATCHDOG_UPDATE_REPO:-/d/SLI_docker/sli}
STAND_CONFIG=${WATCHDOG_STAND_CONFIG:-$UPDATE_HOME/stand-config.json}
# The daily task runs at 03:00; periodic watchdog polls can retry until 03:29.
# Only the first poll in the window
# (PC local time) may claim today's update. Failed attempts wait for tomorrow.
watchdog_stand_window() {
  local today start
  local now=${NOW:-$(date +%s)}
  today=$(date -d "@$now" +%F)
  start=$(date -d "$today 03:00:00" +%s)
  STAND_DAY=$today
  STAND_WINDOW=0
  if (( now >= start && now < start + 1800 )) && [[ ! -d "$UPDATE_HOME/stand-windows/$today" ]]; then
    STAND_WINDOW=1
  fi
  if (( now >= start + 1800 )) || [[ -d "$UPDATE_HOME/stand-windows/$today" ]]; then
    start=$(date -d "$today +1 day 03:00:00" +%s)
  fi
  note "Следующее окно обновления стенда: $(date -d "@$start" '+%Y-%m-%d %H:%M %z') (время ПК)."
}
watchdog_stand_update() {
  local available
  watchdog_stand_window
  if (( DRY )); then
    note "DRY-RUN: Обновление SLI на стенде: main проверяется без остановки служб; окно 03:00, разрешён запуск: $STAND_WINDOW; ручной запуск: deployment.sh --stand-now."
    return
  fi
  available=$("$PYTHON" -X utf8 "$(cygpath -w "$UPDATE_HOME/stand_update.py")" --config "$(cygpath -w "$STAND_CONFIG")" --check-only) || {
    note 'Обновление стенда: проверка версии недоступна; службы не изменены.'; return 0;
  }
  available=${available%$'\r'}
  printf 'Проверка версии стенда: %s; %s.\n' "$(date -d "@$NOW" '+%Y-%m-%d %H:%M %z')" "$available" > "$UPDATE_HOME/.CHECK-STAND.${BASHPID:-$$}" &&
    mv -f "$UPDATE_HOME/.CHECK-STAND.${BASHPID:-$$}" "$UPDATE_HOME/CHECK-STAND.md"
  case "$available" in
    current) note 'Стенд соответствует main.'; return 0;;
    update_available) note 'Доступна новая версия стенда.';;
    *) note 'Обновление стенда: неизвестный результат проверки; запуск отменён.'; return 0;;
  esac
  if [[ ${SLI_STAND_NOW:-0} != 1 ]]; then
    (( STAND_WINDOW )) || { note 'Ожидание ночного окна; службы не изменены.'; return 0; }
    mkdir -p "$UPDATE_HOME/stand-windows" || return
    mkdir "$UPDATE_HOME/stand-windows/$STAND_DAY" 2>/dev/null || return 0
  fi
  mkdir -p "$UPDATE_HOME/logs" || return
  SLI_UPDATE_TARGET=stand SLI_STAND_CONFIG="$STAND_CONFIG" \
    nohup bash "$UPDATE_SCRIPT" >> "$UPDATE_HOME/logs/stand-dispatch.log" 2>&1 < /dev/null &
  note 'Обновление SLI на стенде: проверка запущена; окно 03:00, один запуск в сутки и защита от параллельных запусков.'
}
watchdog_update_status() {
  if [[ -f "$STAND_CONFIG" ]]; then
    watchdog_stand_window
    if [[ -f "$UPDATE_HOME/CHECK-STAND.md" ]]; then
      while IFS= read -r line; do note "$line"; done < "$UPDATE_HOME/CHECK-STAND.md"
    fi
    if [[ -f "$UPDATE_HOME/LAST-STAND.md" ]]; then
      while IFS= read -r line; do note "$line"; done < <(sed -n -E '/^(Обновление SLI на стенде|Этап|Причина|Ready|Целевой коммит):/p' "$UPDATE_HOME/LAST-STAND.md")
    else note 'Обновление SLI на стенде: ожидает первой проверки.'; fi
    note "Полный результат: $UPDATE_HOME/LAST-STAND.md."
    return
  fi
  note ''; note 'Обновление рабочего SLI:'
  if [[ ! -f "$UPDATE_SCRIPT" || ! -f "$(dirname "$UPDATE_SCRIPT")/state.sh" ]]; then
    note 'Обновление: скрипт недоступен.'; return
  fi
  source "$(dirname "$UPDATE_SCRIPT")/state.sh"
  if update_lock_active "$UPDATE_HOME"; then note 'Обновление выполняется; повторный запуск заблокирован.'; fi
  if [[ -f "$UPDATE_HOME/LAST.md" ]]; then
    while IFS= read -r line; do note "$line"; done < <(sed -n -E '/^(Результат|Этап|Причина|Ready|Целевой коммит):/p' "$UPDATE_HOME/LAST.md")
    note "Полный результат: $UPDATE_HOME/LAST.md."
  fi
}
watchdog_update() {
  if [[ -f "$STAND_CONFIG" ]]; then watchdog_stand_update; return; fi
  [[ ! -f ${WATCHDOG_HOLD_FILE:-/d/SLI_docker/watchdog/MIGRATION_HOLD} ]] || { note 'Обновление SLI на ПК отключено (MIGRATION_HOLD).'; return; }
  local deployed remote fetched last=0 cooldown=0
  [[ -f "$UPDATE_SCRIPT" && -f "$(dirname "$UPDATE_SCRIPT")/state.sh" ]] || return 0
  deployed=$(update_deployed_commit "$UPDATE_HOME" "$UPDATE_REPO") || { note 'ALERT: версия развёрнутого SLI неизвестна; обновление отменено.'; return; }
  remote=$(timeout -k 5 45 git -C "$UPDATE_REPO" ls-remote origin refs/heads/main 2>/dev/null | cut -f1) || { note 'Обновление: origin/main недоступен.'; return; }
  [[ "$remote" =~ ^[0-9a-f]{40}$ ]] || { note 'Обновление: некорректный ответ origin/main.'; return; }
  note "Развёрнутый коммит: $deployed; origin/main: $remote."
  [[ "$remote" != "$deployed" ]] || { note 'Рабочий SLI соответствует origin/main.'; return; }
  if update_lock_active "$UPDATE_HOME"; then note 'origin/main отличается; ожидание текущего обновления.'; return; fi
  if [[ -f "$UPDATE_HOME/last-attempt" ]]; then
    read -r last < "$UPDATE_HOME/last-attempt"
    [[ "$last" =~ ^[0-9]+$ ]] || { note 'ALERT: повреждён интервал обновлений; запуск отменён.'; return; }
  fi
  cooldown=$((1800-(NOW-last)))
  if (( cooldown > 0 )); then note "Обновление ожидает интервал 30 минут: осталось $cooldown секунд."; return; fi
  if (( DRY )); then
    note 'DRY-RUN: fetch, подтвердить что origin/main новее развёрнутого; запустить update.sh в фоне (интервал 30 минут).'
    return
  fi
  timeout -k 5 90 git -C "$UPDATE_REPO" fetch --quiet origin main >/dev/null 2>&1 || { note 'Обновление: git fetch не выполнен.'; return; }
  fetched=$(git -C "$UPDATE_REPO" rev-parse origin/main 2>/dev/null) || return
  [[ "$fetched" != "$deployed" ]] || { note 'Рабочий SLI уже соответствует origin/main.'; return; }
  git -C "$UPDATE_REPO" merge-base --is-ancestor "$deployed" "$fetched" || { note 'ALERT: origin/main не является продолжением развёрнутого коммита; запуск отменён.'; return; }
  mkdir -p "$UPDATE_HOME/logs" || { note 'ERROR: каталог обновления недоступен.'; return; }
  printf '%s\n' "$NOW" > "$UPDATE_HOME/.attempt.$$" && mv -f "$UPDATE_HOME/.attempt.$$" "$UPDATE_HOME/last-attempt" || return
  SLI_UPDATE_HOME="$UPDATE_HOME" SLI_UPDATE_REPO="$UPDATE_REPO" \
    nohup bash "$UPDATE_SCRIPT" >> "$UPDATE_HOME/logs/watchdog-dispatch.log" 2>&1 < /dev/null &
  note "Запущен update.sh в фоне, PID $!; целевой коммит $fetched; результат в $UPDATE_HOME/LAST.md."
}

# Direct manual entry point; sourcing continues to use watchdog's context.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  DRY=0
  case "${1:---stand-window}" in --stand-now) export SLI_STAND_NOW=1;; --stand-window) :;; *) echo 'Usage: deployment.sh [--stand-window|--stand-now] [-n]' >&2; exit 2;; esac
  if [[ ${2:-} == -n && $# == 2 ]]; then DRY=1; elif [[ $# -gt 1 ]]; then exit 2; fi
  ROOT=$(cd "$(dirname "$0")" && pwd)
  HOME_DIR=${WATCHDOG_HOME:-$ROOT}
  PYTHON=${WATCHDOG_PYTHON:-$UPDATE_HOME/venv/Scripts/python.exe}
  NOW=$(date +%s)
  note() { printf '%s\n' "$*"; }
  [[ -f "$STAND_CONFIG" ]] || { note 'stand_config_missing'; exit 1; }
  watchdog_stand_update
fi
