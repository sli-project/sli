#!/usr/bin/env bash
# Long-lived parent for taskkill /T. Does not detach grandchildren.
set -uo pipefail
kind=$1; key=$2; name=$3; jobdir=$4
result=failed
auto_lock_token=''
release_auto_lock() {
  if [[ -n "$auto_lock_token" && -f "$WATCHDOG_HOME/watchdog.lock" ]] && [[ $(cut -f3 "$WATCHDOG_HOME/watchdog.lock") == "$auto_lock_token" ]]; then
    rm -f -- "$WATCHDOG_HOME/watchdog.lock"
    rmdir "$WATCHDOG_HOME/watchdog.lock.guard" 2>/dev/null || true
  fi
  auto_lock_token=''
}
finish() {
  release_auto_lock
  printf '%s\n' "$result" > "$jobdir/result.tmp"
  mv -f "$jobdir/result.tmp" "$jobdir/result"
}
trap finish EXIT
trap 'exit 130' INT TERM HUP
# Parent records Windows identity and consumes queue before authorizing work.
for ((i=0;i<30;i++)); do [[ ! -f "$jobdir/start" ]] || break; sleep 1; done
[[ -f "$jobdir/start" ]] || exit 1
cd "$WATCHDOG_REPO" || exit 1
reserve_auto_attempt() {
  local pr=$1 acquired=0 count=0 tmp
  # Same atomic lock as the decision pass; never hold it while running auto_merge.
  for ((i=0;i<300;i++)); do
    if mkdir "$WATCHDOG_HOME/watchdog.lock.guard" 2>/dev/null; then acquired=1; break; fi
    sleep 2
  done
  (( acquired )) || { echo 'Cannot reserve auto_merge repair budget: watchdog lock busy.'; return 1; }
  auto_lock_token="auto-$(date +%s)-$$"
  printf '%s\t%s\t%s\n' "$$" "$(date +%s)" "$auto_lock_token" > "$WATCHDOG_HOME/watchdog.lock" || return 1
  if [[ -f "$WATCHDOG_HOME/attempts.tsv" ]]; then
    count=$(awk -F '\t' -v pr="$pr" '$1==pr {print $2}' "$WATCHDOG_HOME/attempts.tsv")
    count=${count:-0}
  fi
  [[ "$count" =~ ^[0-9]+$ && ${#count} -le 2 ]] || { echo 'Invalid repair budget.'; return 1; }
  if (( count >= 3 )); then
    echo "PR #$pr needs a human: repair budget exhausted; auto_merge not started."
    result=auto_budget_exhausted; return 1
  fi
  tmp="$WATCHDOG_HOME/.attempts-$auto_lock_token"
  if [[ -f "$WATCHDOG_HOME/attempts.tsv" ]]; then
    awk -F '\t' -v pr="$pr" '$1!=pr' "$WATCHDOG_HOME/attempts.tsv" > "$tmp" || return 1
  else : > "$tmp" || return 1; fi
  # Existing auto_merge can invoke ci_fix once. Reserve its maximum possible cost.
  printf '%s\t%s\n' "$pr" "$((count+1))" >> "$tmp" || return 1
  mv -f -- "$tmp" "$WATCHDOG_HOME/attempts.tsv" || return 1
  printf '%s\n' "$pr" > "$jobdir/pr.tmp" && mv -f "$jobdir/pr.tmp" "$jobdir/pr" || return 1
  release_auto_lock
}
case "$kind" in
  ci_fix) bash "$WATCHDOG_CI_SCRIPT" "$key" "$name" || exit 1;;
  conflict_fix) bash "$WATCHDOG_CONFLICT_SCRIPT" "$key" "$name" || exit 1;;
  queue)
    MAX=4 bash "$WATCHDOG_QUEUE_SCRIPT" "$jobdir/queue.txt" > "$jobdir/queue.log" 2>&1 || exit 1
    # q_main's final wait does not propagate the task exit status.
    grep -Eq "(^| )$name rc=0$" "$jobdir/queue.log" || exit 1
    branch="consolidation/codex-$name"
    pr=''
    # Allow a short delay for PR discovery; auto_merge remains existing behavior.
    for ((i=0;i<6;i++)); do
      pr=$(timeout -k 5 45 gh pr list --state open --head "$branch" --limit 2 --json number --jq 'if length == 1 then .[0].number else empty end' 2>/dev/null) || pr=''
      [[ ! "$pr" =~ ^[1-9][0-9]*$ ]] || break
      sleep 10
    done
    [[ "$pr" =~ ^[1-9][0-9]*$ ]] || exit 1
    reserve_auto_attempt "$pr" || exit 1
    bash "$WATCHDOG_AUTO_SCRIPT" "$pr:$name" || exit 1
    ;;
  *) exit 2;;
esac
result=ok
