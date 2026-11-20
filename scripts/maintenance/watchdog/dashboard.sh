#!/usr/bin/env bash
# Optional publisher: failure must not change the watchdog's decisions or exit code.
watchdog_dashboard() {
  local python=${WATCHDOG_PYTHON:-$UPDATE_HOME/venv/Scripts/python.exe} commit deployed_pr
  [[ -f "$python" ]] || python=python
  # Network discovery is read-only and bounded. Never put authentication in output.
  if [[ ${NETWORK:-online} == online ]]; then
    timeout -k 5 30 gh pr list --state open --limit 1000 --json number,title,url > "$WORK/dashboard-prs.json" 2>/dev/null || rm -f "$WORK/dashboard-prs.json"
  fi
  commit=$(cat "$UPDATE_HOME/deployed.commit" 2>/dev/null) || commit=''
  if [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    timeout -k 5 10 git -C "$UPDATE_REPO" show -s --format=%s "$commit" 2>/dev/null | sed -nE 's/.*#([0-9]+).*/\1/p' > "$WORK/dashboard-deployed-pr"
    deployed_pr=$(cat "$WORK/dashboard-deployed-pr")
    if [[ "$deployed_pr" =~ ^[1-9][0-9]*$ && ${NETWORK:-online} == online ]]; then
      timeout -k 5 15 gh pr view "$deployed_pr" --json url --jq .url > "$WORK/dashboard-deployed-url" 2>/dev/null || rm -f "$WORK/dashboard-deployed-url"
    fi
  fi
  timeout -k 5 20 "$python" "$ROOT/dashboard_data.py" \
    --home "$HOME_DIR" --work "$WORK" --update "$UPDATE_HOME" \
    --reports "${WATCHDOG_REPORTS:-$ROOT/../night/REPORTS_NOW.md}" \
    --output "$HOME_DIR/dashboard/data.json" --now "$(date +%s)" --dry "$DRY" --result "$1" >/dev/null 2>&1 \
    || printf '%s\n' 'Dashboard publication failed; previous snapshot retained.' >&2
  return 0
}
