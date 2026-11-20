#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "$(id -u)" == 0 ]]; then
    printf '%s\n' 'Run the development container as dev (--user dev), not root; dependency volumes must remain owned by dev.' >&2
    exit 1
fi

repo=/workspace/sli-platform
venv=/opt/venv
if [[ ! -f "$repo/requirements.txt" || ! -f "$repo/package-lock.json" || ! -f "$repo/frontend/package-lock.json" ]]; then
    printf '%s\n' 'Mount the development clone at /workspace/sli-platform using SLI_DEV_SOURCE.' >&2
    exit 1
fi
cd "$repo"

if [[ ! -x "$venv/bin/python" ]]; then
    python -m venv "$venv"
fi
requirements_hash=$(sha256sum requirements.txt)
python_stamp=$venv/.sli-dev-requirements.sha256
if [[ ! -f "$python_stamp" ]] || [[ "$(cat "$python_stamp")" != "$requirements_hash" ]]; then
    "$venv/bin/python" -m pip install --disable-pip-version-check -r requirements.txt ruff==0.16.9
    printf '%s\n' "$requirements_hash" > "$python_stamp"
fi

install_node_dependencies() {
    local directory=$1
    local dependency_hash stamp
    (
        cd "$directory"
        dependency_hash=$(node --version; npm --version; sha256sum package.json package-lock.json)
        stamp=node_modules/.sli-dev-dependencies.sha256
        if [[ ! -f "$stamp" ]] || [[ "$(cat "$stamp")" != "$dependency_hash" ]]; then
            npm ci
            printf '%s\n' "$dependency_hash" > "$stamp"
        fi
    )
}
install_node_dependencies .
install_node_dependencies frontend

cat <<'NEXT_STEPS'
Development workspace ready: /workspace/sli-platform
Run Linux checks with: docker compose -p sli-dev exec dev bash -lc "cd /workspace/sli-platform && /opt/venv/bin/python -m ruff check tests/unit/test_dev_container.py"
Git, GitHub/PRs, Codex and Claude Code run on the Windows host with its existing auth.
See docs/OPERATIONS_RUNBOOK.md for targeted tests and disposable PostgreSQL setup.
NEXT_STEPS

if (( $# > 0 )); then
    exec "$@"
fi
