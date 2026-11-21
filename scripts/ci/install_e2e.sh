#!/usr/bin/env bash
# Runs inside a disposable Debian 13 systemd container with verified beta kits.
set -euo pipefail
export LC_ALL=C

base=/kits/base/sli-debian-beta-kit
candidate=/kits/candidate/sli-debian-beta-kit

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

install_kit() {
    printf 'Installing kit from %s\n' "$1"
    # The archive installer also runs sli-setup without flags.
    bash "$1/install-beta-kit"
}

postgres_query() {
    runuser -u postgres -- /usr/lib/postgresql/18/bin/psql -XAtw \
        -h /var/run/postgresql -d sli -v ON_ERROR_STOP=1 -c "$1"
}

check_installation() {
    local kit=$1 health_url ready live failed
    health_url=$(python3 -c \
        'import json; print(json.load(open("/etc/sli/runtime.json"))["health_url"])')
    ready=$(curl --fail --silent --show-error --noproxy '*' --cacert /var/lib/sli/tls-ca.crt "$health_url")
    live=$(curl --fail --silent --show-error --noproxy '*' --cacert /var/lib/sli/tls-ca.crt "${health_url%/ready}/live")

    python3 - "$kit/manifest.json" "$ready" "$live" <<'PYTHON'
import json
import sys
from pathlib import Path

kit = json.loads(Path(sys.argv[1]).read_text())
ready = json.loads(sys.argv[2])
live = json.loads(sys.argv[3])
active = json.loads(Path('/opt/sli/current/native-package.json').read_text())
if ready.get('ready') is not True or ready.get('code') != 'ready':
    sys.exit(f'SLI did not report ready: {ready.get("code")}')
if live['runtime_identity']['git_commit'] != kit['git_commit']:
    sys.exit(f'Running API commit differs from kit {kit["git_commit"]}')
if (active['release'], active['version']) != (kit['release'], kit['version']):
    sys.exit(f'Active release {active["release"]} {active["version"]} differs from kit {kit["release"]} {kit["version"]}')
print(f'SLI ready on {active["release"]} {active["version"]}')
PYTHON

    failed=$(systemctl --failed --no-pager --no-legend)
    [[ -z $failed ]] || fail "Failed systemd units: $failed"
}

check_migration() {
    local expected actual
    expected=$(python3 -c 'import json; print(max(row["version"] for row in
        json.load(open("/opt/sli/current/native-runtime.json"))["migration_ledger"]))')
    actual=$(postgres_query 'SELECT max(version) FROM public.schema_migrations')
    [[ $actual == "$expected" ]] || fail "PostgreSQL migration is ${actual:-missing}, expected $expected"
    printf 'PostgreSQL migration %s applied\n' "$actual"
}

case ${1:-} in
    A)
        install_kit "$candidate"
        sli-setup
        check_installation "$candidate"
        ;;
    B)
        install_kit "$base"
        check_installation "$base"
        install_kit "$candidate"
        check_installation "$candidate"
        check_migration
        ;;
    C)
        install_kit "$candidate"
        check_installation "$candidate"
        previous_cluster=$(postgres_query 'SELECT system_identifier FROM pg_control_system()')
        python3 -I "$candidate/remove-beta-kit" --purge-data
        [[ ! -e /var/lib/sli/state/installed.json ]] || fail 'Purge left the installed registry in place'
        install_kit "$candidate"
        check_installation "$candidate"
        cluster=$(postgres_query 'SELECT system_identifier FROM pg_control_system()')
        [[ $cluster != "$previous_cluster" ]] || fail 'Reinstall reused the PostgreSQL cluster after purge'
        printf 'Purge and reinstall created a new PostgreSQL cluster\n'
        ;;
    diagnostics)
        # Export the coordinator's phases and result without backup or credential material.
        python3 - <<'PYTHON'
import json
from pathlib import Path

fields = ('status', 'step', 'previous', 'candidate', 'target_version', 'accepted_release',
          'failure_reason_code', 'reason_code', 'services_restored', 'package_reconciliation_required', 'events')
for transaction in sorted(Path('/var/lib/sli/transactions').glob('*')):
    for name in ('journal.json', 'result.json'):
        path = transaction / name
        if path.is_file():
            try:
                value = json.loads(path.read_text())
            except (OSError, ValueError) as error:
                print(f'{transaction.name}/{name}: {error}')
                continue
            print(f'{transaction.name}/{name}')
            print(json.dumps({field: value[field] for field in fields if field in value}, indent=2))
PYTHON
        ;;
    *) fail 'Usage: install_e2e.sh A|B|C|diagnostics' ;;
esac
