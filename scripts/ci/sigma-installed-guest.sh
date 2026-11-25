#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

input=/mnt/p1-input
database_uuid=$1
backup_root=$2
initial_log=$3
initial_trace=$4
read -r commit tar_hash <"$input/candidate.pin"
[[ "$commit" == 63d35eb8df2912ae1c27a93ed478f81575a3ae2a && "$tar_hash" =~ ^[0-9a-f]{64}$ ]]
grep -qxF 'ID=debian' /etc/os-release
grep -qxE 'VERSION_ID="?13"?' /etc/os-release
printf '%s  %s\n' "$tar_hash" "$input/candidate.tar.gz" | sha256sum --check --strict
release="beta1-${commit:0:12]"
candidate=$(mktemp -d /var/tmp/sigma-kit.XXXXXXXX)
tar -xzf "$input/candidate.tar.gz" -C "$candidate"
printf 'P1_EVIDENCE sigma_stage=stock_install git=%s tar_sha256=%s\n' "$commit" "$tar_hash"
(
    exec 9>"$initial_trace"
    BASH_XTRACEFD=9 bash -x "$candidate/sli-debian-beta-kit/install-beta-kit" \
        --server 127.0.0.1 --bind 127.0.0.1 --port 443 \
        --uuid "$database_uuid" --backup-root "$backup_root" --non-interactive
) >>"$initial_log" 2>&1
mountpoint -q /var/backups/sli
[[ "$backup_root" -ef /var/backups/sli ]]
for unit in sli-dotnet-api.service sli-dotnet-semantic.service sli-postgresql.service; do
    systemctl is-active --quiet "$unit"
done
[[ -z $(dpkg --audit) ]]
python3 -I -B - "$commit" "$release" "$candidate/sli-debian-beta-kit/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

commit, release, manifest = sys.argv[1:]
root = Path("/opt/sli/current").resolve(strict=True)
assert root == Path("/opt/sli/releases") / release
inventory = json.loads((root / "native-runtime.json").read_text())
package = json.loads((root / "native-package.json").read_text())
assert inventory["provenance"]["source_commit"] == commit
assert package["release"] == release
assert package["version"] == json.loads(Path(manifest).read_text())["version"]
site = json.loads(Path("/etc/sli/runtime.json").read_text())
assert site["health_url"] == "https://127.0.0.1/api/health/ready" or site["health_url"] == "https://127.0.0.1:443/api/health/ready"
print("P1_EVIDENCE sigma_package=" + json.dumps(package, sort_keys=True))
PY
curl -q --proto '=https' --noproxy '*' --fail --silent --show-error --max-time 15 \
    --cacert /var/lib/sli/tls-ca.crt https://127.0.0.1/api/health/ready |
    python3 -I -B -c 'import json,sys; assert json.load(sys.stdin)["ready"] is True'
printf 'P1_EVIDENCE sigma_readiness=ready\n'

sql=(runuser -u postgres -- /usr/lib/postgresql/18/bin/psql -XqAtw \
    -h /var/run/postgresql -p 5432 -d sli -v ON_ERROR_STOP=1)
ledger=$("${sql[@]]" -c "select string_agg(version || '/' || name, ',' order by version) from public.schema_migrations where version>=412")
[[ "$ledger" == '412/sigma_history_test,413/workstation_journal_admission' ]]
printf 'P1_EVIDENCE sigma_ledger=%s\n' "$ledger"
[[ $("${sql[@]]" -c 'select count(*) from public.sli_agents') == 0 ]]

fixture=$(mktemp -d /var/tmp/sigma-proof.XXXXXXXX)
chown postgres:postgres "$fixture"
install -o postgres -g postgres -m 0400 /etc/sli/secrets/storage_password "$fixture/storage.password"
install -o postgres -g postgres -m 0400 /etc/sli/secrets/semantic_password "$fixture/semantic.password"
cp -R "$input/sigma-dotnet" "$input/sigma-tests" "$fixture/"
chown -R postgres:postgres "$fixture"
runtime="$fixture/sigma-dotnet"
printf 'P1_EVIDENCE sigma_stage=seed_retained_events\n'
if ! runuser -u postgres -- env HOME="$fixture" DOTNET_CLI_HOME="$fixture" DOTNET_ROOT="$runtime" \
    DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 SIGMA_PROOF_ROOT="$fixture" \
    "$runtime/dotnet" "$fixture/sigma-tests/Sli.Server.Tests.dll" \
    -class Sli.Server.Tests.Semantic.InstalledSigmaGuestFixture -failSkips -noColor \
    -result-xml "$fixture/seed.xml" >"$fixture/seed.log" 2>&1; then
    python3 -I -B - "$fixture/seed.log" <<'PY'
import re
import sys
from pathlib import Path

log = Path(sys.argv[1]).read_text(errors="replace")
for line in log.splitlines():
    if any(marker in line for marker in ("Failed Sli.Server.Tests.Semantic.InstalledSigmaGuestFixture", "PostgresException", "NpgsqlException", "Assertion", "Assert.", "framework", "No test matches", "Total:")):
        print("P1_EVIDENCE sigma_fixture_detail=" + re.sub(r"[^a-zA-Z0-9_. :(),/='\[\]<>-]", "?", line)[:220])
PY
    exit 1
fi
python3 -I -B - "$fixture/seed.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET

tests = list(ET.parse(sys.argv[1]).getroot().iter("test"))
assert len(tests) == 1 and tests[0].get("result") == "Pass"
assert tests[0].get("method") == "SeedRetainedEventFixture"
PY
readback=$("${sql[@]]" -c "
  select count(*) filter (where event_id between 900010 and 900032)::text || '/' ||
    count(*) filter (where event_id=900040)::text
  from public.event_hot where source_sha256 is not null")
[[ "$readback" == '9/1' ]]
printf 'P1_EVIDENCE sigma_retained allowed=9 denied=1\n'

snapshot() {
    "${sql[@]]" -c "select jsonb_build_object('matches',(select count(*) from public.semantic_detection_matches),'findings',(select count(*) from public.findings))"
}
before=$(snapshot)
binary="/opt/sli/dotnet/$release/Sli.Server"
[[ -x "$binary" ]]
printf 'P1_EVIDENCE sigma_stage=installed_cli executable=%s\n' "$binary"
test_cli() {
    runuser -u postgres -- env -i PATH=/usr/bin:/bin HOME="$fixture" \
        ADLOG_SIGMA_TEST_DSN='host=127.0.0.1 port=5432 dbname=sli user=sli_semantic_login' \
        ADLOG_SIGMA_TEST_PASSWORD_FILE="$fixture/semantic.password" \
        "$binary" sigma-history-test --plan "$fixture/$1.json" --rule "$fixture/$2.yml" --page-rows 1
}
for kind in 4698 4702 7045; do
    if ! test_cli "allowed-$kind" "$kind" >"$fixture/response.json" 2>"$fixture/cli.err"; then
        python3 -I -B -c 'import json,sys; v=json.load(sys.stdin); print("P1_EVIDENCE sigma_cli_failure=" + json.dumps({k:v.get(k) for k in ("status","reason")}))' <"$fixture/response.json"
        exit 1
    fi
    python3 -I -B - "$kind" "$fixture/response.json" <<'PY'
import json
import sys
from pathlib import Path

kind, path = sys.argv[1:]
reply = json.loads(Path(path).read_text())
assert (reply["mode"], reply["coverage"], reply["status"]) == ("test", "event_hot_only", "completed")
rows = reply["result"]["counts"]
assert len(rows) == 1
row = rows[0]
expected = dict(scanned=3, evaluable=2, matched=1, unknown=1, rejected=0, skipped=0)
actual = {key: row[key] for key in expected}
print("P1_EVIDENCE sigma_result=" + json.dumps(dict(event_id=int(kind), **actual), sort_keys=True))
assert actual == expected
assert dict(row["reasons"])["field_missing"] == 1
assert len(reply["result"]["samples"]) == 1
assert "sigma-qa-only" not in json.dumps(reply)
PY
done
for plan in denied-4698 mixed-4698; do
    code=0
    test_cli "$plan" 4698 >"$fixture/response.json" 2>"$fixture/cli.err" || code=$?
    [[ "$code" == 1 ]]
    python3 -I -B - "$plan" "$fixture/response.json" <<'PY'
import json
import sys
from pathlib import Path

plan, path = sys.argv[1:]
reply = json.loads(Path(path).read_text())
assert reply == dict(mode="test", coverage="event_hot_only", status="failed", reason="permission_denied")
print("P1_EVIDENCE sigma_acl=" + json.dumps(dict(plan=plan, status=reply["status"], reason=reply["reason"])))
PY
done
after=$(snapshot)
[[ "$before" == "$after" ]]
printf 'P1_EVIDENCE sigma_publication_before=%s after=%s\n' "$before" "$after"
