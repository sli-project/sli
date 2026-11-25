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
release="beta1-${commit:0:12}"
candidate=$(mktemp -d /var/tmp/s5-kit.XXXXXXXX)
tar -xzf "$input/candidate.tar.gz" -C "$candidate"
printf 'P1_EVIDENCE s5_stage=stock_install git=%s tar_sha256=%s\n' "$commit" "$tar_hash"
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
print("P1_EVIDENCE s5_package=" + json.dumps(package, sort_keys=True))
PY
curl -q --proto '=https' --noproxy '*' --fail --silent --show-error --max-time 15 \
    --cacert /var/lib/sli/tls-ca.crt https://127.0.0.1/api/health/ready |
    python3 -I -B -c 'import json,sys; assert json.load(sys.stdin)["ready"] is True'
printf 'P1_EVIDENCE s5_readiness=ready\n'

sql=(runuser -u postgres -- /usr/lib/postgresql/18/bin/psql -XqAtw \
    -h /var/run/postgresql -p 5432 -d sli -v ON_ERROR_STOP=1)
ledger=$("${sql[@]}" -c "select string_agg(version || '/' || name, ',' order by version) from public.schema_migrations where version in (342,412,413)")
[[ "$ledger" == '342/short_storage_retention,412/sigma_history_test,413/workstation_journal_admission' ]]
printf 'P1_EVIDENCE s5_ledger=%s\n' "$ledger"
[[ $("${sql[@]}" -c 'select count(*) from public.sli_agents') == 0 ]]
[[ $("${sql[@]}" -c 'select count(*) from public.event_hot') == 0 ]]

unit=sli-dotnet-storage-lifecycle.service
systemctl is-active --quiet "$unit"
systemctl stop "$unit"
fixture=$(mktemp -d /var/tmp/s5-proof.XXXXXXXX)
install -o postgres -g postgres -m 0400 /etc/sli/secrets/storage_password "$fixture/storage.password"
cp -R "$input/sigma-dotnet" "$input/sigma-tests" "$fixture/"
chown -R postgres:postgres "$fixture"
runtime="$fixture/sigma-dotnet"
printf 'P1_EVIDENCE s5_stage=seed_through_short_writer\n'
if ! runuser -u postgres -- env HOME="$fixture" DOTNET_CLI_HOME="$fixture" DOTNET_ROOT="$runtime" \
    DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 S5_PROOF_ROOT="$fixture" \
    "$runtime/dotnet" "$fixture/sigma-tests/Sli.Server.Tests.dll" \
    -class Sli.Server.Tests.Storage.InstalledStorageS5Fixture -failSkips -noColor \
    -result-xml "$fixture/seed.xml" >"$fixture/seed.log" 2>&1; then
    python3 -I -B - "$fixture/seed.log" <<'PY'
import re
import sys
from pathlib import Path

for line in Path(sys.argv[1]).read_text(errors="replace").splitlines():
    if any(marker in line.lower() for marker in ("installedstorages5fixture", "exception", "assert.", "[fail]", "expected:", "actual:", "detail:", "total:")):
        print("P1_EVIDENCE s5_fixture_detail=" + re.sub(r"[^a-zA-Z0-9_. :(),/='\[\]<>-]", "?", line)[:240])
PY
    exit 1
fi
python3 -I -B - "$fixture/seed.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET

tests = list(ET.parse(sys.argv[1]).getroot().iter("test"))
assert len(tests) == 1 and tests[0].get("result") == "Pass"
assert tests[0].get("method") == "WriteExpiredAndBoundaryEventsThroughShortStorage"
PY
read -r expired survivor domain < <(python3 -I -B - "$fixture/window.json" <<'PY'
from pathlib import Path
import json
import sys

w = json.loads(Path(sys.argv[1]).read_text())
print(w["expired_day"], w["survivor_day"], w["domain_id"])
PY
)
[[ "$expired" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ && "$survivor" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ && "$domain" =~ ^[0-9]+$ ]]

snapshot() {
    "${sql[@]}" -v proof_expired="$expired" -v proof_domain="$domain" <<'SQL'
BEGIN READ ONLY;
SET LOCAL timezone='UTC';
WITH hot_children AS (
    SELECT c.relname,c.oid,pg_get_expr(c.relpartbound,c.oid) AS bounds
    FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid
    WHERE i.inhparent='public.event_hot'::regclass
), hot_rows AS (
    SELECT event_id,tableoid::regclass::text AS physical_table
    FROM public.event_hot WHERE domain_id=:'proof_domain'::bigint
), cold_fact AS (
    SELECT tableoid::regclass::text AS physical_table, event_id, event_kind, fields,
        encode(sha256(convert_to(to_jsonb(f)::text,'UTF8')),'hex') AS sha256
    FROM public.event_cold_facts f WHERE event_id=900021 AND domain_id=:'proof_domain'::bigint
), cold_daily AS (
    SELECT tableoid::regclass::text AS physical_table, day,event_kind,event_count,first_seen_utc,last_seen_utc,actor,source,
        method->>'$server_id' AS recorder,
        encode(sha256(convert_to(to_jsonb(d)::text,'UTF8')),'hex') AS sha256
    FROM public.event_cold_daily d
    WHERE day=:'proof_expired'::date AND domain_id=:'proof_domain'::bigint AND event_kind=4624
)
SELECT jsonb_build_object(
    'expired_regclass',to_regclass('public.event_hot_d'||replace(:'proof_expired','-',''))::text,
    'hot_children',(SELECT jsonb_object_agg(relname,jsonb_build_object('oid',oid,'bounds',bounds)) FROM hot_children),
    'hot_rows',(SELECT jsonb_agg(to_jsonb(h) ORDER BY h.event_id) FROM hot_rows h),
    'cold_fact',(SELECT jsonb_agg(to_jsonb(f) ORDER BY f.event_id) FROM cold_fact f),
    'cold_daily',(SELECT jsonb_agg(to_jsonb(d) ORDER BY d.sha256) FROM cold_daily d),
    'users_snapshot',(SELECT encode(payload_sha256,'hex') FROM users_report_v2_snapshots WHERE domain_id=:'proof_domain'::bigint),
    'computers_snapshot',(SELECT encode(payload_sha256,'hex') FROM computers_v6_source_snapshots WHERE domain_id=:'proof_domain'::bigint)
);
COMMIT;
SQL
}

report() {
    python3 -I -B - "$fixture" "$1" <<'PY'
import http.cookiejar
import json
from pathlib import Path
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

root, phase = Path(sys.argv[1]), sys.argv[2]
base = "https://127.0.0.1"
jar = http.cookiejar.MozillaCookieJar(root / "report.cookies")
if phase == "after":
    jar.load(ignore_discard=True)
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile="/var/lib/sli/tls-ca.crt")),
    urllib.request.HTTPCookieProcessor(jar)
)

def request(path, payload=None):
    headers = {"Accept": "application/json", "Origin": base, "Accept-Language": "en"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, None if payload is None else json.dumps(payload).encode(), headers)
    try:
        with opener.open(req, timeout=30) as response:
            assert response.status == 200 and response.headers.get_content_type() == "application/json"
            return json.load(response)
    except urllib.error.HTTPError as failure:
        result = json.loads(failure.read())
        print("P1_EVIDENCE s5_http_error=" + json.dumps({"path": path.split("?")[0],
              "status": failure.code, "reason": result.get("error")}))
        raise SystemExit(1)

if phase == "before":
    login = request("/api/auth/login", dict(username="admin", password="admin", remember=False))
    if login.get("password_change_required"):
        password = secrets.token_urlsafe(30)
        request("/api/auth/change-initial-password", dict(password=password, repeat=password))
    principal = request("/api/auth/me")["principal"]
    assert principal["username"] == "admin" and principal["role"] == "admin"
    jar.save(ignore_discard=True)

window = json.loads((root / "window.json").read_text())
params = urllib.parse.urlencode(dict(period="custom", baseline_days=30,
                                    **{"from":window["from"], "to":window["to"]}))
data = request("/api/v2/reports/ad.new-logon-pairs/data?" + params)
if data.get("state") != "partial" or len(data.get("items",[])) != 1:
    print("P1_EVIDENCE s5_report_unexpected=" + json.dumps(dict(
        phase=phase, state=data.get("state"), rows=len(data.get("items",[])),
        limitations=[item.get("code") for item in data.get("limitations", [])])))
    raise SystemExit(1)
row = data["items"][0]
expected = {"computer":"PC-1", "user":"synthetic-user-0", "source_event_id":900031,
            "prior_user_logon":"yes", "novelty":"no_baseline", "count":1}
actual = {key:row.get(key) for key in expected}
print("P1_EVIDENCE s5_report_row=" + json.dumps(dict(phase=phase, **actual), sort_keys=True))
assert actual == expected and row["computer_entity_id"] > 0
(root / ("report-" + phase + ".json")).write_text(json.dumps(data, sort_keys=True, separators=(",",":")) + "\n")
PY
}

snapshot >"$fixture/before.json"
report before
printf 'P1_EVIDENCE s5_stage=installed_storage_lifecycle_once\n'
binary="/opt/sli/dotnet/$release/Sli.Server"
dropin="/run/systemd/system/$unit.d"
install -d -m 0755 "$dropin"
cat >"$dropin/s5-proof.conf" <<UNIT
[Service]
Type=oneshot
RemainAfterExit=yes
Restart=no
TimeoutStartSec=180
ExecStart=
ExecStart=$binary storage-lifecycle-worker --once
UNIT
systemctl daemon-reload
if ! systemctl start "$unit"; then
    journalctl -u "$unit" --no-pager -n 20 -o cat |
        grep -E '^[{].*("status"|"result").*[}]$' |
        sed 's/^/P1_EVIDENCE s5_cycle_diagnostic=/' || true
    exit 1
fi
invocation=$(systemctl show "$unit" -p InvocationID --value)
[[ "$invocation" =~ ^[0-9a-f]{32}$ ]]
journalctl "_SYSTEMD_INVOCATION_ID=$invocation" --no-pager -o cat >"$fixture/cycle.log"
snapshot >"$fixture/after.json"
report after

python3 -I -B - "$fixture" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
window = json.loads((root / "window.json").read_text())
expired = "event_hot_d" + window["expired_day"].replace("-", "")
survivor = "event_hot_d" + window["survivor_day"].replace("-", "")
start = json.loads((root / "before.json").read_text())
end = json.loads((root / "after.json").read_text())
cycles = []
for line in (root / "cycle.log").read_text().splitlines():
    if line.startswith("{"):
        item = json.loads(line)
        if item.get("contract") == "sli.storage-lifecycle-result.v1":
            cycles.append(item)
assert len(cycles) == 1
cycle = cycles[0]
print("P1_EVIDENCE s5_cycle=" + json.dumps({k:cycle.get(k) for k in
      ("status","phase","inbox_only","partitions","reason","warning_reason")}, sort_keys=True))
assert (cycle["status"],cycle["phase"],cycle["inbox_only"]) == ("ok","completed",False)
assert cycle.get("warning_reason") is None
assert cycle["partitions"] == dict(hot_partitions=1, cold_partitions=0, snapshot_partitions=0)
assert expired in start["hot_children"] and survivor in start["hot_children"]
assert start["expired_regclass"] == expired and end["expired_regclass"] is None
assert {key:value for key,value in start["hot_children"].items() if key != expired} == end["hot_children"]
assert [r["event_id"] for r in start["hot_rows"] if r["physical_table"] == expired] == [900020,900021]
assert [r["event_id"] for r in start["hot_rows"] if r["physical_table"] == survivor] == [900030,900031]
assert [r["event_id"] for r in end["hot_rows"]] == [900030,900031]
assert all(r["physical_table"] == survivor for r in end["hot_rows"])
print("P1_EVIDENCE s5_hot=" + json.dumps(dict(
    removed=expired, removed_oid=start["hot_children"][expired]["oid"],
    removed_bounds=start["hot_children"][expired]["bounds"],
    survivor=survivor, survivor_oid=end["hot_children"][survivor]["oid"],
    expired_rows_before=2, expired_rows_after=0, survivor_rows=2), sort_keys=True))
assert start["cold_fact"] == end["cold_fact"] and len(end["cold_fact"]) == 1
fact = end["cold_fact"][0]
assert fact["physical_table"].startswith("event_cold_facts_m") and fact["event_kind"] == 4720
assert fact["fields"]["SamAccountName"] == "synthetic-user-0"
assert start["cold_daily"] == end["cold_daily"] and len(end["cold_daily"]) == 1
daily = end["cold_daily"][0]
assert daily["physical_table"].startswith("event_cold_daily_m") and daily["event_kind"] == 4624
assert daily["event_count"] == 1 and daily["actor"].endswith("-10000") and daily["recorder"] == "930001"
assert daily["source"] == "192.0.2.1" and daily["first_seen_utc"] == daily["last_seen_utc"]
for key in ("users_snapshot", "computers_snapshot"):
    assert start[key] == end[key] and re.fullmatch(r"[0-9a-f]{64}",end[key])
print("P1_EVIDENCE s5_cold=" + json.dumps(dict(
    fact_event=4720, fact_partition=fact["physical_table"], fact_sha256=fact["sha256"],
    daily_event=4624, daily_partition=daily["physical_table"], daily_count=daily["event_count"],
    daily_sha256=daily["sha256"], users_snapshot=end["users_snapshot"],
    computers_snapshot=end["computers_snapshot"]), sort_keys=True))
before = (root / "report-before.json").read_bytes()
after = (root / "report-after.json").read_bytes()
assert before == after
print("P1_EVIDENCE s5_report_equal=true report_sha256=" + hashlib.sha256(after).hexdigest())
PY
