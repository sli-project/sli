#!/usr/bin/env bash
# Run as root INSIDE one disposable, isolated Debian 13 amd64 guest with systemd.
# Project-runner preparation:
# Stage artifacts in a project Linux shell job and hand them to the guest.
# The Debian beta-kit build container is for producing the kits, not for this test.
# 1. Download both verified beta-kit artifacts outside the guest. Use a throwaway
#    guest with a separate volume at /var/backups/sli and configured Debian APT
#    sources. Isolate it from production, LAB and operator hosts; allow only the
#    package mirror/runner access needed by this guest.
# 2. In that guest, unpack the exact old kit and run its install-beta-kit with
#    --server 127.0.0.1 --bind 127.0.0.1 --backup-root /var/backups/sli
#    --non-interactive. Do not enroll any agent or import any data.
# 3. The guest provisioner creates the one-use marker inside that same guest:
#    install -o root -g root -m 0600 /proc/sys/kernel/random/boot_id /run/sli-p1-acceptance.boot-id
# 4. Supply the two TAR archives and invoke inside the guest:
#    bash p1-native-410-411-rollback.sh OLD.tar.gz NEW.tar.gz NEW_COMMIT NEW_TAR_SHA256
# OLD is the exact 411 kit from run 45510515483, artifact 14976746044.
# NEW_COMMIT and NEW_TAR_SHA256 must come from the reviewed shared kit run.
# Preserve the printed guest evidence directory for the pass or failure record.

set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C

fail() { printf '411→415 acceptance: %s\n' "$*" >&2; exit 1; }

[[ $# == 4 ]] || fail 'expected OLD.tar.gz NEW.tar.gz NEW_COMMIT NEW_TAR_SHA256'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 && $EUID == 0 ]] ||
    fail 'run as root inside the isolated Linux amd64 guest'
[[ $(< /proc/1/comm) == systemd ]] || fail 'the guest must run systemd as PID 1'
guest=$(systemd-detect-virt) || fail 'a disposable virtualized guest is required'
[[ $guest != wsl ]] || fail 'WSL is outside this test'
python3 -I -B - <<'PY'
import os
import stat
from pathlib import Path

marker = "/run/sli-p1-acceptance.boot-id"
with os.fdopen(os.open(marker, os.O_RDONLY | os.O_NOFOLLOW), encoding="ascii") as stamp:
    info = os.fstat(stamp.fileno())
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
    assert stamp.read().strip() == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
PY
grep -qxF 'ID=debian' /etc/os-release && grep -qxE 'VERSION_ID="?13"?' /etc/os-release ||
    fail 'Debian 13 required'
mountpoint -q /var/backups/sli || fail 'the native backup volume must be mounted'

old_commit=1c25b9f1661ac2412bfc584f3fcbffda1ea95229
old_hash=b3d5b8eb293bebee5142ffd9717620bf3491361bc445dc96bbc35171178177bd
# The verified 410 prefix plus the expected 411 row cover the full baseline.
old_ledger=26ee8d9ac77ea7860e2b46e749980d13a460ea85815b47720b1fbd6dc26ed4cd
new_commit=$3
new_hash=$4
[[ $new_commit =~ ^[a-f0-9]{40}$ && $new_commit != "$old_commit" &&
   $new_hash =~ ^[a-f0-9]{64}$ ]] || fail 'a different reviewed commit and its TAR hash are required'
old_archive=$(realpath -e -- "$1")
new_archive=$(realpath -e -- "$2")
[[ -f $old_archive && -f $new_archive && $old_archive != "$new_archive" ]] ||
    fail 'supply two distinct kit archives'

pg() {
    runuser -u postgres -- psql -XqAt -w -v ON_ERROR_STOP=1 -v VERBOSITY=sqlstate -h /var/run/postgresql -p 5432 -d sli "$@"
}

# The same SQL guard runs first in a read-only transaction and again before
# inserting fixture rows. No scratch directory or fixture is written first.
fixture_guard=$(cat <<'SQL'
DO $fixture$
DECLARE
    entries bigint;
    version_top integer;
    digest text;
    legacy_has_events boolean;
BEGIN
    SELECT count(*), max(version), encode(sha256(convert_to(
        string_agg(jsonb_build_array(version,name,to_jsonb(m)->>'sha256')::text,
                   E'\n' ORDER BY version) FILTER (WHERE version<=410),'UTF8')),'hex')
    INTO entries, version_top, digest
    FROM public.schema_migrations m;
    IF inet_server_addr() IS NOT NULL
       OR current_setting('server_version_num')::integer / 10000 <> 18
       OR entries <> 378 OR version_top IS DISTINCT FROM 411
       OR NOT EXISTS (
           SELECT 1 FROM public.schema_migrations m WHERE version=411 AND name='password_successor_coverage'
           AND to_jsonb(m)->>'sha256'='313281ec2d630a7dc82c7a135a863a7ea444228a0699b488ef177bc657e72279')
       OR digest IS DISTINCT FROM current_setting('sli.acceptance_old_ledger')
       OR EXISTS (SELECT 1 FROM public.sli_agents)
       OR EXISTS (SELECT 1 FROM public.sli_agent_receipts)
       OR EXISTS (SELECT 1 FROM public.sli_agent_packet_inbox)
       OR EXISTS (SELECT 1 FROM public.storage_v2_event_identity_allocations)
       OR EXISTS (SELECT 1 FROM public.event_source_representations_v2)
       OR EXISTS (SELECT 1 FROM public.event_hot)
       OR EXISTS (SELECT 1 FROM public.event_cold_facts)
       OR EXISTS (SELECT 1 FROM public.findings)
    THEN RAISE EXCEPTION 'expected the exact 411 ledger on local PostgreSQL 18 and no collected data';
    END IF;
    -- The native baseline can omit this legacy table. Retain the emptiness guard if it is present.
    IF to_regclass('public.events_v2_core') IS NOT NULL THEN
        EXECUTE 'SELECT EXISTS (SELECT 1 FROM public.events_v2_core)' INTO legacy_has_events;
        IF legacy_has_events THEN
            RAISE EXCEPTION 'expected no collected data in the legacy event table';
        END IF;
    END IF;
END $fixture$;
SQL
)
fixture_settings() {
    printf 'SET LOCAL statement_timeout = %s;\n' "'10s'"
    printf "SET LOCAL sli.acceptance_old_ledger = '%s';\n" "$old_ledger"
}
{ printf '%s\n' 'BEGIN READ ONLY;'; fixture_settings; printf '%s\n' "$fixture_guard" 'ROLLBACK;'; } | pg

installed_ready() {
    local commit=$1 kit="${2:-}" release="beta1-${1:0:12}" url service audit
    url=$(python3 -I -B - "$commit" "$kit" "$release" <<'PY'
import ipaddress
import json
import sys
from pathlib import Path

commit, kit, release = sys.argv[1:]
root = Path("/opt/sli/current").resolve(strict=True)
assert root == Path("/opt/sli/releases") / release
inventory = json.loads((root / "native-runtime.json").read_text())
package = json.loads((root / "native-package.json").read_text())
assert inventory["provenance"]["source_commit"] == commit and package["release"] == release
if kit:
    manifest = json.loads((Path(kit) / "manifest.json").read_text())
    assert package["version"] == manifest["version"]
site = json.loads(Path("/etc/sli/runtime.json").read_text())
address = ipaddress.ip_address(site["bind"])
assert address.is_loopback
host = f"[{address}]" if address.version == 6 else str(address)
port = site.get("https_port", 8443)
assert type(port) is int and 1 <= port <= 65535
health = f"https://{host}:{port}/api/health/ready"
assert site["health_url"] == health
print(health)
PY
)
    for service in sli-dotnet-api.service sli-dotnet-semantic.service sli-postgresql.service; do
        systemctl is-active --quiet "$service"
    done
    audit=$(dpkg --audit)
    [[ -z $audit ]] || fail 'dpkg reports incomplete packages'
    curl -q --proto '=https' --noproxy '*' --fail --silent --show-error --max-time 15 \
        --cacert /var/lib/sli/tls-ca.crt "$url" |
        python3 -I -B -c 'import json,sys; assert json.load(sys.stdin)["ready"] is True'
    printf 'Ready: %s\n' "$release"
}
installed_ready "$old_commit"

work=$(mktemp -d /var/tmp/sli-p1-acceptance.XXXXXXXX)
printf 'Evidence directory in the guest: %s\n' "$work"
trap 'code=$?; if (( code != 0 )); then printf "Acceptance failed. Evidence kept in %s\n" "$work" >&2; fi' EXIT

extract_kit() {
    local archive=$1 hash=$2 commit=$3 directory=$4
    printf '%s  %s\n' "$hash" "$archive" | sha256sum --check --strict
    python3 -I -B - "$archive" "$directory" "$commit" <<'PY'
import json
import re
import sys
import tarfile
from pathlib import Path

archive, directory, commit = sys.argv[1:]
root = Path(directory)
root.mkdir()
with tarfile.open(archive, "r:gz") as kit:
    entries = kit.getmembers()
    names = {entry.name for entry in entries}
    assert len(names) == len(entries)
    for entry in entries:
        if entry.isdir() and entry.name.rstrip("/") == "sli-debian-beta-kit":
            continue
        assert entry.isfile() and re.fullmatch(
            r"sli-debian-beta-kit/[A-Za-z0-9][A-Za-z0-9.+_~-]*", entry.name
        ), entry.name
    kit.extractall(root, members=entries, filter="data")
kit_dir = root / "sli-debian-beta-kit"
manifest = json.loads((kit_dir / "manifest.json").read_text())
assert manifest["git_commit"] == commit and manifest["release"] == "beta1-" + commit[:12]
assert manifest["target"] == "debian-13-amd64"
checksums = (kit_dir / "SHA256SUMS").read_text().splitlines()
assert all(re.fullmatch(r"[a-f0-9]{64}  [A-Za-z0-9][A-Za-z0-9.+_~-]*", row) for row in checksums)
PY
    (cd "$directory/sli-debian-beta-kit" && sha256sum --check --strict --quiet SHA256SUMS)
}
trusted_kit_root=$(mktemp -d /root/sli-p1-rollback-kit.XXXXXXXX)
extract_kit "$old_archive" "$old_hash" "$old_commit" "$trusted_kit_root/predecessor"
extract_kit "$new_archive" "$new_hash" "$new_commit" "$work/candidate"
old_kit="$trusted_kit_root/predecessor/sli-debian-beta-kit"
new_kit="$work/candidate/sli-debian-beta-kit"
python3 -I -B - "$old_kit" <<'PY'
from pathlib import Path
import runpy
import sys

stock = runpy.run_path("/usr/lib/sli/native_install.py", run_name="sli_trusted_kit_probe")
packages = sorted(Path(sys.argv[1]).glob("*.deb"))
assert packages
for package in packages:
    stock["trusted_path"](package)
print("P1_STEP previous_package_paths_verified")
PY

installed_ready "$old_commit" "$old_kit"
printf 'P1_STEP seed_receipts\n'
# The fixture tests persistence. It generates no Windows or AD traffic.
{
    printf '%s\n' 'BEGIN;'
    fixture_settings
    printf '%s\n' "$fixture_guard"
    cat <<'SQL'
INSERT INTO public.sli_agents(id,host_id,key_fingerprint,registration_host_name)
VALUES ('00000000-0000-4000-8000-000000000041','00000000-0000-4000-8000-000000000042',
        repeat('a',64),'sli-p1-acceptance-fixture.invalid');
INSERT INTO public.sli_agent_receipts
    (agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
SELECT '00000000-0000-4000-8000-000000000041','sli.windows.ad-dc',n,
       ('00000000-0000-4000-8000-00000000005' || n)::uuid,
       encode(sha256(convert_to(envelope::text,'UTF8')),'hex'),
       envelope,'{"status":"committed"}',clock_timestamp()-interval '1 day'
FROM generate_series(1,2) AS series(n)
CROSS JOIN LATERAL (SELECT jsonb_build_object('fixture','p1-411', 'sequence',n) AS envelope) p;
-- Reuse one closed row from the queue fixture (case 212). Insert finding
-- metadata only, with no access event, evidence copy or risk job.
INSERT INTO public.findings
    (id,fingerprint,rule_code,title,status,severity,source,actor,target,evidence_count,first_seen_utc,last_seen_utc)
VALUES (212,'semantic:'||encode(sha256('finding-212'::bytea),'hex'),
        'semantic.qw.password-spray','Synthetic finding','closed','high',
        'semantic-production','synthetic-actor','synthetic-object',0,
        (clock_timestamp()-interval '2 days')::text,(clock_timestamp()-interval '1 day')::text);
COMMIT;
SQL
} | pg
printf 'P1_STEP receipt_insert_committed\n'

snapshot() {
    pg <<'SQL'
BEGIN READ ONLY;
SET LOCAL statement_timeout='15s';
SET LOCAL timezone='UTC';
WITH pins AS (
    SELECT count(*) AS entries, max(version) AS version,
           encode(sha256(convert_to(string_agg(jsonb_build_array(version,name,to_jsonb(m)->>'sha256')::text,
               E'\n' ORDER BY version) FILTER (WHERE version<=410),'UTF8')),'hex') AS prefix_sha256,
           coalesce(jsonb_agg(jsonb_build_array(version,name,to_jsonb(m)->>'sha256') ORDER BY version)
               FILTER (WHERE version=411),'[]'::jsonb) AS base_pin,
           coalesce(jsonb_agg(jsonb_build_array(version,name,to_jsonb(m)->>'sha256') ORDER BY version)
               FILTER (WHERE version>411),'[]'::jsonb) AS new_pins
    FROM public.schema_migrations m
), receipt_summary AS (
    SELECT count(*) AS receipts,
           encode(sha256(convert_to(string_agg(to_jsonb(r)::text,E'\n' ORDER BY agent_id,module_id,sequence),
               'UTF8')),'hex') AS receipts_sha256
    FROM public.sli_agent_receipts r
), history_summary AS (
    SELECT count(*) AS findings,
           encode(sha256(convert_to(coalesce(string_agg(to_jsonb(f)::text,E'\n' ORDER BY id),''),
               'UTF8')),'hex') AS findings_sha256
    FROM public.findings f
), decoder AS (
    SELECT pg_get_userbyid(p.proowner) AS decoder_owner,
           p.proacl AS decoder_acl, p.prosecdef AS decoder_security_definer,
           encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex') AS decoder_sha256,
           jsonb_build_object(
               'public_decoder',exists(select 1 from aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                                       where a.grantee=0 and a.privilege_type='EXECUTE'),
               'user_decoder',has_function_privilege('adlog_user',p.oid,'EXECUTE'),
               'worker_decoder',has_function_privilege('adlog_semantic_worker',p.oid,'EXECUTE'),
               'storage_decoder',has_function_privilege('adlog_storage_worker',p.oid,'EXECUTE'),
               'worker_reader',has_function_privilege('adlog_semantic_worker',
                   'public.read_password_episode_portions_v2(jsonb,jsonb,text)','EXECUTE'),
               'worker_finalizer',has_function_privilege('adlog_semantic_worker',
                   'public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)','EXECUTE')) AS rights
    FROM pg_proc p WHERE p.oid='public.password_v2_decode(jsonb,jsonb,jsonb)'::regprocedure
)
SELECT to_jsonb(pins.*)||to_jsonb(receipt_summary.*)||to_jsonb(history_summary.*)||to_jsonb(decoder.*)
       ||jsonb_build_object('agents',(SELECT count(*) FROM public.sli_agents),
           'access_events', (SELECT count(*) FROM public.event_hot)+(SELECT count(*) FROM public.event_cold_facts)
                            +(SELECT count(*) FROM public.event_source_representations_v2))
FROM pins CROSS JOIN receipt_summary CROSS JOIN history_summary CROSS JOIN decoder;
COMMIT;
SQL
}
snapshot > "$work/before.json"
printf 'P1_STEP baseline_snapshot_written\n'
python3 -I -B - "$work/before.json" "$old_ledger" <<'PY'
import json, re, sys
from pathlib import Path
base = json.loads(Path(sys.argv[1]).read_text())
assert type(base) is dict
assert re.fullmatch(r"[a-f0-9]{64}", base["receipts_sha256"])
print("P1_DATA baseline_receipts=" + json.dumps({
    key: base[key] for key in ("entries", "version", "prefix_sha256", "agents", "receipts", "receipts_sha256")
}))
assert (base["entries"], base["version"], base["prefix_sha256"]) == (378, 411, sys.argv[2])
assert base["base_pin"] == [[411, "password_successor_coverage", "313281ec2d630a7dc82c7a135a863a7ea444228a0699b488ef177bc657e72279"]]
assert base["findings"] == 1 and base["access_events"] == 0
assert re.fullmatch(r"[a-f0-9]{64}", base["findings_sha256"])
assert base["decoder_owner"] == "adlog_storage_owner" and base["decoder_security_definer"] is True
assert base["rights"] == {"public_decoder": False, "user_decoder": False, "worker_decoder": False,
                          "storage_decoder": False, "worker_reader": True, "worker_finalizer": True}
assert base["receipts"] == 2 and base["agents"] == 1 and not base["new_pins"]
PY

printf 'P1_STEP baseline_receipts_verified\n'
# Only transactions created in this test are acceptable as evidence.
transactions=/var/lib/sli/transactions
if [[ -d $transactions ]]; then
    find "$transactions" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' > "$work/old-transactions"
else
    : > "$work/old-transactions"
fi
printf 'P1_STEP candidate_install_entered\n'
(
    cd "$new_kit"
    exec 9>"$work/upgrade.trace"
    BASH_XTRACEFD=9 /bin/bash -x ./install-beta-kit --non-interactive
) >"$work/upgrade.log" 2>&1
printf 'P1_STEP candidate_install_completed\n'
installed_ready "$new_commit" "$new_kit"
snapshot > "$work/upgraded.json"

verify_transition() {
    python3 -I -B - "$work" "$old_commit" "$new_commit" "$1" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

work, old, new, phase = sys.argv[1:]
work = Path(work)
before = json.loads((work / "before.json").read_text())
present = json.loads((work / f"{phase}.json").read_text())
old_ids = set((work / "old-transactions").read_text().splitlines())

def read(path):
    return json.loads(path.read_text())

def verified_manifest(root, identifier, expected):
    assert re.fullmatch(r"\d{8}T\d{6}\.\d{6}Z", identifier), identifier
    raw = (root / identifier / "manifest.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    assert json.loads(raw)["consistency_point"]["writers_fenced"] is True

release = "beta1-" + (new if phase == "upgraded" else old)[:12]
status, kind = ("committed", None) if phase == "upgraded" else ("rolled_back", "rollback")
matches = []
for path in Path("/var/lib/sli/transactions").glob("*/result.json"):
    identity = path.parent.name
    if identity in old_ids:
        continue
    result = read(path)
    if result.get("accepted_release") != release or result.get("status") != status:
        continue
    journal = read(path.parent / "journal.json")
    if journal.get("kind") == kind:
        matches.append((identity, result, journal))
assert len(matches) == 1, f"expected one {phase} transaction, found {len(matches)}"
identity, result, journal = matches[0]
assert re.fullmatch(r"[a-f0-9]{32}", identity)
assert identity == result["transaction"] == journal["transaction"]
assert result["terminal"] is True and result["services_restored"] is True
assert result.get("package_reconciliation_required", False) is False
assert journal["previous"] == "beta1-" + old[:12]
backups = Path("/var/backups/sli/native")
if phase == "upgraded":
    assert (present["entries"], present["version"]) == (382, 415)
    assert present["new_pins"] == [
        [412,"sigma_history_test","c6cce426f28c51a2fa9787523d8967d127a9a7b0c796e8f2db1d861ebc52755f"],
        [413,"workstation_journal_admission","0d86c71b7d4e599af4458224562b106f03840a04cb8b469eb10145681f958c5b"],
        [414,"file_audit_smb_catalog","13df311e2c430d52de603a592cde45808d69cd30554c30112398f3bc562ed944"],
        [415,"password_portion_canonical","cba1cc479b34fba8be9d31d718c8953d2bb8da7e3e94e9f6eec1b5c907c99b73"],
    ]
    assert all(present[key] == before[key] for key in (
        "prefix_sha256", "base_pin", "receipts", "receipts_sha256", "agents", "findings",
        "findings_sha256", "access_events", "decoder_owner", "decoder_acl", "decoder_security_definer", "rights"))
    assert present["decoder_sha256"] != before["decoder_sha256"]
    assert result["schema_changed"] is True and journal["checkpoint_storage"] == "backup_volume"
    expected = journal["checkpoint_sha256"]
    point = backups / "upgrade-checkpoints" / identity
    identifier = journal["checkpoint"]
    verified_manifest(point, identifier, expected)
    mode = journal["checkpoint_verification"]
    assert mode in {"integrity", "restore"}
    receipt = read(point / f"{mode}-verified.json")
    assert receipt["terminal"] is True and receipt["status"] == mode + "_verified"
    assert receipt["backup_id"] == identifier and receipt["manifest_sha256"] == expected
elif phase == "rolled-back":
    assert present == before
    upgraded = read(work / "upgraded-proof.json")
    assert journal["checkpoint_transaction"] == upgraded["transaction"]
    expected = journal["safety_backup_sha256"]
    identifier = journal["safety_backup"]
    verified_manifest(backups / "before-restore" / identity, identifier, expected)
else:
    raise AssertionError(phase)
proof = {
    "phase": phase, "transaction": identity, "release": release, "status": status,
    "backup_id": identifier, "backup_manifest_sha256": expected, "data": present,
}
(work / f"{phase}-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
print(json.dumps(proof))
PY
}
verify_transition upgraded
printf 'P1_STEP native_rollback_entered\n'
/usr/sbin/sli-rollback "$old_kit" > "$work/rollback.log" 2>&1
printf 'P1_STEP native_rollback_completed\n'
installed_ready "$old_commit" "$old_kit"
snapshot > "$work/rolled-back.json"
verify_transition rolled-back
