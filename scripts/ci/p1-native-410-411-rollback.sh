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
# OLD is the exact #229 kit from run 45480994082, artifact 14960504617.
# NEW_COMMIT and NEW_TAR_SHA256 must come from the reviewed P1-only kit run.
# Preserve the printed guest evidence directory for the pass or failure record.

set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C

fail() { printf '410→411 acceptance: %s\n' "$*" >&2; exit 1; }

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

old_commit=0f6093b3a9afcecb28fcdd47c7ed50522e50a156
old_hash=38115eee4fe10dbf5a422d13ccbb644ff5c0837cb371cb397579c0fb56b0338e
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
    runuser -u postgres -- psql -XqAt -w -v ON_ERROR_STOP=1 -h /var/run/postgresql -p 5432 -d sli "$@"
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
                   E'\n' ORDER BY version),'UTF8')),'hex')
    INTO entries, version_top, digest
    FROM public.schema_migrations m;
    IF inet_server_addr() IS NOT NULL
       OR current_setting('server_version_num')::integer / 10000 <> 18
       OR entries <> 377 OR version_top IS DISTINCT FROM 410
       OR digest IS DISTINCT FROM current_setting('sli.acceptance_old_ledger')
       OR EXISTS (SELECT 1 FROM public.sli_agents)
       OR EXISTS (SELECT 1 FROM public.sli_agent_receipts)
       OR EXISTS (SELECT 1 FROM public.sli_agent_packet_inbox)
       OR EXISTS (SELECT 1 FROM public.storage_v2_event_identity_allocations)
       OR EXISTS (SELECT 1 FROM public.event_source_representations_v2)
       OR EXISTS (SELECT 1 FROM public.event_hot)
       OR EXISTS (SELECT 1 FROM public.event_cold_facts)
       OR EXISTS (SELECT 1 FROM public.findings)
    THEN RAISE EXCEPTION 'expected the exact 410 ledger on local PostgreSQL 18 and no collected data';
    END IF;
    -- Native 410 omits this legacy table. Retain the emptiness guard if it is present.
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
    local archive=$1 hash=$2 commit=$3 label=$4
    printf '%s  %s\n' "$hash" "$archive" | sha256sum --check --strict
    python3 -I -B - "$archive" "$work/$label" "$commit" <<'PY'
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
    (cd "$work/$label/sli-debian-beta-kit" && sha256sum --check --strict --quiet SHA256SUMS)
}
extract_kit "$old_archive" "$old_hash" "$old_commit" predecessor
extract_kit "$new_archive" "$new_hash" "$new_commit" candidate
old_kit="$work/predecessor/sli-debian-beta-kit"
new_kit="$work/candidate/sli-debian-beta-kit"

installed_ready "$old_commit" "$old_kit"
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
COMMIT;
SQL
} | pg

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
               FILTER (WHERE version>410),'[]'::jsonb) AS new_pins
    FROM public.schema_migrations m
), receipts AS (
    SELECT count(*) AS receipts,
           encode(sha256(convert_to(string_agg(to_jsonb(r)::text,E'\n' ORDER BY agent_id,module_id,sequence),
               'UTF8')),'hex') AS receipts_sha256
    FROM public.sli_agent_receipts r
)
SELECT to_jsonb(pins)||to_jsonb(receipts)
       ||jsonb_build_object('agents',(SELECT count(*) FROM public.sli_agents))
FROM pins CROSS JOIN receipts;
COMMIT;
SQL
}
snapshot > "$work/before.json"
python3 -I -B - "$work/before.json" "$old_ledger" <<'PY'
import json, sys
from pathlib import Path
base = json.loads(Path(sys.argv[1]).read_text())
assert (base["entries"], base["version"], base["prefix_sha256"]) == (377, 410, sys.argv[2])
assert base["receipts"] == 2 and base["agents"] == 1 and not base["new_pins"]
PY

# Only transactions created in this test are acceptable as evidence.
transactions=/var/lib/sli/transactions
if [[ -d $transactions ]]; then
    find "$transactions" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' > "$work/old-transactions"
else
    : > "$work/old-transactions"
fi
(cd "$new_kit" && /bin/bash ./install-beta-kit --non-interactive) > "$work/upgrade.log" 2>&1
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
    assert (present["entries"], present["version"]) == (378, 411)
    assert len(present["new_pins"]) == 1
    version, name, checksum = present["new_pins"][0]
    assert (version, name) == (411, "password_successor_coverage")
    assert checksum == "313281ec2d630a7dc82c7a135a863a7ea444228a0699b488ef177bc657e72279"
    assert all(present[key] == before[key] for key in ("prefix_sha256", "receipts", "receipts_sha256", "agents"))
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
/usr/sbin/sli-rollback "$old_kit" > "$work/rollback.log" 2>&1
installed_ready "$old_commit" "$old_kit"
snapshot > "$work/rolled-back.json"
verify_transition rolled-back
