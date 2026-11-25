#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

input=/mnt/p1-input
database_uuid=$1
backup_root=$2
initial_log=$3
initial_trace=$4
read -r commit tar_hash <"$input/candidate.pin"
[[ "$commit" == 23e9547d1b8231e297b901335c22e7a828a4b946 && "$tar_hash" =~ ^[0-9a-f]{64}$ ]]
grep -qxF 'ID=debian' /etc/os-release
grep -qxE 'VERSION_ID="?13"?' /etc/os-release
printf '%s  %s\n' "$tar_hash" "$input/candidate.tar.gz" | sha256sum --check --strict
release="beta1-${commit:0:12}"
candidate=$(mktemp -d /var/tmp/file-audit-kit.XXXXXXXX)
tar -xzf "$input/candidate.tar.gz" -C "$candidate"
printf 'P1_EVIDENCE file_audit_stage=stock_install git=%s tar_sha256=%s\n' "$commit" "$tar_hash"
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
print("P1_EVIDENCE file_audit_package=" + json.dumps(package, sort_keys=True))
PY
curl -q --proto '=https' --noproxy '*' --fail --silent --show-error --max-time 15 \
    --cacert /var/lib/sli/tls-ca.crt https://127.0.0.1/api/health/ready |
    python3 -I -B -c 'import json,sys; assert json.load(sys.stdin)["ready"] is True'
printf 'P1_EVIDENCE file_audit_readiness=ready\n'

sql=(runuser -u postgres -- /usr/lib/postgresql/18/bin/psql -XqAtw \
    -h /var/run/postgresql -p 5432 -d sli -v ON_ERROR_STOP=1)
ledger=$("${sql[@]}" -c "select string_agg(version || '/' || name, ',' order by version) from public.schema_migrations where version>=412")
[[ "$ledger" == '412/sigma_history_test,413/workstation_journal_admission,414/file_audit_smb_catalog' ]]
printf 'P1_EVIDENCE file_audit_ledger=%s\n' "$ledger"
[[ $("${sql[@]}" -c 'select count(*) from public.sli_agents') == 0 ]]

printf 'P1_EVIDENCE file_audit_stage=installed_https\n'
python3 -I -B - <<'PY'
import http.client
import json
import re
import secrets
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import UUID, uuid4

HOST = "127.0.0.1"
SERVER_CA = "/var/lib/sli/tls-ca.crt"
ADMIN = "/api/v1/admin/agents/file-audit/catalog"
IDENTITY = "/api/v1/agent/identity"
REPORT = "/api/v1/agent/file-audit-catalog-report"

def call(context, method, path, payload=None, headers=None):
    connection = http.client.HTTPSConnection(HOST, 443, context=context, timeout=15)
    request_headers = dict(headers or {})
    body = None
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        request_headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body, request_headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read()), response.getheader("Set-Cookie")
    finally:
        connection.close()

def read(label, context, method, path, payload=None, headers=None, expected=200, error=None):
    status, body, cookie = call(context, method, path, payload, headers)
    reason = body.get("error")
    if status != expected or (error is not None and reason != error):
        safe_reason = reason if isinstance(reason, str) and re.fullmatch(r"[a-z0-9_]+", reason) else "none"
        raise AssertionError(f"{label}: HTTP {status} expected {expected}, error={safe_reason}")
    print(f"P1_EVIDENCE file_audit_step={label} http={status}", flush=True)
    return body, cookie

def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs).stdout

plain = ssl.create_default_context(cafile=SERVER_CA)
login, cookie = read("owner_login", plain, "POST", "/api/auth/login", {"username": "admin", "password": "admin"})
assert login["password_change_required"] is True and cookie is not None
password = secrets.token_urlsafe(32) + "Aa1!"
changed, changed_cookie = read("owner_password_changed", plain, "POST", "/api/auth/change-initial-password",
    {"password": password, "repeat": password}, {"Cookie": cookie.split(";", 1)[0]})
assert changed["authenticated"] is True
if changed_cookie is None:
    resumed, changed_cookie = read("owner_session", plain, "POST", "/api/auth/login",
        {"username": "admin", "password": password})
    assert resumed["authenticated"] is True
assert changed_cookie is not None
owner = {"Cookie": changed_cookie.split(";", 1)[0]}

with tempfile.TemporaryDirectory(prefix="sli-file-audit-peer-") as path:
    root = Path(path)
    key = root / "agent-key.pem"
    csr = root / "agent.csr"
    chain = root / "agent-chain.pem"
    host_id = str(uuid4())
    command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-keyout", str(key), "-subj", "/CN=" + host_id, "-out", str(csr))
    import hashlib
    public_key = command("openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER")
    fingerprint = hashlib.sha256(public_key).hexdigest()
    token, _ = read("owner_token_created", plain, "POST", "/api/v1/admin/agent-tokens",
        {"host_id": host_id, "key_fingerprint": fingerprint}, owner)
    issued, _ = read("certificate_issued", plain, "POST", "/api/v1/agent/enroll",
        {"token": token["token"], "csr_pem": csr.read_text(), "reported_hostname": "file-audit-guest.example.test"})
    agent_id = str(UUID(issued["agent_id"]))
    chain.write_text(issued["certificate_pem"].rstrip() + "\n" + issued["ca_chain_pem"].lstrip())
    agent_context = ssl.create_default_context(cafile=SERVER_CA)
    agent_context.load_cert_chain(str(chain), str(key))
    capability = {"X-SLI-File-Audit-Catalog": "1"}
    pre, _ = read("registered_peer", agent_context, "GET", IDENTITY, headers=capability)
    assert pre["agent_id"] == agent_id and pre["file_audit_read_diagnostics"] is True
    pending, _ = read("catalog_requested", plain, "POST", ADMIN, {"agent_id": agent_id}, owner)
    assert pending["state"] == "pending" and not pending["items"]
    request_id = None
    for attempt in range(3):
        if attempt:
            time.sleep(0.1)
        identity, _ = read("registered_peer_poll", agent_context, "GET", IDENTITY, headers=capability)
        assert identity["agent_id"] == agent_id and identity["file_audit_read_diagnostics"] is True
        request_id = identity.get("file_audit_catalog_request", {}).get("request_id")
        if request_id is not None:
            break
    assert request_id is not None, "The registered agent did not receive its pending catalog request"
    UUID(request_id)
    report = {"request_id": request_id, "status": "ready", "shares": [{"share_name": "Pilot$", "path": r"C:\Pilot"}]}
    read("no_client_certificate", plain, "POST", REPORT, report, expected=401, error="agent_mtls_required")
    still_pending, _ = read("catalog_unchanged_after_denial", plain, "GET", ADMIN + "?agent_id=" + agent_id, headers=owner)
    assert still_pending["state"] == "pending" and not still_pending["items"]
    accepted, _ = read("catalog_accepted_with_registered_certificate", agent_context, "POST", REPORT, report)
    assert accepted["status"] == "accepted"
    result, _ = read("catalog_read_back", plain, "GET", ADMIN + "?agent_id=" + agent_id, headers=owner)
    assert result["state"] == "ready" and len(result["items"]) == 1
    item = result["items"][0]
    assert item["share_name"] == "Pilot$" and item["path"] == r"C:\Pilot"
    UUID(item["collection_scope_id"])
    sql = """
        select (c.source_id=a.host_id::text and a.host_id=:'source_id'::uuid and
                c.request_id=:'request_id'::uuid and c.result_status='ready')::text
        from public.sli_file_audit_smb_catalog c join public.sli_agents a on a.id=c.agent_id
        where a.id=:'agent_id'::uuid;
    """
    persisted = command("runuser", "-u", "postgres", "--", "/usr/lib/postgresql/18/bin/psql",
        "-XqAtw", "-h", "/var/run/postgresql", "-p", "5432", "-d", "sli", "-v", "ON_ERROR_STOP=1",
        "-v", "agent_id=" + agent_id, "-v", "source_id=" + host_id, "-v", "request_id=" + request_id,
        input=sql.encode()).decode().strip()
    assert persisted == "true"
    print("P1_EVIDENCE file_audit_catalog=ready registered_agent_bound=yes source_bound=yes request_bound=yes item_count=1")
PY
