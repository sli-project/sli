"""Exercise ordinary enrollment and signed imports on one disposable installed host."""

import http.cookiejar
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sli_agent.envelope import make_packet
from sli_agent.snapshot_stream import SnapshotStream

BASE = "https://127.0.0.1"
CA = "/var/lib/sli/tls-ca.crt"
DC = "dc-quiet.directory.invalid"
DOMAIN = "directory.invalid"
SID = "S-1-5-21-100000001-200000002-300000003"
HYGIENE = {
    "qw.ad-hardening.privileged-nonexpiring",
    "qw.ad-hardening.machine-account-quota",
    "qw.ad-hardening.lockout-threshold",
}
PSQL = [
    "runuser", "-u", "postgres", "--", "/usr/lib/postgresql/18/bin/psql",
    "-XqAtw", "-h", "/var/run/postgresql", "-p", "5432", "-d", "sli", "-v", "ON_ERROR_STOP=1",
]


def evidence(key, value):
    print("P1_EVIDENCE quiet_" + key + "=" + json.dumps(value, sort_keys=True), flush=True)


def code(value):
    return value if isinstance(value, str) and re.fullmatch(r"[a-z0-9_.-]{1,100}", value) else None


def client(context, cookies=False):
    handlers = [
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context),
    ]
    if cookies:
        handlers.append(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    return urllib.request.build_opener(*handlers)


def request(opener, path, body=None, owner=False):
    headers = {"Accept": "application/json", "Accept-Language": "en", "Content-Type": "application/json"}
    if owner:
        headers["Origin"] = BASE
    req = urllib.request.Request(BASE + path, None if body is None else json.dumps(body).encode(), headers)
    try:
        with opener.open(req, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as err:
        try:
            reason = code(json.loads(err.read()).get("error"))
        except (TypeError, AttributeError, ValueError):
            reason = None
        evidence("http_error", {"path": path.split("?")[0], "status": err.code, "reason": reason})
        raise SystemExit(1) from None


def sql(statement):
    return subprocess.check_output(
        PSQL + ["-c", "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; " + statement + "; COMMIT;"],
        text=True,
    ).strip()


def send_packet(opener, value):
    envelope = value["envelope"]
    receipt = request(opener, "/api/v1/agent/packets", value)
    if receipt.get("status") != "committed":
        evidence("packet_rejected", {"module": envelope["module_id"], "sequence": envelope["sequence"],
            "status": code(receipt.get("status")), "reason": code(receipt.get("error_code"))})
        raise SystemExit(1)
    assert receipt["packet_id"] == envelope["packet_id"]
    assert receipt["payload_sha256"] == envelope["payload_sha256"]
    assert receipt["committed_cursor"] == envelope["cursor_after"]
    return str(UUID(envelope["packet_id"]))


def main(root):
    context = ssl.create_default_context(cafile=CA)
    owner_client = client(context, cookies=True)

    def owner(path, body=None):
        return request(owner_client, path, body, owner=True)

    evidence("stage", "owner_login")
    auth = owner("/api/auth/login", {"username": "admin", "password": "admin", "remember": False})
    if auth.get("password_change_required"):
        password = secrets.token_urlsafe(30)
        owner("/api/auth/change-initial-password", {"password": password, "repeat": password})
    principal = owner("/api/auth/me")["principal"]
    assert principal["username"] == "admin" and principal["role"] == "admin"

    evidence("stage", "console_enrollment")
    issued = owner("/api/v1/admin/agent-console-tokens", {"host_limit": 1, "manage_windows_audit": False})
    token = re.fullmatch(
        r"} 'https://127\.0\.0\.1(?::443)?/' '([A-Za-z0-9_-]{43})' .+",
        issued["command"].splitlines()[-1],
    )
    assert token, "console_token_command_contract"
    key = ec.generate_private_key(ec.SECP256R1())
    host = str(uuid4())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    ).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode("ascii")
    enrollment = request(client(context), "/api/v1/agent/enroll", {
        "token": token[1], "csr_pem": csr, "machine_role": "domain_controller",
        "reported_hostname": DC, "domain_dns": DOMAIN, "forest_dns": DOMAIN, "domain_sid": SID,
    })
    agent = str(UUID(enrollment["agent_id"]))
    cert_chain = enrollment["ca_chain_pem"]
    if isinstance(cert_chain, list):
        cert_chain = "\n".join(cert_chain)
    (root / "agent.crt").write_text(enrollment["certificate_pem"] + "\n" + cert_chain, encoding="ascii")
    (root / "agent.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    mtls = ssl.create_default_context(cafile=CA)
    mtls.load_cert_chain(root / "agent.crt", root / "agent.key")
    agent_client = client(mtls)
    identity = request(agent_client, "/api/v1/agent/identity")
    assert identity["agent_id"] == agent
    assignments = {row["module_id"]: row["config"] for row in identity["assigned_modules"] if row["enabled"]}
    assert {"sli.windows.ad-dc", "sli.ad-snapshot"} <= set(assignments)
    evidence("enrollment", {"active": True, "modules": sorted(assignments), "domain": DOMAIN})

    evidence("stage", "signed_snapshot")
    fixture = Path(sys.argv[1])
    now = datetime.now(timezone.utc)
    stamp = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    families = json.loads((fixture / "ad-publication-source-vector.json").read_text().replace(
        "2026-10-08T12:00:00Z", stamp
    ))["families"]
    stream = SnapshotStream(root / "snapshot", "sli.ad-snapshot")
    state = stream.begin(assignments["sli.ad-snapshot"], now=now)
    cycle = str(UUID(state["cycle_id"]))
    bundle = {
        name: (families[name], len(families[name]["objects" if name == "computers_v6" else "records"]))
        for name in state["policy"]["families"]
    }
    stream.freeze(state, bundle)
    position = None
    receipts = []
    for sequence in range(1, 21):
        chunk = stream.next_sample(position)
        if chunk is None:
            break
        snapshot_packet = make_packet(key, agent_id=agent, sequence=sequence, sample=chunk, now=now)
        receipts.append(send_packet(agent_client, snapshot_packet))
        position = {"cursor_after": chunk.cursor_after}
    else:
        raise AssertionError("snapshot_fixture_exceeded_chunk_bound")
    assert len(receipts) >= len(bundle)
    evidence("snapshot_receipts", {"packets": len(receipts), "families": sorted(bundle)})

    evidence("stage", "signed_event")
    command = [
        str(fixture / "quiet-dotnet/dotnet"), str(fixture / "quiet-ad-dc/QuietAdDc.dll"),
        "packet", str(fixture / "ad-dc-scenarios.json"), str(fixture / "registered-ad-dc.json"),
        str(root / "agent.key"),
    ]
    captured = subprocess.run(command, input=json.dumps({
        "host": host, "agent": agent, "now": now.isoformat(), "config": assignments["sli.windows.ad-dc"],
    }), text=True, check=True, stdout=subprocess.PIPE, timeout=30)
    value = json.loads(captured.stdout)
    assert value["envelope"]["record_count"] == 1
    evidence("dotnet_registered_capture", {"event_id": 4624, "records": 1, "same_assignment_as_preflight": True})
    event = send_packet(agent_client, value)
    evidence("event_receipt", {"event_id": 4624, "committed": 1})

    evidence("stage", "installed_background_import")
    domain = int(sql(f"select id from domains where domain_sid='{SID}' and lower(fqdn)='{DOMAIN}'"))
    assert domain > 0
    query = f"""
      select json_build_object(
        'active_agents', (select count(*) from sli_agents where id='{agent}' and status='active'),
        'event_imported', (select count(*) from sli_agent_packet_inbox where packet_id='{event}' and imported_at is not null),
        'stored_4624', (select count(*) from event_hot where domain_id={domain} and event_kind=4624 and lower(computer)='{DC}'),
        'ad_projection', (select publication_state from sli_agent_snapshot_cycles where cycle_id='{cycle}' and agent_id='{agent}'),
        'ad_transport', (select transport_state from sli_agent_snapshot_cycles where cycle_id='{cycle}' and agent_id='{agent}'),
        'ad_manifest', (select count(*) from sli_agent_snapshot_cycles where cycle_id='{cycle}' and manifest_id is not null),
        'receipts', (select count(*) from sli_agent_receipts where agent_id='{agent}'))
    """
    deadline = time.monotonic() + 220
    while True:
        result = json.loads(sql(query))
        if (result["ad_transport"] == "complete" and result["ad_projection"] == "published"
                and result["event_imported"] == 1 and result["stored_4624"] == 1):
            break
        if time.monotonic() >= deadline:
            evidence("import_incomplete", result)
            raise SystemExit(1)
        time.sleep(5)
    assert result["active_agents"] == result["ad_manifest"] == 1
    assert result["receipts"] == len(receipts) + 1
    evidence("import", result)

    evidence("stage", "installed_home_api")
    params = urllib.parse.urlencode({"contract": "v4", "domain_id": domain, "tz": "UTC"})
    home = owner("/api/v1/home/summary?" + params)
    assert home["domain_id"] == domain
    summary = home["problems"]
    assert isinstance(summary, dict) and type(summary["open_count"]) is int
    total = summary["open_count"]
    assert total >= 0
    evidence("home", {k: summary[k] for k in ("new_count", "closed_count", "open_count")})
    if total:
        queue_params = urllib.parse.urlencode({"population": "open", "domain_id": domain, "limit": 100})
        queue = owner("/api/v2/reports/security.problems/data?" + queue_params)
        rows = queue.get("items")
        assert isinstance(rows, list) and len(rows) == total and queue.get("has_more") is not True, "home_queue_count_mismatch"
        assert all(isinstance(row.get("rule_code"), str) for row in rows)
        hygiene = sum(row["rule_code"] in HYGIENE for row in rows)
    else:
        hygiene = 0
    evidence("acceptance", {"domain_id": domain, "open_hygiene": hygiene, "open_other": total - hygiene})
    assert hygiene <= 10 and total == hygiene, "quiet_state_criterion_failed"


if __name__ == "__main__":
    os.umask(0o077)
    with TemporaryDirectory(prefix="quiet-ad-") as staging:
        try:
            main(Path(staging))
        except Exception as error:
            frame = traceback.extract_tb(error.__traceback__)[-1]
            evidence("fixture_error", {"kind": type(error).__name__, "line": frame.lineno})
            raise
