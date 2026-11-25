"""Verify enrollment and effective assignments on a disposable installed host."""

from contextlib import contextmanager
import http.cookiejar
import hashlib
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
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

BASE = "https://127.0.0.1"
CA = "/var/lib/sli/tls-ca.crt"
DC = "dc-quiet.directory.invalid"
WS = "ws-t40.directory.invalid"
AD = "sli.windows.ad-dc"
AD_SNAPSHOT = "sli.ad-snapshot"
GPO_SNAPSHOT = "sli.gpo-snapshot"
WORKSTATION = "sli.workstations"
ASSIGN = "/api/v1/admin/agents/modules"
IDENTITY = "/api/v1/agent/identity"
DOMAIN = "directory.invalid"
SID = "S-1-5-21-100000001-200000002-300000003"
PSQL = [
    "runuser", "-u", "postgres", "--", "/usr/lib/postgresql/18/bin/psql",
    "-XqAtw", "-h", "/var/run/postgresql", "-p", "5432", "-d", "sli", "-v", "ON_ERROR_STOP=1",
]


def evidence(key, value):
    print("P1_EVIDENCE t40_" + key + "=" + json.dumps(value, sort_keys=True), flush=True)


def code(value):
    return value if isinstance(value, str) and re.fullmatch(r"[a-z0-9_.-]{1,100}", value) else None


def client(context, cookies=False):
    handlers = [
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context),
    ]
    if cookies:
        handlers.append(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    return urllib.request.build_opener(*handlers)


def request(opener, path, body=None, owner=False, observe_error=False):
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
        if observe_error:
            return {"http_status": err.code, "error": reason}
        evidence("http_error", {"path": path.split("?")[0], "status": err.code, "reason": reason})
        raise SystemExit(1) from None


def sql(statement):
    return subprocess.check_output(
        PSQL + ["-c", "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; " + statement + "; COMMIT;"],
        text=True,
    ).strip()


def modules(value):
    return {item["module_id"]: item for item in value["assigned_modules"]}


def brief(value):
    return {
        "revision": value["policy_revision"],
        "modules": {name: entry["enabled"] for name, entry in sorted(modules(value).items())},
        "dc_identity_required": value.get("dc_identity_required", False),
    }


def stored(agent):
    return json.loads(sql(f"""select json_build_object('policy_revision',policy_revision,
        'assigned_modules',assigned_modules,'status',status)
        from sli_agents where id='{agent}'"""))


def enroll(owner, root, label, role, name, owner_approved=False):
    key = ec.generate_private_key(ec.SECP256R1())
    host = str(uuid4())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    ).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode("ascii")
    if owner_approved:
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        grant = owner("/api/v1/admin/agent-tokens", {
            "host_id": host, "key_fingerprint": hashlib.sha256(public).hexdigest(),
            "registration_host_name": name,
        })
        token = grant["token"]
    else:
        issued = owner("/api/v1/admin/agent-console-tokens", {"host_limit": 1, "manage_windows_audit": False})
        match = re.fullmatch(r"} 'https://127\.0\.0\.1(?::443)?/' '([A-Za-z0-9_-]{43})' .+",
                             issued["command"].splitlines()[-1])
        assert match, "console_token_command_contract"
        token = match[1]
    trust = ssl.create_default_context(cafile=CA)
    result = request(client(trust), "/api/v1/agent/enroll", {
        "token": token, "csr_pem": csr, "machine_role": role, "reported_hostname": name,
    })
    agent = str(UUID(result["agent_id"]))
    cert_chain = result["ca_chain_pem"]
    if isinstance(cert_chain, list):
        cert_chain = "\n".join(cert_chain)
    cert_path = root / (label + ".crt")
    cert_path.write_text(result["certificate_pem"] + "\n" + cert_chain, encoding="ascii")
    key_path = root / (label + ".key")
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    trust.load_cert_chain(cert_path, key_path)
    authenticated = client(trust)

    def agent_api(path, body=None):
        response = request(authenticated, path, body)
        if path == IDENTITY:
            assert response["agent_id"] == agent, "unexpected_mtls_identity"
        return response

    return agent, host, agent_api


def run_systemctl(*args):
    subprocess.run(["systemctl", *args], check=True, stdout=subprocess.DEVNULL, timeout=70)


def ready():
    context = ssl.create_default_context(cafile=CA)
    opener = client(context)
    deadline = time.monotonic() + 90
    while True:
        try:
            value = request(opener, "/api/health/ready", observe_error=True)
            if value.get("ready") is True:
                return
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise AssertionError("profile_restart_readiness_timeout")
        time.sleep(2)


@contextmanager
def full_profile():
    directory = Path("/run/systemd/system/sli-dotnet-api.service.d")
    directory.mkdir(parents=True, exist_ok=True)
    drop_in = directory / "90-t40-disposable-profile.conf"
    with drop_in.open("x", encoding="ascii") as entry:
        entry.write("[Service]\nEnvironment=Sli__CollectionProfile=full\n")
    try:
        run_systemctl("daemon-reload")
        run_systemctl("restart", "sli-dotnet-api.service")
        ready()
        yield
    finally:
        drop_in.unlink()
        run_systemctl("daemon-reload")
        run_systemctl("restart", "sli-dotnet-api.service")
        ready()


def expected(value, names):
    actual = {name: item["enabled"] for name, item in modules(value).items()}
    assert actual == names, f"assignment_shape:{actual}"


def main(root):
    owner_client = client(ssl.create_default_context(cafile=CA), cookies=True)

    def owner(path, body=None, observe_error=False):
        return request(owner_client, path, body, owner=True, observe_error=observe_error)

    evidence("stage", "owner_login")
    login = owner("/api/auth/login", {"username": "admin", "password": "admin", "remember": False})
    if login.get("password_change_required"):
        password = secrets.token_urlsafe(30)
        owner("/api/auth/change-initial-password", {"password": password, "repeat": password})
    principal = owner("/api/auth/me")["principal"]
    assert principal["username"] == "admin" and principal["role"] == "admin"
    assert int(sql(f"select count(*) from domains where lower(fqdn)='{DOMAIN}'")) == 0

    evidence("stage", "beta_initial_assignments")
    ws, _, ws_api = enroll(owner, root, "beta-ws", "workstation", WS)
    ws_saved = stored(ws)
    ws_initial = ws_api(IDENTITY)
    evidence("beta_workstation_initial", {"saved": brief(ws_saved), "check_in": brief(ws_initial)})
    expected(ws_saved, {})
    expected(ws_initial, {})
    assert ws_initial["policy_revision"] == 1

    dc, dc_host, dc_api = enroll(owner, root, "beta-dc", "domain_controller", DC)
    dc_initial = dc_api(IDENTITY)
    evidence("beta_dc_initial", brief(dc_initial))
    expected(dc_initial, {AD: True})
    allow = modules(dc_initial)[AD]["config"]["allow_event_ids"]
    assert isinstance(allow, list) and 4624 in allow, "beta_ad_dc_event_allowlist"
    assert dc_initial.get("dc_identity_required") is True
    assert int(sql(f"select count(*) from domains where lower(fqdn)='{DOMAIN}'")) == 0

    evidence("stage", "beta_dc_confirmation")
    receipt = dc_api("/api/v1/agent/policy-report", {
        "applied_policy_revision": dc_initial["policy_revision"], "collection_state": "active",
        "dc_identity": {"machine_role": "domain_controller", "reported_hostname": DC,
                        "domain_dns": DOMAIN, "forest_dns": DOMAIN, "domain_sid": SID},
    })
    assert receipt["applied_policy_revision"] == dc_initial["policy_revision"]
    dc_confirmed = dc_api(IDENTITY)
    evidence("beta_dc_confirmed", {**brief(dc_confirmed), "domain": DOMAIN, "allow_event_ids": len(allow)})
    expected(dc_confirmed, {AD: True, AD_SNAPSHOT: True, GPO_SNAPSHOT: True})
    assert dc_confirmed["policy_revision"] == dc_initial["policy_revision"] + 1
    assert not dc_confirmed.get("dc_identity_required")
    for module in (AD_SNAPSHOT, GPO_SNAPSHOT):
        config = modules(dc_confirmed)[module]["config"]
        assert config["domain_sid"] == SID and config["domain_dns"] == DOMAIN
        assert config["source_instance_id"] == dc_host and config["scope"] == "domain"
    bindings = sql(f"""select count(*) from sli_agent_snapshot_bindings
        where agent_id='{dc}' and domain_sid='{SID}' and enabled""")
    assert bindings == "2"
    evidence("beta_dc_bindings", {"enabled": int(bindings), "same_agent": True, "domain": DOMAIN})

    evidence("stage", "manual_assignments")
    def assign(agent, module, enabled, config, revision, observe_error=False):
        return owner(ASSIGN, {"agent_id": agent, "module_id": module, "enabled": enabled,
                            "config": config, "expected_revision": revision}, observe_error=observe_error)

    gpo_config = modules(dc_confirmed)[GPO_SNAPSHOT]["config"]
    off = assign(dc, GPO_SNAPSHOT, False, gpo_config, dc_confirmed["policy_revision"])
    expected(off, {AD: True, AD_SNAPSHOT: True, GPO_SNAPSHOT: False})
    dc_off = dc_api(IDENTITY)
    expected(dc_off, {AD: True, AD_SNAPSHOT: True, GPO_SNAPSHOT: False})
    on = assign(dc, GPO_SNAPSHOT, True, gpo_config, dc_off["policy_revision"])
    dc_on = dc_api(IDENTITY)
    expected(on, {AD: True, AD_SNAPSHOT: True, GPO_SNAPSHOT: True})
    expected(dc_on, {AD: True, AD_SNAPSHOT: True, GPO_SNAPSHOT: True})
    assert dc_on["policy_revision"] == dc_confirmed["policy_revision"] + 2
    evidence("manual_gpo", {"off_revision": dc_off["policy_revision"], "on_revision": dc_on["policy_revision"],
                            "same_dc": True, "domain": DOMAIN})

    manual_ws = assign(ws, WORKSTATION, True, {}, ws_initial["policy_revision"], observe_error=True)
    ws_manual_check = ws_api(IDENTITY)
    plugin = json.loads(sql("""select to_jsonb(record) from (
        select package_lifecycle,desired_activation from plugin_installations_v1
        where plugin_id='sli.workstations') record""") or "null")
    station_count = int(sql(f"""select count(*) from servers where is_active and role='workstation'
        and (lower(fqdn)='{WS}' or lower(hostname)='{WS}')"""))
    if "http_status" in manual_ws:
        assert (manual_ws["http_status"], manual_ws["error"]) in {
            (503, "module_disabled"), (409, "agent_source_not_bound"),
        }, "unexpected_manual_workstation_error"
        expected(ws_manual_check, {})
        assert ws_manual_check["policy_revision"] == ws_initial["policy_revision"]
        evidence("manual_workstation", {**manual_ws, "check_in": brief(ws_manual_check), "plugin": plugin,
                                        "inventory_matches": station_count})
    else:
        expected(manual_ws, {WORKSTATION: True})
        expected(ws_manual_check, {WORKSTATION: True})
        assert ws_manual_check["policy_revision"] == ws_initial["policy_revision"] + 1
        evidence("manual_workstation", {"http_status": 200, "check_in": brief(ws_manual_check), "plugin": plugin,
                                        "inventory_matches": station_count})

    evidence("stage", "full_initial_assignments")
    with full_profile():
        ws_full, _, ws_full_api = enroll(owner, root, "full-ws", "workstation", WS, owner_approved=True)
        full_ws_saved = stored(ws_full)
        ws_full_check = ws_full_api(IDENTITY)
        full_ws_binding = sql(f"select count(*) from workstation_journal_grants412 where agent_id='{ws_full}' and enabled")
        evidence("full_workstation_initial", {
            "saved": brief(full_ws_saved), "check_in": brief(ws_full_check),
            "enabled_journal_grants": int(full_ws_binding),
        })
        expected(full_ws_saved, {WORKSTATION: True})
        full_ws_policy = modules(full_ws_saved)[WORKSTATION]["config"]
        assert full_ws_policy["allow_event_ids"] is None
        assert full_ws_policy["families"]["processes"] and full_ws_policy["families"]["usb"]
        assert set(modules(ws_full_check)) == {WORKSTATION}

        dc_full, _, dc_full_api = enroll(owner, root, "full-dc", "domain_controller", DC, owner_approved=True)
        full_dc_saved = stored(dc_full)
        dc_full_check = dc_full_api(IDENTITY)
        evidence("full_dc_initial", {"saved": brief(full_dc_saved), "check_in": brief(dc_full_check),
                                     "profile_change": "guest_systemd_environment", "enrollment": "owner_key_bound"})
        expected(full_dc_saved, {AD: True})
        expected(dc_full_check, {AD: True})
        assert modules(dc_full_check)[AD]["config"]["allow_event_ids"] is None
        assert not dc_full_check.get("dc_identity_required")

        evidence("source_lifecycle", {
            "distinct_hostnames": 2, "beta_workstation": stored(ws)["status"], "beta_dc": stored(dc)["status"],
            "full_workstation": stored(ws_full)["status"], "full_dc": stored(dc_full)["status"],
        })

    evidence("completed", {"beta": "verified", "full": "observed", "profile_restored": True})


if __name__ == "__main__":
    os.umask(0o077)
    with TemporaryDirectory(prefix="t40-enrollment-") as directory:
        try:
            main(Path(directory))
        except Exception as error:
            frame = traceback.extract_tb(error.__traceback__)[-1]
            evidence("fixture_error", {"kind": type(error).__name__, "line": frame.lineno,
                                      "message": str(error) if isinstance(error, AssertionError) else None})
            raise
