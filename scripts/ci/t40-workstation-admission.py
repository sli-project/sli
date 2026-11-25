"""Check full workstation enrollment against an existing synthetic inventory record."""

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
WS = "ws-t40-bound.directory.invalid"
EVENT_IDS = [1102, 4624, 4625, 4698, 4732, 4733, 5001, 5010, 5012, 7036, 7040, 7045]
WORKSTATION = "sli.workstations"
ASSIGN = "/api/v1/admin/agents/modules"
IDENTITY = "/api/v1/agent/identity"
DOMAIN = "directory.invalid"
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
            failure = json.loads(err.read())
            reason = code(failure.get("error"))
        except (TypeError, AttributeError, ValueError):
            failure, reason = {}, None
        if observe_error:
            result = {"http_status": err.code, "error": reason}
            allowed = failure.get("allowed_event_ids")
            if isinstance(allowed, list) and all(type(value) is int for value in allowed):
                result["allowed_event_ids"] = allowed
            return result
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


def enroll(owner, root):
    key = ec.generate_private_key(ec.SECP256R1())
    host = str(uuid4())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    ).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode("ascii")
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    grant = owner("/api/v1/admin/agent-tokens", {
        "host_id": host, "key_fingerprint": hashlib.sha256(public).hexdigest(),
        "registration_host_name": WS,
    })
    token = grant["token"]
    trust = ssl.create_default_context(cafile=CA)
    result = request(client(trust), "/api/v1/agent/enroll", {
        "token": token, "csr_pem": csr, "machine_role": "workstation", "reported_hostname": WS,
    })
    agent = str(UUID(result["agent_id"]))
    cert_chain = result["ca_chain_pem"]
    if isinstance(cert_chain, list):
        cert_chain = "\n".join(cert_chain)
    cert_path = root / "workstation.crt"
    cert_path.write_text(result["certificate_pem"] + "\n" + cert_chain, encoding="ascii")
    key_path = root / "workstation.key"
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


def seed_inventory(owner):
    # Retain only the servers-row setup from the signed workstation fixture.
    # Enrollment and admission are exercised through separate product APIs.
    result = owner("/api/v1/setup/domains", {"fqdn": DOMAIN, "forest": DOMAIN})
    assert result["item"]["fqdn"] == DOMAIN
    assert sql(f"select count(*) from servers where lower(fqdn)='{WS}'") == "0"
    command = f"""insert into public.servers(domain_id,hostname,fqdn,role)
        select id,'{WS}','{WS}','workstation'
        from public.domains where fqdn='{DOMAIN}' and not is_archived
        returning id"""
    station_id = int(subprocess.check_output(PSQL + ["-c", command], text=True).strip())
    assert station_id > 0
    evidence("inventory_fixture", {"computer": WS, "server_id": station_id, "matches": 1})
    return station_id


def journal_grants(agent):
    return json.loads(sql(f"""select coalesce(json_agg(json_build_object(
        'server_id',server_id,'computer',computer,'source_id',source_id,'revision',config->>'policy_revision',
        'event_ids',config->'allow_event_ids')), '[]'::json)
        from public.workstation_journal_grants412 where agent_id='{agent}' and enabled"""))


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
    assert sql("select public.workstation_runtime_enabled_v376()") == "t", "workstations_plugin_not_ready"

    evidence("stage", "inventory_fixture")
    station_id = seed_inventory(owner)

    evidence("stage", "full_workstation_enrollment")
    with full_profile():
        agent, host, agent_api = enroll(owner, root)
        initial = stored(agent)
        grants_before = journal_grants(agent)
        effective = agent_api(IDENTITY)
        evidence("bound_full_default", {"saved": brief(initial), "check_in": brief(effective),
            "inventory_matches": 1, "enabled_journal_grants": len(journal_grants(agent))})
        expected(initial, {WORKSTATION: True})
        assert initial["policy_revision"] == 2 and not grants_before
        enabled = modules(initial)[WORKSTATION]["config"]
        assert enabled["allow_event_ids"] is None and enabled["families"]["processes"] and enabled["families"]["usb"]
        expected(effective, {WORKSTATION: False})
        assert effective["policy_revision"] == 3 and not journal_grants(agent)

        def assign(config, revision, observe_error=False):
            return owner(ASSIGN, {"agent_id": agent, "module_id": WORKSTATION, "enabled": True,
                "config": config, "expected_revision": revision}, observe_error=observe_error)

        evidence("stage", "manual_full_profile_rejection")
        refusal = assign({}, effective["policy_revision"], observe_error=True)
        evidence("empty_reenable", refusal)
        assert refusal == {"http_status": 400, "error": "workstation_journal_profile_unsupported",
                           "allowed_event_ids": EVENT_IDS}
        assert stored(agent)["assigned_modules"] == effective["assigned_modules"]
        assert stored(agent)["policy_revision"] == effective["policy_revision"]
        assert not journal_grants(agent)

        evidence("stage", "manual_journal_profile")
        allowed = {"allow_event_ids": EVENT_IDS, "families": {"processes": False, "usb": False}}
        approved = assign(allowed, effective["policy_revision"])
        verified = agent_api(IDENTITY)
        expected(approved, {WORKSTATION: True})
        expected(verified, {WORKSTATION: True})
        assert approved["policy_revision"] == verified["policy_revision"] == 4
        config = modules(verified)[WORKSTATION]["config"]
        grants = journal_grants(agent)
        assert grants == [{"server_id": station_id, "computer": WS, "source_id": host, "revision": "4",
                           "event_ids": EVENT_IDS}]
        assert config["allow_event_ids"] == EVENT_IDS
        assert config["families"]["processes"] is False and config["families"]["usb"] is False
        evidence("manual_grant", {"http_status": 200, "check_in": brief(verified),
            "enabled_journal_grants": len(grants), "station_id_matches": True, "source_id_matches": True,
            "event_ids": EVENT_IDS, "processes": config["families"]["processes"], "usb": config["families"]["usb"]})

        evidence("stage", "manual_empty_resave")
        saved = assign({}, verified["policy_revision"])
        repeated = agent_api(IDENTITY)
        expected(saved, {WORKSTATION: True})
        expected(repeated, {WORKSTATION: True})
        assert saved["policy_revision"] == repeated["policy_revision"] == 5
        after = modules(repeated)[WORKSTATION]["config"]
        assert after == {**config, "policy_revision": "5"}
        assert journal_grants(agent) == [{**grants[0], "revision": "5"}]
        evidence("manual_empty_resave", {"check_in": brief(repeated), "same_profile": True,
            "enabled_journal_grants": 1})

    evidence("completed", {"full": "observed", "manual": "verified", "profile_restored": True})


if __name__ == "__main__":
    os.umask(0o077)
    with TemporaryDirectory(prefix="t40-workstation-") as directory:
        try:
            main(Path(directory))
        except Exception as error:
            frame = traceback.extract_tb(error.__traceback__)[-1]
            evidence("fixture_error", {"kind": type(error).__name__, "line": frame.lineno,
                                      "message": str(error) if isinstance(error, AssertionError) else None})
            raise
