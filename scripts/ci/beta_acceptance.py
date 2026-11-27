#!/usr/bin/env python3
"""Probe the installed beta in the guest and publish its measured results on the runner."""

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import ssl
import time
from dataclasses import dataclass
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import urlencode, urlsplit


HOME = "/api/v1/home/summary"
PROBLEMS = "/api/v2/reports/security.problems/data"
# Same AD hygiene rules as the installed quiet-Home acceptance harness.
HYGIENE = {
    "qw.ad-hardening.privileged-nonexpiring",
    "qw.ad-hardening.machine-account-quota",
    "qw.ad-hardening.lockout-threshold",
}
METRICS = {
    "install": ("commands", "elapsed_ms", "readiness_http"),
    "login": ("initial_http", "gate_http", "gate_api_http", "change_http", "app_http", "home_http", "elapsed_ms"),
    "quiet": ("open_count", "hygiene", "other"),
}
NOTES = {
    "release_failed": "Could not select the published release.",
    "kit_failed": "Could not download and verify the release kit.",
    "vm_failed": "The clean Debian VM did not return a complete result.",
    "not_reached": "An earlier check prevented this measurement.",
    "port_check": "The documented PostgreSQL port check failed.",
    "archive_check": "The documented checksum or extraction command failed.",
    "installer": "The documented installer command failed.",
    "readiness": "The .NET service did not confirm PostgreSQL readiness.",
    "runtime_identity": "The installed .NET service did not confirm the selected commit.",
    "install_limits": "Installation exceeded three commands or 30 minutes.",
    "ca_fingerprint": "The installed CA fingerprint could not be verified against setup output.",
    "initial_login": "Initial sign-in did not require a password change.",
    "password_gate": "The restricted session did not require a password change before opening Home.",
    "password_change": "The password change did not issue an authenticated replacement session.",
    "dotnet_home": "The authenticated .NET Home page or its API did not open.",
    "home_count_unavailable": "Home did not return a measured open-problem count.",
    "queue_count_mismatch": "Could not reconcile the Home count with the open Problems report.",
    "quiet_limits": "Expected at most 10 hygiene problems and zero other problems.",
}


class CheckFailed(Exception):
    pass


def require(condition):
    if not condition:
        raise CheckFailed


def natural(value):
    return type(value) is int and value >= 0


def blank_results(reason):
    return {
        name: {"status": "fail", "reason": reason, **dict.fromkeys(metrics)}
        for name, metrics in METRICS.items()
    }


def elapsed_ms(started):
    return round((time.monotonic() - started) * 1000)


@dataclass
class Response:
    status: int
    headers: http.client.HTTPMessage
    data: bytes

    def json(self):
        value = json.loads(self.data)
        require(isinstance(value, dict))
        return value

    def is_html(self):
        return self.status == 200 and self.headers.get_content_type() == "text/html"


class GuestClient:
    def __init__(self):
        runtime = json.loads(Path("/etc/sli/runtime.json").read_text())
        self.url = urlsplit(runtime["health_url"])
        require(self.url.scheme == "https" and self.url.hostname and self.url.path == "/api/health/ready")
        self.ca = Path("/var/lib/sli/tls-ca.crt")
        self.context = ssl.create_default_context(cafile=str(self.ca))
        self.session = ""

    def call(self, path, payload=None):
        headers = {"Accept": "application/json, text/html", "Origin": f"https://{self.url.netloc}"}
        if self.session:
            headers["Cookie"] = f"adlog_session={self.session}"
        method, body = "GET", None
        if payload is not None:
            method, body = "POST", json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection(self.url.hostname, self.url.port, context=self.context, timeout=30)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            limit = 8 * 1024 * 1024
            data = response.read(limit + 1)
            require(len(data) <= limit)
            return Response(response.status, response.headers, data)
        finally:
            connection.close()

    def accept_session(self, response):
        cookies = SimpleCookie()
        cookies.load(response.headers.get("Set-Cookie", ""))
        cookie = cookies.get("adlog_session")
        require(cookie is not None and cookie.value and cookie["secure"] and cookie["httponly"])
        self.session = cookie.coded_value


def first_login(client, login, install_log):
    login["reason"] = "ca_fingerprint"
    observed = hashlib.sha256(ssl.PEM_cert_to_DER_cert(client.ca.read_text())).hexdigest().upper()
    fingerprint_pattern = r"CA SHA-256 fingerprint:\s*((?:[0-9A-F]{2}:){31}[0-9A-F]{2})"
    fingerprints = re.findall(fingerprint_pattern, install_log.read_text(encoding="utf-8", errors="replace"))
    require({fingerprint.replace(":", "") for fingerprint in fingerprints} == {observed})

    login["reason"] = "initial_login"
    response = client.call("/api/auth/login", {"username": "admin", "password": "admin"})
    login["initial_http"] = response.status
    require(response.status == 200 and response.json().get("password_change_required") is True)
    client.accept_session(response)
    restricted_session = client.session

    login["reason"] = "password_gate"
    response = client.call("/app")
    login["gate_http"] = response.status
    location = urlsplit(response.headers.get("Location", ""))
    require(response.status in {301, 302, 303, 307, 308} and location.path == "/login/change-password")
    require(not location.netloc or (location.scheme == "https" and location.netloc == client.url.netloc))
    require(client.call(location.path).is_html())
    response = client.call(HOME)
    login["gate_api_http"] = response.status
    require(response.status == 403 and response.json().get("error") == "password_change_required")

    login["reason"] = "password_change"
    password = secrets.token_urlsafe(30)
    response = client.call("/api/auth/change-initial-password", {"password": password, "repeat": password})
    login["change_http"] = response.status
    require(response.status == 200 and response.json().get("authenticated") is True)
    client.accept_session(response)
    require(client.session != restricted_session)
    response = client.call("/api/auth/me")
    identity = response.json()
    require(response.status == 200 and identity.get("authenticated") is True and identity["principal"]["username"] == "admin")

    login["reason"] = "dotnet_home"
    response = client.call("/app")
    login["app_http"] = response.status
    require(response.is_html() and b'id="root"' in response.data)
    response = client.call(f"{HOME}?contract=v5&period=24h&tz=UTC&queue=all&page=1&limit=100")
    if response.status == 400 and response.json().get("error") == "home_parameters_invalid":
        # Older public betas used the v4 period contract.
        response = client.call(f"{HOME}?contract=v4&period=24h&tz=UTC")
    login["home_http"] = response.status
    require(response.status == 200)
    home = response.json()
    require(isinstance(home.get("domains"), list) and "problems" in home)
    login.update(status="pass", reason=None)
    return home


def open_count(home):
    problems = home.get("problems")
    count = problems.get("open_count") if isinstance(problems, dict) else None
    require(natural(count))
    return count


def quiet_counts(home, read_problems):
    total = open_count(home)
    if total == 0:
        return 0, 0
    domain = home.get("domain_id")
    require(natural(domain) and domain > 0)
    params = {"population": "open", "domain_id": domain, "limit": 100}
    rules = {}
    cursors = set()
    while True:
        page = read_problems(params)
        items = page.get("items")
        require(isinstance(items, list) and items)
        for row in items:
            require(isinstance(row, dict))
            row_id, code = row.get("id"), row.get("rule_code")
            require(natural(row_id) and row_id not in rules and isinstance(code, str) and code)
            rules[row_id] = code
        require(len(rules) <= total)
        if page.get("has_more") is False:
            break
        cursor = page.get("next_cursor")
        require(page.get("has_more") is True and isinstance(cursor, str) and cursor and cursor not in cursors)
        cursors.add(cursor)
        params["cursor"] = cursor
    require(len(rules) == total)
    # v5 exposes the open queue itself. v4's items were recent period problems.
    if "weak_spots" in home:
        items = home["problems"].get("items")
        require(isinstance(items, list) and all(isinstance(row, dict) and row.get("id") in rules for row in items))
    hygiene = sum(code in HYGIENE for code in rules.values())
    return hygiene, total - hygiene


PROBE_ERRORS = (CheckFailed, OSError, ValueError, KeyError, TypeError, http.client.HTTPException, CookieError)


def probe(commit, install_log, phase, commands, started):
    checks = blank_results("not_reached")
    install, login, quiet = (checks[key] for key in METRICS)
    install.update(reason=phase, commands=commands, elapsed_ms=elapsed_ms(started))
    if phase != "readiness":
        return checks
    try:
        client = GuestClient()
        response = client.call(client.url.path)
        install["readiness_http"] = response.status
        ready = response.json()
        require(response.status == 200 and ready.get("ready") is True and ready.get("code") == "ready")
        install["elapsed_ms"] = elapsed_ms(started)
        install["reason"] = "runtime_identity"
        response = client.call("/api/health/live")
        require(response.status == 200 and response.json()["runtime_identity"]["git_commit"] == commit)
    except PROBE_ERRORS:
        install["elapsed_ms"] = elapsed_ms(started)
        return checks
    if 1 <= commands <= 3 and install["elapsed_ms"] <= 1_800_000:
        install.update(status="pass", reason=None)
    else:
        install["reason"] = "install_limits"

    login_started = time.monotonic()
    try:
        home = first_login(client, login, install_log)
    except PROBE_ERRORS:
        return checks
    finally:
        login["elapsed_ms"] = elapsed_ms(login_started)

    def read_problems(params):
        response = client.call(f"{PROBLEMS}?{urlencode(params)}")
        require(response.status == 200)
        return response.json()

    try:
        quiet["reason"] = "home_count_unavailable"
        quiet["open_count"] = open_count(home)
        quiet["reason"] = "queue_count_mismatch"
        hygiene, other = quiet_counts(home, read_problems)
        quiet.update(hygiene=hygiene, other=other)
        if hygiene <= 10 and other == 0:
            quiet.update(status="pass", reason=None)
        else:
            quiet["reason"] = "quiet_limits"
    except PROBE_ERRORS:
        pass
    return checks


def read_guest_results(path):
    # The virtio channel is guest-controlled. Publish only known statuses, reason codes and numbers.
    with path.open("rb") as stream:
        guest = json.loads(stream.read(8192))
    checks = {}
    for name, metrics in METRICS.items():
        row = guest[name]
        status, reason = row["status"], row["reason"]
        require((status == "pass" and reason is None) or (status == "fail" and reason in NOTES))
        require(all(row[key] is None or natural(row[key]) for key in metrics))
        checks[name] = {"status": status, "reason": reason, **{key: row[key] for key in metrics}}
    return checks


def report():
    directory = Path(os.environ["BETA_RESULTS"])
    directory.mkdir(parents=True, exist_ok=True)
    for step in ("release", "kit", "vm"):
        if os.environ[f"{step.upper()}_OUTCOME"] != "success":
            checks = blank_results(f"{step}_failed")
            break
    else:
        try:
            checks = read_guest_results(directory / "guest.json")
        except (CheckFailed, OSError, ValueError, KeyError, TypeError):
            checks = blank_results("vm_failed")

    def validated_env(key, pattern):
        value = os.environ[key]
        return value if re.fullmatch(pattern, value) else None

    release = validated_env("RELEASE", r"beta-[0-9a-f]{12}")
    report_data = {
        "release": release,
        "commit": validated_env("COMMIT", r"[0-9a-f]{40}"),
        "kit_sha256": validated_env("KIT_SHA256", r"[0-9a-f]{64}"),
        "checks": {"1": checks["install"], "2": checks["login"], "6": checks["quiet"]},
    }
    (directory / "beta-acceptance.json").write_text(json.dumps(report_data, indent=2) + "\n", encoding="utf-8")

    def show(value):
        return "—" if value is None else str(value)

    install, login, quiet = (checks[key] for key in METRICS)
    elapsed = install["elapsed_ms"]
    minutes = f"{elapsed / 60_000:.2f}" if elapsed is not None else "—"
    rows = (
        ("1. Public guide installation", install,
         f"{show(install['commands'])} commands · {minutes} min · readiness HTTP {show(install['readiness_http'])}"),
        ("2. First owner sign-in", login,
         f"HTTP {show(login['initial_http'])} sign-in · {show(login['gate_http'])}/{show(login['gate_api_http'])} page/API gate · "
         f"{show(login['change_http'])} change · {show(login['app_http'])}/{show(login['home_http'])} Home page/API"),
        ("6. Quiet Home", quiet, f"{show(quiet['open_count'])} open · "
         f"{show(quiet['hygiene'])} AD hygiene · {show(quiet['other'])} other"),
    )
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
        summary.write(f"## Clean Debian 13 beta acceptance · {release or 'release unresolved'}\n\n")
        summary.write("| Check | Result | Measurement |\n| --- | --- | --- |\n")
        for title, row, measurement in rows:
            note = NOTES.get(row["reason"])
            detail = f" · {note}" if note else ""
            summary.write(f"| {title} | **{row['status'].upper()}** | {measurement}{detail} |\n")
    passed = all(row["status"] == "pass" for row in checks.values())
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as outputs:
        outputs.write(f"passed={str(passed).lower()}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    commands.add_parser("report")
    guest = commands.add_parser("probe")
    guest.add_argument("commit")
    guest.add_argument("install_log", type=Path)
    guest.add_argument("phase", choices=("port_check", "archive_check", "installer", "readiness"))
    guest.add_argument("commands", type=int)
    guest.add_argument("started", type=float)
    args = parser.parse_args()
    if args.mode == "report":
        report()
    else:
        print(json.dumps(probe(args.commit, args.install_log, args.phase, args.commands, args.started)))


if __name__ == "__main__":
    main()
