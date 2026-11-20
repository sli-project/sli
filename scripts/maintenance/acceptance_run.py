"""Read-only operational probes; never perform backup, restore or recovery actions."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import ssl
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

SERVICES = (
    "postgres", "clickhouse", "warm-tier", "migrate", "api", "backup",
    "post-collection", "what-where-when", "semantic", "entity-state",
    "storage-lifecycle", "ad-snapshot-manifest-coordinator", "remote-access",
)
REPORTS = ("ad.users.v2", "ad.computers.v6", "vpn.connections")
REPORT_STATES = {"ok", "empty", "partial", "stale", "unavailable", "denied"}
BACKUP_ID = re.compile(r"\d{8}T\d{6}\.\d{6}Z")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]*")
SECRET_PATTERNS = {
    "credential_assignment": re.compile(
        r'''(?ix)["']?\b(?:[a-z0-9]+[_-])*(?:password|passwd|pwd|token|access_token|refresh_token|api[_-]?key|client_secret)
        \b["']?\s*[:=]\s*["']?(?!\*|\[redacted\]|<redacted>|redacted\b|null\b|none\b|false\b|true\b)[^\s"',;}{]+'''
    ),
    "authorization": re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_.=-]{8,}"),
    "url_credentials": re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
}


@dataclass(frozen=True)
class Settings:
    project: str
    base_url: str
    compose_files: tuple[str, ...]
    backup_dir: Path
    restore_result: Path
    token_file: Path | None = None
    ca_file: str | None = None
    env_file: str | None = None
    services: tuple[str, ...] = SERVICES
    reports: tuple[str, ...] = REPORTS
    log_lines: int = 1000
    max_age_hours: float = 26
    timeout: float = 15
    allow_production_readonly: bool = False
    login_user_file: Path | None = None


def validate(settings: Settings) -> None:
    # Guard before HTTP, Docker, credential or evidence reads.
    if settings.project.lower() == "sli" and not settings.allow_production_readonly:
        raise ValueError("production_project_refused")
    if not PROJECT.fullmatch(settings.project):
        raise ValueError("invalid_project")
    url = urlsplit(settings.base_url)
    if (url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password
            or url.path not in {"", "/"} or url.query or url.fragment
            or any(char.isspace() for char in settings.base_url)):
        raise ValueError("invalid_base_url")
    if url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("https_required")
    if (not settings.compose_files or not 1 <= settings.log_lines <= 100000
            or not 0 < settings.timeout <= 300 or not 0 < settings.max_age_hours <= 8760):
        raise ValueError("invalid_limits")
    if not settings.services or any(not PROJECT.fullmatch(service) for service in settings.services):
        raise ValueError("invalid_services")
    if not settings.reports or any(not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,79}", key) for key in settings.reports):
        raise ValueError("invalid_reports")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the API credential to a redirect target.
        return None


class Probes:
    def __init__(self, settings: Settings):
        self.settings = settings

    def command(self, arguments: list[str]) -> str:
        result = subprocess.run(arguments, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=self.settings.timeout, check=False)
        if result.returncode:
            raise RuntimeError("command_failed")
        return result.stdout + result.stderr if arguments[1] == "logs" else result.stdout

    def compose(self, arguments: list[str]) -> str:
        command = ["docker", "compose", "-p", self.settings.project]
        for file in self.settings.compose_files:
            command.extend(["-f", file])
        if self.settings.env_file:
            command.extend(["--env-file", self.settings.env_file])
        return self.command([*command, *arguments])

    def http(self, path: str, *, payload: dict | None = None, token: str | None = None) -> tuple[int, dict]:
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            headers["Origin"] = self.settings.base_url.rstrip("/")
            body = json.dumps(payload).encode("utf-8")
        request = Request(self.settings.base_url.rstrip("/") + path, data=body, headers=headers)
        context = ssl.create_default_context(cafile=self.settings.ca_file)
        opener = build_opener(NoRedirect(), HTTPSHandler(context=context))
        try:
            response = opener.open(request, timeout=self.settings.timeout)
        except HTTPError as exc:
            response = exc
        with response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("response_too_large")
            document = json.loads(raw)
            if not isinstance(document, dict):
                raise ValueError("invalid_response")
            return response.code, document


def scan_secrets(logs: str) -> dict[str, int]:
    """Only pattern names and counts escape; never return matching text."""
    return {name: len(pattern.findall(logs)) for name, pattern in SECRET_PATTERNS.items()
            if pattern.search(logs)}


def recent(value: str, now: datetime, max_age_hours: float) -> bool:
    timestamp = datetime.fromisoformat(value)
    return timestamp.tzinfo is not None and 0 <= (now - timestamp).total_seconds() <= max_age_hours * 3600


def read_backup(settings: Settings, now: datetime) -> tuple[Path, dict, str]:
    paths = sorted(path for path in settings.backup_dir.iterdir()
                   if BACKUP_ID.fullmatch(path.name) and path.is_dir() and not path.is_symlink())
    if not paths:
        raise ValueError("backup_missing")
    newest = paths[-1]
    raw = (newest / "manifest.json").read_bytes()
    manifest = json.loads(raw)
    if (manifest["status"] != "success" or manifest["format_version"] != 1
            or manifest["backup_id"] != newest.name
            or not recent(manifest["completed_at_utc"], now, settings.max_age_hours)):
        raise ValueError("backup_invalid_or_stale")
    for component, relative in (("postgres", "postgres/toc.dat"), ("history", "history.zip"), ("warm", "warm.zip")):
        path = newest / relative
        if not path.resolve().is_relative_to(newest.resolve()) or not path.is_file() or path.stat().st_size <= 0:
            raise ValueError("backup_component_missing")
        info = manifest["components"][component]
        if info["size_bytes"] <= 0:
            raise ValueError("backup_component_invalid")
        if component != "postgres" and (info["archive"] != relative or info["size_bytes"] != path.stat().st_size):
            raise ValueError("backup_archive_mismatch")
    return newest, manifest, hashlib.sha256(raw).hexdigest()


def check_restore(settings: Settings, manifest: dict, digest: str, now: datetime) -> bool:
    receipt = json.loads(settings.restore_result.read_text(encoding="utf-8"))
    return (
        receipt["format_version"] == 1 and receipt["status"] == "passed"
        and receipt["source_project"] == settings.project
        and PROJECT.fullmatch(receipt["target_project"]) is not None
        and receipt["target_project"] not in {settings.project, "sli"}
        and receipt["backup_id"] == manifest["backup_id"] and receipt["manifest_sha256"] == digest
        and recent(receipt["completed_at_utc"], now, settings.max_age_hours)
        and datetime.fromisoformat(receipt["completed_at_utc"]) >= datetime.fromisoformat(manifest["completed_at_utc"])
        and receipt["cleanup_passed"] is True
        and receipt.get("fresh_password_login_verified") is True
        and all(receipt["components"][name]["status"] == "passed"
                and receipt["components"][name]["counts_match"] is True for name in ("postgres", "history", "warm"))
        and receipt["components"]["postgres"]["ledger_match"] is True
    )


def run_checks(settings: Settings, probes: Probes | None = None, *, now: datetime | None = None) -> dict:
    validate(settings)
    probes = probes or Probes(settings)
    now = now or datetime.now(timezone.utc)
    checks = []

    def record(name, action):
        try:
            passed, evidence = action()
            checks.append({"check": name, "status": "passed" if passed else "failed", "evidence": evidence})
        except Exception:  # noqa: BLE001 - raw HTTP, SQL, paths and logs must never escape
            checks.append({"check": name, "status": "failed", "evidence": {"code": "probe_failed"}})

    def health(path, ready=False):
        status, payload = probes.http(path)
        passed = status == 200 and (payload.get("ready") is True if ready else payload.get("status") == "ok")
        return passed, {"http_status": status}

    for path in ("/api/health", "/api/health/live", "/api/health/ready"):
        record("health:" + path, lambda path=path: health(path, path.endswith("/ready")))

    containers = []

    def inventory():
        raw = probes.compose(["ps", "--all", "--format", "json"])
        rows = json.loads(raw) if raw.lstrip().startswith("[") else [json.loads(line) for line in raw.splitlines() if line.strip()]
        if not rows or any(not isinstance(row, dict) for row in rows):
            return False, {"code": "empty_or_invalid_inventory"}
        for row in rows:
            identifier = row["ID"]
            if not re.fullmatch(r"[a-f0-9]{12,64}", identifier):
                raise ValueError("invalid_container_id")
            labels = json.loads(probes.command(["docker", "inspect", "--format", "{{json .Config.Labels}}", identifier]))
            if labels.get("com.docker.compose.project") != settings.project:
                raise ValueError("project_mismatch")
        containers.extend(rows)
        return True, {"containers": len(rows)}

    record("services:inventory", inventory)
    for service in settings.services:
        def service_check(service=service):
            rows = [row for row in containers if row.get("Service") == service]
            passed = bool(rows) and all(
                row.get("State") == "exited" and row.get("ExitCode") == 0 if service == "migrate"
                else row.get("State") == "running" and row.get("Health") == "healthy" for row in rows
            )
            return passed, {"containers": len(rows), "states": [
                {"state": row.get("State") if row.get("State") in {"running", "exited", "created", "restarting", "paused", "dead"} else "invalid",
                 "health": row.get("Health") if row.get("Health") in {"healthy", "unhealthy", "starting", ""} else "invalid",
                 "exit_code": row.get("ExitCode") if type(row.get("ExitCode")) is int else None}
                for row in rows
            ]}
        record("service:" + service, service_check)

    # Inventory failure also fails the log scan; an empty list cannot be a clean scan.
    if not containers:
        record("logs:inventory", lambda: (False, {"code": "no_verified_containers"}))
    for index, row in enumerate(containers):
        def log_check(row=row):
            logs = probes.command(["docker", "logs", "--tail", str(settings.log_lines), "--timestamps", row["ID"]])
            matches = scan_secrets(logs)
            return not matches, {"patterns": matches, "tail_limit": settings.log_lines}
        record(f"logs:{index + 1}", log_check)

    def bad_login():
        # Use a dedicated synthetic test account, never the platform owner.
        username = (settings.login_user_file.read_text(encoding="utf-8").strip()
                    if settings.login_user_file else "acceptance-probe")
        if not username or any(char in username for char in "\r\n\0"):
            return False, {"code": "login_probe_account_invalid"}
        status, payload = probes.http("/api/auth/login", payload={
            "username": username, "password": secrets.token_urlsafe(32),
        })
        return status == 401 and payload.get("error") == "invalid_credentials", {"http_status": status}

    record("login:bad_password", bad_login)
    for key in settings.reports:
        def report_check(key=key):
            if settings.token_file is None:
                return False, {"code": "report_credential_required"}
            token = settings.token_file.read_text(encoding="utf-8").strip()
            if not token or any(char.isspace() for char in token):
                return False, {"code": "report_credential_invalid"}
            status, payload = probes.http(f"/api/v2/reports/{key}/data?limit=1", token=token)
            state = payload.get("state")
            passed = isinstance(state, str) and state in REPORT_STATES and (
                status == 200 or (status == 403 and state == "denied") or (status == 503 and state == "unavailable")
            )
            return passed, {"http_status": status, "state": state if isinstance(state, str) and state in REPORT_STATES else "invalid"}
        record("report:" + key, report_check)

    backup = {}

    def backup_check():
        _, manifest, digest = read_backup(settings, now)
        backup.update(manifest=manifest, digest=digest)
        return True, {"manifest_sha256": digest}

    record("backup:recent_complete", backup_check)
    record("restore:receipt", lambda: (
        bool(backup) and check_restore(settings, backup["manifest"], backup["digest"], now),
        {"code": "restore_receipt_checked"},
    ))
    return {"format_version": 1, "status": "passed" if all(check["status"] == "passed" for check in checks) else "failed",
            "checked_at_utc": now.isoformat(), "checks": checks}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--compose-file", action="append", required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--restore-result", type=Path, required=True)
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--login-user-file", type=Path, help="Dedicated synthetic probe account; default acceptance-probe")
    parser.add_argument("--ca-file")
    parser.add_argument("--env-file")
    parser.add_argument("--service", action="append", help="Expected healthy services; replaces default list")
    parser.add_argument("--report", action="append", help="v2 report key; replaces default list")
    parser.add_argument("--log-lines", type=int, default=1000)
    parser.add_argument("--max-age-hours", type=float, default=26)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--allow-production-readonly", action="store_true")
    args = parser.parse_args(argv)
    try:
        settings = Settings(project=args.project, base_url=args.base_url, compose_files=tuple(args.compose_file),
                            backup_dir=args.backup_dir, restore_result=args.restore_result,
                            token_file=args.token_file, ca_file=args.ca_file, env_file=args.env_file,
                            services=tuple(args.service or SERVICES), reports=tuple(args.report or REPORTS),
                            log_lines=args.log_lines, max_age_hours=args.max_age_hours, timeout=args.timeout,
                            allow_production_readonly=args.allow_production_readonly, login_user_file=args.login_user_file)
        result = run_checks(settings)
    except ValueError as exc:
        code = "production_project_refused" if str(exc) == "production_project_refused" else "configuration_refused"
        result = {"format_version": 1, "status": "failed", "checks": [
            {"check": "configuration", "status": "failed", "evidence": {"code": code}},
        ]}
    print(json.dumps(result, indent=2, sort_keys=True))
    print("Acceptance probes: " + result["status"], file=sys.stderr)
    for check in result["checks"]:
        print(f"{check['status'].upper()} {check['check']}", file=sys.stderr)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
