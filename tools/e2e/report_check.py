"""GET-only report smoke check using existing protected report keys (#515).

Run with --domain-key ID=FILE once per domain. Each file must contain a key
issued for that domain and its explicitly selected file/workstation sources.
No keys are issued and no database connections are made by this command.
Requires GNU timeout and curl; the secret travels through stdin, never argv.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit

REPORTS = (
    "events.journal", "security.events.chains", "ad.users.v2", "ad.infrastructure",
    "ad.gpo.v2", "security.problems",
    "vpn.accounts", "vpn.connections",
    *("file-audit." + tab for tab in (
        "overview", "actions", "mass-operations", "permission-changes",
        "access-denials", "out-of-hours", "permissions", "audit-state")),
    *("workstations." + tab for tab in ("logons", "processes", "usb", "protection")),
)
VPN_CONNECTION_TABS = (
    "employees", "session_overlap", "daily", "departments", "entitlements",
    "failed", "authorizations", "policy_denials", "policy_denials_growth",
    "policy_denials_events", "windows", "windows_heatmap",
)
STATES = frozenset({"ok", "empty", "partial", "processing", "stale", "not_collected",
                    "denied", "error", "not_installed"})
FAILED_STATES = frozenset({"denied", "error", "not_installed", "invalid_response"})
TIME_FIELDS = ("time_created_utc", "observed_at", "last_seen_utc", "activity_at")
DEFAULT_OUTPUT = Path("artifacts/REPORTS_NOW.md")


def utc_stamp(value):
    """Normalize only real dates; arbitrary API strings never enter the output."""
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return None
        return stamp.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def parse_response(payload, *, source=None):
    """Summarize the primary returned page, not totals or auxiliary collections."""
    if (not isinstance(payload, dict) or not isinstance(payload.get("state"), str)
            or payload["state"] not in STATES):
        raise ValueError("invalid_response")
    rows = payload.get("items")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("invalid_response")
    more = payload.get("has_more", False)
    if type(more) is not bool:
        raise ValueError("invalid_response")
    if source:
        collections = payload.get("collections")
        # The access boundary removes all collections for a denied report.
        if payload["state"] == "denied" and not rows and collections == {} and not more:
            return {"rows": None, "latest": None, "state": "denied", "has_more": False}
        rows = collections.get(source) if isinstance(collections, dict) else None
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("invalid_response")
    stamps = [stamp for row in rows for field in TIME_FIELDS
              if (stamp := utc_stamp(row.get(field))) is not None]
    # Mass-operation findings carry their observation window in details.
    for row in rows:
        details = row.get("details")
        if isinstance(details, dict) and (stamp := utc_stamp(details.get("window_end"))):
            stamps.append(stamp)
    latest = max(stamps).isoformat() if stamps else None
    return {"rows": len(rows), "latest": latest, "state": payload["state"], "has_more": False if source else more}


def report_query(report, domain_id, now, *, tab=None):
    start = (now - timedelta(hours=24)).isoformat()
    end = now.isoformat()
    query = {"limit": 50, "tz": "UTC"}
    if report == "ad.users.v2":
        query.update(tab="all", account_state="enabled")  # Current enabled users, not a time-filtered journal.
    elif report == "vpn.accounts":
        pass  # Current AD membership; this declaration has no period/domain params.
    elif report == "security.problems":
        query.update(domain=domain_id, time_from=start, time_to=end)
    else:
        query.update(period="custom", **{"from": start, "to": end})
        if report in {"security.events.chains", "vpn.connections"}:
            query["domain"] = domain_id
        if report == "vpn.connections":
            query.update(tab=tab or "employees", overlap_complete="false")
    # Journal/users and plugin reports use the exact scope of the supplied key.
    return query


def read_key(path):
    with Path(path).open(encoding="utf-8-sig") as source:
        mode = os.fstat(source.fileno()).st_mode
        if not stat.S_ISREG(mode) or (os.name != "nt" and mode & 0o077):
            raise ValueError("key_file_not_protected")
        token = source.read(512).strip()
    if not re.fullmatch(r"adl_[A-Za-z0-9_-]{32,128}", token):
        raise ValueError("key_file_invalid")
    return token


def fetch_report(base_url, report, query, token, *, deadline, ca_file=None):
    """Kill each network subprocess on timeout; discard all private diagnostics."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {"http": "TIMEOUT", "state": "timeout", "rows": None, "latest": None}
    budget = min(8.0, remaining)
    url = base_url.rstrip("/") + "/api/v2/reports/" + report + "/data?" + urlencode(query)
    args = ["timeout", "-k", "0.2s", f"{budget:.3f}s", "curl", "--disable",
            "--silent", "--max-time", f"{budget:.3f}", "--max-filesize", "4194304",
            "--proto", "=http,https", "--request", "GET", "--config", "-",
            "--write-out", "\n%{http_code}", "--url", url]
    if ca_file:
        args.extend(["--cacert", str(ca_file)])
    try:
        completed = subprocess.run(
            args, input=f'header = "Authorization: Bearer {token}"\n',
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=budget + 0.5, check=False,
        )
        if completed.returncode:
            return {"http": "TIMEOUT" if completed.returncode in {28, 124, 137} else "ERROR",
                    "state": "request_failed", "rows": None, "latest": None}
        body, _, status = completed.stdout.rpartition("\n")
        if not re.fullmatch(r"[1-5][0-9]{2}", status):
            raise ValueError("invalid_response")
        http = int(status)
        if http != 200:
            return {"http": http, "state": "authentication_failed" if http == 401 else "http_error",
                    "rows": None, "latest": None}
        try:
            source = query.get("tab") if report == "vpn.connections" else None
            return {"http": http, **parse_response(json.loads(body), source=None if source == "employees" else source)}
        except (ValueError, TypeError):
            return {"http": http, "state": "invalid_response", "rows": None, "latest": None}
    except subprocess.TimeoutExpired:
        return {"http": "TIMEOUT", "state": "timeout", "rows": None, "latest": None}
    except (OSError, ValueError):
        return {"http": "ERROR", "state": "request_failed", "rows": None, "latest": None}


def check_reports(base_url, domain_keys, *, seconds=55, ca_file=None):
    deadline = time.monotonic() + seconds
    now = datetime.now(timezone.utc)
    jobs = [(index, domain, token, report, tab) for index, (domain, token) in enumerate(domain_keys, 1)
            for report in REPORTS
            for tab in (VPN_CONNECTION_TABS if report == "vpn.connections" else (None,))]

    def check(job):
        index, domain, token, report, tab = job
        return {"domain": index, "report": report, "tab": tab, **fetch_report(
            base_url, report, report_query(report, domain, now, tab=tab), token,
            deadline=deadline, ca_file=ca_file)}

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(check, jobs))
    return results, now


def render_results(results, now):
    failed = any(row["http"] != 200 or row["state"] in FAILED_STATES for row in results)
    lines = ["# REPORTS_NOW", "", "failed" if failed else "verified", "",
             f"UTC: {now.isoformat()}; окно: 24 часа.", "",
             "Строки и последняя дата относятся к полученной странице или выбранной коллекции; «+» — есть ещё страницы.",
             "ad.users.v2: текущий снимок включённых пользователей (tab=all, account_state=enabled), дата — последняя активность среди полученных пользователей.",
             "vpn.accounts: текущий снимок доступа AD; vpn.connections: все вкладки, строки относятся к выбранной вкладке.",
             "Домены обозначены порядковыми номерами; область журнала/пользователей и источников плагинов задаёт ключ каждого домена.",
             "HTTP 200 и строки не подтверждают полноту сбора; состояние API приведено отдельно.", "",
             "| Домен | Отчёт | Вкладка | HTTP | Строк | Последняя строка (UTC) | Состояние |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for row in results:
        count = "—" if row["rows"] is None else str(row["rows"]) + ("+" if row.get("has_more") else "")
        lines.append(f"| {row['domain']} | {row['report']} | {row.get('tab') or '—'} | {row['http']} | {count} | "
                     f"{row['latest'] or '—'} | {row['state']} |")
    if any(row["http"] == 401 for row in results):
        lines.extend(["", "HTTP 401: ключ не принят при аутентификации (возможны истёкший срок, отзыв или неверный ключ).",
                      "Скрипт передаёт Authorization: Bearer; проверьте метаданные используемого ключа.",
                      "Если ключ истёк, перевыпустите его штатной командой #515 в защищённый файл для нужного домена",
                      "и явно выбранных источников. Обновление приложения не продлевает срок ключа или его назначений."])
    return "\n".join(lines) + "\n", failed


def domain_key(value):
    domain, separator, path = value.partition("=")
    if not separator or not domain.isascii() or not domain.isdecimal() or int(domain) < 1 or not path:
        raise argparse.ArgumentTypeError("expected positive domain ID=protected key file")
    return int(domain), Path(path)


def api_url(value):
    parts = urlsplit(value)
    if (parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password
            or parts.path not in {"", "/"} or parts.query or parts.fragment
            or (parts.scheme == "http" and parts.hostname not in {"127.0.0.1", "localhost", "::1"})):
        raise argparse.ArgumentTypeError("expected HTTPS API origin or local HTTP origin")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", type=api_url, default="https://127.0.0.1:8443")
    parser.add_argument("--domain-key", type=domain_key, action="append", required=True,
                        help="domain ID=protected #515 key file; repeat for every domain")
    parser.add_argument("--ca-file", type=Path, help="CA for the running SLI HTTPS endpoint")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    if len({domain for domain, _ in args.domain_key}) != len(args.domain_key):
        parser.error("duplicate domain ID")
    protected = [path for _, path in args.domain_key] + ([args.ca_file] if args.ca_file else [])
    if any(args.output.resolve() == path.resolve() or
           (args.output.exists() and path.exists() and args.output.samefile(path)) for path in protected):
        parser.error("output must not overwrite protected inputs")
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text("# REPORTS_NOW\n\nin_progress: проверка API за 24 часа.\n", encoding="utf-8")
        keys = [(domain, read_key(path)) for domain, path in args.domain_key]
        if not all(shutil.which(command) for command in ("timeout", "curl")):
            raise ValueError("network_tools_unavailable")
        results, now = check_reports(args.base_url, keys, ca_file=args.ca_file)
        markdown, failed = render_results(results, now)
        args.output.write_text(markdown, encoding="utf-8")
        print(markdown, end="")
        return int(failed)
    except (OSError, ValueError):
        message = "# REPORTS_NOW\n\nfailed: проверьте защищённые файлы ключей, доступность timeout/curl и выходного файла.\n"
        try:
            args.output.write_text(message, encoding="utf-8")
        except OSError:
            pass
        print(message, end="")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
