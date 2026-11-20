"""LAB acceptance exercises. Standard library only; all SLI requests are GETs.

Run with --help. Importing this module never contacts SLI or executes an attack.
"""
from __future__ import annotations

import argparse
import base64
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


HERE = Path(__file__).resolve().parent
WINDOW_SECONDS = 300  # Acceptance criterion, never a service execution limit.
QUEUE = "/api/v2/reports/security.problems/data"
WORKSPACE = "/api/v1/notification-channels/workspace"
ATTACKS = (
    (1, "Подбор пароля", ("semantic.qw.password-brute-force",)),
    (2, "Подбор по многим учётным записям", ("semantic.qw.password-spray",)),
    (3, "Успешный вход после перебора", ("semantic.qw.password-brute-force", "semantic.qw.password-spray")),
    (4, "Kerberoasting", ("semantic.qw.kerberoasting",)),
    (5, "AS-REP", ("semantic.qw.asrep-roasting",)),
    (6, "Добавление в привилегированную группу", ("semantic.qw.privileged-group-addition", "semantic.security.privileged_group_member_added")),
    (7, "Очистка журнала безопасности", ("semantic.qw.security-log-cleared",)),
    (8, "Ослабление аудита", ("semantic.qw.audit-disabled", "semantic.security.audit_controls_changed")),
    (9, "Остановка агента SLI", ("semantic.qw.agent-tamper",)),
    (10, "Новая задача на контроллере домена", ("semantic.security.scheduled_task_created",)),
)
REASONS = {
    "": "—",
    "attack_failed": "Имитация не выполнена",
    "cleanup_failed": "Не удалось вернуть состояние LAB; учения остановлены",
    "cleanup_unverified": "Нет подтверждения возврата состояния LAB; учения остановлены",
    "lab_simulation_busy": "На LAB уже идут учения",
    "api_unavailable": "API SLI не ответил",
    "api_contract_invalid": "Не удалось разобрать ответ API SLI",
    "not_found": "Проблема не появилась за 5 минут",
    "duplicate_problems": "Атака появилась несколькими проблемами",
    "presentation_missing": "Нет русского заголовка или действий",
    "telegram_unverified": "Нет подтверждения Telegram через API",
    "window_exceeded": "Проблема появилась позже 5 минут",
}


class ExerciseError(Exception):
    """Only fixed diagnostic codes may leave a network/process boundary."""


def stamp(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError()
        return result.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError):
        raise ExerciseError("api_contract_invalid") from None


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def parse_page(payload):
    if (not isinstance(payload, dict) or payload.get("error") or
            payload.get("state") in {"error", "denied", "not_collected", "processing"} or
            not isinstance(payload.get("items"), list) or
            any(not isinstance(row, dict) for row in payload["items"]) or
            type(payload.get("has_more")) is not bool):
        raise ExerciseError("api_contract_invalid")
    cursor = payload.get("next_cursor")
    if payload["has_more"] and (not isinstance(cursor, str) or not cursor or len(cursor) > 8192):
        raise ExerciseError("api_contract_invalid")
    return payload["items"], cursor if payload["has_more"] else None


def quiet_snapshot(home, observed_at):
    try:
        count = home["problems_found"]["count"]
        state = home["problems_found"]["state"]
        if type(count) is not int or count < 0:
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ExerciseError("api_contract_invalid") from None
    return {"observed_at_utc": observed_at, "problem_count": count,
            "within_ten": count <= 10 if state in {"ok", "empty"} else None}


def quiet_home_snapshot(home, observed_at):
    if home.get("contract_id") != "sli.home-summary.v3" or "total" not in home:
        raise ExerciseError("api_contract_invalid")
    count = home["total"]
    state = home.get("state")
    if state not in ("ok", "empty", "partial", "stale", "denied", "error"):
        raise ExerciseError("api_contract_invalid")
    if count is not None and (type(count) is not int or count < 0):
        raise ExerciseError("api_contract_invalid")
    if (state == "ok" and not count) or (state == "empty" and count != 0):
        raise ExerciseError("api_contract_invalid")
    return {"observed_at_utc": observed_at, "problem_count": count,
            "within_ten": count <= 10 if state in ("ok", "empty") else None}


def telegram_configured(payload):
    channels = payload.get("channels")
    if not isinstance(channels, list) or any(not isinstance(row, dict) for row in channels):
        raise ExerciseError("api_contract_invalid")
    telegram = [row for row in channels if row.get("kind") == "telegram"]
    if len(telegram) != 1 or type(telegram[0].get("enabled")) is not bool:
        raise ExerciseError("api_contract_invalid")
    return telegram[0]["enabled"]


def delivery_accepted(rows, finding_id, started_at, baseline):
    """Provider acceptance is observable; reading the recipient's phone is not."""
    for row in rows:
        if (row.get("channel") == "telegram" and row.get("object_kind") == "semantic_finding"
                and row.get("finding_id") == finding_id and row.get("state") == "accepted"
                and row.get("id") not in baseline and stamp(row.get("created_at")) >= started_at):
            return True
    return False


def new_problems(rows, attack, baseline, started_at, match_values):
    candidates = []
    for row in rows:
        if row.get("rule_code") not in attack[2] or row.get("status") not in {"new", "confirmed", "repeated"}:
            continue
        if type(row.get("id")) is not int or row["id"] <= 0:
            raise ExerciseError("api_contract_invalid")
        previous = baseline.get(row["id"])
        # updated_at alone can change because somebody assigned or closed a problem.
        last = stamp(row.get("last_seen_utc"))
        if last < started_at or previous is not None and last <= stamp(previous.get("last_seen_utc")):
            continue
        text = json.dumps(row, ensure_ascii=False).casefold()
        if not match_values or not any(value.casefold() in text for value in match_values):
            continue
        code = row.get("title_code")
        if attack[0] == 3 and code != "security.problems.presentation.qw.password-success.title":
            continue
        candidates.append(row)
    return candidates


def result_row(attack, *, found=False, minutes=None, title=None, telegram="unverified", reason="", count=0):
    return {"attack": attack[0], "name": attack[1], "found": found, "minutes": minutes,
            "title": title, "telegram": telegram, "problem_count": count, "reason": reason}


def safe_title(value, token=""):
    text = value if isinstance(value, str) else ""
    if token:
        text = text.replace(token, "[скрыто]")
    text = re.sub(r"adl_[A-Za-z0-9_-]+", "[скрыто]", text)
    return " ".join(text.split())[:512]


def markdown(report):
    def cell(value):
        return html.escape(str(value), quote=False).replace("|", "&#124;").replace("`", "&#96;")

    quiet = report["quiet"]
    outcome = {True: "да", False: "нет", None: "—"}[quiet["within_ten"]]
    count = quiet["problem_count"] if quiet["problem_count"] is not None else "—"
    lines = [f"Тихое состояние ({quiet['observed_at_utc']}): проблем на главной — {count}; ≤10 — {outcome}.",
             "", "| Атака | Найдена | Минут | Заголовок проблемы | Telegram¹ | Итог |",
             "|---|---|---|---|---|---|"]
    labels = {"accepted": "да", "not_configured": "не настроен", "unverified": "—"}
    for row in report["attacks"]:
        values = [f"{row['attack']}. {row['name']}", "да" if row["found"] else "нет",
                  "—" if row["minutes"] is None else f"{row['minutes']:.2f}", row["title"] or "—",
                  labels[row["telegram"]], REASONS[row["reason"]]]
        lines.append("| " + " | ".join(cell(value) for value in values) + " |")
    lines += ["", "¹ «Да» — Telegram принял сообщение по данным API SLI; прочтение получателем не проверяется."]
    return "\n".join(lines) + "\n"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward an operator token to another origin, even on a 302.
        raise ExerciseError("api_unavailable")


class Api:
    def __init__(self, base_url, token):
        parsed = urlsplit(base_url)
        loopback = parsed.hostname == "localhost"
        try:
            loopback |= ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            pass
        if (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback) or
                not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or
                parsed.path not in {"", "/"}):
            raise ExerciseError("api_url_invalid")
        self.base = base_url.rstrip("/")
        self.token = token
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def get(self, path, params=None, deadline=None):
        remaining = 30 if deadline is None else min(30, deadline - time.monotonic())
        if remaining <= 0:
            raise ExerciseError("window_exceeded")
        request = Request(self.base + path + ("?" + urlencode(params) if params else ""),
                          headers={"Authorization": "Bearer " + self.token, "Accept-Language": "ru",
                                   "Accept": "application/json"}, method="GET")
        try:
            with self.opener.open(request, timeout=remaining) as response:
                data = response.read(8 * 1024 * 1024 + 1)
                if len(data) > 8 * 1024 * 1024:
                    raise ExerciseError("api_contract_invalid")
                payload = json.loads(data)
                if not isinstance(payload, dict) or payload.get("error"):
                    raise ExerciseError("api_contract_invalid")
                return payload
        except (HTTPError, URLError, OSError, ValueError):
            raise ExerciseError("api_unavailable") from None

    def pages(self, path, params=None, deadline=None):
        params = dict(params or {})
        rows, cursors = [], set()
        while True:
            page, cursor = parse_page(self.get(path, params, deadline))
            rows.extend(page)
            if cursor is None:
                return rows
            if cursor in cursors:
                raise ExerciseError("api_contract_invalid")
            cursors.add(cursor)
            params["cursor"] = cursor


def run_attack(number, args, inventory):
    common = (HERE / "lab-common.ps1").read_text("utf-8-sig")
    attacks = (HERE / "lab-exercise-attack.ps1").read_text("utf-8-sig")
    data = base64.b64encode(json.dumps(inventory, ensure_ascii=True).encode()).decode()
    script = ("[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)\n" + common + "\n" + attacks +
              "\ntry {\n$inventory = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + data +
              "')) | ConvertFrom-Json\nInvoke-LabExerciseAttack " + str(number) +
              " $inventory | ConvertTo-Json -Depth 6 -Compress\n} catch { "
              "'{\"executed\":false,\"restored\":true,\"reason\":\"attack_failed\",\"match_values\":[]}' }\n")
    # Read the whole script before executing it; no shell interpolation of input.
    launcher = "[Console]::InputEncoding = New-Object Text.UTF8Encoding($false); & ([scriptblock]::Create([Console]::In.ReadToEnd()))"
    encoded = base64.b64encode(launcher.encode("utf-16-le")).decode()
    command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
    if args.ssh_target:
        if not re.fullmatch(r"(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*", args.ssh_target):
            raise ExerciseError("ssh_target_invalid")
        if not args.identity_file:
            raise ExerciseError("ssh_identity_required")
        command = ["ssh", "-i", str(args.identity_file), "-o", "BatchMode=yes", "-o",
                   "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", args.ssh_target] + command
    # The attack process and SSH do not need the SLI token.
    # A curator may launch Python from pwsh 7. Its module path breaks the
    # Windows PowerShell 5.1 security module; let 5.1 build its own defaults.
    child_env = {key: value for key, value in os.environ.items()
                 if key.casefold() not in {args.token_env.casefold(), "psmodulepath"}}
    try:
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=child_env) as process:
            first = True
            while True:
                try:
                    stdout, _ = process.communicate(script.encode("utf-8") if first else None, timeout=10)
                    break
                except subprocess.TimeoutExpired:
                    first = False
                    print(f"Атака {number}: имитация выполняется; ожидаю возврата состояния LAB", file=sys.stderr, flush=True)
            if process.returncode:
                raise ExerciseError("attack_failed")
        result = json.loads(stdout.decode("utf-8-sig").strip())
        if (type(result.get("executed")) is not bool or type(result.get("restored")) is not bool or
                result.get("reason") not in {"", "attack_failed", "cleanup_failed", "lab_simulation_busy"} or
                not isinstance(result.get("match_values"), list) or
                any(not isinstance(v, str) or len(v) > 2048 for v in result["match_values"])):
            raise ExerciseError("attack_failed")
        return result
    except (OSError, ValueError, AttributeError):
        raise ExerciseError("attack_failed") from None


def exercise(api, attack, args, inventory):
    params = {"domain": args.domain_id, "population": "attention", "limit": 200, "tz": "UTC", "tab": "table"}
    baseline = {row["id"]: row for row in api.pages(QUEUE, params)}
    telegram, delivery_baseline = None, set()
    try:
        telegram = telegram_configured(api.get(WORKSPACE))
        delivery_baseline = {row["id"] for row in api.pages(WORKSPACE, {"channel": "telegram", "days": 1})}
    except ExerciseError:
        pass  # Missing read permission is not proof that the channel is unconfigured.
    start = stamp(utc_now())
    began = time.monotonic()
    deadline = began + WINDOW_SECONDS
    try:
        attempt = run_attack(attack[0], args, inventory)
    except ExerciseError:
        # A lost SSH connection does not prove that remote cleanup completed.
        return result_row(attack, reason="cleanup_unverified"), False
    if not attempt["restored"]:
        return result_row(attack, reason="cleanup_failed"), False
    if not attempt["executed"]:
        return result_row(attack, reason=attempt["reason"] or "attack_failed"), True
    # Remote clocks need not be synchronised. Use the curator's monotonic clock
    # for latency; start before SSH so the measured delay is conservative.
    row = result_row(attack, telegram="not_configured" if telegram is False else "unverified", reason="not_found")
    first_seen = None
    last_error = None
    while time.monotonic() < deadline:
        print(f"Атака {attack[0]}: опрос SLI, {int(time.monotonic() - began)} с / 300 с", file=sys.stderr, flush=True)
        try:
            candidates = new_problems(api.pages(QUEUE, params, deadline), attack, baseline, start, attempt["match_values"])
            if candidates:
                first_seen = first_seen if first_seen is not None else time.monotonic() - began
                problem = candidates[0]
                row.update(found=True, minutes=round(first_seen / 60, 4), title=safe_title(problem.get("title"), api.token),
                           problem_count=len(candidates), reason="")
                if len(candidates) != 1:
                    row["reason"] = "duplicate_problems"
                elif not re.search("[А-Яа-яЁё]", row["title"]) or not problem.get("what_happened") or not problem.get("next_text"):
                    row["reason"] = "presentation_missing"
                if telegram is not False:
                    for candidate in candidates:
                        deliveries = api.pages(WORKSPACE, {"channel": "telegram", "finding_id": candidate["id"], "days": 1}, deadline)
                        if delivery_accepted(deliveries, candidate["id"], start, delivery_baseline):
                            row["telegram"] = "accepted"
                if telegram is False or row["telegram"] == "accepted":
                    break
        except ExerciseError as error:
            last_error = str(error)
        time.sleep(min(args.poll_seconds, max(0, deadline - time.monotonic())))
    if row["minutes"] is not None and row["minutes"] > 5:
        row["reason"] = "window_exceeded"
    elif row["found"] and not row["reason"] and row["telegram"] == "unverified":
        row["reason"] = "telegram_unverified"
    elif not row["found"] and last_error:
        row["reason"] = last_error
    return row, True


def write_results(directory, report):
    directory.mkdir(parents=True, exist_ok=True)
    # Fixed filenames, no API-controlled paths and no raw responses/credentials.
    (directory / "lab-exercise.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (directory / "lab-exercise.md").write_text(markdown(report), encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True, help="SLI URL; HTTPS or HTTP loopback tunnel")
    parser.add_argument("--domain-id", required=True, type=int, help="SLI domain ID for LAB")
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--token-env", default="SLI_OPERATOR_TOKEN", help="Environment variable containing an adl_ API token")
    parser.add_argument("--quiet-only", action="store_true")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--ssh-target", help="Existing trusted SSH host for LAB-DC01")
    target.add_argument("--local", dest="on_dc", action="store_true", help="Run in Windows PowerShell 5.1 on LAB-DC01")
    parser.add_argument("--identity-file", type=Path, help="SSH key path (passed to SSH, never read by this script)")
    parser.add_argument("--poll-seconds", default=10, type=int, choices=range(1, 31), metavar="1..30")
    args = parser.parse_args(argv)
    report = None
    try:
        token = os.environ.get(args.token_env, "").strip()
        if not token or "\n" in token or "\r" in token:
            raise ExerciseError("operator_token_required")
        if args.domain_id <= 0 or not args.quiet_only and not (args.on_dc or args.ssh_target):
            raise ExerciseError("lab_target_required")
        if not args.quiet_only and args.ssh_target and not args.identity_file:
            raise ExerciseError("ssh_identity_required")
        api = Api(args.api_url, token)
        home = api.get("/api/v1/home/summary", {"contract": "v3", "domain_id": args.domain_id, "tz": "UTC"})
        snapshot = quiet_home_snapshot if args.quiet_only else quiet_snapshot
        report = {"schema_version": 1, "quiet": snapshot(home, utc_now()), "attacks": [], "complete": args.quiet_only}
        write_results(args.results, report)
        if not args.quiet_only:
            inventory = json.loads((HERE / "lab-data.json").read_text("utf-8-sig"))
            for attack in ATTACKS:
                row, restored = exercise(api, attack, args, inventory)
                report["attacks"].append(row)
                write_results(args.results, report)
                if not restored:
                    break
            report["complete"] = len(report["attacks"]) == len(ATTACKS)
            write_results(args.results, report)
        print(markdown(report))
        passed = report["quiet"]["within_ten"] is True and all(row["found"] and not row["reason"] for row in report["attacks"])
        return 0 if report["complete"] and passed else 1
    except ExerciseError as error:
        print("lab_exercise_failed: " + str(error), file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError):
        print("lab_exercise_failed: local_or_api_contract_error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
