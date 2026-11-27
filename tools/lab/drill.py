"""Score recorded LAB detections using read-only stand observations or an offline export."""

import argparse
import json
import math
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from shlex import join as shell_join

PASSWORD_BRUTE = "semantic.qw.password-brute-force"
PASSWORD_SPRAY = "semantic.qw.password-spray"
PASSWORD_SUCCESS_TITLE = "security.problems.presentation.qw.password-success.title"
OBSERVATION_WINDOW = timedelta(minutes=10)
POLL_INTERVAL = timedelta(seconds=20)
ACCEPTANCE_MINUTES = 5
TEST_ACCOUNTS = "Remove test accounts created for this case."
TITLE_RULE_CODES = r"(?:semantic[.]|qw[.]|security[.]problems[.]presentation[.])"
CYRILLIC = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"


@dataclass(frozen=True)
class Scenario:
    number: int
    name: str
    rules: tuple[str, ...]
    cleanup: str = ""
    title_code: str = ""


SCENARIOS = (
    Scenario(1, "Подбор пароля", (PASSWORD_BRUTE,), TEST_ACCOUNTS),
    Scenario(2, "Подбор по многим учётным записям", (PASSWORD_SPRAY,), TEST_ACCOUNTS),
    Scenario(3, "Успешный вход после перебора", (PASSWORD_BRUTE, PASSWORD_SPRAY), TEST_ACCOUNTS,
             PASSWORD_SUCCESS_TITLE),
    Scenario(4, "Массовый запрос билетов служб", ("semantic.qw.kerberoasting",), TEST_ACCOUNTS),
    Scenario(5, "Запрос билета без предварительной проверки", ("semantic.qw.asrep-roasting",), TEST_ACCOUNTS),
    Scenario(6, "Добавление в привилегированную группу", ("semantic.qw.privileged-group-addition",),
             f"Remove the test group membership. {TEST_ACCOUNTS}"),
    Scenario(7, "Очистка журнала безопасности", ("semantic.qw.security-log-cleared",)),
    Scenario(8, "Ослабление аудита", ("semantic.qw.audit-disabled",), "Restore the saved audit policy."),
    Scenario(9, "Остановка агента SLI", ("semantic.qw.agent-tamper",), "Restart the SLI agent."),
    Scenario(10, "Новая задача или служба на контроллере домена",
             ("semantic.security.dc_scheduled_task_created", "semantic.security.dc_service_installed"),
             "Remove the test task and service."),
)


def print_plan():
    for scenario in sorted(SCENARIOS, key=lambda item: item.number in (7, 9)):
        rules = " / ".join(scenario.rules)
        presentation = f" ({scenario.title_code})" if scenario.title_code else ""
        cleanup = f" — {scenario.cleanup}" if scenario.cleanup else ""
        print(f"{scenario.number}. {scenario.name} — {rules}{presentation}{cleanup}")


def timestamp(value):
    stamp = datetime.fromisoformat(value)
    if stamp.utcoffset() is None:
        raise ValueError("Timestamp requires a UTC offset")
    return stamp


def acceptance_row(scenario, record, *, stand=False):
    row = {
        "scenario": scenario.number, "attack": scenario.name, "found": False,
        "minutes": None, "russian_title": False, "telegram_accepted": False,
    }
    if record is None:
        return row
    start = timestamp(record["started_at"])
    finding = record.get("finding")
    if finding is None:
        return row
    if not isinstance(finding, dict) or type(finding.get("id")) is not int or finding["id"] <= 0:
        raise ValueError("Invalid finding")
    rule = finding["rule_code"]
    if rule not in scenario.rules:
        return row
    if rule in (PASSWORD_BRUTE, PASSWORD_SPRAY):
        success_title = finding.get("title_code") == PASSWORD_SUCCESS_TITLE
        if success_title != bool(scenario.title_code):
            return row

    observed = timestamp(finding["observed_at"])
    last_seen = timestamp(finding["signal_at"] if stand else finding["last_seen_utc"])
    baseline = finding.get("previous_last_seen_utc")
    end = start + OBSERVATION_WINDOW
    if not start <= last_seen <= observed <= end:
        return row
    if baseline is not None and last_seen <= timestamp(baseline):
        return row

    title = finding.get("title")
    russian_title = finding.get("russian_title") is True if stand else (
        isinstance(title, str) and bool(re.search(r"[А-Яа-яЁё]", title))
        and not re.search(r"\b" + TITLE_RULE_CODES, title, re.IGNORECASE)
    )
    # Round up so a late observation cannot display as within five minutes.
    minutes = math.ceil((observed - start) / timedelta(milliseconds=600)) / 100
    row.update(found=True, minutes=minutes, russian_title=russian_title)

    attempt = record.get("telegram_attempt")
    if attempt is not None:
        if not isinstance(attempt, dict) or type(attempt.get("finding_id")) is not int:
            raise ValueError("Invalid Telegram attempt")
        row["telegram_accepted"] = (
            attempt["finding_id"] == finding["id"]
            and attempt["state"] == "accepted"
            and last_seen <= timestamp(attempt["accepted_at"]) <= end
        )
    return row


def scenario_records(records):
    if not isinstance(records, list):
        raise TypeError("Evidence must be a list")
    by_scenario = {}
    numbers = {scenario.number for scenario in SCENARIOS}
    for record in records:
        if not isinstance(record, dict) or type(record.get("scenario")) is not int:
            raise ValueError("Invalid scenario")
        number = record["scenario"]
        if number not in numbers or number in by_scenario:
            raise ValueError("Unknown or duplicate scenario")
        by_scenario[number] = record
    return by_scenario


def build_report(records, *, stand=False):
    by_scenario = scenario_records(records)
    rows = [acceptance_row(scenario, by_scenario.get(scenario.number), stand=stand) for scenario in SCENARIOS]
    return {
        "latency_source": "first_database_observation",
        "passed": all(
            row["found"] and row["minutes"] <= ACCEPTANCE_MINUTES
            and row["russian_title"] and row["telegram_accepted"]
            for row in rows
        ),
        "rows": rows,
    }


def stand_command(target, key):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*@[A-Za-z0-9][A-Za-z0-9.-]*", target):
        raise ValueError("Invalid SSH destination")
    return [
        "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes",
        "-i", str(key.expanduser()), target,
        "sudo -n -u postgres psql -X -qAt -w -v ON_ERROR_STOP=1 -d sli -f -",
    ]


def stand_probe(command, scenario, start, finding, timeout, run=subprocess.run):
    # The only interpolated values are normalized timestamps, fixed rule codes, and a validated numeric ID.
    window_start = f"'{start.astimezone(UTC).isoformat()}'::timestamptz"
    window_end = f"'{(start + OBSERVATION_WINDOW).astimezone(UTC).isoformat()}'::timestamptz"
    if finding is None:
        rules = ",".join(f"'{rule}'" for rule in scenario.rules)
        password_match = ""
        if PASSWORD_BRUTE in scenario.rules or PASSWORD_SPRAY in scenario.rules:
            password_match = f"""
              and coalesce((presentation.facts->>'version' is null
                       and presentation.facts->>'password_success' = 'true'), false)
                  = {'true' if scenario.title_code else 'false'}
            """
        title_code = f"'{PASSWORD_SUCCESS_TITLE}'" if scenario.title_code else "null"
        # Reuse the server's password presentation facts to distinguish cases sharing a rule code.
        sql = f"""
            select json_build_object(
                'id', f.id, 'rule_code', f.rule_code, 'title_code', {title_code}::text,
                'signal_at', current_signal.signal_at,
                'russian_title', translate(f.title, '{CYRILLIC + CYRILLIC.lower()}', '') <> f.title
                                and f.title !~* '[[:<:]]{TITLE_RULE_CODES}'
            )
            from public.findings f
            left join lateral public.password_queue_presentation399(f.id, f.rule_code) presentation on true
            cross join lateral (
                select max(stamp) as signal_at
                from (values (f.created_at), (nullif(f.last_seen_utc::text, '')::timestamptz)) as times(stamp)
                where stamp between {window_start} and least({window_end}, statement_timestamp())
            ) current_signal
            where f.rule_code in ({rules}) and current_signal.signal_at is not null
              and public.is_semantic_finding_published_v1(f.id)
              {password_match}
            order by current_signal.signal_at, f.id limit 1;
        """
    else:
        finding_id = finding["id"]
        if type(finding_id) is not int or finding_id <= 0:
            raise ValueError("Invalid finding ID")
        signal_at = timestamp(finding["signal_at"]).astimezone(UTC).isoformat()
        sql = f"""
            select json_build_object('finding_id', {finding_id}, 'state', a.state, 'accepted_at', a.finished_at)
            from public.semantic_finding_publications p
            join public.notification_outbox j on j.object_id = p.scenario_id
            join public.notification_attempts a on a.job_id = j.id
            where j.channel = 'telegram' and j.object_kind = 'semantic_finding' and a.state = 'accepted'
              and p.finding_id = {finding_id} and public.notification_finding_object(j.object_id) = {finding_id}
              and a.finished_at between '{signal_at}'::timestamptz and least({window_end}, statement_timestamp())
            order by a.finished_at limit 1;
        """
    result = run(
        command, input=(
            f"\\encoding UTF8\nbegin read only;\nset local time zone 'UTC';\n"
            f"set local statement_timeout = {max(1, int(timeout * 1000))};\n{sql}\ncommit;\n"
        ), capture_output=True,
        check=True, encoding="utf-8", timeout=timeout,
    )
    return json.loads(result.stdout) if result.stdout.strip() else None


def observe_stand(starts, command, *, now=lambda: datetime.now(UTC), sleep=time.sleep, run=subprocess.run):
    records = scenario_records(starts)
    starts = {number: timestamp(record["started_at"]) for number, record in records.items()}
    if any(start > now() for start in starts.values()):
        raise ValueError("Scenario start is in the future")
    observations = {number: {"scenario": number, "started_at": start.isoformat()} for number, start in starts.items()}
    pending = [scenario for scenario in SCENARIOS if scenario.number in starts]
    while pending:
        next_poll = now() + POLL_INTERVAL
        for scenario in pending[:]:
            number = scenario.number
            start = starts[number]
            end = start + OBSERVATION_WINDOW
            record = observations[number]
            for key in ("finding", "telegram_attempt"):
                remaining = (end - now()).total_seconds()
                if remaining <= 0 or key == "telegram_attempt" and "finding" not in record:
                    break
                if key in record:
                    continue
                try:
                    result = stand_probe(command, scenario, start, record.get("finding"), remaining, run)
                except subprocess.TimeoutExpired:
                    break
                observed_at = now()
                if result is not None and observed_at <= end:
                    if key == "finding":
                        result["observed_at"] = observed_at.isoformat()
                    record[key] = result
            if now() >= end or "telegram_attempt" in record:
                pending.remove(scenario)
        if pending:
            wake = min(next_poll, *(starts[scenario.number] + OBSERVATION_WINDOW for scenario in pending))
            sleep(max(0, (wake - now()).total_seconds()))
    return build_report(list(observations.values()), stand=True)


def print_report(report):
    print("| Атака | Найдена | Минут до главной | Заголовок на русском | Сообщение в Telegram |")
    print("|---|---|---|---|---|")
    yes_no = {True: "да", False: "нет"}
    for row in report["rows"]:
        minutes = "—" if row["minutes"] is None else f"{row['minutes']:.2f}"
        print(f"| {row['scenario']}. {row['attack']} | {yes_no[row['found']]} | {minutes} |"
              f" {yes_no[row['russian_title']]} | {yes_no[row['telegram_accepted']]} |")
    print("\nВремя рассчитано по первому наблюдению проблемы в базе данных.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="print the ten-scenario plan")
    mode.add_argument("--evidence", type=Path, help="read an offline JSON evidence export")
    mode.add_argument("--observe", type=Path, help="poll the stand for recorded scenario starts in a JSON file")
    parser.add_argument("--stand-ssh", metavar="USER@HOST", help="stand SSH destination for read-only observation")
    parser.add_argument("--stand-key", type=Path, help="stand SSH identity file")
    parser.add_argument("--json-output", type=Path, help="report path (default: drill-results.json)")
    args = parser.parse_args(argv)
    if bool(args.stand_ssh) != bool(args.stand_key) or args.observe and not args.stand_ssh:
        parser.error("--observe requires both --stand-ssh and --stand-key")
    if args.evidence and args.stand_ssh:
        parser.error("stand SSH options require --observe or --dry-run")
    try:
        command = stand_command(args.stand_ssh, args.stand_key) if args.stand_ssh else None
    except (ValueError, RuntimeError):
        parser.error("Invalid stand SSH destination or identity path")
    if args.dry_run:
        if args.json_output is not None:
            parser.error("--json-output requires --evidence or --observe")
        print_plan()
        if command:
            command[command.index("-i") + 1] = "<stand-key>"
            print("\nRead-only stand polling command (SQL on stdin):")
            print(shell_join(command))
        return 0

    source = args.evidence or args.observe
    try:
        records = json.loads(source.read_text(encoding="utf-8"))
        report = observe_stand(records, command) if args.observe else build_report(records)
    except subprocess.SubprocessError:
        print("Read-only stand query failed.", file=sys.stderr)
        return 2
    except (OSError, KeyError, TypeError, ValueError, OverflowError):
        print("Invalid evidence or unreadable observation input.", file=sys.stderr)
        return 2

    output = args.json_output or Path("drill-results.json")
    try:
        if source.resolve() == output.resolve() or output.exists() and output.samefile(source):
            print("Report must use a different file from the evidence.", file=sys.stderr)
            return 2
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError:
        print("Could not write the JSON report.", file=sys.stderr)
        return 2
    print_report(report)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
