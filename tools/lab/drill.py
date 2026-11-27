"""Print the LAB detection plan or score an offline evidence export."""

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

PASSWORD_BRUTE = "semantic.qw.password-brute-force"
PASSWORD_SPRAY = "semantic.qw.password-spray"
PASSWORD_SUCCESS_TITLE = "security.problems.presentation.qw.password-success.title"
OBSERVATION_WINDOW = timedelta(minutes=10)
ACCEPTANCE_MINUTES = 5
TEST_ACCOUNTS = "Remove test accounts created for this case."


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


def acceptance_row(scenario, record):
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
    last_seen = timestamp(finding["last_seen_utc"])
    baseline = finding.get("previous_last_seen_utc")
    end = start + OBSERVATION_WINDOW
    if not start <= last_seen <= observed <= end:
        return row
    if baseline is not None and last_seen <= timestamp(baseline):
        return row

    title = finding.get("title")
    russian_title = isinstance(title, str) and bool(re.search(r"[А-Яа-яЁё]", title)) and not re.search(
        r"\b(?:semantic\.|qw\.|security\.problems\.presentation\.)", title, re.IGNORECASE,
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


def build_report(records):
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
    rows = [acceptance_row(scenario, by_scenario.get(scenario.number)) for scenario in SCENARIOS]
    return {
        "latency_source": "first_database_observation",
        "passed": all(
            row["found"] and row["minutes"] <= ACCEPTANCE_MINUTES
            and row["russian_title"] and row["telegram_accepted"]
            for row in rows
        ),
        "rows": rows,
    }


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
    parser.add_argument("--json-output", type=Path, help="report path (default: drill-results.json)")
    args = parser.parse_args(argv)
    if args.dry_run:
        if args.json_output is not None:
            parser.error("--json-output requires --evidence")
        print_plan()
        return 0

    try:
        report = build_report(json.loads(args.evidence.read_text(encoding="utf-8")))
    except (OSError, KeyError, TypeError, ValueError, OverflowError):
        print("Invalid evidence or unreadable evidence file.", file=sys.stderr)
        return 2

    output = args.json_output or Path("drill-results.json")
    try:
        if args.evidence.resolve() == output.resolve() or output.exists() and output.samefile(args.evidence):
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
