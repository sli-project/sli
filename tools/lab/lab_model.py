"""Synthetic lab inventory and expected-event contract; no Windows/DB imports."""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from uuid import UUID

DOMAIN = "demo.example"
MARKER = "SLI-LAB-SYNTHETIC"
SCENARIOS = {
    "workday_logon", "night_logon", "wrong_password", "password_spray",
    "single_account_brute", "disabled_logon", "privileged_add", "gpo_change", "audit_change",
}
FILE_SCENARIOS = {
    "file_read", "file_modify", "file_delete", "file_rename", "file_permissions",
    "file_mass_read", "file_mass_delete", "file_off_hours", "file_denied", "file_fixture_create",
}
FILE_FIELDS = {"file_path", "share", "operation", "destination_path", "outcome", "audit_required", "local_time"}


def inventory() -> dict:
    # Fictional compound surnames; identifiers and provenance cannot resemble an import.
    given = ("Артём", "Вера", "Илья", "Дарья", "Лев", "Нина", "Марк", "Лада", "Роман", "Алина")
    stems = ("Лугосвет", "Зарелист", "Облакореч", "Снегозор", "Ветролад",
             "Луноград", "Росоцвет", "Тихолес", "Яснокрыл", "Светолуг",
             "Синезар", "Миролист", "Златореч", "Веснозор", "Дальнесвет")
    departments = ("Разработка", "Поддержка", "Финансы", "Закупки", "Логистика",
                   "Аналитика", "Кадры", "Испытания")
    users = []
    for i in range(150):
        surname = stems[i // 10] + ("ова" if i % 2 else "ов")
        users.append({"sam": f"lab.u{i + 1:03}", "given_name": given[i % 10], "surname": surname,
                      "display_name": f"{given[i % 10]} {surname}", "department": departments[i % 8],
                      "enabled": i < 147, "service": False, "spns": [], "marker": MARKER})
    for i, service in enumerate(("web", "jobs"), 1):
        users.append({"sam": f"lab.svc{i:02}", "given_name": "", "surname": "",
                      "display_name": f"Synthetic {service} service", "department": "Сервисные",
                      "enabled": True, "service": True,
                      "spns": [f"HTTP/lab-{service}.{DOMAIN}"], "marker": MARKER})
    return {"schema_version": 1, "domain": DOMAIN, "netbios": "DEMO", "marker": MARKER,
            "departments": list(departments), "users": users,
            "computers": [{"name": f"LAB-{'WS' if i < 32 else 'SRV'}{i + 1:02}",
                           "ou": "Рабочие станции" if i < 32 else "Серверы", "marker": MARKER}
                          for i in range(40)],
            "groups": [f"LAB-Department-{i:02}" for i in range(1, 9)] +
                      ["LAB-VPN", "LAB-All", "LAB-Operators"],
            "gpos": ["LAB-Password", "LAB-Audit", "LAB-Lock", "LAB-Firewall",
                     "LAB-Servers", "LAB-Workstations", "LAB-VPN", "LAB-Updates"]}


def validate_expected(row: dict) -> dict:
    """Reject malformed/unbounded/private material before automatic comparison."""
    required = {"schema_version", "run_id", "scenario", "started_at_utc", "ended_at_utc",
                "actor", "target", "source_address", "event_ids", "executed", "object_id", "target_sid", "related_object_id", "event_object_id"}
    file_row = isinstance(row, dict) and isinstance(row.get("scenario"), str) and row["scenario"] in FILE_SCENARIOS
    if (not isinstance(row, dict) or set(row) != required | (FILE_FIELDS if file_row else set()) or
            type(row["schema_version"]) is not int or row["schema_version"] != 1):
        raise ValueError("lab_expected_schema_invalid")
    try:
        UUID(row["run_id"])
        start, end = (datetime.fromisoformat(row[key].replace("Z", "+00:00"))
                      for key in ("started_at_utc", "ended_at_utc"))
        if start.utcoffset().total_seconds() != 0 or end.utcoffset().total_seconds() != 0 or end < start:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ValueError("lab_expected_time_invalid") from None
    if not isinstance(row["scenario"], str) or row["scenario"] not in SCENARIOS | FILE_SCENARIOS or type(row["executed"]) is not bool:
        raise ValueError("lab_expected_scenario_invalid")
    actor = "DEMO\\" + str(row["target"]) if file_row else "lab-system"
    if row["actor"] != actor or row["source_address"] not in (None, "127.0.0.1"):
        raise ValueError("lab_expected_identity_invalid")
    if not isinstance(row["target"], str) or not re.fullmatch(r"lab\.(?:u\d{3}|svc\d{2})|LAB-[A-Za-z]+", row["target"]):
        raise ValueError("lab_expected_target_invalid")
    if file_row:
        if (not isinstance(row["share"], str)
                or row["share"] not in {"LAB-Finance", "LAB-HR", "LAB-Projects", "LAB-Common", "LAB-Exchange"}
                or not isinstance(row["operation"], str)
                or row["operation"] not in {"read", "create", "modify", "delete", "rename", "permissions"}
                or row["audit_required"] is not True
                or not isinstance(row["outcome"], str)
                or not re.fullmatch(r"success|access_denied|not_attempted|logon_error|empty_file|missing_file|unknown_operation|io_error_\d+", row["outcome"])):
            raise ValueError("lab_expected_file_invalid")
        prefix = "\\\\LAB-DC01.demo.example\\" + row["share"] + "\\"
        for key in ("file_path", "destination_path"):
            path = row[key]
            if key == "destination_path" and path is None:
                continue
            if (not isinstance(path, str) or not path.startswith(prefix)
                    or not re.fullmatch(r"(?:[A-Za-z0-9_-]+\.(?:txt|csv)|Сводка-01\.csv)", path[len(prefix):])):
                raise ValueError("lab_expected_file_path_invalid")
        try:
            if datetime.fromisoformat(row["local_time"]).utcoffset() is None:
                raise ValueError()
        except (TypeError, ValueError):
            raise ValueError("lab_expected_file_time_invalid") from None
    for key in ("object_id", "related_object_id", "event_object_id"):
        if row[key] is not None:
            try:
                UUID(row[key])
            except (ValueError, TypeError, AttributeError):
                raise ValueError("lab_expected_object_invalid") from None
    if row["target_sid"] is not None and (not isinstance(row["target_sid"], str) or
                                           not re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-\d+", row["target_sid"])):
        raise ValueError("lab_expected_sid_invalid")
    if not isinstance(row["event_ids"], list) or not row["event_ids"] or any(
        type(code) is not int or code not in ({4656, 4660, 4663, 4670, 5145} if file_row else {4624, 4625, 4776, 4719, 4728, 5136}) for code in row["event_ids"]
    ):
        raise ValueError("lab_expected_events_invalid")
    return row


def read_expected(path: Path) -> list[dict]:
    # PowerShell 5.1 emits a UTF-8 BOM on a new JSONL file.
    return [validate_expected(json.loads(line)) for line in path.read_text("utf-8-sig").splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(inventory(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8-sig")


if __name__ == "__main__":
    main()
