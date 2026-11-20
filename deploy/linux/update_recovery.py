"""Console diagnostics and checkpoint recovery independent of the web service."""

from __future__ import annotations

import re
from pathlib import Path

from scripts.maintenance.release_package import _bounded_read, read_json

STATUSES = {"running", "rolling_back", "rolled_back", "rejected", "committed", "failed", "recovery_required"}
PHASES = {"verify", "stage", "checkpoint", "drain", "migrate", "activate", "health", "commit", "selftest", "switch"}
STATUS_LABELS = {
    "absent": "журнал отсутствует", "unknown": "неизвестное состояние",
    "unreadable": "не удалось прочитать журнал",
    "running": "выполняется", "rolling_back": "выполняется откат", "rolled_back": "откат завершён",
    "rejected": "отклонено", "committed": "завершено", "failed": "ошибка", "recovery_required": "требуется восстановление",
}
PHASE_LABELS = {
    "verify": "проверка пакета", "stage": "подготовка версии", "checkpoint": "резервная копия",
    "drain": "остановка записи", "migrate": "миграция", "activate": "активация", "health": "проверка готовности",
    "commit": "фиксация", "selftest": "самопроверка", "switch": "переключение указателя", "unknown": "неизвестна",
}


def diagnostic_file(path):
    try:
        return read_json(_bounded_read(path, 8 * 1024 * 1024))
    except (ValueError, OSError):
        return None


def console_status(runtime):
    """Read atomic host files only. Never acquire a writing lock or contact a service."""
    state = Path(runtime) / "state"
    result = {"status": "status", "journals": {}}
    for name, filename in (("server", "update-journal.json"), ("updater", "updater-journal.json")):
        path = state / filename
        if not path.exists():
            result["journals"][name] = {"status": "absent"}
            continue
        value = diagnostic_file(path)
        if value is None:
            result["journals"][name] = {"status": "unreadable"}
            continue
        status, phase, completed = value.get("status"), value.get("phase"), value.get("completed", [])
        result["journals"][name] = {
            "status": status if isinstance(status, str) and status in STATUSES else "unknown",
            "phase": phase if isinstance(phase, str) and phase in PHASES else "unknown",
            "completed": [phase for phase in completed if isinstance(phase, str) and phase in PHASES]
                         if isinstance(completed, list) else [],
            "checkpoint_available": bool(value.get("backup_id")),
            "migration_started": value.get("migration_started") is True,
            "api_readiness": "unverified" if value.get("recovery_api_unchecked") else "unknown",
        }
        from deploy.linux.sli_update import drain_failure_diagnostic
        result["journals"][name].update(drain_failure_diagnostic(value))
        if status == "recovery_required":
            result["journals"][name]["rollback_runtime"] = value.get("rollback_runtime") if value.get(
                "rollback_runtime") in {"previous", "stopped", "unverified"} else "unverified"
            for key in ("reason", "rollback_error", "rollback_fence_error"):
                code = value.get(key)
                if isinstance(code, str) and re.fullmatch(r"update_[a-z0-9_]+", code):
                    result["journals"][name][key] = code
    for name, filename, key in (("server_version", "installed.json", None), ("updater_version", "updater.json", "current")):
        path = state / filename
        if path.exists():
            value = diagnostic_file(path)
            if value is None:
                continue
            if key:
                value = value.get(key, {})
            if not isinstance(value, dict):
                continue
            version = value.get("version")
            if isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
                result[name] = version
    return result


class ConsoleRecoveryHost:
    """Only recovery may replace the HTTPS readiness gate with Docker readback."""
    def __init__(self, host):
        self.host = host

    def __getattr__(self, name):
        return getattr(self.host, name)

    def health(self, journal):
        self.host.recovery_health(journal)


def recover_server(runtime, trust_store, host):
    from deploy.linux.sli_update import Updater, operation_lock, require

    require(host is not None, "update_runtime_configuration_required")
    # Rollback needs the trusted journal/checkpoint, not the candidate package or
    # its signer. The previous checkpoint helper is supplied by this host release.
    updater = Updater(runtime, trust_store or Path(runtime) / "unused-trust.json", ConsoleRecoveryHost(host))
    with operation_lock(updater.state):
        journal = updater.read_journal(updater.journal_path)
        require(not journal.get("candidate_acceptance") or journal["candidate_acceptance"].get("status") == "committed",
                "update_candidate_acceptance_pending")
        if journal["status"] in {"rolled_back", "rejected"}:
            return {"status": journal["status"], "api_readiness": "unverified"}
        updater.validate_resume(journal, rollback=True)
        journal["recovery_api_unchecked"] = True
        updater.save(journal)
        updater.rollback(journal, "update_console_recovery")
    return {**updater.operation_result(journal), "api_readiness": "unverified"}


def accept_candidate(runtime, trust_store, host, operation_id, *, dry_run=False, allow_unhealthy_backup=False):
    from deploy.linux.sli_update import Updater, protected_path, reason_code, require

    require(host is not None and trust_store is not None, "update_runtime_configuration_required")
    # Deliberately NOT ConsoleRecoveryHost: acceptance requires full HTTPS health.
    updater = Updater(runtime, trust_store, host)
    try:
        status = updater.accept_candidate(operation_id=operation_id, dry_run=dry_run,
            **({"allow_unhealthy_backup": True} if allow_unhealthy_backup else {}))
        evidence = updater.operation_result(updater.read_journal(updater.journal_path)) if status == "committed" else {}
    except Exception as exc:
        # The DB or cache may already have committed. Report the durable intent,
        # never a misleading "nothing executed" result or a rollback suggestion.
        try:
            protected_path(updater.state / "update-journal.key")
            journal = updater.read_journal(updater.journal_path)
        except Exception:
            if getattr(updater, "candidate_acceptance_started", False):
                return {"status": "recovery_required", "operation": operation_id,
                        "reason_code": "update_candidate_acceptance_durability_unknown",
                        "acceptance_reason_code": reason_code(exc, "update_candidate_publication_failed"),
                        "journal_status": "unverified", "durability": "unverified",
                        "installed": None, "executed": True}
            raise exc from None
        decision = journal.get("candidate_acceptance") or {}
        if (journal.get("operation") == operation_id and journal.get("status") == "committed"
                and decision.get("status") == "committed"):
            return {"status": "recovery_required", "operation": operation_id,
                    "reason_code": "update_candidate_acceptance_durability_unknown",
                    "acceptance_reason_code": reason_code(exc, "update_candidate_publication_failed"),
                    "journal_status": "committed", "durability": "unverified",
                    "installed": True, "executed": True}
        if journal.get("operation") == operation_id and decision.get("status") == "pending":
            return {"status": "recovery_required", "operation": operation_id,
                    "reason_code": "update_candidate_acceptance_pending",
                    "acceptance_reason_code": reason_code(exc, "update_candidate_publication_failed"),
                    "installed": False, "executed": True}
        if getattr(updater, "candidate_acceptance_started", False):
            return {"status": "recovery_required", "operation": operation_id,
                    "reason_code": "update_candidate_acceptance_durability_unknown",
                    "acceptance_reason_code": reason_code(exc, "update_candidate_publication_failed"),
                    "journal_status": "unverified", "durability": "unverified",
                    "installed": None, "executed": True}
        raise
    return {**evidence, "status": status, "operation": operation_id, "installed": status == "committed",
            "executed": status == "committed"}


def print_status(result):
    print("Состояние локальных журналов (без подключения к БД и API):")
    for name, label in (("server", "Сервер"), ("updater", "Средство обновления")):
        value = result["journals"][name]
        print(f"{label}: {STATUS_LABELS[value['status']]}; фаза: {PHASE_LABELS.get(value.get('phase'), '—')}; "
              f"checkpoint: {'есть' if value.get('checkpoint_available') else 'нет'}.")
        if value["status"] == "recovery_required":
            print({"previous": "Исходная версия и ledger восстановлены; готовность сервисов не подтверждена.",
                   "stopped": "Сервисы приложения остановлены; сервисы данных сохранены.",
                   "unverified": "Состояние сервисов не подтверждено."}[value["rollback_runtime"]])
            from deploy.linux.sli_update import drain_failure_message
            if drain_failure_message(value):
                print(drain_failure_message(value))
            if value.get("rollback_error"):
                print(f"Причина незавершённого отката: {value['rollback_error']}.")
            if value.get("rollback_fence_error"):
                print(f"Причина незавершённой остановки: {value['rollback_fence_error']}.")
    if "server_version" in result:
        print(f"Версия сервера в реестре: {result['server_version']}.")
    if "updater_version" in result:
        print(f"Активная версия средства обновления: {result['updater_version']}.")
