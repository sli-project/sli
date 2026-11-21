#!/usr/bin/env python3
"""Проверка актуальности исполняемых файлов и ключевых контуров репозитория.

Это не попытка угадать назначение файла по имени. Каждый исполняемый сценарий
должен быть явно отнесён к одному из поддерживаемых контуров ниже. Новый или
забытый сценарий делает проверку красной до осознанной классификации.
"""
from __future__ import annotations

import argparse
import ast
import json
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

COMPONENTS: dict[str, tuple[str, ...]] = {
    "runtime": (
        "scripts/collect/collect_windows_events.py",
        "scripts/import/import_ad_context_bundle.py",
        "scripts/import/import_event_jsonl_to_postgres.py",
        "scripts/run_dc_log_pilot.py",
        "scripts/run_server.py",
        "scripts/runtime/account_decoy_worker.py",
        "scripts/runtime/account_watch_worker.py",
        "scripts/runtime/ad_context_snapshot_worker.py",
        "scripts/runtime/ad_snapshot_manifest_coordinator_worker.py",
        "scripts/runtime/ad_snapshot_projection_worker.py",
        "scripts/runtime/collection_worker.py",
        "scripts/runtime/computers_report_v5_snapshot_worker.py",
        "scripts/runtime/computers_report_v6_snapshot_worker.py",
        "scripts/runtime/computers_v6_source_worker.py",
        "scripts/runtime/entity_state_worker.py",
        "scripts/runtime/file_decoy_worker.py",
        "scripts/runtime/file_ransom_worker.py",
        "scripts/runtime/nps_threshold_worker.py",
        "scripts/runtime/post_collection_worker.py",
        "scripts/runtime/semantic_production_worker.py",
        "scripts/runtime/semantic_worker.py",
        "scripts/runtime/storage_lifecycle_worker.py",
        "scripts/runtime/storage_v2_outbox_worker.py",
        "scripts/runtime/remote_access_plugin_host.py",
        "scripts/runtime/users_report_v2_snapshot_worker.py",
        "scripts/runtime/what_where_when_projection_worker.py",
    ),
    "единый_центр_управления": (
        "scripts/maintenance/control_center_lifecycle.py",
        "scripts/maintenance/local_control_center_status.py",
        "tools/ADLog-Toolkit.cmd",
        "tools/adlog-tool.ps1",
        "tools/SLI-ControlCenter.cmd",
        "tools/sli-control-center.ps1",
    ),
    "эксплуатация": (
        "deploy/linux/sli_update.py",
        "deploy/linux/verify_offline_kit.py",
        "deploy/linux/update_checkpoint.py",
        "tools/install-sli-agent.ps1",
        "tools/install-sli-agent-local.ps1",
        "tools/build_update_package.py",
        "tools/release_artifacts.py",
        "tools/stand_update.py",
        "scripts/auth/manage_auth.py",
        "scripts/maintenance/ad_snapshot_runtime_control.py",
        "scripts/maintenance/ad_source_credentials.py",
        "scripts/maintenance/api_get.py",
        "scripts/maintenance/apply_update.py",
        "scripts/maintenance/baseline_snapshot.py",
        "scripts/maintenance/release_package.py",
        "scripts/maintenance/reprocess_agent_quarantine.py",
        "scripts/maintenance/capture_report.py",
        "scripts/maintenance/collect_diagnostics.py",
        "scripts/maintenance/collection_block_control.py",
        "scripts/maintenance/clickhouse_storage_guard.py",
        "scripts/maintenance/cleanup_locked_tmp.cmd",
        "scripts/maintenance/clean_tmp_sid.ps1",
        "scripts/maintenance/configure_ad_context_snapshot.py",
        "scripts/maintenance/current_baseline_gate.py",
        "scripts/maintenance/diagnose_windows_event_access.py",
        "scripts/maintenance/documentation_consolidation.py",
        "scripts/maintenance/export_dev_handoff.py",
        "scripts/maintenance/export_report_snapshots.py",
        "scripts/maintenance/existing_postgres_bootstrap.py",
        "scripts/maintenance/explain_agent_collection_health.py",
        "scripts/maintenance/build_postgres_baseline.py",
        "scripts/maintenance/apply_selected_migrations.py",
        "scripts/maintenance/import_domain_controllers_from_file.py",
        "scripts/maintenance/find_event_catalog_gaps.py",
        "scripts/maintenance/github_sanitary_check.py",
        "scripts/release/make_public_snapshot.py",
        "scripts/maintenance/healthcheck.py",
        "scripts/maintenance/html_inventory_audit.py",
        "scripts/maintenance/http_copy_control.py",
        "scripts/maintenance/inventory_readonly.py",
        "scripts/maintenance/legacy_cutover_readiness.py",
        "scripts/maintenance/Invoke-SLIClaudeTester.ps1",
        "scripts/maintenance/local_postgres_bootstrap.py",
        "scripts/maintenance/md_freshness_check.py",
        "scripts/maintenance/pg_archive_worker.py",
        "scripts/maintenance/pg_runtime_parity_audit.py",
        "scripts/maintenance/pitr_archive_preflight.py",
        "scripts/maintenance/platform_owner_readback.py",
        "scripts/maintenance/postgres_readiness.py",
        "scripts/maintenance/postgres_status.py",
        "scripts/maintenance/postgres_size_breakdown.py",
        "scripts/maintenance/operations_storage_snapshot.py",
        "scripts/maintenance/publish_react_build.py",
        "scripts/maintenance/raw_storage_cleanup.py",
        "scripts/maintenance/replay_retained_dc_batch.py",
        "scripts/maintenance/release_check.py",
        "scripts/maintenance/rollback_update.py",
        "scripts/maintenance/run_entity_state_projection_once.py",
        "scripts/maintenance/runtime_baseline.py",
        "scripts/maintenance/runtime_watchdog.py",
        "scripts/maintenance/run_existing_postgres_bootstrap_prompt.ps1",
        "scripts/install/sli_install.py",
        "scripts/maintenance/self_test.py",
        "scripts/maintenance/semantic_dispatch_partition_recovery.py",
        "scripts/maintenance/semantic_investigation_control.py",
        "scripts/maintenance/server_control.py",
        "scripts/maintenance/storage_cleanup.py",
        "scripts/maintenance/storage_v2_fresh_bootstrap.py",
        "scripts/maintenance/ui_nav_check.py",
        "scripts/maintenance/warm_tier_bootstrap.py",
        "scripts/maintenance/worker_guard.py",
        "scripts/maintenance/worker_supervisor.py",
        "scripts/maintenance/vpn_evidence_grant_control.py",
        "scripts/maintenance/web_server_control.py",
        "scripts/ops/Backup-ProjectSource-NoDb.ps1",
        "scripts/ops/Disable-SLIWorkerSupervisor.ps1",
        "scripts/ops/git_docker.ps1",
        "scripts/ops/Grant-SLICollectorReadAccess.ps1",
        "scripts/ops/Grant-SLIEventChannelReadAccess.ps1",
        "scripts/ops/Grant-SLIEventChannelReadAccessLocal.ps1",
        "scripts/ops/Install-SLIWorkerSupervisor.ps1",
        "scripts/ops/Install-SLIWebServer-v1.ps1",
        "scripts/ops/Install-SLIWebServer-Service.ps1",
        "scripts/ops/WebServer-ServiceSafety.ps1",
        "scripts/ops/Uninstall-SLIWebServer-Service.ps1",
        "scripts/ops/Restart-SLIWorkerSupervisor.ps1",
        "scripts/ops/Start-SLIWebServer-v1.ps1",
        "scripts/ops/Start-SLIWorkerSupervisor.ps1",
        "scripts/package_project.py",
    ),
    "перенос_и_миграции": (
        "scripts/ops/reencrypt_worker_supervisor_secrets.py",
        "scripts/maintenance/ad_context_entity_details_repair.py",
        "scripts/maintenance/ad_context_live_canary.py",
        "scripts/maintenance/ad_snapshot_manifest_canary.py",
        "scripts/maintenance/ad_snapshot_manifest_foundation_migrate.py",
        "scripts/maintenance/db_storage_opt1_finalizer.py",
        "scripts/maintenance/ops_stability1_migrate.py",
        "scripts/maintenance/radius_session_v2_identity_rebind.py",
        "scripts/maintenance/security_problems_report_control.py",
    ),
    "административный_набор": (
        "scripts/ad_context/Export-AdAuditContextBundle.ps1",
        "scripts/ad_context/Export-AdContextBundle.ps1",
        "scripts/ad_context/Export-AdGpoV2Snapshot.ps1",
        "scripts/ad_context/Export-ComputersV6ReferenceSnapshot.ps1",
        "scripts/ad_context/collect_ad_inventory_evidence.ps1",
        "scripts/collect/Collect-DcEventsLastHour.ps1",
        "scripts/dc_client/Invoke-AdLogDcClient.ps1",
        "scripts/dc_client/Register-AdLogDcClientTask.ps1",
        "scripts/maintenance/Run-SLI-AdContext-LiveCanary-v1.ps1",
        "scripts/manual_dc_audit/Invoke-DcAuditLoggingSetup.ps1",
        "scripts/package_admin_toolkit.py",
    ),
    "разработка_и_приёмка": (
        "scripts/ci/pr_scope.py",
        "scripts/ci/server_dotnet_risk.py",
        "scripts/ci/server_dotnet_shard.py",
        "scripts/ci/server_test_durations.py",
        "scripts/ci/t002_clickhouse.py",
        "scripts/ci/shipped_python_tests.py",
        "tools/e2e/replay.py",
        "tools/e2e/report_check.py",
        "tools/e2e/scenario.py",
        "scripts/maintenance/update_acceptance_drill.py",
        "scripts/maintenance/acceptance_run.py",
        "scripts/maintenance/beta_acceptance.py",
        "tools/agent-dev-run.ps1",
        "tools/build-sli-agent-msi.ps1",
        "tools/lab/file_decoy.py",
        "tools/lab/file_ransom.py",
        "tools/lab/lab-01-domain.ps1",
        "tools/lab/lab-02-populate.ps1",
        "tools/lab/lab-03-simulate.ps1",
        "tools/lab/lab-04-agent.ps1",
        "tools/lab/lab-05-file-server.ps1",
        "tools/lab/lab-06-file-simulate.ps1",
        "tools/lab/lab-08-nps-denials.ps1",
        "tools/lab/lab-common.ps1",
        "tools/lab/lab-detection-catalog.ps1",
        "tools/lab/lab-exercise-attack.ps1",
        "tools/lab/lab-exercise.py",
        "tools/lab/lab-orchestrate.ps1",
        "tools/lab/lab-tunnel.ps1",
        "tools/lab/lab-verify.ps1",
        "tools/lab/tests/exercise-contract.ps1",
        "tools/lab/lab_model.py",
        "tools/lab/nps_denials.py",
        "scripts/maintenance/ad_jobs_parity.py",
        "scripts/maintenance/ad_gpo_pilot_acceptance.py",
        "scripts/ai/build_ai_prompt.py",
        "scripts/demo/generate_demo_ad_bundle.py",
        "scripts/demo/load_demo_into_postgres.py",
        "scripts/demo/generate_demo_events.py",
        "scripts/ai/check_redaction_leaks.py",
        "scripts/ai/prepare_ai_preview.py",
        "scripts/ai/run_openai_analysis.py",
        "scripts/apply_project_zip.py",
        "scripts/assets/clean_sli_scene_assets.ps1",
        "scripts/maintenance/dashboard_startup_probe.py",
        "scripts/maintenance/privileged_activity_cost.py",
        "scripts/maintenance/privileged_group_scope_plan.py",
        "scripts/maintenance/report_scoped_category_count_plan.py",
        "scripts/maintenance/register_semantic_chain_pack.py",
        "scripts/maintenance/claude_frontend_candidate_workspace.py",
        "scripts/maintenance/check_ui_domain_binding.py",
        "scripts/maintenance/repository_relevance_audit.py",
        "scripts/maintenance/gpo_v2_reference_score.py",
        "scripts/maintenance/run_pytest.py",
        "scripts/maintenance/validate_event_catalog.py",
        "scripts/dev/compile_sigma_profile.py",
        "scripts/dev/profile_users_v2.py",
        "scripts/dev/run_sigma_history.py",
        "scripts/dev/verify_sigma_package.py",
        "scripts/dev/ui_audit/rules.py",
        "scripts/dev/ui_audit/passport.py",
        "scripts/dev/ui_audit/stand.py",
        "scripts/dev/ui_audit/scenarios.py",
        "scripts/dev/ui_audit/model_review.py",
        "scripts/dev/ui_audit/policy.cjs",
        "scripts/dev/ui_audit/crawl.cjs",
        "scripts/dev/ui_audit/scenario_runner.cjs",
        "scripts/dev/ui_audit/model_walker.cjs",
        "scripts/dev/ui_audit/run_review.sh",
    ),
    "этап_7_исследование": (
        "scripts/maintenance/catalog_required_fields_audit.py",
        "scripts/maintenance/stage7_clickhouse_candidate_a.py",
        "scripts/maintenance/stage7_control_benchmark.py",
        "scripts/maintenance/stage7_clickhouse_candidate_b.py",
        "scripts/maintenance/stage7_control_d_prime_benchmark.py",
        "scripts/maintenance/tier_retention_delete_plan.py",
        "scripts/maintenance/verify_independent_corpus_copy.py",
        "scripts/maintenance/warm_tier_incremental_plan.py",
        "scripts/maintenance/warm_tier_incremental_copy.py",
        "scripts/maintenance/warm_tier_read_probe.py",
        "scripts/maintenance/warm_tier_resource_guard.py",
        "scripts/maintenance/windows_task_correlation_audit.py",
    ),
    "этап_7_не_запускать_до_решения": (
        "scripts/maintenance/record_semantic_control_health.py",
        "scripts/maintenance/run_semantic_calibration_window.py",
        "scripts/maintenance/run_semantic_development_calibration.py",
        "scripts/maintenance/run_semantic_risk_shadow_once.py",
        "scripts/maintenance/run_semantic_shadow_once.py",
        "scripts/maintenance/tier_retention_delete_executor.py",
    ),
    "этап_8_read_only": (
        "scripts/maintenance/domain_posture_canary.py",
        "scripts/maintenance/gpo_permission_canary.py",
        "scripts/maintenance/gpo_report_canary.py",
    ),
    "этап_8_не_запускать_без_решения": (
        "scripts/maintenance/semantic_l1_shadow_control.py",
        "scripts/maintenance/semantic_production_control.py",
    ),
    "этап_9_fixture_only": (
    ),
    "этап_9_disposable_only": (
    ),
    "этап_9_не_запускать_без_решения": (
        "scripts/maintenance/Install-SLI-Stage9RadiusEvidenceRootV1.ps1",
        "scripts/maintenance/Install-SLI-Stage9RadiusEvidenceRootV2.ps1",
        "scripts/maintenance/New-SLI-RadiusAccountingReadOnlyShare.ps1",
        "scripts/maintenance/stage9_radius_identity_owner_migrate.py",
        "scripts/maintenance/stage9_radius_postgres_migrate.py",
        "scripts/maintenance/stage9_radius_registration_apply.py",
    ),
    "этап_9_ручной_runtime_только_по_решению": (
        "scripts/maintenance/stage9_radius_manual_worker.py",
        "scripts/maintenance/stage9_radius_session_consumer_manual.py",
    ),
    "этап_10_disposable_only": (
        "scripts/maintenance/storage_capacity_profile_disposable_acceptance.py",
    ),
    "этап_10_source_only": (
    ),
    "этап_10_bounded_read_only_только_по_решению": (
    ),
    "этап_10_не_запускать_без_решения": (
        "scripts/maintenance/stage10_radius_session_reconciliation_production_control.py",
    ),
    "этап_9_read_only": (
        "scripts/maintenance/Invoke-SLI-RadiusReadOnlyPreflight.ps1",
        "scripts/maintenance/Invoke-SLI-Stage9RadiusEvidenceRootV1.ps1",
        "scripts/maintenance/Invoke-SLI-Stage9RadiusEvidenceRootV2.ps1",
        "scripts/maintenance/stage9_radius_field_quality_audit.py",
        "scripts/maintenance/stage9_radius_correlation_time_preflight.py",
        "scripts/maintenance/stage9_radius_time_aligned_preflight.py",
        "scripts/maintenance/stage9_radius_postgres_production_preflight.py",
    ),
    "этап_11a_bounded_read_only_только_по_решению": (
    ),
    "этап_11a_не_запускать_без_решения": (
    ),
}

FORBIDDEN_ACTIVE_PATHS = (
    "web/react",
    "scripts/ops/Install-AdLogReports.ps1",
    "scripts/import/backfill_event_entities.py",
    "scripts/maintenance/backup_sqlite.py",
    "scripts/maintenance/apply_retention.py",
    "server/app/retention0.py",
    "server/app/semantic_state_evidence_repository.py",
    "scripts/maintenance/findings_pg1_acceptance.py",
    "scripts/maintenance/purge_obsolete_project_files.py",
    "docs/CODEX_REVALIDATION_FIX_REPORT.md",
    "docs/SLI_V4_REAL_DATA_SYSTEM_DESIGN.md",
    "docs/UI_PLATFORM1_ACCEPTANCE.md",
    "docs/STORAGE_V2_SCHEMA_CANARY1.md",
    "docs/sli_v4_recovery",
)


def _is_python_entrypoint(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig", errors="strict"))
    except (OSError, SyntaxError, UnicodeError):
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        try:
            rendered = ast.unparse(node.test)
        except Exception:  # noqa: BLE001, S112 -- Ignore guards that cannot be rendered.
            continue
        if "__name__" in rendered and "__main__" in rendered:
            return True
    return False


#: Owner-local tools kept out of git on purpose (see .gitignore): classified
#: when present on disk, never required to exist in a clean checkout.
LOCAL_ONLY_EXECUTABLES = frozenset({
    "scripts/maintenance/remote_postgres_inventory.py",
})


def _discover_executables() -> set[str]:
    found: set[str] = set()
    for base in (ROOT / "scripts", ROOT / "tools"):
        for path in base.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            suffix = path.suffix.lower()
            if suffix == ".py" and not _is_python_entrypoint(path):
                continue
            if suffix not in {".py", ".ps1", ".cmd", ".bat"}:
                continue
            found.add(path.relative_to(ROOT).as_posix())
    return found


def _duplicates(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


def audit() -> dict[str, object]:
    registered_items = [
        path
        for paths in COMPONENTS.values()
        for path in paths
    ]
    registered = set(registered_items)
    discovered = _discover_executables() - LOCAL_ONLY_EXECUTABLES
    missing = sorted(path for path in registered if not (ROOT / path).is_file())
    unclassified = sorted(discovered - registered)
    duplicate_registration = _duplicates(registered_items)
    forbidden_present = sorted(
        path for path in FORBIDDEN_ACTIVE_PATHS if (ROOT / path).exists()
    )

    env_template = (ROOT / ".env.example").read_text(encoding="utf-8-sig")
    yaml_template = (ROOT / "config" / "adlog_config.example.yaml").read_text(
        encoding="utf-8-sig"
    )
    template_failures: list[str] = []
    if "ADLOG_DB_BACKEND=postgres" not in env_template:
        template_failures.append(".env.example не фиксирует PostgreSQL")
    if "ADLOG_SECURITY_MAX_EVENTS=50000" not in env_template:
        template_failures.append(".env.example содержит неверный штатный лимит")
    if "sqlite" in env_template.lower():
        template_failures.append(".env.example содержит SQLite")
    if yaml_template.lower().count("\nretention:") != 1:
        template_failures.append("пример YAML должен иметь один блок retention")
    if "sqlite" in yaml_template.lower():
        template_failures.append("пример YAML содержит SQLite")

    failures = (
        missing
        + unclassified
        + duplicate_registration
        + forbidden_present
        + template_failures
    )
    return {
        "status": "ok" if not failures else "failed",
        "discovered_executables": len(discovered),
        "registered_executables": len(registered),
        "classifications": {
            name: len(paths) for name, paths in COMPONENTS.items()
        },
        "unclassified": unclassified,
        "missing_registered": missing,
        "duplicate_registration": duplicate_registration,
        "forbidden_active_paths": forbidden_present,
        "template_failures": template_failures,
        "archive_is_runtime_source": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Проверить актуальность исполняемых файлов проекта."
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = audit()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Проверка актуальности репозитория: {result['status']}")
        print(
            "Исполняемые файлы: "
            f"{result['discovered_executables']} обнаружено, "
            f"{result['registered_executables']} классифицировано."
        )
        for key in (
            "unclassified",
            "missing_registered",
            "duplicate_registration",
            "forbidden_active_paths",
            "template_failures",
        ):
            for item in result[key]:
                print(f"- {key}: {item}")
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
