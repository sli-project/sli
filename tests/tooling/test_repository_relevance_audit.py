from __future__ import annotations

from scripts.maintenance.repository_relevance_audit import COMPONENTS, audit


def test_cutover_readiness_is_an_operations_tool() -> None:
    assert "scripts/maintenance/legacy_cutover_readiness.py" in COMPONENTS["эксплуатация"]


def test_model_review_tools_are_development_and_acceptance_tools() -> None:
    assert {
        "scripts/dev/ui_audit/model_review.py",
        "scripts/dev/ui_audit/model_walker.cjs",
    } <= set(COMPONENTS["разработка_и_приёмка"])


def test_users_v2_profiler_is_a_development_and_acceptance_tool() -> None:
    assert "scripts/dev/profile_users_v2.py" in COMPONENTS["разработка_и_приёмка"]


def test_agent_msi_build_is_a_development_and_acceptance_tool() -> None:
    assert "tools/build-sli-agent-msi.ps1" in COMPONENTS["разработка_и_приёмка"]


def test_ui_domain_binding_guard_is_a_development_and_acceptance_tool() -> None:
    assert "scripts/maintenance/check_ui_domain_binding.py" in COMPONENTS["разработка_и_приёмка"]


def test_local_agent_installer_is_an_operations_tool() -> None:
    assert "tools/install-sli-agent-local.ps1" in COMPONENTS["эксплуатация"]


def test_lab_tools_are_development_and_acceptance_tools() -> None:
    assert {
        "tools/lab/file_ransom.py",
        "tools/lab/lab-01-domain.ps1",
        "tools/lab/lab-02-populate.ps1",
        "tools/lab/lab-03-simulate.ps1",
        "tools/lab/lab-04-agent.ps1",
        "tools/lab/lab-05-file-server.ps1",
        "tools/lab/lab-06-file-simulate.ps1",
        "tools/lab/lab-08-nps-denials.ps1",
        "tools/lab/lab-common.ps1",
        "tools/lab/lab-orchestrate.ps1",
        "tools/lab/lab-tunnel.ps1",
        "tools/lab/lab-verify.ps1",
        "tools/lab/lab_model.py",
        "tools/lab/nps_denials.py",
    } <= set(COMPONENTS["разработка_и_приёмка"])


def test_nps_threshold_worker_is_a_runtime_tool() -> None:
    assert "scripts/runtime/nps_threshold_worker.py" in COMPONENTS["runtime"]


def test_file_ransom_worker_is_a_runtime_tool() -> None:
    assert "scripts/runtime/file_ransom_worker.py" in COMPONENTS["runtime"]


def test_account_watch_worker_is_a_runtime_tool() -> None:
    assert "scripts/runtime/account_watch_worker.py" in COMPONENTS["runtime"]


def test_web_service_safety_helper_is_an_operations_tool() -> None:
    assert "scripts/ops/WebServer-ServiceSafety.ps1" in COMPONENTS["эксплуатация"]


def test_repository_executables_are_explicitly_classified() -> None:
    result = audit()

    assert result["status"] == "ok", result
    assert result["unclassified"] == []
    assert result["missing_registered"] == []
    assert result["duplicate_registration"] == []
    assert result["forbidden_active_paths"] == []
    assert result["template_failures"] == []
    assert result["archive_is_runtime_source"] is False
