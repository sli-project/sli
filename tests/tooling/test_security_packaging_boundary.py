from __future__ import annotations

import pytest


@pytest.mark.parametrize("name", [
    "server/sli/ops/worker_supervisor_secrets.py",
    "server/sli/sources/ad_source_credentials.py",
    "server/sli/sources/plugin_worker_credentials.py",
])
def test_source_package_keeps_credential_implementation(name, tmp_path):
    from scripts.package_project import is_excluded_file

    assert not is_excluded_file(tmp_path / name, tmp_path)


@pytest.mark.parametrize("name", [
    "config/secrets/admin.json", "config/source_credentials.json",
    "server/sli/ops/password.txt", "config/local/profile.py", ".env",
    "server/sli/ops/private_key.pem",
])
def test_source_package_still_excludes_secret_material(name, tmp_path):
    from scripts.package_project import is_excluded_file

    assert is_excluded_file(tmp_path / name, tmp_path)


def test_normal_product_package_excludes_administrative_dc_tools() -> None:
    from scripts import package_project

    root = package_project.Path(__file__).resolve().parents[2]
    names = {package_project.rel_posix(path, root) for path in package_project.iter_source_files(root)}

    assert not any(name.startswith("scripts/manual_dc_audit/") for name in names)
    assert not any(name.startswith("scripts/dc_client/") for name in names)
    assert "scripts/run_dc_log_pilot.py" in names
    assert "scripts/auth/manage_auth.py" in names
    assert "server/sli/access/owner_recovery.py" in names


def test_normal_product_package_contains_rebuildable_react_workspace() -> None:
    from scripts import package_project

    root = package_project.Path(__file__).resolve().parents[2]
    names = {package_project.rel_posix(path, root) for path in package_project.iter_source_files(root)}

    assert "frontend/package.json" in names
    assert "frontend/src/main.tsx" in names
    assert not any(name.startswith("frontend/node_modules/") for name in names)


def test_normal_product_package_contains_canonical_dependency_locks() -> None:
    from scripts import package_project

    root = package_project.Path(__file__).resolve().parents[2]
    names = {
        package_project.rel_posix(path, root)
        for path in package_project.iter_source_files(root)
    }

    assert {"package.json", "package-lock.json", "requirements.lock.txt"} <= names


def test_normal_update_rejects_administrative_dc_tools() -> None:
    from scripts.apply_project_zip import is_allowed

    assert not is_allowed("scripts/manual_dc_audit/Invoke-DcAuditLoggingSetup.ps1")
    assert not is_allowed("scripts/dc_client/Register-AdLogDcClientTask.ps1")
    assert is_allowed("scripts/run_dc_log_pilot.py")
    assert is_allowed("frontend/src/main.tsx")
    assert is_allowed("package.json")
    assert is_allowed("package-lock.json")
    assert is_allowed("requirements.lock.txt")
    assert not is_allowed("frontend/node_modules/react/index.js")


def test_administrative_toolkit_is_explicit_and_complete(tmp_path) -> None:
    from scripts.package_admin_toolkit import TOOLKIT_FILES, build_toolkit

    result = build_toolkit(tmp_path / "admin-toolkit.zip", dry_run=True)

    assert result["status"] == "dry_run"
    assert result["manifest"]["normal_product_update_allowed"] is False
    assert result["manifest"]["requires_explicit_operator_review"] is True
    assert result["files"] == list(TOOLKIT_FILES)
