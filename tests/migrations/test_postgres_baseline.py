"""Clean-install PostgreSQL baseline (plan 6.6)."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from deploy.linux.native_pg_inventory import expected_ledger, verify_manifest
from scripts.maintenance import existing_postgres_bootstrap as bootstrap
from tests.migrations.migration_inventory import REVERSIBLE_CHAIN_START, migration_inventory

ROOT = Path(__file__).resolve().parents[2]
BASELINE_DIR = ROOT / "config" / "postgres_baseline"
MIGRATIONS_DIR = ROOT / "config" / "postgres_migrations"


def _migrations():
    return bootstrap.forward_migration_inventory(MIGRATIONS_DIR)


def _installation_domains() -> set[str]:
    # Independent of sanitation exemptions, including in a public genesis tree.
    historical = (MIGRATIONS_DIR / "100_users_report_domain_scope.sql").read_text(encoding="utf-8")
    domains = set(re.findall(r"lower\(domain\.fqdn\)='([^']+)'", historical))
    assert domains, "historical domain extraction must not become a vacuous check"
    return {domain.lower() for domain in domains}


def test_baseline_matches_the_migrations_it_covers() -> None:
    baseline = bootstrap.load_baseline(BASELINE_DIR, _migrations())
    manifest = json.loads((BASELINE_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert baseline.version == manifest["baseline_version"]
    assert set(manifest["migrations"]) == {str(item.version) for item in _migrations() if item.version <= baseline.version}


@pytest.mark.parametrize("version,name", [(299, "login_account_throttle"), (300, "owner_recovery")])
def test_auth_migrations_remain_post_baseline(version: int, name: str) -> None:
    baseline = bootstrap.load_baseline(BASELINE_DIR, _migrations())
    throttle = [item for item in _migrations() if item.version == version]
    assert len(throttle) == 1
    assert throttle[0].name == name
    assert throttle[0].version > baseline.version
    assert throttle[0].path.name == f"{version}_{name}.sql"


def test_baseline_covers_storage_organization_and_plugin_state_migrations() -> None:
    manifest = json.loads((BASELINE_DIR / "manifest.json").read_text(encoding="utf-8"))
    schema = (BASELINE_DIR / "baseline.sql").read_text(encoding="utf-8")
    assert manifest["baseline_version"] == 152
    migrations = {item.version: item for item in _migrations()}
    for version, name in (
        (150, "storage_v2_event_bigint"),
        (151, "organization_neutral_radius_access"),
        (152, "plugin_state"),
    ):
        assert migrations[version].name == name
        assert manifest["migrations"][str(version)] == bootstrap.normalized_sha256(migrations[version].path)
        assert re.search(rf"^\d+\t{version}\t{name}\t", schema, re.MULTILINE)


def test_baseline_contains_the_plugin_state_read_and_write_contract() -> None:
    schema = (BASELINE_DIR / "baseline.sql").read_text(encoding="utf-8")
    assert "CREATE TABLE public.plugin_state_v1 (" in schema
    for function in (
        "read_plugin_states_v1()",
        "set_plugin_enabled_v1(",
        "observe_remote_access_plugin_v1(",
        "finish_remote_access_plugin_drain_v1()",
    ):
        assert f"CREATE FUNCTION public.{function}" in schema
    assert "ALTER TABLE public.plugin_state_v1 OWNER TO adlog_plugin_lifecycle_owner;" in schema


def test_baseline_defines_folded_contract_tables_only_once() -> None:
    schema = (BASELINE_DIR / "baseline.sql").read_text(encoding="utf-8")
    for table in ("platform_settings", "domain_controller_targets", "investigation_finding_links"):
        definitions = re.findall(
            rf"^CREATE TABLE (?:IF NOT EXISTS )?public\.{table}\s*\(",
            schema,
            re.IGNORECASE | re.MULTILINE,
        )
        assert len(definitions) == 1


def test_baseline_has_no_installation_domain_or_install_specific_rows() -> None:
    schema = (BASELINE_DIR / "baseline.sql").read_text(encoding="utf-8")
    roles = (BASELINE_DIR / "roles.sql").read_text(encoding="utf-8")
    assert bootstrap.BASELINE_DOMAIN_PLACEHOLDER in schema
    for domain in _installation_domains():
        assert domain not in schema.lower()
        assert domain not in roles.lower()
    for table in ("public.auth_users", "public.access_platform_owners"):
        assert f"COPY {table} " not in schema
    assert "SELECT pg_catalog.setval('public.auth_users_id_seq', 1, false);" in schema
    assert "CREATE ROLE postgres;" not in roles
    assert "CREATE ROLE adlog_user;" not in roles
    assert "PASSWORD" not in roles.upper()


def test_baseline_replaces_historical_radius_subscription_with_registered_sources() -> None:
    historical = (MIGRATIONS_DIR / "083_vpn_session_evidence_read_boundary.sql").read_text(encoding="utf-8")
    subscription = re.search(r"delivery\.subscription_id\s*=\s*'([^']+)'", historical)
    assert subscription is not None
    schema = (BASELINE_DIR / "baseline.sql").read_text(encoding="utf-8")
    assert subscription.group(1) not in schema
    assert "vpn-radius-session-observations-%-v1" in schema
    assert "radius_vpn_session_evidence_observations_v1" in schema


def test_render_substitutes_only_a_dns_domain(tmp_path: Path) -> None:
    baseline = bootstrap.load_baseline(BASELINE_DIR, _migrations())
    rendered = bootstrap.render_baseline_schema(baseline, "Corp.Example.TEST", tmp_path / "baseline.sql").read_text(encoding="utf-8")
    assert bootstrap.BASELINE_DOMAIN_PLACEHOLDER not in rendered
    assert "corp.example.test" in rendered
    for invalid in ("example", "a'b.test", "a b.test"):
        with pytest.raises(bootstrap.BootstrapError):
            bootstrap.render_baseline_schema(baseline, invalid, tmp_path / "invalid.sql")


def test_edited_baseline_or_covered_migration_is_rejected(tmp_path: Path) -> None:
    copy = tmp_path / "postgres_baseline"
    shutil.copytree(BASELINE_DIR, copy)
    with (copy / "roles.sql").open("a", encoding="utf-8") as handle:
        handle.write("-- edited\n")
    with pytest.raises(bootstrap.BootstrapError, match="baseline_file_mismatch"):
        bootstrap.load_baseline(copy, _migrations())

    migrations = list(_migrations())
    edited = tmp_path / migrations[0].path.name
    edited.write_text(migrations[0].path.read_text(encoding="utf-8") + "\n-- edited\n", encoding="utf-8")
    migrations[0] = bootstrap.Migration(
        version=migrations[0].version, name=migrations[0].name, path=edited, sha256=migrations[0].sha256,
    )
    with pytest.raises(bootstrap.BootstrapError, match="baseline_migrations_mismatch"):
        bootstrap.load_baseline(BASELINE_DIR, migrations)


@pytest.mark.parametrize("covered_version", [100, 101, 106, 107, 108])
def test_baseline_install_order_and_only_newer_migrations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, covered_version: int) -> None:
    baseline = bootstrap.Baseline(version=144, roles_path=tmp_path / "roles.sql", schema_path=tmp_path / "baseline.sql")
    newer = tmp_path / "145_future.sql"
    newer.write_text("select 1;\n", encoding="utf-8")
    migrations = (
        bootstrap.Migration(version=covered_version, name="covered", path=tmp_path / f"{covered_version}_covered.sql", sha256="a" * 64),
        bootstrap.Migration(version=145, name="future", path=newer, sha256="b" * 64),
    )
    calls: list[tuple[str, str]] = []

    def run_psql_file(**kwargs):
        calls.append((kwargs["user"], Path(kwargs["sql_path"]).name))
        return {"status": "ok"}

    monkeypatch.setattr(bootstrap, "run_psql_file", run_psql_file)
    monkeypatch.setattr(bootstrap, "create_platform_owner", lambda executor, password: calls.append(("owner", password)))
    bootstrap.apply_baseline_sequence(
        baseline=baseline, rendered_schema_path=tmp_path / "rendered.sql", migrations=migrations,
        psql=Path("psql"), host="127.0.0.1", port=5432, database="sli", admin_password="admin",
        runtime_password="runtime", platform_owner_password="owner-password", admin_execute=lambda *args: None,
    )
    assert calls == [
        ("postgres", "roles.sql"),
        ("postgres", "rendered.sql"),
        ("owner", "owner-password"),
        ("postgres", "145_future.sql"),
    ]


def test_current_baseline_applies_governance_then_job_queue_with_fake_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    migrations = _migrations()
    baseline = bootstrap.load_baseline(BASELINE_DIR, migrations)
    assert baseline.version == 152
    calls: list[str] = []

    def run_psql_file(**kwargs):
        calls.append(Path(kwargs["sql_path"]).name)
        return {"status": "ok"}

    monkeypatch.setattr(bootstrap, "run_psql_file", run_psql_file)
    monkeypatch.setattr(bootstrap, "create_platform_owner", lambda *args: None)
    bootstrap.apply_baseline_sequence(
        baseline=baseline, rendered_schema_path=tmp_path / "rendered.sql", migrations=migrations,
        psql=Path("psql"), host="127.0.0.1", port=5432, database="sli",
        admin_password="synthetic-admin", runtime_password="synthetic-runtime",
        platform_owner_password="synthetic-owner", admin_execute=lambda *args: None,
    )
    assert calls[:4] == [
        "roles.sql", "rendered.sql", "153_semantic_governance.sql", "154_core_job_queue.sql",
    ]
    assert calls[2:] == [
        f"{version:03}_{name}.sql"
        for version, name in migration_inventory(starting_at=baseline.version + 1)
    ]
    assert not any(name.endswith(".rollback.sql") for name in calls)
    assert "297_agent_stream_import_health.sql" in calls[2:]
    assert len(calls) == len(set(calls))


def test_semantic_governance_is_a_forward_migration_on_top_of_baseline() -> None:
    """153 is applied after the 152 baseline; it declares its own schema objects."""
    manifest = json.loads((BASELINE_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["baseline_version"] == 152
    migration = (BASELINE_DIR.parent / "postgres_migrations" / "153_semantic_governance.sql").read_text(encoding="utf-8")
    for table in ("semantic_suppressions", "semantic_policy_admission", "semantic_control_audit"):
        assert f"create table {table} (" in migration.lower()
    assert "152" in migration and "plugin_state" in migration


def test_runtime_switch_is_applied_after_the_baseline() -> None:
    migrations = [item for item in _migrations() if item.version == 296]
    assert [(item.version, item.name, item.path.name) for item in migrations] == [
        (296, "agent_runtime_switch", "296_agent_runtime_switch.sql"),
    ]
    baseline = bootstrap.load_baseline(BASELINE_DIR, _migrations())
    assert baseline.version < migrations[0].version


@pytest.mark.parametrize("previous", [
    version for version, _ in migration_inventory(starting_at=REVERSIBLE_CHAIN_START)[:-1]
])
def test_each_predecessor_accepts_next_migration_in_ascending_order(tmp_path, monkeypatch, previous):
    baseline = bootstrap.Baseline(
        version=previous, roles_path=tmp_path / "roles.sql", schema_path=tmp_path / "baseline.sql",
    )
    calls = []
    monkeypatch.setattr(bootstrap, "run_psql_file", lambda **kwargs: calls.append(Path(kwargs["sql_path"]).name))
    monkeypatch.setattr(bootstrap, "create_platform_owner", lambda *args: None)
    bootstrap.apply_baseline_sequence(
        baseline=baseline, rendered_schema_path=tmp_path / "rendered.sql", migrations=_migrations(),
        psql=Path("psql"), host="127.0.0.1", port=5432, database="sli",
        admin_password="synthetic-admin", runtime_password="synthetic-runtime",
        platform_owner_password="synthetic-owner", admin_execute=lambda *args: None,
    )
    expected = [(row["version"], row["name"]) for row in expected_ledger(ROOT) if row["version"] > previous]
    assert expected and all(version > previous for version, _ in expected)
    assert [version for version, _ in expected] == sorted({version for version, _ in expected})
    manifest = json.loads((ROOT / "deploy/linux/native_pg_ledger.json").read_text("utf-8"))
    verify_manifest(ROOT, manifest)
    assert calls == ["roles.sql", "rendered.sql"] + [f"{version:03}_{name}.sql" for version, name in expected]
