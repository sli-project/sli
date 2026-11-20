"""L04: DB authority, installation seed and no organisation defaults."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import (
    Baseline,
    BootstrapError,
    render_baseline_schema,
)



def test_baseline_seeds_report_domain_in_database_without_changing_source(tmp_path: Path) -> None:
    source = tmp_path / "source.sql"
    original = "-- __SLI_REPORT_DOMAIN__\n"
    source.write_text(original, encoding="utf-8")
    baseline = Baseline(version=166, roles_path=tmp_path / "roles.sql", schema_path=source)
    target = render_baseline_schema(
        baseline, " Install.Example.Invalid ", tmp_path / "rendered.sql", seed_report_domain=True,
    )
    rendered = target.read_text(encoding="utf-8")
    assert "__SLI_REPORT_DOMAIN__" not in rendered
    assert "INSERT INTO public.platform_settings (key, value, updated_by)" in rendered
    assert "VALUES ('reports.domain_fqdn', 'install.example.invalid', 'installer')" in rendered
    assert "ON CONFLICT (key) DO NOTHING" in rendered
    assert source.read_text(encoding="utf-8") == original
    unseeded = render_baseline_schema(baseline, "example.invalid", tmp_path / "unseeded.sql")
    assert "INSERT INTO public.platform_settings" not in unseeded.read_text(encoding="utf-8")


@pytest.mark.parametrize("domain", ["", "example", "a'b.invalid", "example.invalid;select"])
def test_bootstrap_refuses_invalid_domain_before_writing(tmp_path: Path, domain: str) -> None:
    baseline = Baseline(version=166, roles_path=tmp_path / "roles.sql", schema_path=tmp_path / "missing.sql")
    target = tmp_path / "rendered.sql"
    with pytest.raises(BootstrapError, match="source_domain_config_invalid"):
        render_baseline_schema(baseline, domain, target)
    assert not target.exists()
