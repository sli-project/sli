from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_computers_report_migration_registers_separate_scoped_report() -> None:
    migration = (ROOT / "config/postgres_migrations/101_computers_report_v1.sql").read_text(encoding="utf-8")
    normalized = "".join(migration.split()).casefold()

    assert "'ad.assets.computers',1,'компьютерыactivedirectory','ad_computer'" in normalized
    assert "'ad.computers',1,'компьютеры'" in normalized
    assert "'target_path','/computers-report'" in normalized
    assert "array['identity_basic','technical','security']" in normalized
    assert "array['view','export']" in normalized
    # Historical migration bytes are pinned by the V6 predecessor contract.
    # Its registration guard and package grant must select the same domain;
    # clean installs use the configured domain in the PostgreSQL baseline.
    domain_filters = normalized.split("lower(domain.fqdn)='")[1:]
    assert len(domain_filters) == 2
    assert domain_filters[0].split("'", 1)[0] == domain_filters[1].split("'", 1)[0]
    assert "jsonb_build_object('kind','domain','ids',jsonb_build_array(domain.id))" in normalized
    assert "insertintoschema_migrations(version,name)values(101,'computers_report_v1')" in normalized

    rollback = (ROOT / "config/postgres_migrations/101_computers_report_v1.rollback.sql").read_text(encoding="utf-8").casefold()
    assert "report_key='ad.computers'" in rollback
    assert "dataset_key='ad.assets.computers'" in rollback
    assert "version=101" in rollback
