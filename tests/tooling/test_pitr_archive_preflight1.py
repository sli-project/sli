from __future__ import annotations

from pathlib import Path


def test_destination_requires_a_different_volume() -> None:
    from scripts.maintenance.pitr_archive_preflight import independent_destination

    assert independent_destination(r"C:\PostgreSQL\data", r"D:\sli-pitr") is True
    assert independent_destination(r"C:\PostgreSQL\data", r"C:\sli-pitr") is False
    assert independent_destination(r"\\files01\pgdata\data", r"\\files02\archive\sli") is True
    assert independent_destination(r"\\files01\pgdata\data", r"\\files01\pgdata\archive") is False


def test_destination_uses_device_for_existing_posix_paths(tmp_path: Path) -> None:
    from scripts.maintenance.pitr_archive_preflight import independent_destination

    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    assert independent_destination(str(source), str(destination)) is False


def test_preflight_is_read_only_and_redacts_archive_command() -> None:
    source = Path("scripts/maintenance/pitr_archive_preflight.py").read_text(encoding="utf-8").lower()
    assert '"archive_command_sha256"' in source
    assert '"archive_command_present"' in source
    assert '"postgres_settings_changed": false' in source
    assert '"postgres_restarted": false' in source
    assert "alter system" not in source
    assert "pg_reload_conf" not in source
    assert "start-service" not in source
    assert "restart-service" not in source
