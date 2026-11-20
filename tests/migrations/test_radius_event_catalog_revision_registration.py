import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CATALOG_VERSION = "2026-07-30-radius-descriptor-v1"
FORWARD_PATH = (
    ROOT
    / "config/postgres_migrations/082_radius_event_catalog_revision_registration.sql"
)
ROLLBACK_PATH = (
    ROOT
    / "config/postgres_migrations"
    / "082_radius_event_catalog_revision_registration.rollback.sql"
)


def test_radius_catalog_revision_registration_matches_the_emitting_contract() -> None:
    descriptor = json.loads(
        (ROOT / "config/radius_event_catalog.json").read_text(encoding="utf-8")
    )
    source_pack = (
        ROOT / "server/source_packs/windows_nps_radius.py"
    ).read_text(encoding="utf-8")
    forward = FORWARD_PATH.read_text(encoding="utf-8").lower()

    assert descriptor["version"] == CATALOG_VERSION
    assert f'noise_catalog_version="{CATALOG_VERSION}"' in source_pack
    assert "migration 082 requires migration 051" in forward
    assert "migration 082 requires event_catalog_revisions" in forward
    assert "migration 082 requires the catalog revision trigger" in forward
    assert "insert into event_catalog_revisions(version)" in forward
    assert f"values('{CATALOG_VERSION}')" in forward
    assert "on conflict(version) do nothing" in forward
    assert "values(82,'radius_event_catalog_revision_registration')" in forward


def test_radius_catalog_revision_registration_is_exact_and_additive() -> None:
    forward = FORWARD_PATH.read_text(encoding="utf-8").lower()
    rollback = ROLLBACK_PATH.read_text(encoding="utf-8").lower()

    assert forward.count(CATALOG_VERSION) == 1
    assert "select distinct" not in forward
    assert "insert into event_catalog_revisions(version)\nselect" not in forward
    assert "create table" not in forward
    assert "alter table" not in forward
    assert "drop " not in forward
    assert "create or replace function" not in forward
    assert "create trigger" not in forward
    assert "update event_catalog_revisions" not in forward
    assert "delete from event_catalog_revisions" not in forward
    assert "rollback 082 is forbidden" in rollback
    assert CATALOG_VERSION in rollback


def test_radius_catalog_revision_trigger_must_fire_in_origin_mode() -> None:
    forward = FORWARD_PATH.read_text(encoding="utf-8")
    predicate = re.search(
        r"\btgenabled\s+in\s*\((?P<modes>[^)]*)\)",
        forward,
        flags=re.IGNORECASE,
    )

    assert predicate is not None, "migration 082 must name origin-capable modes"
    admitted_modes = set(re.findall(r"'([A-Z])'", predicate.group("modes")))
    actual = {
        mode: mode in admitted_modes
        for mode in ("O", "A", "R", "D")
    }
    assert actual == {"O": True, "A": True, "R": False, "D": False}
    assert forward.lower().count("tgenabled") == 1
