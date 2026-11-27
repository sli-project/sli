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
