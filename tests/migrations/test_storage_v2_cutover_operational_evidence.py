from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = "config/postgres_migrations/082_radius_event_catalog_revision_registration.sql"
ROLLBACK_PATH = "config/postgres_migrations/082_radius_event_catalog_revision_registration.rollback.sql"
# SHA-256 of the committed (LF) content; checkouts may convert to CRLF on Windows.
FORWARD_SHA256 = "8cddd92971282e306510b6a40f7e6fb9557edd2b2c099858f3e40cdf8af047f9"


def test_migration_082_and_rollback_match_recorded_checksums() -> None:
    forward = (ROOT / MIGRATION_PATH).read_bytes()
    rollback = (ROOT / ROLLBACK_PATH).read_bytes()
    ledger = json.loads((ROOT / "deploy/linux/native_pg_ledger.json").read_text(encoding="utf-8"))["files"]
    assert sha256(forward.replace(b"\r\n", b"\n")).hexdigest() == ledger[MIGRATION_PATH] == FORWARD_SHA256
    assert sha256(rollback.replace(b"\r\n", b"\n")).hexdigest() == ledger[ROLLBACK_PATH]
    assert b"migration 082 requires migration 051" in forward
    assert b"migration 082 requires events_v2_core" in forward
    assert b"migration 082 requires the catalog revision trigger" in forward
