from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
OLD_PR83_HEAD = "f069a22210fcd0de9782b940e50f79adce03fa5e"
MIGRATION_PATH = "config/postgres_migrations/082_radius_event_catalog_revision_registration.sql"
ROLLBACK_PATH = "config/postgres_migrations/082_radius_event_catalog_revision_registration.rollback.sql"
# SHA-256 of the committed (LF) content; checkouts may convert to CRLF on Windows.
FORWARD_SHA256 = "8cddd92971282e306510b6a40f7e6fb9557edd2b2c099858f3e40cdf8af047f9"


def _old_file(path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{OLD_PR83_HEAD}:{path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return result.stdout.decode("utf-8")


def _git_stdout(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def test_pr83_disposition_is_independently_verifiable_from_source() -> None:
    forward = (ROOT / MIGRATION_PATH).read_bytes()
    rollback = (ROOT / ROLLBACK_PATH).read_text(encoding="utf-8")
    old_forward_blob = _git_stdout("rev-parse", f"{OLD_PR83_HEAD}:{MIGRATION_PATH}")
    current_forward_blob = _git_stdout("rev-parse", f"HEAD:{MIGRATION_PATH}")
    old_rollback_blob = _git_stdout("rev-parse", f"{OLD_PR83_HEAD}:{ROLLBACK_PATH}")
    current_rollback_blob = _git_stdout("rev-parse", f"HEAD:{ROLLBACK_PATH}")

    assert old_forward_blob == current_forward_blob == "4559a4bdb0cbb902441a96f483c0c7f84b3a1767"
    assert old_rollback_blob == current_rollback_blob
    assert (ROOT / MIGRATION_PATH).read_text(encoding="utf-8") == _old_file(MIGRATION_PATH)
    assert rollback == _old_file(ROLLBACK_PATH)
    assert sha256(forward.replace(b"\r\n", b"\n")).hexdigest() == FORWARD_SHA256
    assert b"migration 082 requires migration 051" in forward
    assert b"migration 082 requires events_v2_core" in forward
    assert b"migration 082 requires the catalog revision trigger" in forward
