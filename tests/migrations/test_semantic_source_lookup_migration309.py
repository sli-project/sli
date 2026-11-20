"""The large-installation lookup fix must preserve the native authority gates."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_lookup_migration_is_reversible_and_requires_previous_maximum():
    path = ROOT / "config/postgres_migrations/309_semantic_source_lookup.sql"
    assert path.exists(), "large-database lookup migration is missing"
    forward = path.read_text("utf-8")
    rollback = path.with_suffix(".rollback.sql").read_text("utf-8")
    for text in (forward, rollback):
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in text
        assert "set local role adlog_storage_owner" in text
        assert "set local lock_timeout='5s'" in text
        assert text.strip().endswith("commit;")
    assert "version=308 and name='semantic_review_row_lock'" in forward
    assert "version>=309" in forward
    assert "version>309" in rollback
    assert "default_detection_sources_before_v301()" in forward
    assert "file_audit_decoy_stream_v309" in forward
    assert "file_audit_context_window_v309" in forward
    assert "file_audit_discovery_stream_v309" in forward
