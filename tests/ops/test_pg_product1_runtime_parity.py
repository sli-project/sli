from pathlib import Path


def test_pg_findings_no_longer_explicit_limited():
    text=Path("server/sli/semantic/findings.py").read_text(encoding="utf-8")
    assert "findings_refresh_pg_not_implemented" not in text
    assert "_refresh_findings_postgres" in text

def test_post_collection_recovery_and_retention_wired():
    pipeline=Path("server/sli/sources/post_collection_pipeline.py").read_text(encoding="utf-8")
    http=Path("server/api/http_server.py").read_text(encoding="utf-8")
    assert "attempt_count" in pipeline and "cleanup_post_collection_jobs" in pipeline
    assert "recover_stale_post_collection_jobs()" in http

def test_collector_health_exposes_post_collection():
    text=Path("server/sli/sources/collector_health.py").read_text(encoding="utf-8")
    assert '"post_collection": post_collection' in text
