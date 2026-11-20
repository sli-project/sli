from pathlib import Path

from server.sli.semantic.semantic_development_calibration import assert_development_only, evaluate_development_fixture
from server.sli.semantic.semantic_processing import SemanticFeatureSettings
from scripts.runtime import semantic_worker


def test_development_fixture_is_measured_but_never_claims_production_accuracy() -> None:
    result = evaluate_development_fixture(["confirmed_security"] * 8 + ["false_positive"] * 2)
    assert result["state"] == "measured"
    assert result["rate_percent"] == 20.0
    assert result["development_contract_ready"] is True
    assert result["counts_as_analyst_sample"] is False
    assert result["production_accuracy_claim"] is False
    assert_development_only(result)


def test_semantic_worker_is_fail_closed_to_development_modes() -> None:
    source = Path("scripts/runtime/semantic_worker.py").read_text(encoding="utf-8")
    assert "finding creation" in source
    assert "lifecycle_status='enabled'" in source
    assert 'allowed_modes": ["test", "shadow"]' in source


def test_semantic_worker_commits_scope_guard_before_job_transactions(
    monkeypatch,
) -> None:
    class Connection:
        commits = 0

        def commit(self) -> None:
            self.commits += 1

    conn = Connection()
    monkeypatch.setattr(
        semantic_worker,
        "_guard_development_scope",
        lambda actual: None if actual is conn else (_ for _ in ()).throw(
            AssertionError("unexpected connection")
        ),
    )

    semantic_worker._prepare_connection(conn)

    assert conn.commits == 1


def test_semantic_worker_uses_controller_authorized_archive_reader(monkeypatch) -> None:
    class Connection:
        def close(self) -> None:
            pass

    archive = object()
    observed = []
    monkeypatch.setattr(semantic_worker, "_connect", Connection)
    monkeypatch.setattr(semantic_worker, "_prepare_connection", lambda _conn: None)
    monkeypatch.setattr(
        semantic_worker,
        "_archive_reader",
        lambda: (_ for _ in ()).throw(
            AssertionError("authorized reader must not fall back to env routing")
        ),
    )
    monkeypatch.setattr(
        semantic_worker.SemanticFeatureSettings,
        "from_env",
        classmethod(lambda cls: SemanticFeatureSettings()),
    )
    monkeypatch.setattr(
        semantic_worker,
        "process_semantic_outbox",
        lambda _conn, *, archive, settings, limit: observed.append(archive)
        or {"completed": 0, "failed": 0},
    )
    monkeypatch.setattr(
        semantic_worker,
        "process_semantic_dispatch",
        lambda _conn, *, archive, settings, limit: observed.append(archive)
        or {"completed": 0, "failed": 0},
    )

    result = semantic_worker.run_once(limit=1, archive=archive)

    assert result["status"] == "ok"
    assert observed == [archive, archive]
