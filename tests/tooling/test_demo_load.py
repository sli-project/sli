from __future__ import annotations

import pytest

from scripts.demo import load_demo_into_postgres as loader


class _Cursor:
    def __init__(self, domains: list[str], has_events: bool) -> None:
        self._domains, self._has_events, self._last = domains, has_events, ""

    def execute(self, sql: str, params=None) -> None:
        self._last = sql

    def fetchall(self):
        return [{"fqdn": domain} for domain in self._domains]

    def fetchone(self):
        return {"has_events": self._has_events}


def test_demo_target_must_be_clean_and_bound_to_the_demo_domain() -> None:
    loader.check_target(_Cursor(["example.test"], False))
    with pytest.raises(loader.DemoLoadError, match="exactly one domain"):
        loader.check_target(_Cursor(["corp.example.org"], False))
    with pytest.raises(loader.DemoLoadError, match="exactly one domain"):
        loader.check_target(_Cursor(["example.test", "other.test"], False))
    with pytest.raises(loader.DemoLoadError, match="not empty"):
        loader.check_target(_Cursor(["example.test"], True))


def test_demo_loader_refuses_non_loopback_and_missing_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADLOG_PG_DSN", "postgresql://adlog_user@db.example.test:5432/sli_demo")
    monkeypatch.setenv("ADLOG_PG_ADMIN_USER", "postgres")
    monkeypatch.setenv("ADLOG_PG_ADMIN_PASSWORD", "synthetic-test-value")
    with pytest.raises(loader.DemoLoadError, match="loopback"):
        loader._admin_connection()
    monkeypatch.delenv("ADLOG_PG_ADMIN_PASSWORD")
    with pytest.raises(loader.DemoLoadError, match="required"):
        loader._admin_connection()


def test_demo_loader_does_not_inject_a_runtime_report_domain(monkeypatch, tmp_path, capsys) -> None:
    events = tmp_path / "events"
    folder = events / "DC01-synthetic"
    folder.mkdir(parents=True)
    (folder / "Security.jsonl").write_text("", encoding="utf-8")
    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}", encoding="utf-8")
    monkeypatch.delenv("ADLOG_REPORT_DOMAIN_FQDN", raising=False)
    from server.sli.core import paths

    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "data")

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def cursor(self):
            return self

        def commit(self):
            pass

    monkeypatch.setattr(loader, "_admin_connection", Connection)
    monkeypatch.setattr(loader, "check_target", lambda _cur: None)
    admitted_locations = []
    monkeypatch.setattr(loader, "admit_storage", lambda _cur, location: admitted_locations.append(location))
    environments = []

    def run(_command, environment):
        environments.append(environment)
        return "{}"

    monkeypatch.setattr(loader, "_run", run)
    assert loader.main(["--events", str(events), "--bundle", str(bundle)]) == 0
    assert len(environments) == 2
    assert admitted_locations == [tmp_path / "data" / "storage-v2-archive"]
    assert all("ADLOG_REPORT_DOMAIN_FQDN" not in env for env in environments)
    assert not (tmp_path / "data").exists()
    assert '"status": "ok"' in capsys.readouterr().out
