from __future__ import annotations

from contextlib import contextmanager
import importlib
from pathlib import Path


def test_importer_loads_protected_environment_only_when_requested(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    module = importlib.import_module("scripts.import.import_ad_context_bundle")
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text("{}", encoding="utf-8")
    calls: list[str] = []

    monkeypatch.setattr(
        module,
        "_load_protected_supervisor_environment",
        lambda: calls.append("environment"),
    )
    monkeypatch.setattr(module, "load_bundle", lambda path: {"path": str(path)})

    @contextmanager
    def fake_connect():
        calls.append("connect")
        yield object()

    monkeypatch.setattr(module, "_connect", fake_connect)
    monkeypatch.setattr(
        module,
        "import_bundle",
        lambda conn, bundle: {"run_id": "run-1", "imported": 3},
    )

    assert module.main([str(bundle_path), "--load-supervisor-environment"]) == 0
    output = capsys.readouterr().out

    assert calls == ["environment", "connect"]
    assert '"credential_values_exposed": false' in output
    assert '"imported": 3' in output


def test_importer_does_not_load_protected_environment_by_default(
    monkeypatch,
    tmp_path: Path,
) -> None:
    module = importlib.import_module("scripts.import.import_ad_context_bundle")
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text("{}", encoding="utf-8")
    calls: list[str] = []

    monkeypatch.setattr(
        module,
        "_load_protected_supervisor_environment",
        lambda: calls.append("environment"),
    )
    monkeypatch.setattr(module, "load_bundle", lambda path: {})

    @contextmanager
    def fake_connect():
        yield object()

    monkeypatch.setattr(module, "_connect", fake_connect)
    monkeypatch.setattr(module, "import_bundle", lambda conn, bundle: {})

    assert module.main([str(bundle_path)]) == 0
    assert calls == []
