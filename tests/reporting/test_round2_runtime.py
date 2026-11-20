from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from server.sli.reporting import dashboard_fast


importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")


def test_jsonl_stream_opens_file_once_and_keeps_empty_object(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "Security.jsonl"
    raw = b"{}\n{\"event_id\":4624,\"channel\":\"Security\"}\n"
    path.write_bytes(raw)
    opens = 0
    original_open = Path.open

    def counted_open(self: Path, *args, **kwargs):
        nonlocal opens
        if self == path:
            opens += 1
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counted_open)
    digest = hashlib.sha256()
    rows = list(importer.iter_jsonl(path, digest=digest))

    assert opens == 1
    assert rows == [{}, {"event_id": 4624, "channel": "Security"}]
    assert digest.hexdigest() == hashlib.sha256(raw).hexdigest()


def _entry(*, severity: str = "high", provider: str = "Provider-A", channel: str = "Security") -> dict[str, object]:
    return {
        "event_id": 4624, "provider_name": provider, "channel": channel,
        "severity": severity,
        "card": {"risk_rules": [{"severity": "critical", "all": [{"contains_any": ["token"]}]}]},
        "title": "presentation-only",
    }


def test_dashboard_semantic_cache_uses_canonical_content_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, ...]] = []
    current = [_entry()]
    dashboard_fast._compile_dashboard_risk_sql.cache_clear()
    monkeypatch.setattr(dashboard_fast, "all_event_catalog_entries", lambda: list(current))
    monkeypatch.setattr(
        dashboard_fast, "compile_catalog_risk_sql",
        lambda ids, **_kwargs: calls.append(tuple(ids)) or SimpleNamespace(case_sql="%s", case_params=("high",)),
    )

    dashboard_fast._dashboard_risk_projection()
    dashboard_fast._dashboard_risk_projection()
    assert len(calls) == 1

    current[:] = [_entry(severity="medium")]
    dashboard_fast._dashboard_risk_projection()
    assert len(calls) == 2

    current[:] = [_entry(severity="medium", provider="Provider-B")]
    dashboard_fast._dashboard_risk_projection()
    assert len(calls) == 3

    current[:] = [_entry(severity="medium", provider="Provider-B", channel="System")]
    dashboard_fast._dashboard_risk_projection()
    assert len(calls) == 4

    first = dashboard_fast._dashboard_catalog_fingerprint([_entry()])
    second = dashboard_fast._dashboard_catalog_fingerprint([{**_entry(), "title": "changed presentation"}])
    assert first == second
    assert len(first) == 64
