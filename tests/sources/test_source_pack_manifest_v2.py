"""Source pack manifest v2 (ADR 0012): normalizer entry points with safe defaults."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from server.source_packs import normalizers, registry


@pytest.fixture
def entry_module(monkeypatch: pytest.MonkeyPatch):
    """A minimal external normalizer: only the three required handlers."""
    module = types.ModuleType("sli_source_packs.example_minimal")
    module.minimal = types.SimpleNamespace(
        event_facts=lambda **_kwargs: {"fact": 1},
        entity_semantics=lambda **_kwargs: "entities",
        event_label=lambda event_id, lang: f"label {event_id} {lang}",
    )
    module.broken = types.SimpleNamespace(event_facts=lambda **_kwargs: {})
    monkeypatch.setitem(sys.modules, "sli_source_packs", types.ModuleType("sli_source_packs"))
    monkeypatch.setitem(sys.modules, "sli_source_packs.example_minimal", module)
    monkeypatch.setattr(normalizers, "_ENTRY_NORMALIZERS", {})
    return module


def test_entry_normalizer_needs_only_the_core_handlers(entry_module) -> None:
    normalizer = normalizers.load_normalizer_entry("example-v1", "sli_source_packs.example_minimal:minimal")
    assert normalizer.event_label(4624, "ru") == "label 4624 ru"
    assert normalizer.event_facts(event_id=1) == {"fact": 1}
    assert normalizer.finding_rules() == {}
    assert normalizer.event_ids_for_search_family("logon") == ()
    assert normalizer.investigation_category(1) == "other"
    assert normalizer.correlation_id(channel="x", event_id=1, event_data={}) is None
    assert normalizer.semantic_core_role_filters("t", (), {}) is None


def test_missing_core_handler_and_foreign_module_are_rejected(entry_module) -> None:
    with pytest.raises(ValueError, match="lacks required handler: entity_semantics"):
        normalizers.load_normalizer_entry("broken-v1", "sli_source_packs.example_minimal:broken")
    with pytest.raises(ValueError, match="not allowed"):
        normalizers.load_normalizer_entry("os-v1", "os:path")


def test_bundled_ids_cannot_be_replaced_and_entries_resolve_first(entry_module) -> None:
    impostor = normalizers.load_normalizer_entry("windows-ad-dc-v1", "sli_source_packs.example_minimal:minimal")
    with pytest.raises(ValueError, match="reserved"):
        normalizers.register_source_normalizer(impostor)
    normalizers.register_source_normalizer(normalizers.load_normalizer_entry("example-v1", "sli_source_packs.example_minimal:minimal"))
    assert normalizers.get_source_normalizer("example-v1").event_label(1, "en") == "label 1 en"
    from server.sli.plugins.ad.windows_ad_dc import normalizer as ad_normalizer

    assert normalizers.get_source_normalizer("windows-ad-dc-v1") is ad_normalizer
    assert "windows-ad-dc-v1" not in normalizers._NORMALIZERS


def _manifest(tmp_path: Path, **overrides) -> Path:
    data = {
        "schema_version": 2, "pack_id": "example.minimal", "version": "0.1.0", "display_name": "Example",
        "channels": ["Security"], "adapters": ["windows-eventlog-pywin32"], "event_catalog": "radius_event_catalog.json",
        "normalizer": "example-v1", "normalizer_entry": "sli_source_packs.example_minimal:minimal",
        "entity_contract": "identity-ladder-v1", "analysis_contract": "example-v1", "capabilities": ["authentication", ""],
        **overrides,
    }
    path = tmp_path / "example.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_manifest_v2_registers_its_normalizer_and_capabilities(entry_module, tmp_path: Path) -> None:
    pack = registry._load_manifest(_manifest(tmp_path))
    assert pack.normalizer_id == "example-v1" and pack.capabilities == ("authentication",)
    assert pack.public_dict()["capabilities"] == ["authentication"]
    assert normalizers.get_source_normalizer("example-v1") is not None


def test_entry_in_a_v1_manifest_and_bad_entries_fail_closed(entry_module, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires schema_version 2"):
        registry._load_manifest(_manifest(tmp_path, schema_version=1))
    with pytest.raises(ValueError, match="normalizer entry failed"):
        registry._load_manifest(_manifest(tmp_path, normalizer_entry="sli_source_packs.example_minimal:missing"))


def test_bundled_v1_manifests_still_load() -> None:
    packs = registry._source_packs()
    assert {pack.pack_id for pack in packs} >= {"sli.windows.vpn-radius"}
    assert all(pack.normalizer_id is None or registry.get_source_normalizer(pack.normalizer_id) for pack in packs)


def test_v2_may_declare_no_bundled_adapter_but_v1_may_not(entry_module, tmp_path: Path) -> None:
    assert registry._load_manifest(_manifest(tmp_path, adapters=[])).adapters == ()
    with pytest.raises(ValueError, match="requires non-empty adapters"):
        registry._load_manifest(_manifest(tmp_path, schema_version=1, adapters=[], normalizer_entry=""))
