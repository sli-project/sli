from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from collections.abc import Iterable
from typing import Any

from server.sli.core.paths import CONFIG_DIR
from server.source_packs.registry import catalog_paths_for_event, get_source_pack


CATALOG_PATH = CONFIG_DIR / "event_catalog.json"
NOISE_CLASS_NOT_CLASSIFIED = "not_classified"
NOISE_CLASSES = frozenset({"signal", "context", "noise"})


def lookup_event_catalog(event_id: int, channel: str | None = None, provider_name: str | None = None) -> dict[str, Any] | None:
    entry, _version = _lookup_event_catalog_with_version(
        event_id,
        channel,
        provider_name,
    )
    return entry


@lru_cache(maxsize=4096)
def event_noise_classification(
    event_id: int,
    channel: str | None = None,
    provider_name: str | None = None,
) -> tuple[str, str]:
    """Resolve browsing classification from the canonical catalogue.

    The lookup preserves channel/provider identity; Event ID alone is not
    sufficient because the same numeric ID can carry different semantics in
    different Windows channels.  Absence is explicit and never rejects an
    otherwise valid event.
    """
    entry, version = _lookup_event_catalog_with_version(
        event_id,
        channel,
        provider_name,
    )
    if entry is None:
        return NOISE_CLASS_NOT_CLASSIFIED, version
    noise_class = str(entry.get("noise_class") or "").strip().lower()
    if noise_class not in NOISE_CLASSES:
        return NOISE_CLASS_NOT_CLASSIFIED, version
    return noise_class, version


def _lookup_event_catalog_with_version(
    event_id: int,
    channel: str | None,
    provider_name: str | None,
) -> tuple[dict[str, Any] | None, str]:
    event_id = int(event_id)
    channel_key = _norm(channel)
    provider_key = _norm(provider_name)
    paths = catalog_paths_for_event(channel, provider_name, str(event_id))
    versions: list[str] = []
    for path in paths:
        version = _catalog_version_for_path(str(path))
        if version not in versions:
            versions.append(version)
        catalog = _catalog_index_for_path(str(path))
        keys = [
            (channel_key, event_id, provider_key),
            (channel_key, event_id, ""),
            ("", event_id, provider_key),
            ("", event_id, ""),
        ]
        for key in keys:
            if key in catalog:
                return dict(catalog[key]), version
    return None, "|".join(versions) or "catalog-unavailable"


def catalog_has_rule(event_id: int, channel: str | None = None, provider_name: str | None = None) -> bool:
    return lookup_event_catalog(event_id, channel, provider_name) is not None


def lookup_event_descriptor(
    source: str,
    stream: str,
    event_key: str,
) -> dict[str, Any] | None:
    """Lookup the source-neutral v2 descriptor identity.

    Explicit v2 entries use ``source + stream + event_key`` directly. The
    bundled Windows source pack also exposes unchanged v1 rows through the same
    API by deriving stream from channel and event_key from numeric event_id.
    """
    source_key = _norm(source)
    stream_key = _norm(stream)
    event_key_normalized = _norm(event_key)
    pack = get_source_pack(source)
    paths: list[tuple[Path, str | None]] = []
    if pack and pack.catalog_path:
        paths.append((pack.catalog_path, pack.pack_id))
    fallback = CATALOG_PATH.resolve()
    if all(path.resolve() != fallback for path, _legacy_source in paths):
        paths.append((fallback, None))
    for path, legacy_source in paths:
        index = _descriptor_index_for_path(str(path), legacy_source or "")
        entry = index.get((source_key, stream_key, event_key_normalized))
        if entry is not None:
            return dict(entry)
    return None


def lookup_semantic_event_descriptor(
    source: str,
    stream: str,
    event_key: str,
    provider_name: str | None,
) -> dict[str, Any] | None:
    """Resolve the exact descriptor-v2 identity used by semantic mappings.

    ``event_key`` deliberately remains a string. Numeric Windows Event IDs are
    one source-specific representation, not the cross-source contract.
    """
    descriptor = lookup_event_descriptor(source, stream, event_key)
    if descriptor is None:
        return None
    expected_provider = _norm(descriptor.get("provider_name"))
    actual_provider = _norm(provider_name)
    if not expected_provider or actual_provider != expected_provider:
        return None
    return descriptor


def event_catalog_entries(event_ids: Iterable[int]) -> list[dict[str, Any]]:
    """Return declared catalogue entries for a bounded set of Event IDs.

    Consumers that compile catalogue semantics (for example into a database
    predicate) must read the same declarations as :func:`lookup_event_catalog`
    rather than maintain a second Event ID taxonomy.  The bundled source pack
    currently points at this canonical catalogue; lookup still owns the
    channel/provider precedence at the row boundary.
    """
    wanted = {int(value) for value in event_ids}
    if not wanted:
        return []
    data = _load_catalog(CATALOG_PATH)
    return [dict(entry) for entry in data.get("entries", []) if int(entry.get("event_id") or 0) in wanted]


def all_event_catalog_entries() -> list[dict[str, Any]]:
    """Return the canonical bundled catalogue for bounded aggregate views."""
    data = _load_catalog(CATALOG_PATH)
    return [dict(entry) for entry in data.get("entries", [])]


@lru_cache(maxsize=8)
def _catalog_index_for_path(raw_path: str) -> dict[tuple[str, int, str], dict[str, Any]]:
    data = _load_catalog(Path(raw_path))
    index: dict[tuple[str, int, str], dict[str, Any]] = {}
    for entry in data.get("entries", []):
        event_id = int(entry["event_id"])
        channel = _norm(entry.get("channel"))
        provider = _norm(entry.get("provider_name"))
        index[(channel, event_id, provider)] = entry
    return index


@lru_cache(maxsize=8)
def _catalog_version_for_path(raw_path: str) -> str:
    data = _load_catalog(Path(raw_path))
    return str(data.get("version") or "unversioned-catalog").strip()[:255]


@lru_cache(maxsize=16)
def _descriptor_index_for_path(
    raw_path: str,
    legacy_source: str,
) -> dict[tuple[str, str, str], dict[str, Any]]:
    data = _load_catalog(Path(raw_path))
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in data.get("entries", []):
        if any(key in entry for key in ("source", "stream", "event_key")):
            key = (
                _norm(entry.get("source")),
                _norm(entry.get("stream")),
                _norm(entry.get("event_key")),
            )
        elif legacy_source:
            key = (
                _norm(legacy_source),
                _norm(entry.get("channel")),
                _norm(str(entry.get("event_id") or "")),
            )
        else:
            continue
        index[key] = entry
    return index


def _load_catalog(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"entries": []}
    return json.loads(path.read_text(encoding="utf-8"))


def _norm(value: str | None) -> str:
    return str(value or "").strip().lower()
