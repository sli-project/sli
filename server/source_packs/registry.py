from __future__ import annotations

"""Registry for source packs shipped with this repository.

The registry intentionally loads JSON manifests only.  It never imports code
from a pack, scans arbitrary directories, or accepts a user-supplied module.
This keeps the first extensibility contract safe for closed installations.
"""

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from server.sli.core.paths import CONFIG_DIR
from server.source_packs.adapters import get_source_adapter
from server.source_packs.collector_contract import CollectorSpec, parse_collector_spec
from server.source_packs.contracts import (
    SemanticCoreRoleFilter,
    SemanticEventIdentity,
)
from server.source_packs.normalizers import (
    SourceNormalizer,
    get_source_normalizer,
    load_normalizer_entry,
    register_source_normalizer,
)
from server.sli.plugins.registry import SOURCE_PACK_OWNERS, plugin_installed


PACKS_DIR = CONFIG_DIR / "source_packs"
_SUPPORTED_SCHEMA_VERSIONS = frozenset({1, 2})


def canonical_manifest_sha256(raw: bytes) -> str:
    """Hash the repository manifest independent of checkout EOL policy."""
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


@dataclass(frozen=True)
class SourcePack:
    pack_id: str
    version: str
    display_name: str
    source_kind: str
    channels: tuple[str, ...]
    provider_channels: tuple[tuple[str, str], ...]
    event_identities: tuple[tuple[str, str, str], ...]
    sections: tuple[str, ...]
    adapters: tuple[str, ...]
    catalog_path: Path | None
    entity_contract: str
    analysis_contract: str
    normalizer_id: str | None
    manifest_sha256: str
    #: Manifest v2: families / fact kinds the source provides (reports' coverage).
    capabilities: tuple[str, ...] = ()
    #: Manifest v2 collector (declared, validated, never started by the registry).
    collector: CollectorSpec | None = None

    def matches(
        self,
        channel: str | None,
        provider_name: str | None = None,
        event_key: str | None = None,
    ) -> bool:
        if self.source_kind != "event":
            return False
        channel_key = _norm(channel)
        if channel_key not in {_norm(value) for value in self.channels}:
            return False
        provider_key = _norm(provider_name)
        if not provider_key:
            return True
        event_key_normalized = _norm(event_key)
        if event_key_normalized:
            return (
                channel_key,
                provider_key,
                event_key_normalized,
            ) in self.event_identities
        return (channel_key, provider_key) in self.provider_channels

    def public_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "version": self.version,
            "display_name": self.display_name,
            "source_kind": self.source_kind,
            "channels": list(self.channels),
            "sections": list(self.sections),
            "adapters": list(self.adapters),
            "entity_contract": self.entity_contract,
            "analysis_contract": self.analysis_contract,
            "normalizer": self.normalizer_id,
            "manifest_sha256": self.manifest_sha256,
            # Declared by manifest v2 only; a v1 pack's public shape is unchanged.
            **({"capabilities": list(self.capabilities)} if self.capabilities else {}),
            **({"collector": {"kind": self.collector.kind, "entry": self.collector.entry}} if self.collector else {}),
        }


@lru_cache(maxsize=4096)
def resolve_source_pack(
    channel: str | None,
    provider_name: str | None = None,
    event_key: str | None = None,
) -> SourcePack | None:
    """Resolve a bundled pack by channel and, when present, exact provider.

    Calls without provider are used for collection metadata and resolve channel
    ownership.  Event processing supplies provider and therefore fails closed
    unless the pack's accepted descriptor catalogue declares that provider for
    the stream.
    """
    matches = [
        pack
        for pack in _source_packs()
        if pack.matches(channel, provider_name, event_key)
    ]
    if _norm(provider_name) and _norm(event_key) and len(matches) > 1:
        raise ValueError(
            "multiple source packs own exact event identity "
            f"{channel}/{provider_name}/{event_key}"
        )
    return matches[0] if matches else None


def get_source_pack(pack_id: str) -> SourcePack | None:
    wanted = str(pack_id or "").strip()
    return next((pack for pack in _source_packs() if pack.pack_id == wanted), None)


def resolve_source_normalizer(
    channel: str | None,
    provider_name: str | None = None,
    event_key: str | None = None,
) -> SourceNormalizer | None:
    pack = resolve_source_pack(channel, provider_name, event_key)
    return get_source_normalizer(pack.normalizer_id) if pack else None


def semantic_event_identities_for_types(
    semantic_types: tuple[str, ...] | list[str],
) -> tuple[SemanticEventIdentity, ...]:
    """Resolve source-owned exact identities without teaching core source IDs."""

    wanted = tuple(
        sorted({str(value).strip() for value in semantic_types if str(value).strip()})
    )
    if not wanted:
        return ()
    resolved: dict[
        tuple[str, str, str, str], SemanticEventIdentity
    ] = {}
    for pack in _source_packs():
        if pack.source_kind != "event":
            continue
        normalizer = get_source_normalizer(pack.normalizer_id)
        if normalizer is None:
            continue
        for identity in normalizer.semantic_event_identities(wanted):
            key = (
                identity.source.casefold(),
                identity.stream.casefold(),
                identity.event_key.casefold(),
                identity.provider_name.casefold(),
            )
            prior = resolved.get(key)
            if prior is not None and prior != identity:
                raise ValueError(
                    "source packs disagree on semantic event identity "
                    + "/".join(key)
                )
            resolved[key] = identity
    return tuple(resolved[key] for key in sorted(resolved))


def semantic_core_role_filters_for_identity(
    identity: SemanticEventIdentity,
    *,
    join_roles: tuple[str, ...],
    trigger_roles: dict[str, str],
) -> tuple[SemanticCoreRoleFilter, ...] | None:
    """Ask the owning source pack for a compact exact-role prefilter."""

    pack = get_source_pack(identity.source)
    normalizer = get_source_normalizer(pack.normalizer_id) if pack else None
    if normalizer is None:
        return None
    return normalizer.semantic_core_role_filters(
        identity.semantic_type,
        join_roles,
        trigger_roles,
    )


def list_source_packs() -> list[dict[str, Any]]:
    """Return safe, declarative metadata for the authenticated operations UI."""
    return [pack.public_dict() for pack in _source_packs()]


def catalog_paths_for_event(
    channel: str | None,
    provider_name: str | None = None,
    event_key: str | None = None,
) -> tuple[Path, ...]:
    """Return pack-owned catalog first, then the historic core fallback.

    The fallback makes migration non-destructive while DC moves onto the
    contract.  New packs must explicitly name their catalog in the manifest.
    """
    pack = resolve_source_pack(channel, provider_name, event_key)
    paths: list[Path] = [pack.catalog_path] if pack and pack.catalog_path else []
    fallback = (CONFIG_DIR / "event_catalog.json").resolve()
    if fallback not in paths:
        paths.append(fallback)
    return tuple(paths)


def source_pack_metadata_for_channels(channels: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    """Describe the bundled adapter-backed packs that own a collection result.

    This metadata is deliberately written alongside a collection summary rather
    than into production event rows.  It gives operations evidence of the
    semantic contract used for a cycle without a schema migration or a runtime
    behavior change during the DC migration pilot.
    """
    resolved: dict[str, SourcePack] = {}
    for channel in channels:
        for pack in _source_packs():
            # Packet-only and pack-owned collectors do not claim the generic
            # channel acquisition adapters. Exact event ownership is separate.
            if pack.adapters and pack.matches(channel):
                resolved[pack.pack_id] = pack
    return [resolved[key].public_dict() for key in sorted(resolved)]


def validate_adapter_for_channels(adapter_id: str, channels: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    """Fail closed only for a known pack with an incompatible adapter.

    Unclaimed channels remain possible during the incremental migration, so the
    core can retain its existing fallback behavior.  Once a channel is claimed
    by an adapter-backed bundled pack, its manifest becomes the authority for
    supported acquisition adapters.
    """
    metadata = source_pack_metadata_for_channels(channels)
    for pack in metadata:
        if adapter_id not in pack["adapters"]:
            raise ValueError(
                f"adapter {adapter_id} is not declared by source pack {pack['pack_id']}"
            )
    return metadata


def validate_adapter_for_pack(adapter_id: str, pack_id: str) -> dict[str, Any]:
    pack = get_source_pack(pack_id)
    if pack is None:
        raise ValueError(f"unknown source pack: {pack_id}")
    if get_source_adapter(adapter_id) is None or adapter_id not in pack.adapters:
        raise ValueError(f"adapter {adapter_id} is not declared by source pack {pack.pack_id}")
    return pack.public_dict()


@lru_cache(maxsize=1)
def _source_packs() -> tuple[SourcePack, ...]:
    if not PACKS_DIR.is_dir():
        return ()
    packs = []
    for path in sorted(PACKS_DIR.glob("*.json")):
        try:
            declaration = json.loads(path.read_bytes().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid source pack manifest: {path.name}") from exc
        owner = SOURCE_PACK_OWNERS.get(declaration.get("pack_id")) if isinstance(declaration, dict) else None
        if owner is None or plugin_installed(owner):
            packs.append(_load_manifest(path))
    ids = [pack.pack_id for pack in packs]
    if len(ids) != len(set(ids)):
        raise ValueError("source pack ids must be unique")
    return tuple(packs)


def _load_manifest(path: Path) -> SourcePack:
    raw = path.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid source pack manifest: {path.name}") from exc
    if not isinstance(data, dict) or int(data.get("schema_version") or 0) not in _SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"unsupported source pack manifest schema: {path.name}")
    pack_id = _required_text(data, "pack_id", path)
    version = _required_text(data, "version", path)
    display_name = _required_text(data, "display_name", path)
    source_kind = str(data.get("source_kind") or "event").strip().lower()
    if source_kind not in {"event", "context"}:
        raise ValueError(f"source pack {path.name} has unsupported source_kind")
    channels = _text_list(data, "channels", path) if source_kind == "event" else ()
    sections = _text_list(data, "sections", path) if source_kind == "context" else ()
    # Manifest v2 may declare no bundled adapter: its collector is described by
    # the pack itself (ADR 0012); v1 still requires a known adapter.
    v2_without_adapters = int(data.get("schema_version") or 0) >= 2 and not data.get("adapters")
    adapters = () if v2_without_adapters else _text_list(data, "adapters", path)
    unknown_adapters = [adapter for adapter in adapters if get_source_adapter(adapter) is None]
    if unknown_adapters:
        raise ValueError(f"source pack {path.name} declares unknown adapters: {', '.join(unknown_adapters)}")
    catalog_path = None
    if source_kind == "event":
        catalog_ref = _required_text(data, "event_catalog", path)
        catalog_path = _safe_config_file(catalog_ref, path)
        if not catalog_path.is_file():
            raise ValueError(f"source pack catalog is missing: {path.name}")
    normalizer_id = None
    provider_channels: tuple[tuple[str, str], ...] = ()
    event_identities: tuple[tuple[str, str, str], ...] = ()
    if source_kind == "event":
        normalizer_id = _required_text(data, "normalizer", path)
        entry = str(data.get("normalizer_entry") or "").strip()
        if entry:
            if int(data.get("schema_version") or 0) < 2:
                raise ValueError(f"source pack {path.name}: normalizer_entry requires schema_version 2")
            try:
                register_source_normalizer(load_normalizer_entry(normalizer_id, entry))
            except (ImportError, AttributeError, ValueError) as exc:
                raise ValueError(f"source pack {path.name} normalizer entry failed: {exc}") from exc
        if get_source_normalizer(normalizer_id) is None:
            raise ValueError(
                f"source pack {path.name} declares unknown normalizer: {normalizer_id}"
            )
        provider_channels = _catalog_provider_channels(catalog_path)
        event_identities = _catalog_event_identities(catalog_path)
    return SourcePack(
        pack_id=pack_id,
        version=version,
        display_name=display_name,
        source_kind=source_kind,
        channels=channels,
        provider_channels=provider_channels,
        event_identities=event_identities,
        sections=sections,
        adapters=adapters,
        catalog_path=catalog_path,
        entity_contract=_required_text(data, "entity_contract", path),
        analysis_contract=_required_text(data, "analysis_contract", path),
        normalizer_id=normalizer_id,
        manifest_sha256=canonical_manifest_sha256(raw),
        capabilities=tuple(str(item).strip() for item in data.get("capabilities") or [] if str(item).strip()),
        collector=_collector_spec(data, path),
    )


def _collector_spec(data: dict[str, Any], path: Path) -> CollectorSpec | None:
    if "collector" not in data:
        return None
    if int(data.get("schema_version") or 0) < 2:
        raise ValueError(f"source pack {path.name}: collector requires schema_version 2")
    try:
        return parse_collector_spec(data.get("collector"))
    except ValueError as exc:
        raise ValueError(f"source pack {path.name} collector: {exc}") from exc


def _catalog_provider_channels(path: Path) -> tuple[tuple[str, str], ...]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid source pack catalog: {path.name}") from exc
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"source pack catalog requires entries: {path.name}")
    pairs = {
        (
            _norm(str(entry.get("stream") or entry.get("channel") or "")),
            _norm(str(entry.get("provider_name") or "")),
        )
        for entry in entries
        if isinstance(entry, dict)
        and str(entry.get("stream") or entry.get("channel") or "").strip()
        and str(entry.get("provider_name") or "").strip()
    }
    return tuple(sorted(pairs))


def _catalog_event_identities(
    path: Path,
) -> tuple[tuple[str, str, str], ...]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid source pack catalog: {path.name}") from exc
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"source pack catalog requires entries: {path.name}")
    identities = [
        (
            _norm(str(entry.get("stream") or entry.get("channel") or "")),
            _norm(str(entry.get("provider_name") or "")),
            _norm(str(entry.get("event_key") or entry.get("event_id") or "")),
        )
        for entry in entries
        if isinstance(entry, dict)
    ]
    if any(not all(identity) for identity in identities):
        raise ValueError(
            f"source pack catalog has incomplete event identity: {path.name}"
        )
    if len(identities) != len(set(identities)):
        raise ValueError(
            f"source pack catalog has duplicate event identity: {path.name}"
        )
    return tuple(sorted(identities))


def _safe_config_file(reference: str, manifest_path: Path) -> Path:
    candidate = (CONFIG_DIR / reference).resolve()
    config_root = CONFIG_DIR.resolve()
    if candidate != config_root and config_root not in candidate.parents:
        raise ValueError(f"source pack path escapes config directory: {manifest_path.name}")
    return candidate


def _required_text(data: dict[str, Any], key: str, path: Path) -> str:
    value = str(data.get(key) or "").strip()
    if not value:
        raise ValueError(f"source pack {path.name} requires {key}")
    return value


def _text_list(data: dict[str, Any], key: str, path: Path) -> tuple[str, ...]:
    values = data.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"source pack {path.name} requires non-empty {key}")
    result = tuple(str(value).strip() for value in values if str(value).strip())
    if not result or len({_norm(value) for value in result}) != len(result):
        raise ValueError(f"source pack {path.name} has invalid {key}")
    return result


def _norm(value: str | None) -> str:
    return str(value or "").strip().casefold()
