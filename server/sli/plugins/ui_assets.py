"""Versioned, local-only UI packages; installation is a trusted code boundary."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from server.sli.plugin_validation import (
    UI_API as UI_API,
    PLUGIN_ID as PLUGIN_ID,
    ASSET_PATH as ASSET_PATH,
    SHA256 as SHA256,
    MAX_ASSET_BYTES as MAX_ASSET_BYTES,
    PluginUiError as PluginUiError,
    validate_descriptor as validate_descriptor,
)
from server.sli.core.paths import WEB_DIR
from server.sli.plugins.update_runtime import generation, fenced


def package_root() -> Path:
    override = os.environ.get("SLI_PLUGIN_UI_DIR", "").strip()
    return (Path(override) if override else WEB_DIR / "plugin-ui").resolve()


def _local_file(root: Path, relative: str) -> Path:
    # Reject symlinks too: resolving a symlink within the package is unnecessary
    # for installed assets and could bypass the package's installation boundary.
    base = root.resolve()
    candidate = base / relative
    root = base
    for part in Path(relative).parts:
        root = root / part
        if root.is_symlink():
            raise PluginUiError("plugin_ui_invalid_descriptor")
    if not candidate.resolve().is_relative_to(base):
        raise PluginUiError("plugin_ui_invalid_descriptor")
    return candidate


def load_package(plugin_id: str, *, allow_draining: bool = False) -> tuple[dict[str, Any], bytes]:
    if not PLUGIN_ID.fullmatch(plugin_id):
        raise PluginUiError("plugin_ui_invalid_descriptor")
    if not allow_draining and fenced(plugin_id):
        raise PluginUiError("plugin_ui_updating")
    root = package_root()
    active = generation(plugin_id)
    directory = active / "ui" if active else _local_file(root, plugin_id)
    try:
        descriptor_path = _local_file(directory, "descriptor.json")
        if descriptor_path.stat().st_size > 64 * 1024:
            raise PluginUiError("plugin_ui_invalid_descriptor")
        descriptor = validate_descriptor(json.loads(descriptor_path.read_text("utf-8")), plugin_id)
        asset = _local_file(directory, descriptor["entry"]["path"])
        with asset.open("rb") as stream:
            payload = stream.read(MAX_ASSET_BYTES + 1)
        if len(payload) > MAX_ASSET_BYTES:
            raise PluginUiError("plugin_ui_invalid_descriptor")
        payload.decode("utf-8")
    except FileNotFoundError:
        raise PluginUiError("plugin_ui_not_installed") from None
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PluginUiError("plugin_ui_invalid_descriptor") from None
    if hashlib.sha256(payload).hexdigest() != descriptor["entry"]["sha256"]:
        raise PluginUiError("plugin_ui_integrity_failed")
    return descriptor, payload
