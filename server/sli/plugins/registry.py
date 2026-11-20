"""Reviewed bundled entry points shared by report, source and job registries.

Manifests declare ownership; they cannot supply executable module names. Missing
package directories are excluded before importing any plugin implementation.
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from threading import RLock
from types import ModuleType

from server.sli.plugin_validation import load_package_manifest
from server.sli.plugins import update_runtime

ROOT = Path(__file__).resolve().parents[3]
# Explicit loader boundary: only reviewed entry points may register code.
BUNDLED = {
    "sli.remote-access": "server.sli.plugins.remote_access.registration",
    "sli.ad": "server.sli.plugins.ad.registration",
    "sli.gpo": "server.sli.plugins.gpo.registration",
    "sli.file-audit": "server.sli.plugins.file_audit.registration",
    "sli.workstations": "server.sli.plugins.workstations.registration",
    "sli.sigma": "server.sli.plugins.sigma.registration",
}
# Legacy compatibility imports remain at their original report paths.
# The core report scanner must leave their discovery to their package owner.
PLUGIN_REPORT_MODULES = frozenset({
    "vpn_audit", "vpn_connections", "nps_policy_denials",
    "ad_state", "users", "computers", "computer_logons", "new_logon_pairs",
    "gpo",
})
SOURCE_PACK_OWNERS = {"sli.windows.vpn-radius": "sli.remote-access", "sli.windows.ad-dc": "sli.ad",
                      "sli.windows.file-audit": "sli.file-audit"}
NORMALIZER_OWNERS = {"windows-nps-radius-v1": "sli.remote-access", "windows-ad-dc-v1": "sli.ad",
                     "windows-file-audit-v1": "sli.file-audit"}
_reload_lock = RLock()
_generations: dict[str, str | None] = {}


@dataclass
class Contributions:
    hooks: dict[str, Callable] = field(default_factory=dict)
    jobs: dict[str, tuple[Callable, Callable]] = field(default_factory=dict)


def discover_plugins() -> tuple[tuple[str, str], ...]:
    """Do not confuse a retained manifest with an installed executable package."""
    return tuple(
        (plugin_id, entry)
        for plugin_id, entry in BUNDLED.items()
        if (ROOT / f"config/plugin_packages/v3/{plugin_id}.json").is_file()
        and (ROOT / Path(*entry.split(".")).with_suffix(".py")).is_file()
    )


@lru_cache(maxsize=1)
def _bundled_plugins() -> dict[str, Contributions]:
    plugins = {}
    for plugin_id, entry in discover_plugins():
        load_package_manifest(plugin_id, root=ROOT)
        # The bundled generation is the normally imported package: evicting it
        # here would split already imported compatibility aliases from the
        # implementation the registry then serves. Only an installed update
        # generation goes through load_generation().
        contribution = Contributions()
        importlib.import_module(entry).register(contribution)
        plugins[plugin_id] = contribution
    return plugins


def load_generation(plugin_id: str, path: Path | None) -> Contributions:
    """Reload only a reviewed plugin namespace, including deferred imports.

    The updater fences and drains this namespace before changing its pointer.
    VP07 puts VPN implementations beneath this package; no core files change.
    """
    entry = BUNDLED.get(plugin_id)
    if entry is None:
        raise ValueError("plugin_update_not_allowlisted")
    package_name = entry.rsplit(".", 1)[0]
    directory = path / "backend" if path else ROOT / Path(*package_name.split("."))
    for name, module in tuple(sys.modules.items()):
        # Compatibility paths point to the same implementation module. Evict
        # those aliases too, including their parent-package attributes, so a
        # later import cannot retain an executor from the previous generation.
        implementation_name = getattr(module, "__name__", "")
        if (name == package_name or name.startswith(package_name + ".")
                or implementation_name == package_name
                or implementation_name.startswith(package_name + ".")):
            parent, _, child = name.rpartition(".")
            owner = sys.modules.get(parent)
            if owner is not None and getattr(owner, child, None) is module:
                delattr(owner, child)
            sys.modules.pop(name, None)
    importlib.invalidate_caches()
    initializer = directory / "__init__.py"
    if initializer.is_file():
        spec = importlib.util.spec_from_file_location(package_name, initializer, submodule_search_locations=[str(directory)])
        package = importlib.util.module_from_spec(spec)
        sys.modules[package_name] = package
        spec.loader.exec_module(package)
    else:
        package = ModuleType(package_name)
        package.__path__ = [str(directory)]
        sys.modules[package_name] = package
    parent, _, child = package_name.rpartition(".")
    setattr(importlib.import_module(parent), child, package)
    contribution = Contributions()
    importlib.import_module(entry).register(contribution)
    return contribution


def registered_plugins() -> dict[str, Contributions]:
    with _reload_lock:
        plugins = _bundled_plugins()
        for plugin_id in BUNDLED:
            path = update_runtime.generation(plugin_id)
            token = str(path) if path else None
            if token != _generations.get(plugin_id):
                plugins[plugin_id] = load_generation(plugin_id, path)
                _generations[plugin_id] = token
        return plugins


def _clear_plugins():
    _bundled_plugins.cache_clear()
    _generations.clear()


registered_plugins.cache_clear = _clear_plugins


def plugin_installed(plugin_id: str) -> bool:
    return plugin_id in registered_plugins()


def plugin_hook(plugin_id: str, name: str) -> Callable | None:
    plugin = registered_plugins().get(plugin_id)
    if plugin is None or name not in plugin.hooks:
        return None
    def invoke(*args, **kwargs):
        with update_runtime.admission(plugin_id):
            return registered_plugins()[plugin_id].hooks[name](*args, **kwargs)
    return invoke


def call_plugin(plugin_id: str, name: str, *args, **kwargs):
    hook = plugin_hook(plugin_id, name)
    if hook is None:
        return {"state": "not_installed", "reason": "plugin_not_installed",
                "plugin_id": plugin_id, "items": []}
    return hook(*args, **kwargs)


def require_plugin(plugin_id: str, name: str, *args, **kwargs):
    """Source/admission adapters cannot use a missing-report payload as input."""
    hook = plugin_hook(plugin_id, name)
    if hook is None:
        raise RuntimeError("plugin_not_installed")
    return hook(*args, **kwargs)


def plugin_job_handlers(plugin_id: str, handler_id: str) -> tuple[Callable, Callable]:
    plugin = registered_plugins().get(plugin_id)
    if plugin is None or handler_id not in plugin.jobs:
        raise ValueError("handler_version_unavailable")
    def guarded(index):
        def invoke(*args, **kwargs):
            with update_runtime.admission(plugin_id):
                return registered_plugins()[plugin_id].jobs[handler_id][index](*args, **kwargs)
        return invoke
    return guarded(0), guarded(1)
