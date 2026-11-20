"""Read-only generation pointers and per-plugin Linux admission locks.

Only the host updater writes this directory. Runtime containers mount it read
only; locks are held across a complete hook or queue publication, never a pool.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
import re
import time

_pinned: dict[str, Path | None] = {}


def root() -> Path | None:
    value = os.environ.get("SLI_PLUGIN_RUNTIME_DIR", "").strip()
    return Path(value) if value else None


def directory(plugin_id: str) -> Path | None:
    if not re.fullmatch(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+", plugin_id):
        raise ValueError("plugin_update_invalid_id")
    base = root()
    return base / plugin_id if base else None


def fenced(plugin_id: str) -> bool:
    base = directory(plugin_id)
    return base is not None and (base / "draining.json").exists()


def lock_path(plugin_id: str) -> Path | None:
    locks = os.environ.get("SLI_PLUGIN_LOCK_DIR", "").strip()
    base = directory(plugin_id)
    # Bundled manifests are pre-existing, per-owner inodes shared by every
    # container. Never introduce a new lock while an untracked call is running.
    return Path(locks) / (plugin_id + ".json") if locks else base / "admission.lock" if base else None


def generation(plugin_id: str) -> Path | None:
    if plugin_id in _pinned:
        return _pinned[plugin_id]
    base = directory(plugin_id)
    if base is None or not (base / "active.json").is_file():
        return None
    value = json.loads((base / "active.json").read_text("utf-8"))
    name = value.get("generation")
    if not isinstance(name, str) or not re.fullmatch(r"[a-f0-9]{64}", name):
        raise ValueError("plugin_update_invalid_generation")
    path = base / "versions" / name
    if path.is_symlink() or not path.resolve().is_relative_to(base.resolve()):
        raise ValueError("plugin_update_invalid_generation")
    return path


def job_manifests(plugin_id: str, bundled: Path) -> list[tuple[Path | None, dict]]:
    """Retain pinned jobs from older generations; only the active one schedules."""
    paths = [(None, bundled)] if bundled.is_file() else []
    base = directory(plugin_id)
    if base and (base / "versions").is_dir():
        paths.extend((path, path / "backend/jobs-v3.json") for path in sorted((base / "versions").iterdir())
                     if re.fullmatch(r"[a-f0-9]{64}", path.name) and not path.is_symlink()
                     and (path / "release.json").is_file())
    return [(path, json.loads(manifest.read_text("utf-8"))) for path, manifest in paths]


def pin_job(plugin_id: str, version: str, manifest_sha256: str, bundled: Path) -> None:
    from server.sli.core.job_queue import digest
    for path, manifest in job_manifests(plugin_id, bundled):
        if manifest["plugin_id"] == plugin_id and manifest["plugin_version"] == version and digest(manifest) == manifest_sha256:
            _pinned[plugin_id] = path
            return
    raise ValueError("handler_version_unavailable")


@contextmanager
def admission(plugin_id: str):
    """Double-check the fence after locking to close the drain/admit race."""
    path = lock_path(plugin_id)
    if fenced(plugin_id):
        raise RuntimeError("plugin_update_draining")
    if path is None:
        yield
        return
    import fcntl
    with path.open("rb") as stream:
        fcntl.flock(stream, fcntl.LOCK_SH)
        if fenced(plugin_id):
            raise RuntimeError("plugin_update_draining")
        yield


def wait_drained(plugin_id: str, timeout: float) -> None:
    import fcntl
    path = lock_path(plugin_id)
    if path is None or not fenced(plugin_id):
        raise RuntimeError("plugin_update_fence_required")
    deadline = time.monotonic() + timeout
    with path.open("rb") as stream:
        while True:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("plugin_update_drain_timeout") from None
                time.sleep(0.05)


@contextmanager
def optional_admission(plugin_id: str):
    """Skip this plugin's queue while continuing to dispatch other owners."""
    from contextlib import ExitStack
    with ExitStack() as stack:
        try:
            stack.enter_context(admission(plugin_id))
        except RuntimeError as exc:
            if str(exc) != "plugin_update_draining":
                raise
            yield False
        else:
            yield True


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("drain", "health"))
    parser.add_argument("plugin_id")
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--version")
    args = parser.parse_args()
    if args.action == "drain":
        wait_drained(args.plugin_id, args.timeout)
    else:
        from server.sli.plugins.registry import load_generation
        from server.sli.plugins.ui_assets import load_package
        path = generation(args.plugin_id)
        if path is not None:
            manifest = json.loads((path / "release.json").read_text("utf-8"))
            from deploy.linux.plugin_update import validate_payload
            validate_payload(path, manifest)
        contribution = load_generation(args.plugin_id, path)
        if path is not None and set(contribution.jobs) != set(manifest["handlers"]):
            raise RuntimeError("plugin_update_handler_mismatch")
        # Health checks are plugin-owned and must be read-only.
        if "health" not in contribution.hooks or contribution.hooks["health"]() is not True:
            raise RuntimeError("plugin_update_health_failed")
        descriptor, _ = load_package(args.plugin_id, allow_draining=True)
        if descriptor["version"] != args.version:
            raise RuntimeError("plugin_update_ui_version_mismatch")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("plugin_update_runtime_failed") from None
