"""Private, disposable caches for the pinned pySigma data loaders.

Never reopen ~/.cache/pysigma: an old pickle cache may already be poisoned.
POSIX uses newly created service-owned 0700 directories. On Windows, where
chmod(0700) does not enforce a private DACL, disk caching is disabled instead.
"""
from __future__ import annotations

import importlib
import json
import os
import stat
import tempfile
import threading

_lock = threading.Lock()
_prepared = False
_directory: tempfile.TemporaryDirectory | None = None


class _MemoryCache:
    """Only JSON data; no persisted objects, pickle, or filesystem access."""

    def __init__(self):
        self.values = {}

    def get(self, key, default=None):
        value = self.values.get(key)
        return json.loads(value) if value is not None else default

    def set(self, key, value):
        self.values[key] = json.dumps(value, allow_nan=False)
        return True

    def clear(self):
        self.values.clear()

    def close(self):
        self.clear()


def _private_directory():
    # mkdtemp creates an unpredictable directory exclusively, with mode 0700.
    # Require the system temp parent to be root-owned and sticky if writable
    # by others, so another user cannot rename our directory after creation.
    parent = os.lstat("/tmp")
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or (
        parent.st_mode & 0o022 and not parent.st_mode & stat.S_ISVTX
    ):
        raise RuntimeError("unsafe_sigma_cache_parent")
    directory = tempfile.TemporaryDirectory(prefix="sli-sigma-", dir="/tmp")
    info = os.lstat(directory.name)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        directory.cleanup()
        raise RuntimeError("unsafe_sigma_cache_directory")
    return directory


def prepare_sigma_caches():
    """Call before importing a parser or validator that can load MITRE data.

    The private adapter is deliberately restricted to the pinned pySigma API;
    fail closed if its cache hooks change. No dataset is loaded or downloaded.
    """
    global _prepared, _directory
    with _lock:
        if _prepared:
            return
        modules = [importlib.import_module("sigma.data." + name) for name in ("mitre_attack", "mitre_d3fend")]
        if any(not callable(vars(module).get("_get_cache")) or not callable(vars(module).get("set_cache_dir")) for module in modules):
            raise RuntimeError("unsupported_sigma_cache_api")
        if os.name == "posix":
            directory = _private_directory()
            try:
                for module in modules:
                    path = os.path.join(directory.name, module.__name__.rsplit(".", 1)[-1])
                    os.mkdir(path, 0o700)
                    module.set_cache_dir(path)
            except Exception:
                directory.cleanup()
                raise
            _directory = directory  # Keep alive until process exit.
        else:
            for module in modules:
                previous = vars(module).get("_cache")
                if previous is not None:
                    previous.close()
                cache = _MemoryCache()
                module._cache = cache
                module._get_cache = lambda cache=cache: cache
        _prepared = True
