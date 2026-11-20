"""Compatibility exports for the AD-owned Windows event normalizer."""
import importlib
import sys

from server.sli.plugins.ad import windows_ad_dc as _implementation

# Preserve a single module object even when an old nested path is imported first.
for _name in ("analysis", "catalog", "entities", "facts", "investigation", "semantics"):
    sys.modules[f"{__name__}.{_name}"] = importlib.import_module(f"{_implementation.__name__}.{_name}")
sys.modules[__name__] = _implementation
