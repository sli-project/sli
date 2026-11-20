"""Compatibility alias for the plugin-owned implementation."""
import sys

from server.sli.plugins.ad import snapshot_import as _implementation

sys.modules[__name__] = _implementation
