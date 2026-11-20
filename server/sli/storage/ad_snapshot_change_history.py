"""Compatibility alias for the plugin-owned implementation."""
import sys

from server.sli.plugins.ad.snapshots import change_history as _implementation

sys.modules[__name__] = _implementation
