"""Compatibility alias for the plugin-owned implementation."""
import sys

from server.sli.plugins.ad.context import projection as _implementation

sys.modules[__name__] = _implementation
