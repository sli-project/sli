"""Compatibility alias for the AD-owned implementation."""
import sys

from server.sli.plugins.ad import targets as _implementation

sys.modules[__name__] = _implementation
