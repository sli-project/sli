"""Compatibility alias for the AD-owned implementation."""
import sys

from server.sli.plugins.ad import setup as _implementation

sys.modules[__name__] = _implementation
