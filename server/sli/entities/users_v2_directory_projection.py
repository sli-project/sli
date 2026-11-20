"""Compatibility alias for the AD-owned implementation."""
import sys

from server.sli.plugins.ad import directory_projection as _implementation

sys.modules[__name__] = _implementation
