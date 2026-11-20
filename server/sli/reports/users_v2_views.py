"""Compatibility alias for the AD-owned implementation."""
import sys

from server.sli.plugins.ad.reports import users_v2_views as _implementation

sys.modules[__name__] = _implementation
