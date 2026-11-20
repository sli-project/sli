"""Compatibility alias for the AD-owned implementation."""
import sys

from server.sli.plugins.ad.reports import computers_v6_reporting_items as _implementation

sys.modules[__name__] = _implementation
