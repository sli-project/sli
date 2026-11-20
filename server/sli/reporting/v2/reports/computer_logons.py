"""Compatibility alias for the AD-owned implementation."""
import sys

from server.sli.plugins.ad.reports.definitions import computer_logons as _implementation

sys.modules[__name__] = _implementation
