"""Compatibility alias for the AD-owned implementation."""
import sys

from server.sli.plugins.ad.reports.definitions import new_logon_pairs as _implementation

sys.modules[__name__] = _implementation
