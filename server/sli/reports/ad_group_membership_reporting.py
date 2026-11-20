"""Compatibility alias for the AD-owned implementation."""
import sys

from server.sli.plugins.ad.reports import ad_group_membership_reporting as _implementation

sys.modules[__name__] = _implementation
