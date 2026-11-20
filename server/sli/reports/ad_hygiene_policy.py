"""Compatibility alias for the AD-owned implementation."""
import sys

from server.sli.plugins.ad.reports import ad_hygiene_policy as _implementation

sys.modules[__name__] = _implementation
