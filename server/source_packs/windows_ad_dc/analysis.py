"""Compatibility alias for the AD-owned normalization rules."""
import sys

from server.sli.plugins.ad.windows_ad_dc import analysis as _implementation

sys.modules[__name__] = _implementation
