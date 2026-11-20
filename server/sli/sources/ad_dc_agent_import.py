"""Compatibility alias for the AD-owned bounded event importer."""
import sys

from server.sli.plugins.ad import event_import as _implementation

sys.modules[__name__] = _implementation
