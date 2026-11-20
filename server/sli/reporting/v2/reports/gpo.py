"""Compatibility alias for the GPO-owned implementation."""
import sys

from server.sli.plugins.gpo.reports import definition as _implementation

sys.modules[__name__] = _implementation
