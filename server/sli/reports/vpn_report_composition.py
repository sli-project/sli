"""Compatibility import for the sli.remote-access-owned implementation."""

import sys

from server.sli.plugins.remote_access.reports import vpn_report_composition as _implementation

sys.modules[__name__] = _implementation
