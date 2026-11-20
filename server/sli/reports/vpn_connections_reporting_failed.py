"""Compatibility import for the sli.remote-access-owned implementation."""

import sys

from server.sli.plugins.remote_access.reports import vpn_connections_reporting_failed as _implementation
from server.sli.plugins.remote_access.reports.vpn_connections_reporting_failed import (
    _failed_authorization_collection_coverage as _failed_authorization_collection_coverage,
)

sys.modules[__name__] = _implementation
