"""Report framework v2 (ADR 0010): declarations, registry and a single API.

A report is a ``ReportDefinition`` in ``server/sli/reporting/v2/reports``.
Existing report engines are reused; only the way a report is connected to
access control, parameters, the API and the UI shell is unified here.
"""

from server.sli.reporting.v2.definition import (
    AccessRequirement,
    AccessRule,
    Column,
    Detail,
    Param,
    QueryContext,
    ReportDefinition,
    View,
)
from server.sli.reporting.v2.registry import catalog, get_report, registered_reports

__all__ = [
    "AccessRequirement", "AccessRule", "Column", "Detail", "Param", "QueryContext", "ReportDefinition", "View",
    "catalog", "get_report", "registered_reports",
]
