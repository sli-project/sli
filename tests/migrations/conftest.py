from __future__ import annotations

import pytest

from server.sli.core import platform_settings


@pytest.fixture
def installation_report_domain(monkeypatch: pytest.MonkeyPatch) -> str:
    """Use a synthetic installation domain, independent of historical allowlists."""
    domain = "example.test"
    stored_row = platform_settings._stored_row
    monkeypatch.setattr(platform_settings, "_stored_row", lambda key: {"value": domain} if key == "reports.domain_fqdn" else stored_row(key))
    return domain
