"""The plugin page reads declarations without adding policy writes or DB reads."""
from copy import deepcopy

import pytest

from server.sli.plugins import settings


@pytest.mark.parametrize("plugin_id", [
    "sli.ad", "sli.gpo", "sli.workstations", "sli.file-audit", "sli.remote-access", "sli.sigma",
])
def test_settings_return_bundled_rules_without_mutating_declarations(monkeypatch, plugin_id):
    declaration = settings.metadata(plugin_id)
    before = deepcopy(declaration)
    monkeypatch.setattr(settings, "metadata", lambda _: declaration)
    monkeypatch.setattr("server.sli.core.platform_settings._resolve",
                        lambda spec: (spec.default or "", "default", None))

    result = settings.read_settings(plugin_id)

    assert result["rules"] == before["rules"]
    assert result["schema"] == before["settings"]
    assert declaration == before
