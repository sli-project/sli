"""The operator CLI retains HTTPS, owner-session authorization and secret prompts."""
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from server.sli.agents import admin

AGENT = "00000000-0000-4000-8000-000000000001"


def test_cli_uses_hidden_session_prompt_and_shared_owner_route(monkeypatch, capsys):
    connection = Mock()
    connection.getresponse.return_value = SimpleNamespace(status=200, read=lambda n: json.dumps({"agent_id": AGENT}).encode())
    monkeypatch.setattr(admin.http.client, "HTTPSConnection", lambda *a, **kw: connection)
    monkeypatch.setattr(admin.ssl, "create_default_context", lambda **kw: object())
    prompts = []
    monkeypatch.setattr(admin.getpass, "getpass", lambda prompt: prompts.append(prompt) or "fixture-session-secret")
    assert admin.main(["--server-url", "https://core.invalid", "--ca-bundle", "fixture.pem",
                       "assign-workstations", "--agent-id", AGENT]) == 0
    assert prompts and capsys.readouterr().out == "agent_module_assigned\n"
    args, kwargs = connection.request.call_args
    assert args == ("POST", "/api/v1/admin/agents/modules")
    assert kwargs["headers"]["Cookie"] == "adlog_session=fixture-session-secret"
    assert json.loads(kwargs["body"]) == {"agent_id": AGENT, "module_id": "sli.workstations", "enabled": True, "config": {}}
    connection.close.assert_called_once()


@pytest.mark.parametrize("url", ["http://core.invalid", "https://core.invalid/path", "https://fixture@core.invalid"])
def test_cleartext_or_credential_url_rejected_before_connection(monkeypatch, url):
    monkeypatch.setattr(admin.http.client, "HTTPSConnection", lambda *a, **kw: pytest.fail("must not connect"))
    with pytest.raises(ValueError):
        admin.assign(server_url=url, ca_bundle="fixture.pem", session_token="fixture", agent_id=AGENT, enabled=True, config={})


def test_failures_do_not_print_credentials_or_response_details(monkeypatch, capsys):
    monkeypatch.setattr(admin.getpass, "getpass", lambda *a: "fixture-secret")
    def fail(**kwargs):
        raise RuntimeError("fixture-private-error")
    monkeypatch.setattr(admin, "assign", fail)
    with pytest.raises(SystemExit) as error:
        admin.main(["--server-url", "https://core.invalid", "--ca-bundle", "fixture.pem",
                    "assign-workstations", "--agent-id", AGENT])
    assert error.value.code == 1
    assert capsys.readouterr().err == "agent_admin_operation_failed\n"
