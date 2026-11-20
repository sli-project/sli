"""Runtime replacement validates authority and explicit confirmation before SQL."""
from unittest.mock import Mock

import pytest

from server.api.routes import agents
from server.sli.agents import runtime_switch
from server.sli.agents.ca import AgentError
from tests.unit.test_agent_sequence_recovery_api import Handler

OLD = "00000000-0000-4000-8000-000000000001"
NEW = "00000000-0000-4000-8000-000000000002"
BODY = {"old_agent_id": OLD, "new_agent_id": NEW, "phase": "prepare", "confirm": True}
PATH = "/api/v1/admin/agents/replace"


@pytest.mark.parametrize("body", [None, {}, {**BODY, "confirm": False}, {**BODY, "phase": "force"},
                                 {**BODY, "new_agent_id": OLD}, {**BODY, "extra": True}])
def test_invalid_request_never_queries(body):
    cur = Mock()
    with pytest.raises(AgentError):
        runtime_switch.replace(cur, body, actor="session:1", access={"platform_owner": True})
    cur.execute.assert_not_called()


def test_no_authority_never_queries():
    cur = Mock()
    with pytest.raises(AgentError, match="agent_replacement_denied"):
        runtime_switch.replace(cur, BODY, actor="session:1", access={})
    cur.execute.assert_not_called()


@pytest.mark.parametrize("options", [{"authenticated": False}, {"owner": False}, {"mutation": False}])
def test_route_checks_authority_and_csrf(monkeypatch, options):
    execute = Mock()
    monkeypatch.setattr(agents, "_execute", execute)
    handler = Handler(**options)
    assert agents.try_handle_post(handler, PATH)
    execute.assert_not_called()


@pytest.mark.parametrize("access", [{"platform_owner": True}, {"capabilities": ["access.manage"]}])
def test_service_calls_single_atomic_function(access):
    cur = Mock()
    cur.fetchone.return_value = {"result": {"state": "draining"}}
    assert runtime_switch.replace(cur, BODY, actor="session:1", access=access) == {"state": "draining"}
    assert cur.execute.call_count == 1
    assert cur.execute.call_args.args[1] == (OLD, NEW, "prepare", "session:1")


@pytest.mark.parametrize("owner", [True, False])
def test_route_accepts_owner_or_access_manage(monkeypatch, owner):
    handler = Handler(owner=owner, manage=not owner)
    handler.body = BODY
    service = Mock(return_value={"state": "draining"})
    monkeypatch.setattr(runtime_switch, "replace", service)
    monkeypatch.setattr(agents, "_execute", lambda h, operation: operation("cursor"))
    assert agents.try_handle_post(handler, PATH)
    service.assert_called_once_with("cursor", BODY, actor="session:1", access={"platform_owner": owner})


def test_msi_instance_parameter_reaches_existing_enrollment_option():
    from pathlib import Path
    from xml.etree import ElementTree as ET
    root = Path(__file__).resolve().parents[2] / "agent-dotnet"
    xml = ET.parse(root / "installer/SliAgent.wxs")
    ns = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
    assert xml.find(".//w:Property[@Id='INSTANCE_NAME']", ns).attrib["Secure"] == "yes"
    assert xml.find(".//w:RegistryValue[@Name='InstanceName']", ns).attrib["Value"] == "[INSTANCE_NAME]"
    assert '"InstanceName"' in (root / "src/Sli.Agent.Windows/MsiConfiguration.cs").read_text()
    registration = ET.parse(root / "installer/Registration.wxs")
    action = registration.find(".//w:CustomAction[@Id='ValidateInstanceName']", ns)
    assert action.attrib["DllEntry"] == "ValidateInstanceName" and action.attrib["Return"] == "check"
    for sequence in ("InstallUISequence", "InstallExecuteSequence"):
        check = registration.find(f".//w:{sequence}/w:Custom[@Action='ValidateInstanceName']", ns)
        assert check.attrib == {"Action": "ValidateInstanceName", "Before": "LaunchConditions", "Condition": "NOT REMOVE"}


def test_handoff_support_report_is_authenticated_policy_metadata():
    from server.sli.agents import policies
    from tests.unit.test_agent_policies import Cursor
    cur = Cursor()
    cur.agent["collection_policy"] = {"state": "drain"}
    policies.report(cur, cur.agent, {"applied_policy_revision": 1, "collection_state": "paused", "runtime_handoff_supported": True})
    assert cur.agent["rights_probe"]["runtime_handoff_supported"] is True
    with pytest.raises(AgentError):
        policies.report(cur, cur.agent, {"applied_policy_revision": 1, "runtime_handoff_supported": "true"})


@pytest.mark.parametrize("ready", [True, False])
def test_cli_commits_prepare_and_releases_connection_before_polling(monkeypatch, ready):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from server.sli.agents import runtime_switch_admin as cli
    events = []

    @contextmanager
    def connection():
        events.append("open")
        yield SimpleNamespace(cursor=lambda: cursor(), commit=lambda: events.append("commit"))
        events.append("close")

    @contextmanager
    def cursor():
        yield "cursor"

    def replace(cur, body, **kwargs):
        phase = body["phase"]
        events.append(phase)
        if phase == "complete" and not ready:
            raise AgentError("agent_replacement_not_ready", 409)
        return {"state": "draining" if phase == "prepare" else "completed"}

    monkeypatch.setattr(cli, "connect", connection)
    monkeypatch.setattr(cli, "owner_principal", lambda _: {"id": 1})
    monkeypatch.setattr(cli, "effective_access", lambda _: {"platform_owner": True})
    monkeypatch.setattr(cli.runtime_switch, "replace", replace)
    result = cli.run(SimpleNamespace(owner_user_id=1, actor="fixture", old_agent_id=OLD, new_agent_id=NEW, confirm=True, wait_seconds=0))
    assert result["state"] == ("completed" if ready else "draining")
    assert events[:4] == ["open", "prepare", "commit", "close"]
    assert events[4:6] == ["open", "complete"]
