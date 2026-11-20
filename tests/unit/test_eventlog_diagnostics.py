"""Bounded, source-free diagnostics and heartbeat compatibility."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sli_agent.policies import AppliedPolicy, acknowledge_policy
from sli_collect.eventlog_diagnostics import diagnostic, validate_observations


def test_hresult_and_cursor_without_exception_text_or_bookmark():
    exc = OSError("password=private-event")
    exc.winerror = 5
    exc.hresult = -2147024891
    value = diagnostic(exc, "Security", {"record_id": 42, "bookmark": "private-xml"}, "seek")
    assert value["winerror"] == 5 and value["hresult"] == -2147024891
    assert value["record_id"] == 42 and value["bookmark_present"] is True
    assert "private" not in str(value)


def observation():
    return {"channel": "Security", "observed_at_utc": "2026-10-11T00:00:00+00:00",
            "policy_revision": 3, "error": diagnostic(OSError(), "Security",
                {"record_id": 42, "bookmark": "private"}, "read")}


@pytest.mark.parametrize("change", [
    {"message": "private"}, {"channel": "private-host"}, {"policy_revision": True},
    {"observed_at_utc": "private"}, {"error": {"message": "private"}},
])
def test_rejects_unbounded_or_private_fields(change):
    with pytest.raises(ValueError, match="eventlog_diagnostics_invalid"):
        validate_observations([{**observation(), **change}])


def test_duplicate_channels_and_oversized_heartbeat_rejected():
    with pytest.raises(ValueError):
        validate_observations([observation(), observation()])
    with pytest.raises(ValueError):
        validate_observations([observation()] * 9)


def test_ack_only_sends_diagnostics_when_server_advertises_support():
    transport = Mock()
    modules = AppliedPolicy([], {}, {"applied_policy_revision": 3})
    identity = SimpleNamespace()
    acknowledge_policy(modules, transport, identity, diagnostics=[observation()])
    assert "eventlog_diagnostics" not in transport.post.call_args.args[1]
    modules.diagnostics_supported = True
    acknowledge_policy(modules, transport, identity, diagnostics=[observation()])
    assert transport.post.call_args.args[1]["eventlog_diagnostics"] == [observation()]


def test_native_read_observations_survive_restart_and_success_clears_error(tmp_path):
    from datetime import datetime, timezone

    from sli_agent.eventlog_health import EventLogHealth
    from sli_agent.workstations import WorkstationsModule
    module = WorkstationsModule("fixture", reader=Mock(side_effect=OSError("private-event")))
    health = EventLogHealth(tmp_path)
    module.collect(now=datetime(2026, 10, 11, tzinfo=timezone.utc))
    health.observe(module, 3)
    restarted = EventLogHealth(tmp_path)
    assert restarted.observations()[0]["error"]["exception_class"] == "OSError"
    assert "private" not in health.path.read_text()
    module.reader = Mock(return_value=[])
    module.collect(now=datetime(2026, 10, 11, tzinfo=timezone.utc))
    restarted.observe(module, 4)
    assert EventLogHealth(tmp_path).observations()[0]["error"] is None
    assert restarted.observations()[0]["policy_revision"] == 4


def test_invalid_persisted_diagnostics_are_never_forwarded(tmp_path):
    from sli_agent.eventlog_health import EventLogHealth
    (tmp_path / "eventlog-health.json").write_text('[{"message":"private"}]')
    assert EventLogHealth(tmp_path).observations() == []


def test_server_reports_exact_mtls_agent_and_preserves_legacy_heartbeat():
    import json

    from server.sli.agents import policies
    from tests.unit.test_agent_policies import Cursor
    cur = Cursor()
    body = {"applied_policy_revision": 1, "eventlog_diagnostics": [{**observation(), "policy_revision": 1}]}
    policies.report(cur, cur.agent, body)
    saved = json.loads(next(params[1] for sql, params in cur.calls if sql.startswith("update sli_agents set applied_policy_revision")))
    assert saved["eventlog_diagnostics"]["items"] == body["eventlog_diagnostics"]
    assert all(params[-1] == cur.agent["id"] for sql, params in cur.calls if sql.startswith("update sli_agents"))
    cur.calls.clear()
    policies.report(cur, {**cur.agent, "rights_probe": saved}, {"applied_policy_revision": 1})
    assert json.loads(cur.calls[0][1][1])["eventlog_diagnostics"] == saved["eventlog_diagnostics"]


@pytest.mark.parametrize("values", [[{**observation(), "message": "private"}], [observation()]])
def test_server_rejects_private_fields_or_future_policy_before_writing(values):
    from server.sli.agents import policies
    from server.sli.agents.ca import AgentError
    from tests.unit.test_agent_policies import Cursor
    cur = Cursor()
    with pytest.raises(AgentError, match="invalid_agent_eventlog_diagnostics"):
        policies.report(cur, cur.agent, {"applied_policy_revision": 1, "eventlog_diagnostics": values})
    assert cur.calls == []


def test_inventory_exposes_diagnostics_separately_from_probe(monkeypatch):
    from server.sli.agents import registry, removal
    from tests.unit.test_agent_policies import Cursor
    cur = Cursor()
    cur.agent["rights_probe"] = {"eventlog_diagnostics": {"reported_at": observation()["observed_at_utc"],
        "items": [observation()]}, "pending": {"request_id": "fixture"}}
    from datetime import datetime, timezone
    # T095: список агентов читает last_seen и created_at из строки (как реальная выборка).
    cur.agent.setdefault("last_seen", datetime.now(timezone.utc))
    cur.agent.setdefault("created_at", datetime.now(timezone.utc))
    batches = iter([[cur.agent], [], [], []])
    cur.execute = lambda sql, params=(): cur.calls.append((sql, params))
    cur.fetchall = lambda: next(batches)
    def domain_metadata():
        sql = cur.calls[-1][0]
        if sql.startswith("select details->>'reason' as reason from sli_agent_audit"):
            return None  # T095: причина отключения записи (у активного агента её нет)
        assert sql.startswith("select b.password_detection_domain_id as domain_id")
        return None
    cur.fetchone = domain_metadata
    monkeypatch.setattr(removal, "visibility", lambda *args: None)
    inventory = registry.list_agents(cur, actor="fixture")
    assert inventory["items"][0]["password_detection_domain"] == {
        "status": "unconfigured", "domain_id": None, "domain_fqdn": None}
    assert inventory["items"][0]["eventlog_diagnostics"]["items"] == [observation()]
    assert inventory["items"][0]["rights_probe"] == {"pending": {"request_id": "fixture"}}


@pytest.mark.parametrize("stage", ["query", "seek", "anchor", "render"])
def test_native_reader_retains_failure_stage_and_closes_handles(monkeypatch, stage):
    import sys

    from sli_collect.bookmarked_eventlog import read_local
    closed = []
    class NativeError(Exception):
        winerror = 15011
    def fail():
        raise NativeError("private XML and account")
    query = SimpleNamespace(Close=lambda: closed.append("query"))
    bookmark = SimpleNamespace(Close=lambda: closed.append("bookmark"))
    event = SimpleNamespace(Close=lambda: closed.append("event"))
    backend = SimpleNamespace(EvtQueryChannelPath=1, EvtQueryForwardDirection=2,
        EvtSeekRelativeToBookmark=4, EvtSeekStrict=8, EvtRenderEventXml=1, error=NativeError,
        EvtQuery=lambda *args: fail() if stage == "query" else query,
        EvtCreateBookmark=lambda *args: bookmark,
        EvtSeek=lambda *args, **kwargs: fail() if stage == "seek" else None,
        EvtNext=lambda *args: fail() if stage == "anchor" else [event],
        EvtRender=lambda *args: fail())
    monkeypatch.setitem(sys.modules, "win32evtlog", backend)
    with pytest.raises(RuntimeError) as failure:
        read_local("Security", {"record_id": None if stage == "render" else 42,
            "bookmark": "" if stage == "render" else "private-bookmark"}, 2)
    assert failure.value.diagnostic["stage"] == stage
    assert failure.value.diagnostic["winerror"] == 15011
    assert "private" not in str(failure.value.diagnostic)
    assert closed == ([] if stage == "query" else
        ["event", "bookmark", "query"] if stage == "render" else ["bookmark", "query"])
