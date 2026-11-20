"""AC-CTL pause/drain must precede any NPS spool delivery or source read."""
from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from sli_agent import policies, runtime
from sli_agent.config import AgentConfig
from sli_agent.modules import HeartbeatModule
from sli_agent.spool import Spool
from tests.unit.test_sli_agent_nps import NOW, HOST, AGENT, CONFIG, NPS_MODULE, ACCOUNTING_MODULE, accounting_config


@pytest.mark.parametrize("state,sent,collected", [("active", 1, 1), ("paused", 0, 0), ("drain", 1, 0),
                                               ("unavailable", 0, 0)])
@pytest.mark.parametrize("module", [NPS_MODULE, ACCOUNTING_MODULE])
def test_runtime_applies_current_control_before_sending_or_capturing(tmp_path, monkeypatch, state, sent, collected, module):
    config = AgentConfig("https://core.invalid", tmp_path / "ca", tmp_path)
    key = ec.generate_private_key(ec.SECP256R1())
    identity = SimpleNamespace(agent_id=AGENT, key=key)
    spool = Spool(tmp_path / "spool", max_bytes=65536, max_age_seconds=86400)
    sample = replace(HeartbeatModule(HOST).collect(now=NOW), module_id=module)
    saved = spool.capture(key, agent_id=AGENT, sample=sample)
    calls = []
    audit_report = {"policy_revision": 2, "management_state": "disabled",
                    "command_line_enabled": None, "families": {}}
    class Collector:
        module_id = module
        policy = deepcopy(CONFIG if module == NPS_MODULE else accounting_config(tmp_path))
        def collect(self, *_args, **_kwargs):
            calls.append("capture")
            return replace(HeartbeatModule(HOST).collect(saved["envelope"]), module_id=module)
    def modules(*args):
        return [Collector()] if len(args) == 3 else []
    def checkin(*_args, **_kwargs):
        calls.append("checkin")
        if state == "unavailable":
            raise OSError("fixture-private-diagnostic")
        return {"agent_id": AGENT, "assigned_modules": [], "policy_revision": 2,
                "collection_policy": {"state": state}}
    def upload(_path, value, **_kwargs):
        if _path == "/api/v1/agent/windows-audit-report":
            calls.append("audit")
            assert value == {"windows_audit": audit_report}
            return {}
        if _path == "/api/v1/agent/policy-report":
            calls.append("ack")
            assert value == {"applied_policy_revision": 2,
                             "collection_state": "active" if state == "active" else "paused"}
            return {"applied_policy_revision": 2}
        assert _path == "/api/v1/agent/packets"
        calls.append("send")
        e = value["envelope"]
        return {"contract_id": "sli.agent-receipt.v1", "packet_id": e["packet_id"], "payload_sha256": e["payload_sha256"],
            "status": "committed", "committed_cursor": e["cursor_after"], "evidence_ref": "fixture-evidence",
            "committed_at_utc": NOW.isoformat(), "error_code": None}
    monkeypatch.setattr(runtime, "IdentityStore", lambda *_: SimpleNamespace(prepare=lambda: {"host_id": HOST},
        load=lambda: identity, renew_if_due=lambda *_a, **_kw: None))
    monkeypatch.setattr(runtime, "Transport", lambda *_: SimpleNamespace(get=checkin, post=upload))
    monkeypatch.setattr(runtime, "AuditManager", lambda *_: SimpleNamespace(reconcile=lambda *_a: audit_report))
    monkeypatch.setattr(runtime, "configured_modules", modules)
    monkeypatch.setattr(policies, "configured_modules", modules)
    class Stop:
        done = False
        def is_set(self):
            return self.done
        def wait(self, _delay):
            self.done = True
    runtime.run(config, Stop())
    assert calls[0] == "checkin" and calls.count("send") == sent and calls.count("capture") == collected
    assert calls.count("ack") == (0 if state == "unavailable" else 1)
    assert calls.count("audit") == (0 if state == "unavailable" else 1)
    if state != "unavailable":
        assert calls.index("ack") < calls.index("audit")
        if sent:
            assert calls.index("send") < calls.index("audit")
        if collected:
            assert calls.index("audit") < calls.index("capture")
    status = json.loads((tmp_path / "status.json").read_text())
    assert "fixture-private" not in json.dumps(status)
    if state in ("paused", "unavailable"):
        assert list(spool.pending())[0]["envelope"] == saved["envelope"]
