"""Lock scope contracts; real PostgreSQL concurrency is tested separately."""
from contextlib import nullcontext

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents import import_authorization, registry, snapshot_consumer
from tests.unit.test_agent_registry import enroll, lifecycle, request  # noqa: F401
from sli_agent.envelope import digest


def test_transport_keeps_exclusive_nonkey_lock_and_certificate_order(lifecycle):
    cur, ca, _, _ = lifecycle
    _, der = enroll(lifecycle)
    cur.calls.clear()
    registry.authenticate(cur, ca, der)
    sql = [call[0] for call in cur.calls]
    assert sql[0] == "select * from sli_agents where id=%s for no key update"
    assert "sli_agent_certificates" in sql[1] and sql[1].endswith("for update")
    assert sql[2].startswith("update sli_agents set last_seen=")


def test_renew_keeps_strong_lifecycle_lock_before_certificate(lifecycle):
    cur, ca, _, _ = lifecycle
    _, der = enroll(lifecycle)
    cur.calls.clear()
    registry.renew(cur, ca, der, {"csr_pem": request(ec.generate_private_key(ec.SECP256R1()))})
    sql = [call[0] for call in cur.calls]
    assert sql[0] == "select * from sli_agents where id=%s for update"
    assert "sli_agent_certificates" in sql[1]


class AuthorizationCursor:
    def __init__(self, module):
        self.module, self.calls = module, []
        self.packet = {"fixture": True}
        self.envelope = {"agent_id": "fixture", "packet_id": "fixture", "payload_sha256": digest(self.packet)}

    def execute(self, sql, args):
        self.calls.append(sql)

    def fetchone(self):
        if len(self.calls) == 1:
            return {"status": "active", "host_id": "00000000-0000-4000-8000-000000000001",
                    "assigned_modules": [{"module_id": self.module, "enabled": True}]}
        return {"envelope": self.envelope, "envelope_sha256": digest(self.envelope)}


@pytest.mark.parametrize("module", ["sli.ad-snapshot", "sli.gpo-snapshot"])
def test_snapshot_lifecycle_mode_is_explicit(module):
    cur = AuthorizationCursor(module)
    import_authorization.authorize_packet(cur, cur.envelope, cur.packet, module=module, snapshot=True)
    assert cur.calls[0].endswith("for key share")


def test_event_import_default_remains_strong():
    cur = AuthorizationCursor("sli.workstations")
    import_authorization.authorize_packet(cur, cur.envelope, cur.packet, module=cur.module)
    assert cur.calls[0].endswith("for update")


def test_snapshot_mode_cannot_be_used_for_event_import():
    cur = AuthorizationCursor("sli.workstations")
    with pytest.raises(import_authorization.PacketPending, match="agent_snapshot_module_invalid"):
        import_authorization.authorize_packet(cur, cur.envelope, cur.packet, module=cur.module, snapshot=True)
    assert cur.calls == []


def test_snapshot_consumer_explicitly_requests_snapshot_mode(monkeypatch):
    modes = []
    class Cursor:
        def execute(self, *args):
            pass
        def fetchall(self):
            return [{"cycle_id": "fixture", "module_id": "sli.ad-snapshot", "slot_start_utc": "fixture"}]
        def fetchone(self):
            return {"envelope": {}, "payload": {}}
    class Connection:
        def transaction(self):
            return nullcontext()
        def cursor(self):
            return nullcontext(Cursor())
    def authorize(*args, snapshot=False, **kwargs):
        modes.append(snapshot)
        raise import_authorization.PacketPending("fixture-stop")
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", authorize)
    snapshot_consumer.consume_snapshot_cycles(Connection())
    assert modes == [True]
