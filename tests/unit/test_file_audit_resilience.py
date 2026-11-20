"""Synthetic restart, lost ACK and Security generation acceptance."""
from copy import deepcopy
from datetime import timedelta

import pytest

from server.sli.agent_ingest import receive_packet
from server.sli.plugins.file_audit.agent_ingest import packet_rows
from sli_agent.envelope import make_packet
from sli_agent.spool import Spool, SpoolFull
from tests.unit.test_agent_ingest import Ledger
from tests.unit.test_file_audit_agent_ingest import packet
from tests.unit.test_file_audit_collection import NOW, collector, xml
from tests.unit.test_file_audit_contracts import AGENT, settings


def test_offline_restart_lost_ack_and_policy_change_preserve_exact_delivery(tmp_path):
    key, _, identity, assignment = packet()
    options = {"max_bytes": 100000, "max_age_seconds": 60}
    spool = Spool(tmp_path, **options)
    sample = collector(reader=lambda *_: [(xml(1), "b1")], path_check=lambda *_: "file").collect(now=NOW)
    value = spool.capture(key, agent_id=AGENT, sample=sample, now=NOW)
    ledger = Ledger()
    receipt = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)
    assert receipt["status"] == "committed"
    restarted = Spool(tmp_path, **options)
    assert restarted.pending() == [value]
    with pytest.raises(SpoolFull, match="age_limit"):
        restarted.capture(key, agent_id=AGENT,
            sample=collector(reader=lambda *_: []).collect(restarted.captured("sli.file-audit"), now=NOW),
            now=NOW + timedelta(days=8))
    assert restarted.pending() == [value]
    identity = deepcopy(identity)
    identity["assigned_modules"][0]["config"]["policy_revision"] = "2"
    retry = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value,
                           now=NOW + timedelta(days=8))
    assert retry["status"] == "duplicate" and len(ledger.imports) == 1
    assert restarted.acknowledge(value, retry)
    assert not restarted.pending()
    next_sample = collector({**settings(), "policy_revision": "2"},
        reader=lambda *_: [(xml(2), "b2")], path_check=lambda *_: "file").collect(
            restarted.captured("sli.file-audit"), now=NOW)
    next_value = restarted.capture(key, agent_id=AGENT, sample=next_sample, now=NOW)
    assert next_value["envelope"]["sequence"] == 2
    assert next_value["envelope"]["cursor_before"] == value["envelope"]["cursor_after"]
    assert packet_rows(identity, identity["assigned_modules"][0], next_value["envelope"], next_value["payload"])


def test_proven_journal_reset_is_durable_gap_then_resumes_at_reused_record_id(tmp_path):
    from sli_agent.file_audit_journal import JournalGap
    key, first, identity, assignment = packet()
    ledger = Ledger()
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=first, now=NOW)["status"] == "committed"
    def cleared(*_):
        raise JournalGap()
    reset = collector(reader=cleared).collect(first["envelope"], now=NOW)
    assert reset.generation != first["envelope"]["generation"]
    assert reset.continuity_state == "gap" and reset.lost_count is None
    assert reset.cursor_before == {"strategy": "bookmark", "token": ""}
    gap = make_packet(key, agent_id=AGENT, sequence=2, sample=reset, now=NOW)
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=gap, now=NOW)["status"] == "committed"
    spool = Spool(tmp_path, max_bytes=100000, max_age_seconds=86400)
    spool.capture(key, agent_id=AGENT, sample=reset, now=NOW)
    restarted = Spool(tmp_path, max_bytes=100000, max_age_seconds=86400)
    sample = collector(reader=lambda *_: [(xml(1), "new-b1")], path_check=lambda *_: "file").collect(
        restarted.captured("sli.file-audit"), now=NOW)
    assert sample.generation == reset.generation
    resumed = make_packet(key, agent_id=AGENT, sequence=3, sample=sample, now=NOW)
    assert packet_rows(identity, assignment, resumed["envelope"], resumed["payload"])
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=resumed, now=NOW)["status"] == "committed"


def test_observed_clear_event_marks_gap_without_inventing_loss_count():
    raw = xml(1, 1102, path="").replace("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Eventlog")
    sample = collector(reader=lambda *_: [(raw, "b1")]).collect(now=NOW)
    assert sample.continuity_state == "gap" and sample.lost_count is None
    key, _, identity, assignment = packet()
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    assert packet_rows(identity, assignment, value["envelope"], value["payload"])
