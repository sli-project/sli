"""Synthetic CH publication, retained facts and corruption after XML expiry."""
from copy import deepcopy
import json

import pytest

from server.sli.storage import permanent_fact_history as history


@pytest.fixture
def publication(monkeypatch):
    core = {"id": 41, "event_id": 4663, "server_id": 1, "normalized_hash": "61" * 32,
            "time_created_utc": "2026-01-01T00:00:00Z", "noise_class": "context"}
    facts = {"file_audit_facts_json": json.dumps({"path": r"C:\synthetic\item", "access_mask": 2})}
    event = {"event_db_id": 41, "event_key": 4663, "server_id": 1,
             "time_created_utc": history._json_ch_time(core["time_created_utc"]), "noise_class": "context",
             "core_json": json.dumps(core), "facts_json": json.dumps(facts),
             "row_sha256": history._payload_sha({"core": core, "facts": facts}), "batch_sha256": "a" * 64}
    link = {"event_db_id": 41, "entity_id": 1, "link_role": "subject", "details_json": "{}",
            "time_created_utc": event["time_created_utc"], "row_sha256": "b" * 64, "batch_sha256": "a" * 64}
    batch = {"batch_sha256": "a" * 64, "first_event_db_id": 41, "last_event_db_id": 41}
    source, restored = deepcopy(([event], [link])), deepcopy(([event], [link], [batch]))
    monkeypatch.setattr(history, "_source_batch", lambda *a, **kw: deepcopy(source))
    def rows(_port, sql, **_kwargs):
        if ".published_batches" in sql:
            return restored[2]
        if ".links" in sql:
            return restored[1]
        return restored[0]
    monkeypatch.setattr(history, "_rows", rows)
    return restored


def test_restored_file_facts_and_links_pass_exact_retention_verification(publication):
    history.verify_preserved_candidates(1234, [{"id": 41, "normalized_hash": b"a" * 32}])
    detail = history.read_published_event(1234, 41)
    assert detail["source_payload_state"] == "expired" and detail["record_xml"] is None
    assert json.loads(detail["retained_facts"]["file_audit_facts_json"])["access_mask"] == 2
    assert history._fact_payload({"event_id": 41, "file_audit_facts_json": None}) == {}


@pytest.mark.parametrize("fault", ["facts", "hash", "links", "publication", "duplicate"])
def test_restored_history_with_corruption_or_missing_links_cannot_authorize_cleanup(publication, fault):
    if fault == "facts":
        publication[0][0]["facts_json"] = "{}"
    elif fault == "hash":
        publication[0][0]["row_sha256"] = "c" * 64
    elif fault == "links":
        publication[1].clear()
    elif fault == "publication":
        publication[2].clear()
    else:
        publication[0].append(deepcopy(publication[0][0]))
    with pytest.raises(RuntimeError):
        history.verify_preserved_candidates(1234, [{"id": 41, "normalized_hash": b"a" * 32}])
