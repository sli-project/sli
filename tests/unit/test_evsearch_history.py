"""ES05 synthetic history, publication, policy and integrity contracts; no DB."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from server.sli.events import evsearch_history as reader
from server.sli.events.evsearch_normalizer import normalize_request


NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)
FIELDS = ("id", "event_id", "channel", "provider", "server_id", "domain_id", "ip",
          "time_created_utc", "message_sample", "source_payload_state")


def search(**changes):
    return normalize_request({"contract_version": "evsearch.v1", **changes}, now=NOW)


def condition(key, op, value=None, **changes):
    return {"field": key, "operator": op, **({"value": value} if value is not None else {}), **changes}


def access(scope=None):
    return {
        "policy_revision": "policy-v1", "decision_id": "decision-v1",
        "reports": [{"report_key": "events.explorer", "allowed": True,
                     "allowed_actions": ["view"], "grants": [{
                         "scope": scope or {"kind": "domain", "ids": [7]},
                         "field_categories": ["technical"], "allowed_actions": ["view"],
                     }]}],
    }


def publication():
    fields = (*FIELDS, "account", "account_kind", "q", "outcome", "account_privileged",
              "privilege_grant_confirmed", "source_station", "related_object", "file_path")
    return {
        "dataset_key": "events.v2", "revision": "publication-v1",
        "fields_json": [{"key": key, "category": "technical"} for key in fields],
        "definition_json": {
            "columns": list(fields), "actions": ["view"],
            "evsearch_questions": {key: ["event_id", "provider", "channel"]
                                   for key in ("lockouts", "failed_logons", "admin_logons", "new_admins", "log_cleared")},
        },
    }


def stored(event_id=41, **changes):
    core = {
        "id": event_id, "event_id": 4740, "server_id": 9, "domain_id": 7,
        "time_created_utc": "2026-10-18T12:00:00+00:00", "noise_class": "",
        "channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
        "ip_address": None, "normalized_hash": "AA" * 32,
        **changes,
    }
    facts = {"message_sample": "retained sample"}
    return {
        "event_db_id": event_id, "event_key": core["event_id"], "server_id": core["server_id"],
        "time_created_utc": reader.history._json_ch_time(core["time_created_utc"]), "noise_class": core["noise_class"],
        "core_json": json.dumps(core), "facts_json": json.dumps(facts),
        "row_sha256": reader.history._payload_sha({"core": core, "facts": facts}),
    }


def manifest(rows):
    identity = {
        "first_event_db_id": min(row["event_db_id"] for row in rows),
        "last_event_db_id": max(row["event_db_id"] for row in rows),
        "event_count": len(rows), "link_count": 0,
        "event_sequence_sha256": reader.history._sequence_sha(rows),
        "link_sequence_sha256": reader.history._sequence_sha([]),
    }
    identity["batch_sha256"] = reader.history._payload_sha(identity)
    for row in rows:
        row["batch_sha256"] = identity["batch_sha256"]
    return identity


class History:
    def __init__(self, rows=None):
        self.rows = rows or [stored()]
        self.batches = [manifest(self.rows)]
        self.calls = []
        self.after_manifest = None

    def query(self, sql, timeout_ms):
        self.calls.append((sql, timeout_ms))
        assert 0 < timeout_ms <= 8000
        if "FROM sli_history.published_batches WHERE" in sql:
            result = deepcopy(self.batches)
            if self.after_manifest:
                self.after_manifest()
            return result
        return deepcopy(self.rows)


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setattr(reader.history, "primary_read_enabled", lambda: True)
    source = History()
    args = dict(access=access(), publication=publication(), fields=FIELDS)
    return source, args


def read(setup, query=None, **changes):
    source, args = setup
    return reader.ClickHouseHistoryReader(query_rows=source.query).read(query or search(), **{**args, **changes})


def test_cold_facts_found_with_expired_payload_and_no_unpublished_fields(setup):
    source, _ = setup
    result = read(setup, search(question_id="lockouts"))
    assert result.coverage == "unknown"
    assert result.items == [{
        "id": 41, "event_id": 4740, "channel": "Security", "server_id": 9, "domain_id": 7,
        "provider": "Microsoft-Windows-Security-Auditing", "ip": None,
        "time_created_utc": "2026-10-18T12:00:00+00:00", "message_sample": "retained sample",
        "source_payload_state": "expired",
    }]
    assert "retained sample" not in repr(result)
    assert len(result.publication_watermark) == 64
    assert len(source.calls) == 2
    sql = source.calls[1][0]
    assert "JSONExtract(e.core_json,'domain_id','Nullable(Int64)') IN (7)" in sql
    assert "e.event_key IN (4740)" in sql
    assert "PREWHERE e.time_created_utc >=" in sql and "e.time_created_utc <" in sql
    assert "ORDER BY e.time_created_utc DESC,e.event_db_id DESC" in sql
    assert source.batches[0]["batch_sha256"] in sql
    assert "published_batches" not in sql  # pinned set, not a live subquery
    assert "record_xml" not in result.items[0] and "message_text" not in result.items[0]


def test_private_storage_identity_survives_field_projection_and_merges_with_hot_capture(setup):
    from server.sli.events.evsearch_postgres import read_hot_capture
    from server.sli.events.evsearch_ownership import merge_captures

    _, args = setup
    cold = read(setup, fields=("channel",)).capture
    assert cold.items == ({"channel": "Security"},)
    assert cold.identities[0].event_id == 41

    def pg(sql, params, **budgets):
        return [{"channel": "Security", "_evsearch_id": event_id,
                 "_evsearch_time": "2026-10-18T12:00:00+00:00", "_evsearch_fingerprint": bytes.fromhex("AA" * 32)}
                for event_id in (41, 42)]

    hot = read_hot_capture(search(), access=args["access"], publication=args["publication"],
                           fields=("channel",), query_rows=pg)
    result = merge_captures(search(), hot=hot, cold=cold)
    assert result.items == ({"channel": "Security"}, {"channel": "Security"})
    assert result.manifest.owners == ((42, "postgres"), (41, "postgres"))
    assert result.coverage == result.storage_coverage.status == "unknown"


def test_no_published_batch_still_has_a_bound_empty_capture(setup):
    source, _ = setup
    source.batches = []
    result = read(setup, fields=("id",))
    assert result.capture.store == "clickhouse"
    assert result.capture.items == result.capture.identities == ()
    assert result.capture.watermark == result.publication_watermark
    assert result.coverage == "unknown"


def test_invalid_fingerprint_is_rejected_even_when_fact_checksum_is_valid(setup):
    source, _ = setup
    source.rows = [stored(normalized_hash=None)]
    source.batches = [manifest(source.rows)]
    with pytest.raises(reader.HistoryError, match="history_integrity_error"):
        read(setup, fields=("id",))


def test_new_publication_after_capture_does_not_change_pinned_set(setup):
    source, _ = setup
    late = [stored(81)]
    late_batch = manifest(late)
    source.after_manifest = lambda: source.batches.append(late_batch)
    result = read(setup)
    assert late_batch["batch_sha256"] not in source.calls[1][0]
    assert result.publication_watermark == reader.history._payload_sha([source.batches[0]["batch_sha256"]])


def test_no_published_batches_never_reads_unpublished_events(setup):
    source, _ = setup
    source.batches = []
    result = read(setup)
    assert result.items == [] and result.coverage == "unknown"
    assert len(source.calls) == 1
    assert "FROM sli_history.published_batches WHERE batch_sha256 IN" in source.calls[0][0]


@pytest.mark.parametrize("query", [
    search(q="opaque"), search(exclude_machine_system=True),
    search(conditions=[condition("account", "not_in", [11], role="target")]),
    search(conditions=[condition("source_station", "missing")]),
    search(conditions=[condition("related_object", "eq", 11)]),
    search(conditions=[condition("file_path", "exists")]),
    search(question_id="failed_logons"), search(question_id="admin_logons"), search(question_id="new_admins"),
])
def test_unavailable_predicate_fails_before_any_history_io(setup, query):
    source, _ = setup
    with pytest.raises(reader.HistoryError, match="^evsearch.history_predicate_unavailable$"):
        read(setup, query)
    assert source.calls == []


@pytest.mark.parametrize("change", ["access", "field", "category", "action", "dataset"])
def test_denied_policy_never_reaches_history_or_manifest(setup, change):
    source, args = setup
    if change == "access":
        args["access"]["reports"] = []
    elif change == "field":
        args["publication"]["definition_json"]["columns"].remove("message_sample")
    elif change == "category":
        args["access"]["reports"][0]["grants"][0]["field_categories"] = []
    elif change == "action":
        args["publication"]["definition_json"]["actions"] = ["export"]
    else:
        args["publication"]["dataset_key"] = "other"
    with pytest.raises(PermissionError, match="evsearch.policy_denied"):
        read(setup)
    assert source.calls == []


@pytest.mark.parametrize("scope", [
    {"mode": "restricted", "clauses": [{"entity_ids": [11]}]},
    {"mode": "restricted", "clauses": [{"plugin_ids": ["opaque"]}]},
    {"mode": "restricted", "clauses": [{"source_instance_ids": ["opaque"]}]},
    {"mode": "restricted", "clauses": [{"device_ids": ["opaque"]}, {"device_ids": ["server:9"]}]},
])
def test_unexecutable_scope_is_not_replaced_with_executable_union_branch(setup, scope):
    source, args = setup
    args["access"] = access(scope)
    with pytest.raises(reader.HistoryError, match="history_predicate_unavailable"):
        read(setup)
    assert source.calls == []


@pytest.mark.parametrize("scope,fragment", [
    ({"kind": "all"}, "(1)"),
    ({"kind": "server", "ids": [9]}, "e.server_id IN (9)"),
    ({"kind": "channel", "values": ["Security"]}, "'channel','Nullable(String)') IN ('Security')"),
    ({"mode": "restricted", "clauses": [{"device_ids": ["server:9"], "collection_scope_ids": ["ad-domain:7"]}]},
     "e.server_id IN (9)"),
])
def test_supported_resource_policies_are_compiled_before_selection(setup, scope, fragment):
    source, args = setup
    args["access"] = access(scope)
    assert read(setup).items
    assert all(fragment in sql for sql, _ in source.calls)


@pytest.mark.parametrize("key,value", [("domain_id", 8), ("channel", "other"), ("server_id", 10)])
def test_out_of_scope_row_is_rejected_even_with_valid_fact_hash(setup, key, value):
    source, args = setup
    args["access"] = access({"mode": "restricted", "clauses": [{
        "device_ids": ["server:9"], "collection_scope_ids": ["ad-domain:7"],
    }]}) if key != "channel" else access({"kind": "channel", "values": ["Security"]})
    source.rows = [stored(**{key: value})]
    source.batches = [manifest(source.rows)]
    with pytest.raises(reader.HistoryError, match="history_integrity_error"):
        read(setup)


def test_negative_condition_keeps_null_and_exists_is_explicit(setup):
    source, _ = setup
    assert read(setup, search(conditions=[condition("ip", "not_in", ["192.0.2.1"])] )).items
    assert "isNull(toIPv6OrNull(JSONExtract(e.core_json,'ip_address','Nullable(String)'))) OR" in source.calls[1][0]
    with pytest.raises(reader.HistoryError, match="history_integrity_error"):
        read(setup, search(conditions=[condition("ip", "exists")]))


def test_typed_ip_matches_canonical_address_without_name_resolution(setup):
    source, _ = setup
    source.rows = [stored(ip_address="2001:0db8:0:0:0:0:0:1")]
    source.batches = [manifest(source.rows)]
    result = read(setup, search(conditions=[condition("ip", "eq", "2001:db8::1")]))
    assert result.items[0]["ip"] == "2001:db8::1"
    assert "toIPv6OrNull(" in source.calls[1][0] and "toIPv6('2001:db8::1')" in source.calls[1][0]


@pytest.mark.parametrize("timestamp,allowed", [
    ("2026-10-18T00:00:00+00:00", True), ("2026-10-19T00:00:00+00:00", False),
    ("2026-10-17T23:59:59.999999+00:00", False),
])
def test_period_is_half_open_in_sql_and_verified_facts(setup, timestamp, allowed):
    source, _ = setup
    source.rows = [stored(time_created_utc=timestamp)]
    source.batches = [manifest(source.rows)]
    if allowed:
        assert read(setup).items
    else:
        with pytest.raises(reader.HistoryError, match="history_integrity_error"):
            read(setup)


def test_projection_does_not_return_sensitive_fields_used_only_for_filtering(setup):
    result = read(setup, fields=("id",))
    assert result.items == [{"id": 41}]
    assert result.source_payload_state == "expired"


@pytest.mark.parametrize("damage", ["hash", "identity", "index", "time", "noise", "json", "unpublished", "duplicate", "range"])
def test_tampered_duplicate_or_unpublished_rows_are_integrity_errors(setup, damage):
    source, _ = setup
    row = source.rows[0]
    if damage == "hash":
        row["facts_json"] = '{}'
    elif damage == "identity":
        row["event_db_id"] += 1
    elif damage == "index":
        row["event_key"] += 1
    elif damage == "time":
        row["time_created_utc"] = "2026-10-18 13:00:00.000000"
    elif damage == "noise":
        row["noise_class"] = "other"
    elif damage == "json":
        row["core_json"] = "[]"
    elif damage == "unpublished":
        row["batch_sha256"] = "0" * 64
    elif damage == "duplicate":
        source.rows.append(deepcopy(row))
    else:
        source.batches[0]["first_event_db_id"] = 50
        identity = {key: source.batches[0][key] for key in reader._IDENTITY_KEYS}
        source.batches[0]["last_event_db_id"] = identity["last_event_db_id"] = 60
        source.batches[0]["batch_sha256"] = row["batch_sha256"] = reader.history._payload_sha(identity)
    with pytest.raises(reader.HistoryError, match="^evsearch.history_integrity_error$"):
        read(setup)


@pytest.mark.parametrize("damage", ["duplicate", "hash", "overlap", "excess"])
def test_invalid_publication_manifest_fails_before_fact_query(setup, damage):
    source, _ = setup
    if damage == "duplicate":
        source.batches *= 2
    elif damage == "hash":
        source.batches[0]["event_count"] += 1
    elif damage == "excess":
        source.batches *= reader.MAX_BATCHES + 1
    else:
        rows = [stored(41), stored(42)]
        source.batches.append(manifest(rows))
    with pytest.raises(reader.HistoryError, match="history_(integrity_error|limit_exceeded)"):
        read(setup)
    assert len(source.calls) == 1


def test_stored_publication_predicate_is_not_ignored(setup):
    source, args = setup
    args["publication"]["definition_json"]["filters"] = [{"field": "event_id", "op": "eq", "value": 4740}]
    assert read(setup).items
    assert all("e.event_key IN (4740)" in sql for sql, _ in source.calls)
    args["publication"]["definition_json"]["filters"] = [{"field": "outcome", "op": "eq", "value": "failure"}]
    source.calls.clear()
    with pytest.raises(reader.HistoryError, match="history_predicate_unavailable"):
        read(setup)
    assert not source.calls


def test_published_predicate_field_requires_its_own_category_grant(setup):
    source, args = setup
    args["publication"]["definition_json"]["filters"] = [{"field": "channel", "op": "eq", "value": "Security"}]
    next(field for field in args["publication"]["fields_json"] if field["key"] == "channel")["category"] = "security"
    with pytest.raises(PermissionError, match="policy_denied"):
        read(setup, fields=("id",))
    assert not source.calls


def test_seed_filter_schema_is_not_misread_as_a_builder_predicate(setup):
    _, args = setup
    args["publication"]["definition_json"]["filters"] = [{"key": "channel", "ops": ["eq", "in"]}]
    assert read(setup).items


def test_indexed_server_and_event_filters_precede_json_parsing(setup):
    source, args = setup
    args["access"] = access({"kind": "server", "ids": [9]})
    read(setup, search(question_id="lockouts"))
    for sql, _ in source.calls:
        early = sql.split("PREWHERE ")[1].split(" WHERE ")[0]
        assert "e.server_id IN (9)" in early and "e.event_key IN (4740)" in early
        assert "JSONExtract" not in early


def test_post_body_literals_are_escaped_and_no_values_become_query_parameters(setup):
    source, _ = setup
    query = search(conditions=[condition("message_sample", "not_in", ["opaque'\\ OR 1=1"])])
    assert read(setup, query).items
    assert "'opaque\\'\\\\ OR 1=1'" in source.calls[1][0]


def test_one_deadline_covers_both_queries_and_decoding(setup):
    source, args = setup
    tick = [0.0]
    base = source.query

    def query(sql, timeout_ms):
        result = base(sql, timeout_ms)
        tick[0] += 3
        return result

    result = reader.ClickHouseHistoryReader(query_rows=query, clock=lambda: tick[0]).read(search(), **args)
    assert result.items
    assert [timeout for _, timeout in source.calls] == [8000, 5000]
    source.calls.clear()
    with pytest.raises(reader.HistoryError, match="history_timeout"):
        reader.ClickHouseHistoryReader(query_rows=query, clock=lambda: tick[0]).read(search(), **args, timeout_ms=2000)
    assert len(source.calls) == 1


def test_limit_rejects_partial_top_and_disabled_history_does_not_query(setup, monkeypatch):
    source, _ = setup
    source.rows = [stored(41), stored(42)]
    source.batches = [manifest(source.rows)]
    with pytest.raises(reader.HistoryError, match="history_limit_exceeded"):
        read(setup, limit=1)
    monkeypatch.setattr(reader.history, "primary_read_enabled", lambda: False)
    source.calls.clear()
    with pytest.raises(reader.HistoryError, match="history_unavailable"):
        read(setup)
    assert not source.calls


@pytest.mark.parametrize("changes", [{"limit": 0}, {"limit": reader.MAX_ROWS + 1}, {"limit": True},
                                    {"timeout_ms": "8000"}, {"timeout_ms": 0}, {"timeout_ms": 8001}])
def test_invalid_budgets_fail_before_io(setup, changes):
    source, _ = setup
    with pytest.raises(reader.ContractError, match="invalid_request"):
        read(setup, **changes)
    assert not source.calls


def test_existing_storage_route_admission_is_used(setup, monkeypatch):
    source, _ = setup
    seen = []

    def route(**kwargs):
        seen.append(kwargs)
        raise PermissionError("synthetic route denial")

    monkeypatch.setattr(reader, "resolve_storage_route", route)
    with pytest.raises(PermissionError, match="synthetic route denial"):
        read(setup, authorization="opaque")
    assert seen == [{"authorization": "opaque", "consumer": reader.StorageRouteConsumer.EVENT_SEARCH}]
    assert not source.calls


def test_transport_is_bounded_readonly_and_does_not_send_values_in_url(monkeypatch):
    seen = []
    closed = []
    monkeypatch.setattr(reader.history, "configured_read_port", lambda: 8123)
    monkeypatch.setattr(reader.history, "_history_auth", lambda: ("synthetic", "synthetic"))

    def stream(port, sql, **kwargs):
        seen.append((port, sql, kwargs))
        try:
            yield {"field": "value"}
        finally:
            closed.append(True)

    monkeypatch.setattr(reader, "_http_stream_json_rows", stream)
    assert reader._query_rows("SELECT 1", 1500) == [{"field": "value"}]
    _, sql, options = seen[0]
    assert sql == "SELECT 1 FORMAT JSONEachRow"
    assert options["timeout"] == 1.5
    assert options["params"]["max_execution_time"] == "1.5"
    for key, value in {"readonly": "1", "max_threads": "2", "max_memory_usage": "134217728",
                       "max_bytes_before_external_sort": "0", "max_bytes_before_external_group_by": "0",
                       "log_queries": "0", "log_query_threads": "0", "result_overflow_mode": "throw"}.items():
        assert options["params"][key] == value
    assert all(not key.startswith("param_") for key in options["params"])
    assert closed == [True]


@pytest.mark.parametrize("failure,code", [(RuntimeError("opaque"), "history_unavailable"),
                                         (TimeoutError("opaque"), "history_timeout"),
                                         (ValueError("opaque"), "history_integrity_error")])
def test_transport_errors_do_not_echo_source_data(monkeypatch, failure, code):
    monkeypatch.setattr(reader.history, "configured_read_port", lambda: 8123)
    monkeypatch.setattr(reader.history, "_history_auth", lambda: ("synthetic", "synthetic"))

    def stream(*args, **kwargs):
        raise failure
        yield

    monkeypatch.setattr(reader, "_http_stream_json_rows", stream)
    with pytest.raises(reader.HistoryError) as error:
        reader._query_rows("SELECT 1", 1000)
    assert str(error.value) == f"evsearch.{code}"


def test_history_error_codes_have_both_translations():
    root = Path(__file__).resolve().parents[2]
    dictionaries = [json.loads((root / f"config/i18n/server.{locale}.json").read_text(encoding="utf-8"))
                    for locale in ("ru", "en")]
    assert dictionaries[0].keys() == dictionaries[1].keys()
    for code in ("history_unavailable", "history_predicate_unavailable", "history_timeout",
                 "history_integrity_error", "history_limit_exceeded"):
        assert all(messages[f"evsearch.{code}"] for messages in dictionaries)
