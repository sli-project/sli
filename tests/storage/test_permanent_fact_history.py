import json
from datetime import datetime, timezone

import pytest

from server.sli.storage import permanent_fact_history as history


@pytest.fixture
def retained_link(monkeypatch):
    detail = {"event_id": 41, "entity_id": 3, "link_role": "subject", "role_id": 2}
    row = {
        "event_db_id": 41, "entity_id": 3, "link_role": "subject",
        "time_created_utc": "2026-09-10 00:00:00.000000",
        "details_json": json.dumps(detail), "row_sha256": history._payload_sha(detail),
        "batch_sha256": "a" * 64,
    }
    monkeypatch.setattr(history, "read_published_events_many", lambda *a: {41: {
        "time_created_utc": "2026-09-10T00:00:00+00:00", "_history_batch_sha256": "a" * 64,
    }})
    monkeypatch.setattr(history, "_rows", lambda *a: [row])
    return row, detail


def test_retained_link_details_are_available_without_files(retained_link):
    _row, detail = retained_link
    assert history.read_published_links_many(57847, [41]) == {41: [detail]}


@pytest.mark.parametrize("field,value", [
    ("row_sha256", "b" * 64), ("batch_sha256", "b" * 64),
    ("entity_id", 4), ("event_db_id", 42),
])
def test_retained_link_details_reject_corruption(retained_link, field, value):
    row, _ = retained_link
    row[field] = value
    with pytest.raises(RuntimeError, match="published_history_link"):
        history.read_published_links_many(57847, [41])


def test_retained_link_details_reject_duplicate(retained_link, monkeypatch):
    row, _ = retained_link
    monkeypatch.setattr(history, "_rows", lambda *a: [row, row])
    with pytest.raises(RuntimeError, match="published_history_link_duplicate"):
        history.read_published_links_many(57847, [41])


def test_retention_verification_uses_retained_details_after_archive_removal(monkeypatch):
    calls = []

    def source(*a, **kw):
        calls.append(kw)
        return [], []

    monkeypatch.setattr(history, "_source_batch", source)
    monkeypatch.setattr(history, "_readback", lambda *a, **kw: ({41}, set(), {41: "a" * 64}))
    with pytest.raises(RuntimeError, match="retention_candidate_source_count_mismatch"):
        history.verify_preserved_candidates(57847, [{"id": 41, "normalized_hash": b"a" * 32}])
    assert calls[0]["history_port"] == 57847


@pytest.mark.parametrize("stream", [False, True])
def test_http_failure_does_not_disclose_query_payload(monkeypatch, stream):
    from server.sli.storage import storage_lifecycle_io as transport

    class Response:
        status = 500

        def read(self, *a):
            return b"sensitive_event_payload"

    class Connection:
        def request(self, *a, **kw):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(transport.http.client, "HTTPConnection", lambda *a, **kw: Connection())
    with pytest.raises(RuntimeError) as error:
        if stream:
            list(transport._http_stream_json_rows(1234, "query"))
        else:
            transport._http_query(1234, "query")
    assert "sensitive_event_payload" not in str(error.value)
    assert "ClickHouse HTTP 500" in str(error.value)


def test_source_batch_uses_bigint_for_exact_core_facts_and_links(monkeypatch):
    event_id = 2_147_483_648

    class Connection:
        def __init__(self):
            self.calls = []
            self.sql = ""

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def cursor(self):
            return self

        def execute(self, sql, params=()):
            self.sql = sql
            self.calls.append((sql, params))

        def fetchall(self):
            if "from events_v2_core e" in self.sql:
                return [{
                    "id": event_id, "event_id": 4740, "server_id": 1,
                    "time_created_utc": datetime(2026, 10, 1, tzinfo=timezone.utc),
                }]
            return []

    connection = Connection()
    monkeypatch.setattr(history, "_connect", lambda: connection)
    monkeypatch.setattr(history, "read_published_links_many", lambda *args: {})
    events, links = history._source_batch(0, 1, exact_ids=[event_id], history_port=1234)
    assert [row["event_db_id"] for row in events] == [event_id]
    assert events[0]["event_key"] == 4740
    assert links == []
    exact_queries = [(sql, params) for sql, params in connection.calls if "any(" in sql]
    assert len(exact_queries) == 3
    for sql, params in exact_queries:
        assert "::bigint[]" in sql
        assert [event_id] in params


@pytest.mark.parametrize("details,reason", [
    ({}, "history_source_link_details_missing"),
    ({41: [{"event_id": 41, "entity_id": 3, "link_role": "subject", "role_id": 9}]},
     "history_source_link_role_mismatch"),
    (FileNotFoundError("private archive path"), "history_source_archive_unavailable"),
    (PermissionError("private archive path"), "history_source_archive_permission_denied"),
])
def test_source_copy_distinguishes_unavailable_details_from_corruption(monkeypatch, details, reason):
    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def cursor(self):
            return self

        def execute(self, sql, params=()):
            self.sql = sql

        def fetchall(self):
            if "from events_v2_core e" in self.sql:
                return [{"id": 41, "event_id": 4740, "server_id": 1,
                         "time_created_utc": datetime(2026, 10, 1, tzinfo=timezone.utc)}]
            if "from event_entity_link_blocks_v2" in self.sql:
                return [{"event_id": 41, "entity_id": 3, "role_id": 2, "link_role": "subject"}]
            return []

    monkeypatch.setattr(history, "_connect", Connection)
    def archive(*args, **kwargs):
        if isinstance(details, Exception):
            raise details
        return details

    monkeypatch.setattr(history.ArchiveReader, "read_link_details_many", archive)
    with pytest.raises(RuntimeError) as error:
        history._source_batch(0, 1)
    assert str(error.value) == reason


@pytest.mark.parametrize("operation", ["query", "insert", "stream"])
def test_history_transport_outage_has_safe_retryable_reason(monkeypatch, operation):
    monkeypatch.setattr(history, "_history_auth", lambda: ("synthetic", "synthetic"))

    def unavailable(*args, **kwargs):
        raise ConnectionRefusedError("private endpoint")

    monkeypatch.setattr(history, "_transport_query", unavailable)
    monkeypatch.setattr(history, "_transport_insert_json_rows", unavailable)

    def stream(*args, **kwargs):
        yield from unavailable()

    monkeypatch.setattr(history, "_transport_stream_json_rows", stream)
    with pytest.raises(RuntimeError, match="^history_clickhouse_unavailable$"):
        if operation == "query":
            history.next_after_id(1234)
        elif operation == "insert":
            history._http_insert_json_rows(1234, "synthetic", [{}])
        else:
            list(history._stream_rows(1234, "SELECT 1"))


@pytest.mark.parametrize("status,retryable", [(503, True), (401, False), (403, False), (500, False)])
def test_history_transport_keeps_authentication_and_sql_failures_unhealthy(monkeypatch, status, retryable):
    from server.sli.storage.lifecycle_health import EXPECTED_BLOCK_REASONS
    from server.sli.storage.purge_audit import failure_reason

    monkeypatch.setattr(history, "_history_auth", lambda: ("synthetic", "synthetic"))

    def fail(*args, **kwargs):
        raise RuntimeError(f"ClickHouse HTTP {status}:request_failed")

    monkeypatch.setattr(history, "_transport_query", fail)
    with pytest.raises(RuntimeError) as error:
        history.next_after_id(1234)
    assert (failure_reason(error.value) in EXPECTED_BLOCK_REASONS) is retryable
