"""Import hot paths with transactional fakes; no runtime database."""
from contextlib import contextmanager

import pytest

from server.sli.storage.storage_v2_backfill import SourceBatch, _dictionary_maps
from server.sli.storage.storage_v2_repository import (
    PostgresStorageV2Repository,
    _read_link_block_tails,
)


class Dictionaries:
    def __init__(self):
        self.values = {"storage_v2_channel": {"Security": 1}, "storage_v2_role": {"subject": 2}}
        self.connections = 0
        self.inserts = []
        self.fail_commit = False
        self.omit_readback = False
        self.rows = []

    @contextmanager
    def connect(self):
        self.connections += 1
        yield self
        if self.fail_commit:
            raise RuntimeError("fixture-commit-failed")

    @contextmanager
    def cursor(self):
        yield self

    def execute(self, sql, params):
        table = sql.split("from ")[1].split()[0] if sql.startswith("select") else sql.split("into ")[1].split("(")[0]
        values = self.values.setdefault(table, {})
        if sql.startswith("select"):
            self.rows = [{"value": value, "id": values[value]} for value in params[0]
                         if value in values and not self.omit_readback]
        else:
            self.inserts.append((table, params[0]))
            for value in params[0]:
                # Simulate a concurrent insert winning ON CONFLICT, which has
                # no RETURNING row; the following SELECT must resolve its ID.
                values.setdefault(value, len(values) + 10)

    def fetchall(self):
        return self.rows


def test_bulk_dictionaries_use_one_connection_and_do_not_write_existing_values():
    db = Dictionaries()
    repository = PostgresStorageV2Repository(db.connect)
    expected = {"channel": {"Security": 1}, "role": {"subject": 2}, "domain": {}}
    values = {kind: set(items) for kind, items in expected.items()}
    assert repository.dictionary_maps(values) == expected
    assert db.connections == 1 and db.inserts == []
    assert repository.dictionary_maps(values) == expected
    assert repository.dictionary_id("channel", "Security") == 1
    assert db.connections == 1


def test_bulk_dictionaries_resolve_racing_inserts_in_one_committed_transaction():
    db = Dictionaries()
    repository = PostgresStorageV2Repository(db.connect)
    result = repository.dictionary_maps({"channel": {"Security", "System"}, "role": {"target"}})
    assert result == {"channel": {"Security": 1, "System": 11}, "role": {"target": 11}}
    assert db.connections == 1
    assert db.inserts == [("storage_v2_channel", ["System"]), ("storage_v2_role", ["target"])]


@pytest.mark.parametrize("failure", ["commit", "readback"])
def test_failed_dictionary_transaction_never_populates_identity_cache(failure):
    db = Dictionaries()
    db.fail_commit = failure == "commit"
    db.omit_readback = failure == "readback"
    repository = PostgresStorageV2Repository(db.connect)
    with pytest.raises(RuntimeError):
        repository.dictionary_maps({"channel": {"Security", "System"}})
    assert repository._dictionary_ids == {}
    db.fail_commit = db.omit_readback = False
    assert repository.dictionary_maps({"channel": {"System"}})["channel"]["System"] == 11
    assert db.connections == 2


def test_bulk_dictionaries_validate_table_names_before_connecting():
    db = Dictionaries()
    with pytest.raises(KeyError, match="unsupported dictionary kind"):
        PostgresStorageV2Repository(db.connect).dictionary_maps({"fixture-invalid": {"value"}})
    assert db.connections == 0


def test_publication_uses_bulk_dictionary_resolution_and_preserves_empty_kinds():
    db = Dictionaries()
    result = _dictionary_maps(PostgresStorageV2Repository(db.connect), SourceBatch(
        events=({"channel": "Security"},), entities=(), links=({"link_role": "subject"},),
    ))
    assert result["channel"] == {"Security": 1}
    assert result["role"] == {"subject": 2}
    assert result["provider"] == {}
    assert db.connections == 1


@pytest.mark.parametrize("invalid", [None, "empty", "first", "last"])
def test_tail_read_keeps_identity_arrays_and_rejects_invalid_bounds(invalid):
    row = {"entity_id": 7, "block_no": 12000, "event_ids": [90000, 90001],
           "role_ids": [2, 3], "first_event_id": 90000, "last_event_id": 90001,
           "identity_sha256": b"x" * 32}
    if invalid == "empty":
        row["event_ids"] = []
    elif invalid == "first":
        row["first_event_id"] = 1
    elif invalid == "last":
        row["last_event_id"] = 1

    class Cursor:
        def execute(self, sql, params):
            assert params == ([7, 8],)
            # Bound the database work to one backward lookup per entity.
            assert "where entity_id=wanted.entity_id order by block_no desc limit 1" in sql

        def fetchall(self):
            return [row]  # Entity 8 has no historical blocks.

    if invalid:
        with pytest.raises(RuntimeError, match="first/last range mismatch"):
            _read_link_block_tails(Cursor(), [7, 8])
    else:
        tails = _read_link_block_tails(Cursor(), [7, 8])
        assert set(tails) == {7}
        assert tails[7].block_no == 12000
        assert tails[7].event_ids == (90000, 90001)
        assert tails[7].role_ids == (2, 3)
        assert tails[7].identity_sha256 == b"x" * 32
