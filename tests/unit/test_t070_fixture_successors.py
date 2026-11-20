"""The producer test fixture must recognize the exact T070 successor."""
import json

import pytest

from tests.migrations import test_report_producer_migration285 as producer
from tests.migrations.migration_inventory import migration_inventory

CANONICAL_SUCCESSORS = migration_inventory(starting_at=300)


class ReachedRollback(Exception):
    pass


class Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0]

    def fetchall(self):
        return self.rows


@pytest.mark.parametrize("successors", [
    list(reversed(CANONICAL_SUCCESSORS[:2])),
    CANONICAL_SUCCESSORS[:1] * 2,
    CANONICAL_SUCCESSORS[1:2],  # Missing the canonical predecessor.
    CANONICAL_SUCCESSORS[:1] + CANONICAL_SUCCESSORS[2:3],  # Gap inside the chain.
    [(CANONICAL_SUCCESSORS[-1][0] + 1, "synthetic_foreign")],
])
def test_unattested_successor_chain_is_rejected_before_mutation(monkeypatch, successors):
    fixture = producer.t070_fixture
    monkeypatch.setattr(fixture, "assert_disposable_database", lambda _: None)

    class Connection:
        def execute(self, statement):
            assert statement.startswith("select version,name,sha256"), "must reject before mutation"
            return Result([(version, name, None) for version, name in successors])

    with pytest.raises(ValueError, match="t070_fixture_successor_invalid"):
        with fixture.without_successors(Connection()):
            pytest.fail("unattested chain was admitted")


def test_successor_hash_mismatch_is_rejected_before_mutation(monkeypatch):
    fixture = producer.t070_fixture
    monkeypatch.setattr(fixture, "assert_disposable_database", lambda _: None)

    class Connection:
        def execute(self, statement):
            assert statement.startswith("select version,name,sha256"), "must reject before mutation"
            return Result([(*CANONICAL_SUCCESSORS[0], "0" * 64)])

    with pytest.raises(ValueError, match="t070_fixture_successor_invalid"):
        with fixture.without_successors(Connection()):
            pytest.fail("incorrect hash was admitted")


@pytest.mark.parametrize("version,name", migration_inventory(starting_at=300))
def test_producer_fixture_rolls_back_and_restores_successor(monkeypatch, version, name):
    monkeypatch.setattr(producer, "assert_disposable_database", lambda _: None)
    executed = []
    monkeypatch.setattr(producer.t070_fixture, "execute_script", lambda conn, script: executed.append(script))

    class Connection:
        def execute(self, statement):
            assert statement == f'select version,name from public.schema_migrations where version>{version - 1} order by version'
            return Result([(version, name)])

    conn = Connection()
    successors = producer.rollback_successors(conn, after=version - 1)
    assert successors == [(version, name)]
    producer.restore_successors(conn, successors)
    assert executed == [(producer.ROOT / f"config/postgres_migrations/{version}_{name}{suffix}").read_text("utf-8")
                        for suffix in (".rollback.sql", ".sql")]


def test_exact_288_chain_is_admitted_before_rollback(monkeypatch):
    monkeypatch.setattr(producer, "assert_disposable_database", lambda _: None)
    monkeypatch.setattr(producer.t070_fixture, "preflight", lambda _: (_ for _ in ()).throw(ReachedRollback()))

    class Connection:
        def execute(self, statement, *args):
            if "version=284" in statement:
                return Result([{"version": 284, "name": "event_source_identity"}])
            if "version>285" in statement:
                return Result([{"version": 286, "name": "sigma_rule_labels"},
                    {"version": 287, "name": "workstation_inventory_job"},
                    {"version": 288, "name": "file_audit_service_filter"}])
            raise ReachedRollback

    with pytest.raises(ReachedRollback):
        producer.predecessor(Connection())


@pytest.mark.parametrize("successor", [
    {"version": 288, "name": "synthetic_foreign"},
    {"version": 289, "name": "synthetic_future"},
])
def test_foreign_or_future_successor_is_rejected_before_mutation(monkeypatch, successor):
    monkeypatch.setattr(producer, "assert_disposable_database", lambda _: None)

    class Connection:
        def execute(self, statement, *args):
            if "version=284" in statement:
                return Result([{"version": 284, "name": "event_source_identity"}])
            if "version>285" in statement:
                return Result([{"version": 286, "name": "sigma_rule_labels"},
                    {"version": 287, "name": "workstation_inventory_job"}, successor])
            raise AssertionError("unexpected mutation or preflight")

    with pytest.raises(ValueError, match="producer_fixture_successor_invalid"):
        producer.predecessor(Connection())


def test_288_preflight_rejects_foreign_function_before_mutation(monkeypatch):
    fixture = producer.t070_fixture
    monkeypatch.setattr(fixture, "assert_disposable_database", lambda _: None)

    class Connection:
        def execute(self, statement, *args):
            assert statement.lstrip().startswith("select")
            return Result([{"valid": False}])

    with pytest.raises(ValueError, match="t070_fixture_successor_invalid"):
        fixture.preflight(Connection())


def test_exact_catalog_rejects_foreign_search_path():
    fixture = producer.t070_fixture
    check = getattr(fixture, "_matches_catalog", None)
    assert callable(check)
    catalog = {"version": True, "future": False, "owner": "adlog_file_audit_owner",
        "language": "plpgsql", "kind": "f", "security_definer": True, "strict": False,
        "leakproof": False, "volatility": "s", "parallel": "u", "returns_set": False,
        "returns_jsonb": True, "default_args": 0, "config": ["search_path=pg_catalog, pg_temp"],
        "public_execute": False, "body": "synthetic-exact"}
    assert check(catalog, "synthetic-exact")
    for config in (["search_path=public, pg_temp"], None, ["search_path=pg_catalog, pg_temp", "row_security=off"]):
        assert not check({**catalog, "config": config}, "synthetic-exact")
    for key, value in [("security_definer", False), ("public_execute", True), ("owner", "other"),
                       ("language", "sql"), ("volatility", "v"), ("strict", True), ("leakproof", True),
                       ("parallel", "s"), ("returns_set", True), ("returns_jsonb", False),
                       ("default_args", 1), ("body", "foreign"), ("future", True), ("version", False)]:
        assert not check({**catalog, key: value}, "synthetic-exact")


@pytest.mark.parametrize("successors", [
    # Historical pre-300 installations may contain a subset. The canonical
    # chain from 300 must be a prefix, for every current and future successor.
    *[[item for item in migration_inventory(starting_at=296) if item[0] < 300 and item[0] in versions]
      for versions in ((), (296,), (297,), (299,), (296, 297), (296, 297, 299))],
    *[CANONICAL_SUCCESSORS[:length] for length in range(1, len(CANONICAL_SUCCESSORS) + 1)],
])
@pytest.mark.parametrize("dict_rows", [False, True])
def test_attested_successors_unwind_in_reverse_and_restore_in_order(monkeypatch, successors, dict_rows):
    fixture = producer.t070_fixture
    monkeypatch.setattr(fixture, "execute_script", lambda conn, script: conn.execute(script))
    monkeypatch.setattr(fixture, "assert_disposable_database", lambda _: None)
    executed = []
    manifest = json.loads((fixture.ROOT.parents[1] / "deploy/linux/native_pg_ledger.json").read_text("utf-8"))

    def pinned(version, name):
        return manifest["files"][f"config/postgres_migrations/{version}_{name}.sql"]

    hashes = {version: pinned(version, name) if version % 2 else None for version, name in successors}
    predecessor_hash = pinned(288, "file_audit_service_filter")
    catalog = {"version": True, "future": False, "owner": "adlog_file_audit_owner",
        "language": "plpgsql", "kind": "f", "security_definer": True, "strict": False,
        "leakproof": False, "volatility": "s", "parallel": "u", "returns_set": False,
        "returns_jsonb": True, "default_args": 0, "config": ["search_path=pg_catalog, pg_temp"],
        "public_execute": False, "body": fixture._body(fixture._function(fixture.ROOT / "288_file_audit_service_filter.sql"))}

    class Connection:
        predecessor = predecessor_hash

        def execute(self, statement, params=None):
            if statement.startswith("select version,name"):
                return Result([{"version": version, "name": name, "sha256": hashes[version]}
                    if dict_rows else (version, name, hashes[version])
                    for version, name in successors])
            if statement.startswith("select sha256"):
                return Result([{"sha256": self.predecessor} if dict_rows else (self.predecessor,)])
            if statement.startswith("select jsonb_build_object"):
                return Result([{"catalog": catalog} if dict_rows else (catalog,)])
            if statement.startswith("update public.schema_migrations"):
                executed.append((statement, params))
                if "version=288" in statement:
                    assert self.predecessor is None
                    self.predecessor = params[0]
                return Result([])
            executed.append(statement)
            return Result([])

        def rollback(self):
            raise AssertionError("unexpected rollback")

    def script(version, name, suffix):
        return (fixture.ROOT / f"{version}_{name}{suffix}").read_text("utf-8")

    conn = Connection()
    with fixture.without_successors(conn):
        assert executed == [script(version, name, ".rollback.sql") for version, name in reversed(successors)]
        conn.predecessor = None
    assert executed == ([script(version, name, ".rollback.sql") for version, name in reversed(successors)]
        + [("update public.schema_migrations set sha256=%s where version=288 and name='file_audit_service_filter' and sha256 is null", (predecessor_hash,))]
        + [operation for version, name in successors for operation in (
            script(version, name, ".sql"),
            ("update public.schema_migrations set sha256=%s where version=%s", (hashes[version], version)))])
    assert conn.predecessor == predecessor_hash


def test_online_indexes_execute_outside_multi_statement_query():
    executed = []

    class Connection:
        autocommit = True

        def execute(self, statement):
            executed.append(statement)

    producer.t070_fixture.execute_script(Connection(),
        "begin;select 1;commit;\ncreate index concurrently x on t(a)\n where a>0;\nbegin;select 2;commit;")
    assert executed == ["begin;select 1;commit;\n", "create index concurrently x on t(a)\n where a>0;",
                        "\nbegin;select 2;commit;"]
    Connection.autocommit = False
    with pytest.raises(ValueError, match="online_requires_autocommit"):
        producer.t070_fixture.execute_script(Connection(), "drop index concurrently x;")
