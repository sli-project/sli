"""Canonical password state/health boundary on guarded synthetic PostgreSQL."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import uuid4

import pytest

from server.sli.semantic import password_attack_v2 as detector
from tests.migrations.test_password_attacks_v2_migration import (
    AGENT, SCOPE, _connection, acl_pg as acl_pg, native_pg as native_pg,
    password_base_pg as password_base_pg, password_pg as password_pg,
)

from tests.migrations.test_password_attacks_v2_reservation_migration import (
    reservation_pg as reservation_pg,  # noqa: PLC0414 -- pytest fixture export
)

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/273_password_attacks_v2.sql"
EXECUTION = detector.Rule(SCOPE, "brute").execution
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def _call(conn, name, *args):
    placeholders = ",".join(["%s::jsonb"] * len(args))
    return conn.execute(f"select public.{name}({placeholders}) as result",
                        tuple(json.dumps(item) for item in args)).fetchone()["result"]


def _begin(conn, scope=SCOPE, execution=EXECUTION):
    return _call(conn, "begin_password_attempt", asdict(scope), execution)


def _read(conn, scope=SCOPE, execution=EXECUTION):
    return _call(conn, "read_password_checkpoint_v2", asdict(scope), execution)


def test_begin_attempt_persists_health_only(password_pg):
    with _connection(password_pg, worker=True) as worker:
        started = _begin(worker)  #Autocommit is the separate issuance transaction.
        assert started["token"] > 0 and started["state_revision"] == 0
        saved = _read(worker)
        assert saved["state_document"] is None and saved["watermark"] is None
        assert saved["active_token"] == started["token"]
        assert saved["health"]["last_completed_at"] is None
        assert saved["health"]["status"] == "unknown"


def _observe(conn, token, diagnostics=None):
    diagnostics = diagnostics if diagnostics is not None else {"source_error": {"count": 1, "from": None, "to": None}}
    return conn.execute("select public.observe_password_failure_v2(%s::jsonb,%s::jsonb,%s,%s::jsonb) as result",
                        (json.dumps(asdict(SCOPE)), json.dumps(EXECUTION), token, json.dumps(diagnostics))).fetchone()["result"]


def _commit(conn, token, revision, state):
    return conn.execute("select public.commit_password_state_v2(%s::jsonb,%s::jsonb,%s,%s,%s::jsonb) as result",
                        (json.dumps(asdict(SCOPE)), json.dumps(EXECUTION), token, revision, json.dumps(state))).fetchone()["result"]


def _state():
    from tests.unit.test_password_attack_v2 import event
    native = event(1, 0, scope=SCOPE)
    return detector.State(detector.Rule(SCOPE, "brute").pin, native.at, 0, (native.member,), ()).document


def _seed_state(admin, state, revision=7):
    #Owner-only synthetic stored history: never a claimed public admission.
    # Deferred guards must see the checkpoint and its complete projection together.
    with admin.transaction():
        admin.execute("""update semantic_password_checkpoints set state_document=%s::jsonb,state_revision=%s,
            watermark=%s,coverage_epoch=%s,history_started=true where pin=%s""",
            (json.dumps(state), revision, state["watermark"], state["epoch"], detector.Rule(SCOPE, "brute").pin))
        admin.execute("delete from semantic_password_window_members")
        for member in state["window"]:
            admin.execute("""insert into semantic_password_window_members(scope_digest,pin,member_document)
                select scope_digest,pin,%s::jsonb from semantic_password_checkpoints where pin=%s""",
                (json.dumps(member), detector.Rule(SCOPE, "brute").pin))


@contextmanager
def _second_principal(source):
    from psycopg import sql
    login = "sli_test_password_state_" + uuid4().hex
    with _connection(source) as admin:
        admin.execute(sql.SQL("create role {} login").format(sql.Identifier(login)))
        admin.execute(sql.SQL("grant adlog_semantic_worker to {}").format(sql.Identifier(login)))
        admin.execute("""insert into finding_evidence_source_bindings select oid,rolname,%s,%s,%s,%s,
            '','core_event',7,null,%s from pg_roles where rolname=%s""",
            (SCOPE.installation_id, SCOPE.plugin_id, SCOPE.source_instance_id, SCOPE.source_generation, AGENT, login))
    try:
        with _connection((source[0], login), worker=True) as other:
            yield other
    finally:
        with _connection(source) as admin:
            admin.execute(sql.SQL("drop role {}").format(sql.Identifier(login)))


def test_canonical_handover_preserves_nonempty_frozen_history(reservation_pg):
    from tests.migrations.test_password_attacks_v2_reservation_migration import (
        _admit,
        _native,
        _new_root,
        _root,
    )
    password_pg = reservation_pg
    rule = detector.Rule(SCOPE, "brute")
    emission = _new_root(_root().occurrences, epoch=3)
    with _connection(password_pg) as admin:
        # Complete synthetic admitted history, including native costs, QW and jobs.
        # The owner fixture only supplies the later frozen checkpoint transition.
        _native(admin, emission.occurrences)
        admitted = _admit(admin, emission)
        episode = detector.Episode(emission.episode_key, emission.entity, emission.seed, emission.endpoint,
            root_id=emission.emission_id, last_emission=emission.emission_id, sequence=1,
            budget=detector.Budget(**admitted["totals"]), frozen=True)
        state = _state()
        state["epoch"] = 3
        state["window"][0]["witness"] = detector._pack(emission.seed)
        state["watermark"] = emission.endpoint.at.isoformat()
        state["episodes"] = detector.State(rule.pin, emission.endpoint.at, 3, (), (episode,)).document["episodes"]
        with admin.transaction():
            admin.execute("""update semantic_password_episode_budgets set frozen=true,
                frozen_at=clock_timestamp(),frozen_reason='episode_evidence_budget_exhausted',
                barrier_unresolved=true,tracking_endpoint=last_admitted_endpoint,
                tracking_epoch=coverage_epoch,tracking_through=last_admitted_as_of where pin=%s""", (rule.pin,))
            _seed_state(admin, state)
    assert state["window"]
    with _connection(password_pg, worker=True) as first:
        _begin(first)
        assert _read(first)["state_document"] == state
    with _second_principal(password_pg) as second:
        _begin(second)
        saved = _read(second)
        assert saved["state_document"] == state and saved["state_revision"] == 7
        assert saved["epoch"] == 3 and saved["state_document"]["episodes"][0]["frozen"]
    with _connection(password_pg, worker=True) as first:
        assert _read(first)["state_document"] == state
    with _connection(password_pg) as admin:
        assert admin.execute("select count(*) as n from semantic_password_checkpoints").fetchone()["n"] == 1


def test_valid_state_commit_is_blocked_without_reservation_authority(password_pg):
    import psycopg
    with _connection(password_pg, worker=True) as worker:
        token = _begin(worker)["token"]
        before = _read(worker)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="password_v2_state_authority_unavailable"):
            _commit(worker, token, 0, _state())
        after = _read(worker)
        assert {key: after[key] for key in ("state_revision", "state_document", "watermark", "epoch")} == {
            key: before[key] for key in ("state_revision", "state_document", "watermark", "epoch")}
        assert after["state_document"] is None and after["watermark"] is None and after["state_revision"] == 0
        assert after["health"]["last_completed_at"] is None


@pytest.mark.parametrize("case", ["revision", "token"])
def test_state_cas_checks_precede_authority_gate(password_pg, case):
    import psycopg
    with _connection(password_pg, worker=True) as worker:
        token = _begin(worker)["token"]
        if case == "token":
            _begin(worker)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="password_v2_(attempt|state)_conflict"):
            _commit(worker, token, 1 if case == "revision" else 0, _state())


@pytest.mark.parametrize("mutation", ["extra", "version_null", "storage_null", "epoch_bool", "pin", "member_extra", "duplicate", "ref_scope",
    "hash", "time", "budget_bool", "reason", "window_type", "episode_type"])
def test_state_strict_shape_rejects_before_authority_gate(password_pg, mutation):
    import psycopg
    state = _state()
    if mutation == "extra": state["verified"] = True
    elif mutation == "version_null": state["version"] = None
    elif mutation == "storage_null": state["window"][0]["witness"]["ref"]["storage_kind"] = None
    elif mutation == "epoch_bool": state["epoch"] = True
    elif mutation == "pin": state["pin"] = "0" * 64
    elif mutation == "member_extra": state["window"][0]["verified"] = True
    elif mutation == "duplicate": state["window"] *= 2
    elif mutation == "ref_scope": state["window"][0]["witness"]["ref"]["scope"]["source_generation"] = "old"
    elif mutation == "hash": state["window"][0]["witness"]["ref"]["sha256"] = "wrong"
    elif mutation == "time": state["window"][0]["witness"]["at"] = "2026-01-01T00:00:00Z"
    elif mutation == "budget_bool":
        witness = state["window"][0]["witness"]
        state["episodes"] = [{"key": "a" * 64, "entity": "b" * 64, "seed": witness, "last": witness,
            "root_id": None, "last_emission": None, "sequence": 0, "budget": {"ref_occurrences": True,
            "portions": 0, "xml_bytes": 0}, "frozen": False, "prequalification": []}]
    elif mutation == "reason": state["window"][0]["reason"] = "healthy"
    elif mutation == "window_type": state["window"] = {}
    else: state["episodes"] = [None]
    with _connection(password_pg, worker=True) as worker:
        token = _begin(worker)["token"]
        with pytest.raises(psycopg.errors.InvalidParameterValue, match="password_v2_state_invalid"):
            _commit(worker, token, 0, state)


@pytest.mark.parametrize("field", ["window", "episodes"])
def test_state_count_limit_is_explicit(password_pg, field):
    import psycopg
    state = _state()
    state[field] = [None] * 10001
    with _connection(password_pg, worker=True) as worker:
        token = _begin(worker)["token"]
        with pytest.raises(psycopg.errors.ProgramLimitExceeded, match="password_v2_state_bound"):
            _commit(worker, token, 0, state)


@pytest.mark.parametrize("value", [None, True, False, 0, 123456789, "ASCII\x7f\b\t\n", "кириллица😀尾", {"z": [1, "😀"], "a": "\x7f"}])
def test_exact_python_default_json_byte_count(password_pg, value):
    with _connection(password_pg) as admin:
        actual = admin.execute("select public.password_v2_json_bytes(%s::jsonb) as n", (json.dumps(value),)).fetchone()["n"]
        assert actual == len(json.dumps(value).encode("utf-8"))


def _sized_state(target):
    state = _state()
    template = state["window"][0]
    state["window"] = []
    base = len(json.dumps(state).encode())
    approx = len(json.dumps(template).encode()) + 2
    n = (target - base) // (approx + 4) - 50
    for index in range(n):
        member = deepcopy(template)
        member["witness"]["ref"]["native_id"] = str(index + 1)
        state["window"].append(member)
    gap = target - len(json.dumps(state).encode())
    #Each valid bigint identity supplies up to18 variable decimal digits;
    #no arbitrary padding/unknown schema field creates the exact boundary.
    for index, member in enumerate(reversed(state["window"])):
        old = member["witness"]["ref"]["native_id"]
        increase = min(gap, 18 - len(old))
        if increase:
            member["witness"]["ref"]["native_id"] = str(10 ** (len(old) + increase - 1) + index)
            gap -= increase
        if gap == 0: break
    assert gap == 0
    state["window"].sort(key=lambda member: int(member["witness"]["ref"]["native_id"]))
    assert len(json.dumps(state).encode()) == target
    return state


@pytest.mark.parametrize("extra", [0, 1])
def test_exact_state_4mib_python_spaced_boundary(password_pg, extra):
    import psycopg
    state = _sized_state(4194304 + extra)
    with _connection(password_pg) as admin:
        if extra:
            with pytest.raises(psycopg.errors.ProgramLimitExceeded, match="password_v2_state_bound"):
                admin.execute("select public.password_v2_check_state(%s::jsonb,%s::jsonb,%s)",
                              (json.dumps(state), json.dumps(asdict(SCOPE)), detector.Rule(SCOPE, "brute").pin))
        else:
            assert admin.execute("select public.password_v2_check_state(%s::jsonb,%s::jsonb,%s) as n",
                (json.dumps(state), json.dumps(asdict(SCOPE)), detector.Rule(SCOPE, "brute").pin)).fetchone()["n"] == 4194304


def test_stored_projection_corruption_does_not_reset_history(password_pg):
    import psycopg
    from psycopg import sql

    def snapshot(worker):
        saved = _read(worker)
        # Read time changes; every persisted history and health field must match.
        saved["health"].pop("as_of")
        return saved

    with _connection(password_pg, worker=True) as worker:
        _begin(worker)
    with _connection(password_pg) as admin:
        _seed_state(admin, _state())
    with _connection(password_pg, worker=True) as worker:
        before = snapshot(worker)
    # The deferred storage guard must reject a committed projection mismatch.
    with (
        _connection(password_pg) as admin,
        pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="password_v2_checkpoint_corrupt"),
        admin.transaction(),
    ):
        admin.execute("delete from semantic_password_window_members")
    with _connection(password_pg, worker=True) as worker:
        assert snapshot(worker) == before
    # Deliberate uncommitted damage is visible in this transaction only.
    # Exercise real worker authorization on the same connection, then roll back.
    with _connection(password_pg) as admin, admin.transaction(force_rollback=True):
        admin.execute("delete from semantic_password_window_members")
        admin.execute(sql.SQL("set session authorization {}").format(sql.Identifier(password_pg[1])))
        admin.execute("set role adlog_semantic_worker")
        try:
            for operation in (lambda: _read(admin), lambda: _begin(admin)):
                with (
                    pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="password_v2_checkpoint_corrupt"),
                    admin.transaction(),
                ):
                    operation()
        finally:
            admin.execute("reset role")
            admin.execute("reset session authorization")
    with _connection(password_pg, worker=True) as worker:
        assert snapshot(worker) == before


def test_separate_begin_survives_source_rollback_then_health_only_failure(password_pg):
    import psycopg
    with _connection(password_pg, worker=True) as worker:
        token = _begin(worker)["token"]
        with pytest.raises(psycopg.errors.DivisionByZero), worker.transaction():
            worker.execute("select 1/0")
        assert _observe(worker, token)
        saved = _read(worker)
        assert saved["active_token"] == token and saved["last_observed_token"] == token
        assert saved["state_document"] is None and saved["watermark"] is None and saved["state_revision"] == 0
        assert saved["health"]["status"] == "error"
        assert saved["health"]["loss"]["source_error"]["count_lower_bound"] == 1
        assert saved["health"]["loss"]["source_error"]["count_exact"] is True


def test_rolled_back_issuance_has_no_observable_authorization(password_pg):
    import psycopg
    with _connection(password_pg, worker=True) as worker:
        with worker.transaction(force_rollback=True):
            token = _begin(worker)["token"]
        assert not _observe(worker, token)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="password_v2_checkpoint_absent"):
            _read(worker)


def test_old_or_equal_health_observation_never_overwrites_newer_attempt(password_pg):
    with _connection(password_pg, worker=True) as worker:
        first = _begin(worker)["token"]
        second = _begin(worker)["token"]
        assert second > first and not _observe(worker, first)
        assert _observe(worker, second) and not _observe(worker, second)
        assert _read(worker)["last_observed_token"] == second


@pytest.mark.parametrize("seconds,status", [(290, "healthy"), (301, "stale")])
def test_db_read_ttl_and_issuance_never_refresh_healthy(password_pg, seconds, status):
    with _connection(password_pg, worker=True) as worker:
        _begin(worker)
    with _connection(password_pg) as admin:
        #Owner fixture only: no public successful-health shortcut exists.
        admin.execute("""update semantic_password_checkpoints set health_status='healthy',
            last_completed_at=clock_timestamp()-(%s * interval '1 second')""", (seconds,))
    with _connection(password_pg, worker=True) as worker:
        before = _read(worker)["health"]["last_completed_at"]
        _begin(worker)
        after = _read(worker)["health"]
        assert after["last_completed_at"] == before and after["status"] == status


def _bucket(hour, count, minimum, maximum):
    return {"hour": hour, "count": count, "observed_min": minimum.isoformat(), "observed_max": maximum.isoformat(),
            "from": "2026-01-01T00:00:00+00:00", "to": "2026-01-01T00:10:00+00:00"}


def test_mixed_24h_boundary_is_lower_bound_and_empty_read_preserves_loss(password_pg):
    with _connection(password_pg, worker=True) as worker:
        _begin(worker)
    with _connection(password_pg) as admin:
        now = admin.execute("select clock_timestamp() as at").fetchone()["at"]
        cutoff = now - timedelta(hours=24)
        boundary = cutoff.replace(minute=0, second=0, microsecond=0)
        whole = now - timedelta(hours=1)
        slots = [None] * 25
        mixed_hour = int(boundary.timestamp()) // 3600
        slots[mixed_hour % 25] = _bucket(mixed_hour, 100, boundary, boundary + timedelta(hours=1, microseconds=-1))
        whole_hour = int(whole.timestamp()) // 3600
        slots[whole_hour % 25] = _bucket(whole_hour, 3, whole, whole)
        admin.execute("update semantic_password_checkpoints set loss_buckets=%s::jsonb", (json.dumps({"too_late": slots}),))
    with _connection(password_pg, worker=True) as worker:
        for _ in range(2):
            loss = _read(worker)["health"]["loss"]["too_late"]
            assert loss["count_lower_bound"] == 4 and loss["count_exact"] is False
            assert "observation_window_from" in loss and "as_of" in loss


def test_expired_final_loss_disappears_and_ring_is_fixed_25_slots(password_pg):
    with _connection(password_pg, worker=True) as worker:
        token = _begin(worker)["token"]
        assert _observe(worker, token)
    with _connection(password_pg) as admin:
        stored = admin.execute("select loss_buckets from semantic_password_checkpoints").fetchone()["loss_buckets"]
        assert len(stored["source_error"]) == 25
        old = admin.execute("select clock_timestamp()-interval '25 hours' as at").fetchone()["at"]
        slots = [None] * 25
        hour = int(old.timestamp()) // 3600
        slots[hour % 25] = _bucket(hour, 5, old, old)
        admin.execute("update semantic_password_checkpoints set loss_buckets=%s::jsonb", (json.dumps({"source_error": slots}),))
    with _connection(password_pg, worker=True) as worker:
        assert _read(worker)["health"]["loss"] == {}


@pytest.mark.parametrize("diagnostics", [{"healthy": {"count": 1, "from": None, "to": None}},
    {"source_error": {"count": True, "from": None, "to": None}},
    {"source_error": {"count": -1, "from": None, "to": None}},
    {"source_error": {"count": 1, "from": None, "to": None, "verified": True}}])
def test_failure_observation_rejects_freeform_success_and_untyped_counts(password_pg, diagnostics):
    import psycopg
    with _connection(password_pg, worker=True) as worker:
        token = _begin(worker)["token"]
        with pytest.raises(psycopg.errors.InvalidParameterValue):
            _observe(worker, token, diagnostics)


def test_source_checkpoint_locks_serialize_two_issuers(password_pg):
    import psycopg
    with _connection(password_pg, worker=True) as first, _connection(password_pg, worker=True) as second:
        with first.transaction():
            token = _begin(first)["token"]
            second.execute("set lock_timeout='200ms'")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                _begin(second)
        assert _begin(second)["token"] > token


def test_worker_cannot_read_or_mutate_private_state_sequence_or_helpers(password_pg):
    import psycopg
    with _connection(password_pg, worker=True) as worker:
        _begin(worker)
        for table in ("semantic_password_checkpoints", "semantic_password_window_members"):
            for query in ("select * from ", "delete from "):
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    worker.execute(query + table)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.execute("select nextval('semantic_password_attempt_seq')")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.execute("select password_v2_check_state(%s::jsonb,%s::jsonb,%s)",
                           (json.dumps(_state()), json.dumps(asdict(SCOPE)), detector.Rule(SCOPE, "brute").pin))


@pytest.mark.parametrize("operation", ["begin", "read", "commit", "observe"])
def test_every_operation_reauthenticates_session_login(password_pg, operation):
    import psycopg
    with _connection(password_pg, worker=True) as worker:
        token = _begin(worker)["token"]
    with _connection(password_pg) as unbound:
        unbound.execute("set role adlog_semantic_worker")
        unbound.execute("select set_config('sli.principal_name',%s,false)", (password_pg[1],))
        action = {"begin": lambda: _begin(unbound), "read": lambda: _read(unbound),
                  "commit": lambda: _commit(unbound, token, 0, _state()), "observe": lambda: _observe(unbound, token)}[operation]
        with pytest.raises(psycopg.errors.InsufficientPrivilege): action()


def test_state_objects_rollback_with_unpublished_migration(password_base_pg):
    import psycopg
    import psycopg.rows
    marker = "insert into public.schema_migrations(version,name) values(273,'password_attacks_v2');"
    with psycopg.connect(password_base_pg, autocommit=True, row_factory=psycopg.rows.dict_row) as admin:
        with pytest.raises(psycopg.errors.DivisionByZero):
            admin.execute(PATH.read_text("utf-8-sig").replace(marker, "select 1/0;\n" + marker))
        admin.execute("rollback")
        for obj in ("semantic_password_checkpoints", "semantic_password_window_members", "semantic_password_attempt_seq"):
            assert admin.execute("select to_regclass(%s) as value", ("public." + obj,)).fetchone()["value"] is None


@pytest.mark.parametrize("field,value", [("version", None), ("kind", None), ("rule_id", None),
    ("rule_version", True), ("rule_sha256", "a" * 64), ("rule_id", "qw.password-custom")])
def test_execution_requires_exact_existing_rule_shape(password_pg, field, value):
    import psycopg
    execution = deepcopy(EXECUTION)
    execution[field] = value
    with _connection(password_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.InvalidParameterValue, match="password_v2_arguments_invalid"):
            _begin(worker, execution=execution)


def test_full_scope_unicode_canonical_digest_and_rule_pin_isolate_state(password_pg):
    from server.sli.semantic.qw_input import _digest
    other_scope = replace(SCOPE, source_instance_id="fixture-漢😀\x7f")
    other_execution = detector.Rule(other_scope, "brute").execution
    with _connection(password_pg) as admin:
        admin.execute("""insert into finding_evidence_source_bindings select principal_oid,principal_name,
            installation_id,plugin_id,%s,source_generation,collection_scope_id,storage_kind,log_source_id,agent_key,agent_id
            from finding_evidence_source_bindings where plugin_id='sli.windows.ad-dc'""", (other_scope.source_instance_id,))
    with _connection(password_pg, worker=True) as worker:
        first = _begin(worker)
        other = _begin(worker, scope=other_scope, execution=other_execution)
        assert first["token"] != other["token"]
        assert _read(worker)["active_token"] == first["token"]
        assert not _observe(worker, other["token"])
    with _connection(password_pg) as admin:
        row = admin.execute("select scope_digest,pin from semantic_password_checkpoints where scope_json=%s::jsonb",
                            (json.dumps(asdict(other_scope)),)).fetchone()
        assert bytes(row["scope_digest"]).hex() == _digest(asdict(other_scope))
        assert row["pin"] == _digest(other_execution)


def test_effective_private_grants_include_report_reader_and_inheritance(password_pg):
    with _connection(password_pg) as admin:
        for role in ("adlog_user", "adlog_storage_worker", "adlog_semantic_worker", password_pg[1]):
            for table in ("semantic_password_checkpoints", "semantic_password_window_members"):
                for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"):
                    assert not admin.execute("select has_table_privilege(%s,%s,%s) as allowed",
                                             (role, "public." + table, privilege)).fetchone()["allowed"]
            for privilege in ("USAGE", "SELECT", "UPDATE"):
                assert not admin.execute("select has_sequence_privilege(%s,%s,%s) as allowed",
                    (role, "public.semantic_password_attempt_seq", privilege)).fetchone()["allowed"]
            assert not admin.execute("select has_function_privilege(%s,%s,'EXECUTE') as allowed",
                (role, "public.password_v2_check_state(jsonb,jsonb,text)")).fetchone()["allowed"]
        for role in ("adlog_user", "adlog_storage_worker"):
            assert not admin.execute("select has_function_privilege(%s,%s,'EXECUTE') as allowed",
                (role, "public.begin_password_attempt(jsonb,jsonb)")).fetchone()["allowed"]


def test_recreated_login_does_not_inherit_old_binding(password_pg):
    import psycopg
    from psycopg import sql
    with _connection(password_pg) as admin:
        name = sql.Identifier(password_pg[1])
        admin.execute(sql.SQL("drop role {}").format(name))
        admin.execute(sql.SQL("create role {} login").format(name))
        admin.execute(sql.SQL("grant adlog_semantic_worker to {}").format(name))
    with _connection(password_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege): _begin(worker)


def test_new_private_tables_revoke_existing_report_reader_default_grants(password_base_pg):
    import psycopg
    with psycopg.connect(password_base_pg, autocommit=True) as admin:
        admin.execute("alter default privileges for role adlog_storage_owner in schema public grant select,insert on tables to adlog_user")
        admin.execute(PATH.read_text("utf-8-sig"))
        for table in ("semantic_password_checkpoints", "semantic_password_window_members"):
            for privilege in ("SELECT", "INSERT"):
                assert not admin.execute("select has_table_privilege('adlog_user',%s,%s)",
                                         ("public." + table, privilege)).fetchone()[0]


def test_multiple_fixed_diagnostics_share_one_atomic_observation(password_pg):
    with _connection(password_pg, worker=True) as worker:
        token = _begin(worker)["token"]
        assert _observe(worker, token, {"source_error": {"count": 3, "from": None, "to": None},
            "too_late": {"count": 2, "from": None, "to": None}})
        health = _read(worker)["health"]
        assert health["status"] == "error" and health["reason"] == "source_error"
        assert health["loss"]["source_error"]["count_lower_bound"] == 3
        assert health["loss"]["too_late"]["count_lower_bound"] == 2


def test_ring_overwrites_only_expired_slot_and_preserves_surviving_bucket(password_pg):
    with _connection(password_pg, worker=True) as worker:
        token = _begin(worker)["token"]
    with _connection(password_pg) as admin:
        now = admin.execute("select clock_timestamp() as at").fetchone()["at"]
        hour = int(now.timestamp()) // 3600
        slots = [None] * 25
        slots[hour % 25] = _bucket(hour - 25, 50, now - timedelta(hours=25), now - timedelta(hours=25))
        slots[(hour - 1) % 25] = _bucket(hour - 1, 2, now - timedelta(hours=1), now - timedelta(hours=1))
        admin.execute("update semantic_password_checkpoints set loss_buckets=%s::jsonb", (json.dumps({"source_error": slots}),))
    with _connection(password_pg, worker=True) as worker:
        assert _observe(worker, token)
        loss = _read(worker)["health"]["loss"]["source_error"]
        assert loss["count_lower_bound"] == 3 and loss["count_exact"] is True
