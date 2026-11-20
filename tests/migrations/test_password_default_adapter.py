"""Actual public default adapter -> discovery -> managed producer/COMMIT queue.

Synthetic issued metadata/receipts and ordinary owner-disabled unrelated policies
are fixture setup, not normal acquisition or enabled-other-detector acceptance.
"""
from dataclasses import asdict
import json

import pytest

from server.sli.semantic import default_detections as defaults
from server.sli.semantic import account_decoy, account_watch, nps_threshold, password_attacks
from server.sli.semantic import password_attack_policy as factory
from server.sli.semantic import password_attack_v2 as pure
from server.sli.semantic import semantic_risk_runtime_repository as runtime
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from tests.migrations.test_password_managed_conveyor import (
    SCOPE, _authority, _identity, _native_managed, _publication_authority, _region, _source,
    acl_pg as acl_pg, conveyor_pg as conveyor_pg, coordinator_pg as coordinator_pg,
    coverage_pg as coverage_pg, managed_base_pg as managed_base_pg,
    managed_pg as managed_pg, native_pg as native_pg, original_base as original_base,
    password_base_pg as password_base_pg, password_pg as password_pg,
    reservation_pg as reservation_pg,
)
from tests.migrations.test_password_policy_management_migration import connection, owner_choice

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def _disabled_unrelated(source):
    policies = []
    for module, cls in ((account_decoy, account_decoy.DecoyRule), (account_watch, account_watch.WatchRule)):
        rule = cls(scope=SCOPE, evaluation_mode="enabled")
        policies.append(module.risk_policy(rule, policy_id=defaults.policy_id(rule.execution)))
    disabled = "qw.disabled-account-logon"
    policies.append(password_attacks.risk_policy(SCOPE, disabled,
        policy_id=defaults.policy_id(password_attacks.execution(SCOPE, disabled))))
    nps = nps_threshold.ThresholdRule(scope=SCOPE, evaluation_mode="enabled")
    policies.append(nps_threshold.risk_policy(nps, policy_id=defaults.policy_id(
        {"rule_id": "qw.nps-denials", "scope": asdict(SCOPE), "rule_sha256": nps.rule_sha256})))
    for policy in policies:
        with connection(source, writer=True) as writer, writer.transaction(), writer.cursor() as cur:
            runtime.register_risk_policy(cur, policy=policy)
            for status in ("validated", "test", "shadow"):
                runtime.transition_risk_policy(cur, policy_id=policy.policy_id, policy_version=1, target_status=status)
        # Existing physical app LOGIN, actual governance+153 audit; no fake
        # policy body or admission/reader shortcut is installed by this test.
        owner_choice(source, policy, False)
    return tuple(policies)


def _prepare_discovery(source):
    from psycopg.rows import dict_row
    with connection(source) as admin:
        admin.row_factory = dict_row
        before = _authority(admin), _publication_authority(admin)
        assert admin.execute("select to_regprocedure('public.default_detection_sources()') as v").fetchone()["v"] is None
        # The reduced accepted native fixture omitted these157 receipt fields.
        # Only their real typed agent key/positive sequence semantics are added.
        admin.execute("alter table sli_agent_receipts add column agent_id uuid references sli_agents(id), "
                      "add column sequence bigint check(sequence>0)")
        _native_managed(admin)
        admin.execute("""update sli_agent_receipts r set agent_id=(r.envelope->>'agent_id')::uuid,
            sequence=core.id from raw_log_files raw join events_v2_core core on core.raw_log_file_id=raw.id
            where raw.file_path='agent-packet:'||r.packet_id::text""")
        assert admin.execute("select count(*) as n from sli_agent_receipts where agent_id is null "
                             "or sequence is null").fetchone()["n"] == 0
        admin.execute("alter table sli_agent_receipts alter agent_id set not null,alter sequence set not null, "
                      "add unique(agent_id,module_id,sequence)")
        admin.execute("set role adlog_storage_owner")
        sql267 = _source("267_file_audit_discovery_join.sql")
        admin.execute(_region(sql267, "create function public.file_audit_discovery_witness_v267",
                              "create or replace function public.default_detection_sources"))
        admin.execute(_region(sql267, "create or replace function public.default_detection_sources",
                              "insert into public.schema_migrations"))
        # Exact existing262 declaration, not a new runtime privilege.
        sql262 = _source("262_default_native_detections.sql")
        acl = "revoke all on function public.default_detection_sources() from public;\ngrant execute on function public.default_detection_sources() to adlog_semantic_worker;"
        assert acl in sql262
        admin.execute(acl)
        admin.execute("reset role")
        assert (_authority(admin), _publication_authority(admin)) == before
        native_bytes = admin.execute("select sum(octet_length(convert_to(event_rows->0->>'xml','UTF8'))) as n "
                                     "from sli_agent_packet_inbox").fetchone()["n"]
        return before, native_bytes


def test_public_default_adapter_discovers_and_commits_managed_native_queue(conveyor_pg):
    from psycopg.rows import dict_row
    authority, native_bytes = _prepare_discovery(conveyor_pg)
    unrelated = _disabled_unrelated(conveyor_pg)
    rules = tuple(pure.Rule(SCOPE, kind) for kind in ("brute", "spray"))
    policies = tuple(factory.risk_policy(rule) for rule in rules)
    with connection(conveyor_pg) as observer:
        observer.row_factory = dict_row
        assert observer.execute("select count(*) as n from semantic_risk_policies where policy_id=any(%s)",
                                ([p.policy_id for p in policies],)).fetchone()["n"] == 0
        for table in ("semantic_password_checkpoints", "semantic_password_episode_budgets", "semantic_qw_signals", "semantic_risk_evaluation_jobs"):
            assert observer.execute("select count(*) as n from " + table).fetchone()["n"] == 0
    with connection(conveyor_pg, worker=True) as worker:
        worker.row_factory = dict_row
        worker.execute("set role adlog_semantic_worker")
        assert assert_semantic_worker_least_privilege(worker.cursor())["exclusive_worker_membership"]
        identity = _identity(worker)
        result = defaults.run_default_detections(worker)
        assert worker.info.transaction_status == 0 and _identity(worker) == identity
        # Actual267 SQL discovery, never a supplied list or fake function.
        with worker.transaction():
            discovered = [r["source"] for r in worker.execute("select source from public.default_detection_sources()").fetchall()]
            page = worker.execute("select read_default_file_acl_resources(null,1) as v").fetchone()["v"]
        source, = discovered
        assert source["scope"] == asdict(SCOPE)
        assert page["items"] == []
        assert result["sources"] == len(discovered)+len(page["items"]) == 1
        assert result["jobs"] == 1 and result["failed"] == 0
        assert result["coverage_counts"] == {"healthy": 2, "partial": 0, "error": 0,
            "unknown": 0, "stale": 0, "disabled": 0, "failed": 0}
        assert result["password_work_counts"] == {"native_items": 20, "xml_bytes": 2*native_bytes,
            "retained_queries": 0, "reservation_occurrences": 10, "window_queries": 2,
            "reservation_calls": 1, "tracking_calls": 0, "completion_calls": 2}
        assert _identity(worker) == identity and worker.info.transaction_status == 0
    # A separate observer proves queue/canonical State visibility after return.
    with connection(conveyor_pg) as observer:
        observer.row_factory = dict_row
        assert (_authority(observer), _publication_authority(observer)) == authority
        for policy in policies:
            row = observer.execute("select * from semantic_risk_policies where policy_id=%s", (policy.policy_id,)).fetchone()
            assert row["definition_json"] == dict(policy.definition)
            assert bytes(row["definition_sha256"]) == policy.definition_sha256 and row["policy_version"] == 1
        checkpoints = observer.execute("select * from semantic_password_checkpoints order by pin").fetchall()
        assert {c["pin"] for c in checkpoints} == {r.pin for r in rules}
        assert all(c["scope_json"] == asdict(SCOPE) and c["health_status"] == "healthy" and c["state_revision"] == 1
                   and c["last_successful_cutoff"] == c["watermark"]
                   and c["active_token"] == c["last_observed_token"] for c in checkpoints)
        signal, = observer.execute("select * from semantic_qw_signals").fetchall()
        job, = observer.execute("select * from semantic_risk_evaluation_jobs").fetchall()
        ledger, = observer.execute("select * from semantic_password_episode_budgets").fetchall()
        assert signal["document_json"]["rule_id"] == "qw.password-brute-force"
        assert signal["document_json"]["rule_version"] == 2
        assert job["qw_signal_id"] == signal["signal_id"] and job["policy_id"] == policies[0].policy_id
        assert job["evaluation_status"] == "queued" and job["evaluation_mode"] == "enabled"
        assert ledger["pin"] == rules[0].pin and ledger["reserved_ref_occurrences"] == 10
        assert ledger["last_sequence"] == 1 and not ledger["frozen"]
        assert observer.execute("select count(*) as n from semantic_policy_admission where policy_id=any(%s) "
            "and enabled is false", ([p.policy_id for p in unrelated],)).fetchone()["n"] == 4
        legacy = [defaults.policy_id(password_attacks.execution(SCOPE, name))
                  for name in ("qw.password-brute-force", "qw.password-spray")]
        assert observer.execute("select count(*) as n from semantic_risk_policies where policy_id=any(%s)",
                                (legacy,)).fetchone()["n"] == 0
