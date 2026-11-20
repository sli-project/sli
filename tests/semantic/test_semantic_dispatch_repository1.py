from datetime import datetime, timedelta, timezone

import pytest

from server.sli.semantic.semantic_correlation import SemanticRelation
from server.sli.semantic.semantic_correlation_repository import CorrelationRuleDefinition
from server.sli.semantic.semantic_dispatch import compile_correlation_rule
import server.sli.semantic.semantic_dispatch_repository as repository


def _rule():
    return compile_correlation_rule(
        CorrelationRuleDefinition(
            rule_id="dispatch-rule",
            rule_version=1,
            rule_kind="all_of",
            definition={
                "type": "all_of",
                "inputs": ["type.one", "type.two"],
                "join_roles": ["source_host", "session_principal"],
                "window_seconds": 300,
                "output_relation_kind": "relation.one-two",
                "confidence": "medium",
                "explanation": "same host and session",
            },
        )
    )


class Cursor:
    def __init__(self) -> None:
        self.sql = ""
        self.params = ()
        self.history = []

    def execute(self, sql, params=()):
        self.sql = " ".join(sql.split()).lower()
        self.params = params
        self.history.append((self.sql, params))

    def fetchone(self):
        return None

    def fetchall(self):
        return []


def test_subscription_replacement_requires_exact_draft_rule() -> None:
    rule = _rule()

    class SubscriptionCursor(Cursor):
        def fetchone(self):
            if self.sql.startswith("select lifecycle_status"):
                return {
                    "lifecycle_status": "draft",
                    "definition_sha256": rule.definition_sha256,
                }
            return None

    cur = SubscriptionCursor()
    repository.replace_rule_subscriptions(cur, rule=rule)
    combined = "\n".join(sql for sql, _ in cur.history)
    assert "for update" in combined
    assert "delete from semantic_correlation_subscriptions" in combined
    assert combined.count("insert into semantic_correlation_subscriptions") == 2

    class ActiveCursor(SubscriptionCursor):
        def fetchone(self):
            return {
                "lifecycle_status": "test",
                "definition_sha256": rule.definition_sha256,
            }

    with pytest.raises(RuntimeError, match="only in draft"):
        repository.replace_rule_subscriptions(ActiveCursor(), rule=rule)


def test_enqueue_is_idempotent_and_marks_only_ingestion_lateness() -> None:
    rule = _rule()
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)

    class EnqueueCursor(Cursor):
        inserted = None

        def execute(self, sql, params=()):
            super().execute(sql, params)
            if self.sql.startswith("insert into semantic_correlation_dispatch_jobs"):
                self.inserted = params

        def fetchone(self):
            if "from normalized_events" in self.sql:
                return {
                    "normalized_event_id": "00000000-0000-0000-0000-000000000001",
                    "semantic_type": "type.one",
                    "occurred_at_utc": occurred,
                    "source_ingested_at": occurred + timedelta(minutes=6),
                    "roles_json": {"source_host": "dc-1"},
                }
            if "where idempotency_key" in self.sql:
                return {
                    "job_id": self.inserted[0],
                    "normalized_event_id": self.inserted[1],
                    "partition_key": self.inserted[5],
                    "is_late": self.inserted[7],
                }
            return None

        def fetchall(self):
            if "from semantic_correlation_subscriptions" in self.sql:
                return [
                    {
                        "rule_id": rule.rule_id,
                        "rule_version": rule.rule_version,
                        "definition_sha256": rule.definition_sha256,
                        "rule_kind": rule.rule_kind,
                        "definition_json": {
                            "type": "all_of",
                            "inputs": ["type.one", "type.two"],
                            "join_roles": ["source_host", "session_principal"],
                            "window_seconds": 300,
                            "output_relation_kind": "relation.one-two",
                            "confidence": "medium",
                            "explanation": "same host and session",
                        },
                    }
                ]
            return []

    cur = EnqueueCursor()
    jobs = repository.enqueue_dispatch_jobs(
        cur,
        normalized_event_id="00000000-0000-0000-0000-000000000001",
    )
    assert len(jobs) == 1
    assert cur.inserted[7] is True
    assert "on conflict(idempotency_key) do nothing" in "\n".join(
        sql for sql, _ in cur.history
    )


def test_historical_enqueue_limits_subscriptions_to_exact_rule_ids() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)

    class FilterCursor(Cursor):
        def fetchone(self):
            if "from normalized_events" in self.sql:
                return {
                    "normalized_event_id": "00000000-0000-0000-0000-000000000031",
                    "semantic_type": "authentication.session.failed",
                    "occurred_at_utc": occurred,
                    "source_ingested_at": occurred,
                    "roles_json": {}, "facts_json": {}, "quality_json": {},
                }
            return None

    cur = FilterCursor()
    assert repository.enqueue_dispatch_jobs(
        cur,
        normalized_event_id="00000000-0000-0000-0000-000000000031",
        allowed_rule_ids=("investigation.account.lockout.preceded-by-failures",),
    ) == ()
    subscription_query = next(
        (sql, params) for sql, params in cur.history
        if "from semantic_correlation_subscriptions" in sql
    )
    assert "rule.rule_id=any" in subscription_query[0]
    assert subscription_query[1][-1] == ["investigation.account.lockout.preceded-by-failures"]

    with pytest.raises(ValueError, match="allowed_rule_ids"):
        repository.enqueue_dispatch_jobs(
            FilterCursor(),
            normalized_event_id="00000000-0000-0000-0000-000000000031",
            allowed_rule_ids=(),
        )


def test_investigation_enqueue_limits_subscription_to_exact_rule_identity() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    digest = bytes.fromhex("11" * 32)

    class FilterCursor(Cursor):
        def fetchone(self):
            if "from normalized_events" in self.sql:
                return {
                    "normalized_event_id": "00000000-0000-0000-0000-000000000031",
                    "semantic_type": "authentication.session.failed",
                    "occurred_at_utc": occurred,
                    "source_ingested_at": occurred,
                    "roles_json": {}, "facts_json": {}, "quality_json": {},
                }
            return None

    cur = FilterCursor()
    assert repository.enqueue_dispatch_jobs(
        cur,
        normalized_event_id="00000000-0000-0000-0000-000000000031",
        allowed_rule_identities=(("investigation.rule", 3, digest),),
    ) == ()
    sql, params = next(
        (sql, params) for sql, params in cur.history
        if "from semantic_correlation_subscriptions" in sql
    )
    assert "rule.rule_id=%s and rule.rule_version=%s and rule.definition_sha256=%s" in sql
    assert params[-3:] == ("investigation.rule", 3, digest)


def test_cross_dc_context_predicates_are_exact_non_empty_and_fail_closed() -> None:
    sid = "S-1-5-21-100-200-300-400"
    cases = (
        ("domain_account_sid", f"domain:7|account_sid:{sid}", 2),
        ("domain_member_group_sid", f"domain:7|member_sid:{sid}|group_sid:{sid}", 2),
        ("domain_account_member_sid", f"domain:7|account_member_sid:{sid}", 3),
    )
    for partition_kind, partition_key, parameter_count in cases:
        rule = type("Rule", (), {"partition_kind": partition_kind})()
        predicate, parameters = repository._cross_dc_context_predicate(rule, partition_key)
        assert "{}" not in parameters
        assert len(parameters) == parameter_count
        assert predicate.count("@> %s::jsonb") == parameter_count
    with pytest.raises(RuntimeError, match="exact SID key"):
        repository._cross_dc_context_predicate(
            type("Rule", (), {"partition_kind": "domain_account_sid"})(),
            "domain:7|account_sid:not-a-sid",
        )


def test_enqueue_cross_dc_rule_uses_exact_domain_and_sid_partition() -> None:
    definition = {
        "type": "count_then",
        "inputs": ["authentication.session.failed", "authentication.account.locked"],
        "partition_kind": "domain_account_sid",
        "window_seconds": 900,
        "minimum_count": 2,
        "strict_time_order": True,
        "output_relation_kind": "authentication.account.lockout_preceded_by_failures_observed",
        "confidence": "medium",
        "explanation": "Observed exact domain and SID sequence; this makes no causal claim.",
    }
    source_rule = CorrelationRuleDefinition(
            rule_id="investigation.account.lockout.preceded-by-failures",
            rule_version=1,
            rule_kind="count_then",
            definition=definition,
        )
    rule = compile_correlation_rule(source_rule)
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)

    class CrossDcEnqueueCursor(Cursor):
        inserted = None

        def execute(self, sql, params=()):
            super().execute(sql, params)
            if self.sql.startswith("insert into semantic_correlation_dispatch_jobs"):
                self.inserted = params

        def fetchone(self):
            if "from normalized_events" in self.sql:
                return {
                    "normalized_event_id": "00000000-0000-0000-0000-000000000021",
                    "semantic_type": "authentication.session.failed",
                    "occurred_at_utc": occurred,
                    "source_ingested_at": occurred,
                    "roles_json": {"source_host": "dc-1", "affected_entity": "sid:S-1-5-21-100-200-300-400"},
                    "facts_json": {"domain_id": 7},
                    "quality_json": {},
                }
            if "where idempotency_key" in self.sql:
                return {
                    "job_id": self.inserted[0],
                    "normalized_event_id": self.inserted[1],
                    "partition_key": self.inserted[5],
                    "is_late": self.inserted[7],
                }
            return None

        def fetchall(self):
            if "from semantic_correlation_subscriptions" in self.sql:
                return [{
                    "rule_id": rule.rule_id,
                    "rule_version": rule.rule_version,
                    "definition_sha256": rule.definition_sha256,
                    "rule_kind": rule.rule_kind,
                    "definition_json": source_rule.definition_json,
                }]
            return []

    cur = CrossDcEnqueueCursor()
    assert len(repository.enqueue_dispatch_jobs(
        cur, normalized_event_id="00000000-0000-0000-0000-000000000021"
    )) == 1
    assert cur.inserted[5] == "domain:7|account_sid:S-1-5-21-100-200-300-400"


def test_claim_and_expiry_are_bounded_leased_operations() -> None:
    cur = Cursor()
    assert repository.claim_dispatch_jobs(cur, limit=999, lease_seconds=1) == []
    assert "for update of job skip locked" in cur.sql
    assert cur.params[0] == 16
    assert cur.params[2] == 60

    filtered = Cursor()
    assert repository.claim_dispatch_jobs(
        filtered,
        limit=3,
        allowed_rule_ids=("investigation.account.unlock.after-lock",),
    ) == []
    assert "rule_id=any" in filtered.sql
    assert filtered.params[0] == ["investigation.account.unlock.after-lock"]
    assert filtered.params[1] == 3

    exact = Cursor()
    digest = bytes.fromhex("22" * 32)
    job_id = "00000000-0000-0000-0000-000000000099"
    assert repository.claim_dispatch_jobs(
        exact,
        limit=3,
        allowed_rule_identities=(("investigation.rule", 4, digest),),
        allowed_job_ids=(job_id,),
    ) == []
    assert "join semantic_correlation_rules rule" in exact.sql
    assert "rule.rule_version=%s" in exact.sql
    assert "job.job_id=any(%s::uuid[])" in exact.sql
    assert "for update of job skip locked" in exact.sql
    assert exact.params[:4] == (
        "investigation.rule", 4, digest, [job_id],
    )

    empty = Cursor()
    assert repository.claim_dispatch_jobs(empty, allowed_job_ids=()) == []
    assert empty.history == []

    with pytest.raises(ValueError, match="timezone-aware"):
        repository.expire_correlation_candidates(
            Cursor(), before_utc=datetime(2026, 7, 19)
        )
    cur = Cursor()
    assert repository.expire_correlation_candidates(
        cur, before_utc=datetime(2026, 7, 19, tzinfo=timezone.utc), limit=9000
    ) == ()
    assert "for update skip locked limit" in cur.sql
    assert cur.params[1] == 1000


def test_late_evidence_reopen_is_exact_and_idempotent_in_sql(monkeypatch) -> None:
    rule = _rule()
    relation = SemanticRelation(
        relation_kind=rule.output_relation_kind,
        source_event_ids=(1, 2),
        contribution_key="dispatch:stable",
        confidence="medium",
        explanation="same host and session",
    )
    monkeypatch.setattr(
        repository,
        "persist_correlation_candidate",
        lambda *args, **kwargs: "00000000-0000-0000-0000-000000000010",
    )

    class StateCursor(Cursor):
        def fetchone(self):
            return {
                "candidate_id": "00000000-0000-0000-0000-000000000010",
                "candidate_status": "matched",
                "reopen_count": 1,
                "late_evidence_count": 1,
            }

    cur = StateCursor()
    state = repository.persist_dispatched_relation(
        cur, rule=rule, relation=relation, late_source_event_ids=(2,)
    )
    assert state.reopen_count == 1
    assert state.late_evidence_count == 1
    assert "and not evidence.is_late" in cur.sql
    assert "candidate.candidate_status='expired' and changed.changed_count > 0" in cur.sql
    assert cur.params[2] == [2]
    with pytest.raises(ValueError, match="must belong"):
        repository.persist_dispatched_relation(
            cur, rule=rule, relation=relation, late_source_event_ids=(3,)
        )
