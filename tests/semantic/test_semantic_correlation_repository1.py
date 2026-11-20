from datetime import datetime, timedelta, timezone

import pytest

from server.sli.semantic.semantic_correlation import SemanticRelation
from server.sli.semantic.semantic_correlation_repository import (
    CorrelationRuleDefinition,
    claim_correlation_replays,
    complete_correlation_replay,
    heartbeat_correlation_replay,
    persist_correlation_candidate,
    schedule_correlation_replay,
    transition_correlation_rule,
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


def test_rule_definition_rejects_executable_payloads_and_type_mismatch() -> None:
    with pytest.raises(ValueError, match="must match"):
        CorrelationRuleDefinition(
            rule_id="rule", rule_version=1, rule_kind="count", definition={"type": "rate"}
        )
    with pytest.raises(ValueError, match="forbidden"):
        CorrelationRuleDefinition(
            rule_id="rule",
            rule_version=1,
            rule_kind="count",
            definition={"type": "count", "sql": "select 1"},
        )


def test_rule_transition_is_explicit_and_rejects_invalid_jump() -> None:
    class TransitionCursor(Cursor):
        def fetchone(self):
            if self.sql.startswith("select lifecycle_status"):
                return {"lifecycle_status": "enabled"}
            return {"lifecycle_status": "test"}

    with pytest.raises(ValueError, match="enabled -> test"):
        transition_correlation_rule(
            TransitionCursor(), rule_id="rule", rule_version=1, target_status="test"
        )


def test_candidate_persistence_requires_one_host_and_appends_exact_evidence() -> None:
    occurred = datetime(2026, 7, 19, 1, tzinfo=timezone.utc)

    class CandidateCursor(Cursor):
        def __init__(self) -> None:
            super().__init__()
            self.candidate_id = None

        def execute(self, sql, params=()):
            super().execute(sql, params)
            if self.sql.startswith("insert into semantic_correlation_candidates"):
                self.candidate_id = params[0]

        def fetchone(self):
            if "from semantic_correlation_rules" in self.sql:
                return {"lifecycle_status": "test"}
            if "from semantic_correlation_candidates" in self.sql:
                return {
                    "candidate_id": self.candidate_id,
                    "relation_kind": "authentication.session.has_special_privileges",
                    "partition_key": "1",
                    "confidence": "high",
                }
            if "max(evidence_order)" in self.sql:
                return {"last_order": -1}
            return None

        def fetchall(self):
            if "from normalized_events" in self.sql:
                return [
                    {
                        "normalized_event_id": "00000000-0000-0000-0000-000000000001",
                        "source_event_id": 1,
                        "occurred_at_utc": occurred,
                        "roles_json": {"source_host": "1"},
                    },
                    {
                        "normalized_event_id": "00000000-0000-0000-0000-000000000002",
                        "source_event_id": 2,
                        "occurred_at_utc": occurred + timedelta(seconds=1),
                        "roles_json": {"source_host": "1"},
                    },
                ]
            return []

    cur = CandidateCursor()
    candidate_id = persist_correlation_candidate(
        cur,
        rule_id="session-special-privileges",
        rule_version=1,
        evidence_contract=(1, "windows-ad-dc", "1.0"),
        relation=SemanticRelation(
            "authentication.session.has_special_privileges",
            (1, 2),
            "session-special-privileges:1:0x1:1:2",
            "high",
            "exact source host and LogonId",
        ),
    )
    assert candidate_id == cur.candidate_id
    combined = "\n".join(sql for sql, _ in cur.history)
    evidence_query = next((sql, params) for sql, params in cur.history if "from normalized_events" in sql)
    assert "semantic_contract_version=%s" in evidence_query[0]
    assert evidence_query[1] == ([1, 2], 1, "windows-ad-dc", "1.0")
    assert "pg_advisory_xact_lock" in combined
    assert "insert into semantic_correlation_candidate_evidence" in combined
    assert "evidence_count=(select count(*)" in combined


def test_candidate_evidence_renumbering_is_sequenced_and_fail_closed() -> None:
    source = __import__(
        "server.sli.semantic.semantic_correlation_repository", fromlist=["persist_correlation_candidate"]
    )
    rendered = "\n".join(
        value for value in source.persist_correlation_candidate.__code__.co_consts
        if isinstance(value, str)
    )
    assert "evidence_order=evidence_order+16384" in rendered
    assert "correlation evidence cannot be safely renumbered" in rendered
    assert "shifted as" not in rendered


def test_candidate_persistence_accepts_explicit_cross_dc_partition() -> None:
    occurred = datetime(2026, 7, 19, 1, tzinfo=timezone.utc)
    partition_key = "domain:7|account_sid:S-1-5-21-100-200-300-400"

    class CrossDcCandidateCursor(Cursor):
        def __init__(self) -> None:
            super().__init__()
            self.candidate_id = None

        def execute(self, sql, params=()):
            super().execute(sql, params)
            if self.sql.startswith("insert into semantic_correlation_candidates"):
                self.candidate_id = params[0]

        def fetchone(self):
            if "from semantic_correlation_rules" in self.sql:
                return {"lifecycle_status": "test"}
            if "from semantic_correlation_candidates" in self.sql:
                return {
                    "candidate_id": self.candidate_id,
                    "relation_kind": "authentication.account.lockout_preceded_by_failures_observed",
                    "partition_key": partition_key,
                    "confidence": "medium",
                }
            if "max(evidence_order)" in self.sql:
                return {"last_order": -1}
            return None

        def fetchall(self):
            if "from normalized_events" in self.sql:
                return [
                    {
                        "normalized_event_id": "00000000-0000-0000-0000-000000000011",
                        "source_event_id": 11,
                        "occurred_at_utc": occurred,
                        "roles_json": {"source_host": "dc-1"},
                    },
                    {
                        "normalized_event_id": "00000000-0000-0000-0000-000000000012",
                        "source_event_id": 12,
                        "occurred_at_utc": occurred + timedelta(seconds=1),
                        "roles_json": {"source_host": "dc-2"},
                    },
                ]
            return []

    cur = CrossDcCandidateCursor()
    assert persist_correlation_candidate(
        cur,
        rule_id="investigation.account.lockout.preceded-by-failures",
        rule_version=1,
        relation=SemanticRelation(
            "authentication.account.lockout_preceded_by_failures_observed",
            (11, 12),
            "dispatch:cross-dc-lock-12",
            "medium",
            "Observed exact domain and SID sequence; this makes no causal claim.",
            partition_key,
        ),
    ) == cur.candidate_id
    inserted = next(params for sql, params in cur.history if sql.startswith("insert into semantic_correlation_candidates"))
    assert inserted[5] == partition_key


def test_candidate_persistence_rejects_non_numeric_domain_sid_partition() -> None:
    occurred = datetime(2026, 7, 19, 1, tzinfo=timezone.utc)

    class InvalidPartitionCursor(Cursor):
        def __init__(self) -> None:
            super().__init__()
            self.candidate_id = None

        def execute(self, sql, params=()):
            super().execute(sql, params)
            if self.sql.startswith("insert into semantic_correlation_candidates"):
                self.candidate_id = params[0]

        def fetchone(self):
            if "from semantic_correlation_rules" in self.sql:
                return {"lifecycle_status": "test"}
            if "from semantic_correlation_candidates" in self.sql:
                return {
                    "candidate_id": self.candidate_id,
                    "relation_kind": "authentication.account.lockout_preceded_by_failures_observed",
                    "partition_key": "domain:7|account_sid:S-1-5-21-not-numeric",
                    "confidence": "medium",
                }
            if "max(evidence_order)" in self.sql:
                return {"last_order": -1}
            return None

        def fetchall(self):
            if "from normalized_events" in self.sql:
                return [
                    {
                        "normalized_event_id": "00000000-0000-0000-0000-000000000021",
                        "source_event_id": 21,
                        "occurred_at_utc": occurred,
                        "roles_json": {"source_host": "dc-1"},
                    },
                    {
                        "normalized_event_id": "00000000-0000-0000-0000-000000000022",
                        "source_event_id": 22,
                        "occurred_at_utc": occurred + timedelta(seconds=1),
                        "roles_json": {"source_host": "dc-2"},
                    },
                ]
            return []

    with pytest.raises(ValueError, match="exact bounded SID key"):
        persist_correlation_candidate(
            InvalidPartitionCursor(),
            rule_id="investigation.account.lockout.preceded-by-failures",
            rule_version=1,
            relation=SemanticRelation(
                "authentication.account.lockout_preceded_by_failures_observed",
                (21, 22),
                "dispatch:invalid-cross-dc",
                "medium",
                "Observed exact domain and SID sequence; this makes no causal claim.",
                "domain:7|account_sid:S-1-5-21-not-numeric",
            ),
        )


def test_candidate_persistence_reorders_replayed_evidence_by_observed_time() -> None:
    occurred = datetime(2026, 7, 19, 1, tzinfo=timezone.utc)

    class CandidateCursor(Cursor):
        def __init__(self) -> None:
            super().__init__()
            self.candidate_id = None

        def execute(self, sql, params=()):
            super().execute(sql, params)
            if self.sql.startswith("insert into semantic_correlation_candidates"):
                self.candidate_id = params[0]

        def fetchone(self):
            if "from semantic_correlation_rules" in self.sql:
                return {"lifecycle_status": "test"}
            if "from semantic_correlation_candidates" in self.sql:
                return {
                    "candidate_id": self.candidate_id,
                    "relation_kind": "authentication.password_reset_followed_by_logon_observed",
                    "partition_key": "domain:7|account_sid:S-1-5-21-100-200-300-400",
                    "confidence": "medium",
                }
            if "max(evidence_order)" in self.sql:
                return {"last_order": -1}
            return None

        def fetchall(self):
            if "from normalized_events" in self.sql:
                return [
                    {"normalized_event_id": f"00000000-0000-0000-0000-{source_id:012d}", "source_event_id": source_id, "occurred_at_utc": occurred + timedelta(minutes=offset), "roles_json": {"source_host": "dc-1"}}
                    for source_id, offset in ((1, 0), (3, 30), (2, 10))
                ]
            return []

    cur = CandidateCursor()
    persist_correlation_candidate(
        cur,
        rule_id="investigation.password.reset-then-logon",
        rule_version=2,
        relation=SemanticRelation(
            "authentication.password_reset_followed_by_logon_observed",
            (1, 2, 3), "dispatch:anchor-1", "medium", "observed alternatives",
            "domain:7|account_sid:S-1-5-21-100-200-300-400",
        ),
    )

    assert "row_number()over(orderbynormalized.occurred_at_utc,normalized.source_event_id)" in "".join(
        sql for sql, _ in cur.history
    ).replace(" ", "")


def test_replay_window_is_bounded_and_claim_uses_leases() -> None:
    start = datetime(2026, 7, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="within 7 days"):
        schedule_correlation_replay(
            Cursor(),
            rule_id="rule",
            rule_version=1,
            range_start_utc=start,
            range_end_utc=start + timedelta(days=8),
        )
    cur = Cursor()
    assert claim_correlation_replays(cur, limit=999, lease_seconds=1) == []
    assert "for update skip locked" in cur.sql
    assert cur.params[0] == 16
    assert cur.params[2] == 60


def test_replay_heartbeat_and_completion_reject_invalid_metrics() -> None:
    class LeaseCursor(Cursor):
        def fetchone(self):
            return {"replay_id": "replay"}

    cur = LeaseCursor()
    assert heartbeat_correlation_replay(
        cur, replay_id="replay", lease_token="token", lease_seconds=1
    )
    assert cur.params[0] == 60
    with pytest.raises(ValueError, match="timezone-aware"):
        complete_correlation_replay(
            cur,
            replay_id="replay",
            lease_token="token",
            checkpoint_utc=datetime(2026, 7, 19),
            processed_events=1,
            matched_candidates=1,
        )
    with pytest.raises(ValueError, match="non-negative"):
        complete_correlation_replay(
            cur,
            replay_id="replay",
            lease_token="token",
            checkpoint_utc=datetime(2026, 7, 19, tzinfo=timezone.utc),
            processed_events=-1,
            matched_candidates=0,
        )
