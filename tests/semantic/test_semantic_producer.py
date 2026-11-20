from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

from server.sli.semantic.semantic_producer import (
    MAX_UNKNOWN_TASKS_PER_BATCH,
    _eligible_investigation_context_ids,
    publish_investigation_candidates,
    select_investigation_context_expansion_ids,
    publish_semantic_candidates,
    select_semantic_queue_candidates,
)
from server.sli.storage.storage_v2_repository import PostgresStorageV2Repository


def _row(
    source_event_id: int,
    event_key: str,
    *,
    stream: str = "Security",
    provider: str = "Microsoft-Windows-Security-Auditing",
) -> dict[str, object]:
    return {
        "source_event_id": source_event_id,
        "event_key": event_key,
        "stream": stream,
        "provider_name": provider,
    }


def test_prequeue_selection_keeps_signal_skips_context_and_bounds_unknown() -> None:
    rows = [
        _row(1, "4719"),
        _row(2, "4624"),
        *[_row(index, str(900000 + index)) for index in range(3, 103)],
    ]

    selected, counters = select_semantic_queue_candidates(rows)

    assert selected[0].source_event_id == 1
    assert selected[0].selection_reason == "signal"
    assert counters == {
        "scanned": 102,
        "signal_queued": 1,
        "unknown_queued": 6,
        "unknown_suppressed": 94,
        "context_skipped": 1,
        "noise_skipped": 0,
    }
    assert len(selected) == 7
    assert counters["unknown_queued"] <= MAX_UNKNOWN_TASKS_PER_BATCH


def test_explicit_bounded_selection_can_include_context() -> None:
    selected, counters = select_semantic_queue_candidates(
        [_row(2, "4624")],
        include_context=True,
    )

    assert [(item.source_event_id, item.selection_reason) for item in selected] == [
        (2, "explicit_context")
    ]
    assert counters["context_skipped"] == 0


def test_selected_retained_vocabulary_member_is_never_silently_lost_as_unknown() -> None:
    """An exact controller-selected ID is explicit context, not a capped unknown sample."""
    rows = [_row(index, "4727") for index in range(1, 40)]

    selected, counters = select_semantic_queue_candidates(
        rows,
        include_context=True,
        context_event_ids=tuple(range(1, 40)),
    )

    assert [item.source_event_id for item in selected] == list(range(1, 40))
    assert {item.selection_reason for item in selected} == {"related_context"}
    assert counters["unknown_queued"] == 0
    assert counters["unknown_suppressed"] == 0


def test_unclaimed_provider_is_unknown_not_a_cross_provider_match() -> None:
    selected, counters = select_semantic_queue_candidates(
        [_row(7, "4719", provider="Other Provider")]
    )

    assert [item.selection_reason for item in selected] == ["descriptor_missing"]
    assert counters["unknown_queued"] == 1


def test_publication_uses_one_bounded_identity_query_and_caller_cursor(
    monkeypatch,
) -> None:
    class Cursor:
        def __init__(self) -> None:
            self.sql = ""
            self.params = ()

        def execute(self, sql, params=()):
            self.sql = str(sql)
            self.params = params

        def fetchall(self):
            return [_row(11, "4719")]

    queued: list[tuple[int, dict[str, str]]] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_producer.enqueue_semantic_job",
        lambda _cur, *, source_event_id, payload: queued.append(
            (source_event_id, dict(payload))
        )
        or f"job-{source_event_id}",
    )
    cur = Cursor()

    result = publish_semantic_candidates(cur, [11, 11])

    assert "where core.id=any(%s)" in cur.sql
    assert cur.params == ([11],)
    assert queued == [(11, {"selection_reason": "signal"})]
    assert result["queued"] == 1


def test_publication_requires_explicit_admission_to_queue_context(monkeypatch) -> None:
    class Cursor:
        def execute(self, _sql, _params=()):
            return None

        def fetchall(self):
            return [_row(12, "4624")]

    queued: list[tuple[int, dict[str, str]]] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_producer.enqueue_semantic_job",
        lambda _cur, *, source_event_id, payload: queued.append(
            (source_event_id, dict(payload))
        ),
    )

    result = publish_semantic_candidates(
        Cursor(),
        [12],
        include_context=True,
    )

    assert queued == [(12, {"selection_reason": "explicit_context"})]
    assert result["queued"] == 1


def test_investigation_publication_queues_only_context_after_successful_reset(monkeypatch) -> None:
    class Cursor:
        def __init__(self) -> None:
            self.sql = ""
            self.params = ()

        def execute(self, sql, params=()):
            self.sql = " ".join(str(sql).split())
            self.params = params

        def fetchall(self):
            if "join events_v2_core reset_event" in self.sql:
                reset_at = datetime(2026, 9, 13, 1, 0, tzinfo=timezone.utc)
                return [
                    {
                        "source_event_id": source_event_id,
                        "login_domain_id": 7,
                        "login_target_user_sid": "S-1-5-21-100-200-300-400",
                        "login_time_created_utc": reset_at + timedelta(minutes=30),
                        "reset_domain_id": 7,
                        "reset_target_user_sid": "S-1-5-21-100-200-300-400",
                        "reset_time_created_utc": reset_at,
                        "reset_keywords": keywords,
                    }
                    for source_event_id, keywords in (
                        (12, "0x8020000000000000"),
                        (13, "0x8010000000000000"),
                    )
                ]
            requested = set(self.params[0])
            return [
                row
                for row in (_row(12, "4624"), _row(13, "4624"))
                if row["source_event_id"] in requested
            ]

    queued: list[tuple[int, dict[str, str]]] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_producer.enqueue_semantic_job",
        lambda _cur, *, source_event_id, payload: queued.append(
            (source_event_id, dict(payload))
        ),
    )

    result = publish_investigation_candidates(Cursor(), [12, 13])

    assert queued == [(12, {"selection_reason": "related_context"})]
    assert result["queued"] == 1
    assert result["context_skipped"] == 0


def test_investigation_publication_excludes_generic_signals_outside_report_vocabulary(
    monkeypatch,
) -> None:
    rows = {
        31: _row(31, "4719"),
        32: _row(32, "4625"),
        33: _row(33, "5504"),
        34: _row(34, "4719", provider="Other Provider"),
        35: _row(35, "4776"),
        36: _row(36, "1102", provider="Microsoft-Windows-Eventlog"),
    }

    class Cursor:
        def __init__(self) -> None:
            self.sql = ""
            self.params = ()

        def execute(self, sql, params=()):
            self.sql = " ".join(str(sql).split())
            self.params = params

        def fetchall(self):
            if "join events_v2_core reset_event" in self.sql:
                return []
            if "candidate.id as source_event_id" in self.sql:
                return []
            requested = set(self.params[0])
            return [rows[source_event_id] for source_event_id in sorted(requested)]

    queued: list[tuple[int, dict[str, str]]] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_producer.enqueue_semantic_job",
        lambda _cur, *, source_event_id, payload: queued.append(
            (source_event_id, dict(payload))
        ),
    )

    result = publish_investigation_candidates(
        Cursor(), [31, 32, 33, 34, 35, 36],
    )

    assert queued == [
        (31, {"selection_reason": "signal"}),
        (32, {"selection_reason": "signal"}),
        (35, {"selection_reason": "signal"}),
        (36, {"selection_reason": "signal"}),
    ]
    assert result["queued"] == 4


def test_investigation_publication_schedules_durable_late_reset_expansion(monkeypatch) -> None:
    class Cursor:
        def __init__(self) -> None:
            self.sql = ""
            self.params = ()

        def execute(self, sql, params=()):
            self.sql = " ".join(str(sql).split())
            self.params = params

        def fetchall(self):
            if "join events_v2_core reset_event" in self.sql:
                return []
            if "candidate.id as source_event_id" in self.sql:
                return [{
                    "source_event_id": 20,
                    "keywords": "0x8020000000000000",
                }]
            assert self.params[0] == [20]
            return [_row(20, "4724")]

    queued: list[tuple[int, str, dict[str, str]]] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_producer.enqueue_semantic_job",
        lambda _cur, *, source_event_id, payload, job_kind="normalize_event": queued.append(
            (source_event_id, job_kind, dict(payload))
        ),
    )

    result = publish_investigation_candidates(Cursor(), [20])

    assert queued == [
        (20, "normalize_event", {"selection_reason": "signal"}),
        (20, "investigation_context", {"selection_reason": "late_context_expansion"}),
    ]
    assert result["queued"] == 2


def test_late_reset_context_expansion_is_bounded_and_reports_continuation() -> None:
    reset_at = datetime(2026, 9, 13, 1, 0, tzinfo=timezone.utc)

    class Cursor:
        def __init__(self) -> None:
            self.sql = ""
            self.params = ()

        def execute(self, sql, params=()):
            self.sql = " ".join(str(sql).split())
            self.params = params

        def fetchone(self):
            return {
                "domain_id": 7,
                "target_user_sid": "S-1-5-21-100-200-300-400",
                "time_created_utc": reset_at,
                "event_id": 4724,
                "channel": "Security",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "keywords": "0x8020000000000000",
            }

        def fetchall(self):
            assert "limit %s" in self.sql.casefold()
            assert self.params[-1] == 101
            return [{
                "source_event_id": value,
                "login_target_user_sid": "S-1-5-21-100-200-300-400",
            } for value in range(1, 102)]

    selected, has_more = select_investigation_context_expansion_ids(
        Cursor(),
        reset_source_event_id=20,
        limit=100,
    )

    assert selected == tuple(range(1, 101))
    assert has_more is True


def test_late_reset_context_expansion_applies_exact_sid_before_page_limit() -> None:
    """Noncanonical SQL candidates cannot consume the bounded expansion page."""
    reset_at = datetime(2026, 9, 13, 1, 0, tzinfo=timezone.utc)

    class Cursor:
        def __init__(self) -> None:
            self.sql = ""
            self.params = ()

        def execute(self, sql, params=()):
            self.sql = " ".join(str(sql).split())
            self.params = params

        def fetchone(self):
            return {
                "domain_id": 7,
                "target_user_sid": "S-1-5-21-100-200-300-400",
                "time_created_utc": reset_at,
                "event_id": 4724,
                "channel": "Security",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "keywords": "0x8020000000000000",
            }

        def fetchall(self):
            return [{
                "source_event_id": 9,
                "login_target_user_sid": "S-1-5-21-100-200-300-400",
            }]

    cur = Cursor()
    selected, has_more = select_investigation_context_expansion_ids(
        cur, reset_source_event_id=20, limit=1,
    )

    assert selected == (9,)
    assert has_more is False
    assert "login.target_user_sid=%s" in cur.sql
    assert "lower(nullif(btrim(login.target_user_sid),'')" not in cur.sql
    assert cur.params[3] == "S-1-5-21-100-200-300-400"


def test_investigation_context_requires_exact_identity_time_and_success() -> None:
    reset_at = datetime(2026, 9, 13, 1, 0, tzinfo=timezone.utc)

    def row(source_event_id: int, **changes):
        value = {
            "source_event_id": source_event_id,
            "login_domain_id": 7,
            "login_target_user_sid": "S-1-5-21-100-200-300-400",
            "login_time_created_utc": reset_at + timedelta(minutes=30),
            "reset_domain_id": 7,
            "reset_target_user_sid": "S-1-5-21-100-200-300-400",
            "reset_time_created_utc": reset_at,
            "reset_keywords": "0x8020000000000000",
        }
        value.update(changes)
        return value

    assert _eligible_investigation_context_ids([
        row(1),
        row(2, reset_target_user_sid="S-1-5-21-OTHER"),
        row(3, reset_domain_id=8),
        row(4, login_time_created_utc=reset_at + timedelta(hours=1, seconds=1)),
        row(5, reset_keywords="0x8010000000000000"),
        row(6, login_time_created_utc=reset_at),
    ]) == (1,)


def test_investigation_context_rejects_noncanonical_sid_variants() -> None:
    """A valid SQL candidate must still satisfy the shared exact-SID contract."""
    reset_at = datetime(2026, 9, 13, 1, 0, tzinfo=timezone.utc)

    def row(source_event_id: int, sid: str) -> dict[str, object]:
        return {
            "source_event_id": source_event_id,
            "login_domain_id": 7,
            "login_target_user_sid": sid,
            "login_time_created_utc": reset_at + timedelta(minutes=30),
            "reset_domain_id": 7,
            "reset_target_user_sid": sid,
            "reset_time_created_utc": reset_at,
            "reset_keywords": "0x8020000000000000",
        }

    assert _eligible_investigation_context_ids([
        row(1, "S-1-5-21-100-200-300-400"),
        row(2, "-"),
        row(3, "S-1-5-21-100-200-300-400 "),
        row(4, "s-1-5-21-100-200-300-400"),
        row(5, "S-1-5-21-100-200-300-٤٠٠"),
        row(6, "S-1-5-21-100-200-300"),
    ]) == (1,)


def test_storage_v2_invokes_semantic_publication_before_transaction_failpoint() -> None:
    source = inspect.getsource(PostgresStorageV2Repository.write_verified_rows)

    publication = source.index("self._semantic_publisher(cur, event_ids)")
    interruption = source.index('self._failpoint("after_verified_chunk_rows")')

    assert publication < interruption


def test_backfill_delegates_canonical_rows_to_cursor_scoped_writer() -> None:
    source = inspect.getsource(PostgresStorageV2Repository.write_verified_chunk)

    assert "self.write_verified_rows(" in source
