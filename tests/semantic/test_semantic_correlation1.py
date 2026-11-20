from datetime import datetime, timedelta, timezone

from server.sli.semantic.semantic_correlation import aggregate_bruteforce_attempts, correlate_session_privilege_observation
from server.sli.semantic.semantic_processing import StoredEvent, normalize_windows_event


def _event(identity: int, windows_id: int, minute: int, data: dict[str, str]):
    return normalize_windows_event(
        StoredEvent(
            identity,
            windows_id,
            'Security',
            'DC1',
            datetime(2026, 7, 18, 8, minute, tzinfo=timezone.utc),
            data,
            provider='Microsoft-Windows-Security-Auditing',
        )
    )


def test_session_relation_requires_server_scoped_logon_identity() -> None:
    relation = correlate_session_privilege_observation([
        _event(1, 4624, 0, {'TargetUserName': 'alice', 'TargetLogonId': '0x1'}),
        _event(2, 4672, 1, {'SubjectUserName': 'alice', 'SubjectLogonId': '0x1'}),
    ])
    assert relation[0].relation_kind == 'authentication.session.has_special_privileges'
    assert 'не повышение прав' in relation[0].explanation


def test_session_relation_rejects_out_of_window_reuse() -> None:
    events = [
        _event(3, 4624, 0, {'TargetUserName': 'alice', 'TargetLogonId': '0x2'}),
        _event(4, 4672, 30, {'SubjectUserName': 'alice', 'SubjectLogonId': '0x2'}),
    ]
    assert correlate_session_privilege_observation(events, window=timedelta(minutes=15)) == []


def test_bruteforce_is_explicit_aggregate_not_generic_proximity() -> None:
    events = [_event(index, 4625, index, {'TargetUserName': 'alice', 'IpAddress': '192.0.2.6'}) for index in range(1, 6)]
    relations = aggregate_bruteforce_attempts(events)
    assert len(relations) == 1 and len(relations[0].source_event_ids) == 5
