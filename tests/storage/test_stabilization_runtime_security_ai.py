from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from tests.support.pg_fake import FakePgStore


def _seed_security_events(store: FakePgStore) -> None:
    for record_id, event_id, target in [(1, 4724, 'ivanov'), (2, 4740, 'ivanov'), (3, 4728, 'admin')]:
        store.add_event(
            event_id=event_id, time=f"2026-07-07T08:0{record_id}:00Z", record_id=record_id,
            subject='admin', subject_domain='DEMO', target=target, target_domain='DEMO',
            ip='192.0.2.7', workstation='WS01', event_data={},
        )


def test_runtime_storage_cleanup_is_dry_run_and_moves_only_on_apply(tmp_path: Path) -> None:
    from server.sli.storage.runtime_storage import apply_raw_cleanup_plan, build_raw_cleanup_plan, get_runtime_storage_summary

    raw = tmp_path / 'data' / 'raw'
    old = raw / 'pilot' / 'old.jsonl'
    old.parent.mkdir(parents=True)
    old.write_text('{}\n', encoding='utf-8')
    old_time = time.time() - 10 * 86400
    os.utime(old, (old_time, old_time))
    archive = tmp_path / 'data' / 'raw_archive'

    plan = build_raw_cleanup_plan(raw_dir=raw, archive_dir=archive, older_than_days=7)
    assert plan['total_candidates'] == 1
    dry = apply_raw_cleanup_plan(plan, apply=False)
    assert old.exists()
    assert dry['mode'] == 'dry-run'
    applied = apply_raw_cleanup_plan(plan, apply=True)
    assert not old.exists()
    assert (archive / 'pilot' / 'old.jsonl').exists()
    summary = get_runtime_storage_summary(root=tmp_path)
    assert 'sizes' in summary and 'disk' in summary


def test_security_events_monitor_groups_and_links(monkeypatch) -> None:
    from server.sli.events.security_events_monitor import get_security_events_monitor_data, render_security_events_monitor_report

    store = FakePgStore().install_security_monitor(monkeypatch)
    _seed_security_events(store)
    data = get_security_events_monitor_data(group='passwords', account='ivanov')
    assert len(data['items']) == 1
    assert data['items'][0]['group_label'] == 'Пароли'
    html = render_security_events_monitor_report(data)
    assert 'Ключевые события безопасности' in html
    assert 'Цепочка' in html


def test_collector_history_records_speed_metrics(monkeypatch) -> None:
    from server.sli.sources import collector_adaptive
    from server.sli.core import postgres_runtime_pipeline

    executed: list[tuple[str, tuple]] = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, sql, params=()):
            executed.append((' '.join(sql.split()).lower(), params))

        def fetchone(self):
            return None

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(postgres_runtime_pipeline, 'connect', lambda: Conn())
    monkeypatch.setattr(postgres_runtime_pipeline, 'log_event', lambda *args, **kwargs: None)
    monkeypatch.setattr(collector_adaptive, 'log_event', lambda *args, **kwargs: None)
    summary = {'channels': [{'channel': 'Security', 'status': 'completed', 'count': 3, 'started_at': '2026-07-07T08:00:00Z', 'finished_at': '2026-07-07T08:00:05Z', 'duration_seconds': 5, 'max_events': 500, 'timeout_seconds': 900}]}
    postgres_runtime_pipeline.record_collector_channel_runs_pg(server='DC1', summary=summary, import_stats={'Security': {'inserted': 3, 'skipped': 0}}, import_duration_ms=200)
    runs = [params for sql, params in executed if 'insert into collector_channel_runs' in sql]
    assert len(runs) == 1
    assert runs[0][16] == 5000  # query_duration_ms
    assert runs[0][17] == 200  # import_duration_ms
    assert runs[0][22] and runs[0][22] > 0  # events_per_second


def test_redaction_leak_checker_blocks_sensitive_payload() -> None:
    from server.sli.access.redaction_leak_check import check_redaction_leaks

    blocked = check_redaction_leaks({'user': 'DEMO\\ivanov', 'ip': '192.0.2.7'}, redaction_level='strict')
    assert blocked['blocked'] is True
    ok = check_redaction_leaks({'user': 'account_001', 'ip': 'ip_001', 'time': '08:00:00'}, redaction_level='strict')
    assert ok['status'] == 'ok'


@pytest.mark.posix_only
def test_runtime_storage_cleanup_can_zip_archive_and_explain_exclusions(tmp_path: Path) -> None:
    from server.sli.storage.runtime_storage import apply_raw_cleanup_plan, build_raw_cleanup_plan, get_runtime_storage_summary

    raw = tmp_path / 'data' / 'raw'
    old = raw / 'pilot' / 'old.jsonl'
    recent = raw / 'pilot' / 'recent.jsonl'
    old.parent.mkdir(parents=True)
    old.write_text('{}\n', encoding='utf-8')
    recent.write_text('{}\n', encoding='utf-8')
    old_time = time.time() - 10 * 86400
    os.utime(old, (old_time, old_time))
    archive = tmp_path / 'data' / 'raw_archive'

    plan = build_raw_cleanup_plan(raw_dir=raw, archive_dir=archive, older_than_days=7, archive_mode='zip')
    assert plan['archive_mode'] == 'zip'
    assert plan['total_candidates'] == 1
    assert plan['exclusion_summary']['recent_file'] == 1
    applied = apply_raw_cleanup_plan(plan, apply=True)

    assert not old.exists()
    assert recent.exists()
    assert applied['archived'][0]['archive_name'] == 'pilot/old.jsonl'
    assert Path(applied['zip_path']).is_file()
    summary = get_runtime_storage_summary(root=tmp_path)
    assert summary['last_raw_cleanup']['archive_mode'] == 'zip'
    assert summary['last_raw_cleanup']['archived_count'] == 1
