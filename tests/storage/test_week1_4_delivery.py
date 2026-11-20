from __future__ import annotations

from pathlib import Path

import pytest

from tests.support.pg_fake import FakePgStore


def _seed_story(store: FakePgStore) -> None:
    rows = [
        (1, 4625, '2026-07-07T08:00:00Z', 'alice', 'alice', '192.0.2.2', 'WS01', 'bad password'),
        (2, 4624, '2026-07-07T08:05:00Z', 'alice', 'alice', '192.0.2.2', 'WS01', 'successful logon'),
        (3, 4672, '2026-07-07T08:06:00Z', 'alice', 'alice', '192.0.2.2', 'WS01', 'special privileges'),
        (4, 4724, '2026-07-07T08:10:00Z', 'admin', 'alice', '192.0.2.11', 'WS02', 'password reset'),
        (5, 4740, '2026-07-07T08:20:00Z', 'DC1$', 'alice', '192.0.2.2', 'WS01', 'account locked'),
    ]
    for record_id, event_id, ts, subject, target, ip, workstation, msg in rows:
        store.add_event(
            event_id=event_id, time=ts, time_local=ts.replace('T', ' ').replace('Z', ''), record_id=record_id,
            subject=subject, target=target, ip=ip, workstation=workstation, message=msg,
            event_data={'TargetUserName': target, 'IpAddress': ip},
        )


def test_operations_config_and_system_health(tmp_path: Path) -> None:
    from server.sli.core.app_config import load_config
    from server.sli.ops.system_health import get_system_health, render_system_health_report

    cfg_file = tmp_path / 'adlog_config.yaml'
    cfg_file.write_text('retention:\n  raw_retention_days: 7\nhealth:\n  lag_warn_minutes: 45\n', encoding='utf-8')
    cfg = load_config(cfg_file)
    assert cfg.raw_retention_days == 7
    assert cfg.health_lag_warn_minutes == 45

    # The removed file argument is rejected before any database access.
    with pytest.raises(TypeError):
        get_system_health(tmp_path / 'not-the-runtime-db')
    assert callable(render_system_health_report)


def test_retention_plan_is_dry_run_by_default(tmp_path: Path, monkeypatch) -> None:
    from server.sli.core.app_config import AdLogConfig
    from server.sli.storage.retention import apply_retention

    old = tmp_path / 'old.log'
    old.write_text('x', encoding='utf-8')
    import os, time
    os.utime(old, (time.time() - 5 * 86400, time.time() - 5 * 86400))
    monkeypatch.setattr("server.sli.storage.storage_policy.DATA_DIR", tmp_path / "data")
    monkeypatch.setattr("server.sli.storage.storage_policy.ROOT", tmp_path)
    monkeypatch.setattr("server.sli.storage.storage_policy.LOG_DIR", tmp_path)
    cfg = AdLogConfig(reports_dir=str(tmp_path), log_dir=str(tmp_path), log_retention_days=1)
    dry = apply_retention(apply=False, config=cfg)
    assert dry['mode'] == 'dry_run'
    assert old.exists()
    assert dry['total_candidates'] >= 1
    assert dry['legacy_planner_retired'] is True


def test_legacy_retention_apply_is_fail_closed(tmp_path: Path, monkeypatch) -> None:
    from server.sli.core.app_config import AdLogConfig
    from server.sli.storage.retention import apply_retention

    old = tmp_path / 'old.log'
    old.write_text('must remain', encoding='utf-8')
    import os, time
    os.utime(old, (time.time() - 5 * 86400, time.time() - 5 * 86400))
    monkeypatch.setattr("server.sli.storage.storage_policy.DATA_DIR", tmp_path / "data")
    monkeypatch.setattr("server.sli.storage.storage_policy.ROOT", tmp_path)
    monkeypatch.setattr("server.sli.storage.storage_policy.LOG_DIR", tmp_path)
    cfg = AdLogConfig(reports_dir=str(tmp_path), log_dir=str(tmp_path), log_retention_days=1)

    result = apply_retention(apply=True, config=cfg)

    assert result['status'] == 'blocked'
    assert result['mode'] == 'blocked'
    assert result['apply_supported'] is False
    assert result['deleted'] == []
    assert result['errors'][0]['code'] == 'legacy_retention_apply_disabled'
    assert old.read_text(encoding='utf-8') == 'must remain'


def test_investigation_workspace_links_chain_and_findings(tmp_path: Path, monkeypatch) -> None:
    from server.sli.semantic import investigation
    from server.sli.semantic.investigation import get_investigation_workspace_data, render_investigation_workspace_report

    _seed_story(FakePgStore().install_event_search(monkeypatch))
    # Findings storage is PostgreSQL-only; the store only supplies the event chain.
    monkeypatch.setattr(
        investigation,
        'get_findings_data',
        lambda **kwargs: {
            'backend': 'postgres',
            'items': [
                {'id': 1, 'title': 'Неудачный вход', 'severity': 'high', 'status': 'new', 'target': 'alice', 'evidence_count': 1},
                {'id': 2, 'title': 'Сброс пароля', 'severity': 'high', 'status': 'new', 'target': 'alice', 'evidence_count': 1},
            ],
            'summary': [],
        },
    )
    data = get_investigation_workspace_data(q='alice', time_from='2026-07-01T00:00:00Z')
    assert data['summary']['total_events'] == 5
    assert data['summary']['chain_events'] >= 4
    assert data['summary']['findings'] >= 2
    html = render_investigation_workspace_report(data)
    assert 'Рабочее место расследования' in html
    assert 'Цепочка событий' in html
    assert 'Связанные findings' in html
