from __future__ import annotations

from server.sli.reporting.ui_labels import status_label

BS = chr(92)


def test_findings_report_deduplicates_entities_and_localizes_status() -> None:
    from server.sli.semantic.findings import render_findings_report

    actor = {"entity_type": "account", "display_name": "DEMO" + BS + "admin", "entity_role": "actor"}
    target = {"entity_type": "account", "display_name": "DEMO" + BS + "ivanov", "entity_role": "target"}
    data = {
        "generated_at_utc": "2026-07-07T08:03:00Z",
        "summary": [{"severity": "high", "status": "repeated", "count": 1}],
        "items": [{
            "id": 1, "title": "Сброс пароля", "severity": "high", "status": "repeated", "confidence": 0.7,
            "actor": "DEMO" + BS + "admin", "target": "DEMO" + BS + "ivanov", "source": "192.0.2.7",
            "evidence_count": 3, "repeat_count": 2, "recommended_action": "Проверить основание.",
            # 200 duplicated rows, as a join without grouping would produce them
            "entities": [dict(actor) for _ in range(100)] + [dict(target) for _ in range(100)],
            "evidence": [{"event_db_id": 1, "event_id": 4724, "hostname": "DC1"}],
        }],
    }

    report = render_findings_report(data)
    assert 'Findings: объекты проверки' in report
    assert 'Что сделать' in report
    assert 'повторяется' in report
    assert '>repeated<' not in report
    assert 'UTC: 2026-' not in report
    assert report.count("DEMO" + BS + "admin") == 2  # actor card + related entity, not hundreds of repeats
    assert len(report) < 80000


def test_findings_status_labels_are_localized() -> None:
    assert status_label('repeated') == 'повторяется'
    assert status_label('false_positive') == 'ложное срабатывание'
