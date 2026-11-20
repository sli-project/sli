from __future__ import annotations

import argparse
from pathlib import Path
from zipfile import ZipFile

from scripts.maintenance.export_report_snapshots import (
    CaptureResult,
    _safe_name,
    _warnings_for_text,
    build_targets,
    make_zip,
    write_index,
    write_manifest,
)


def test_build_targets_contains_core_reports_and_api() -> None:
    targets = build_targets(["administrator"], include_api=True)
    paths = {target.path for target in targets}

    assert "/" in paths
    assert "/reports/findings.html" in paths
    assert "/reports/security-events-monitor.html" in paths
    assert "/api/collector/health" in paths
    assert any(target.path.startswith("/reports/account-timeline.html?q=administrator") for target in targets)


def test_safe_name_is_filesystem_friendly() -> None:
    assert _safe_name("/reports/event-details.html?event_id=4724&channel=Security") == "reports_event-details.html_event_id=4724_channel=security"
    assert _safe_name("DOMAIN\\User Name") == "domain_user_name"


def test_warning_detector_finds_raw_iso_timestamp() -> None:
    warnings = _warnings_for_text("<span>2026-07-07T12:34:56Z</span>", 200, 42)
    assert "найден сырой ISO timestamp" in warnings


def test_warning_detector_finds_long_related_entities_block() -> None:
    text = "<p>Связанные сущности: " + ("user01; " * 260) + "</p>"
    warnings = _warnings_for_text(text, 200, len(text.encode("utf-8")))
    assert any("слишком длинный блок связанных сущностей" in warning for warning in warnings)


def test_manifest_index_and_zip_are_created(tmp_path: Path) -> None:
    result = CaptureResult(
        name="findings",
        kind="html",
        source_url="http://127.0.0.1:8080/reports/findings.html",
        output_file="findings.html",
        status_code=200,
        ok=True,
        bytes=123,
        elapsed_ms=7,
        warnings=["найден сырой ISO timestamp"],
    )
    (tmp_path / "findings.html").write_text("<html>ok</html>", encoding="utf-8")
    args = argparse.Namespace(q=["administrator"], timeout=30, no_api=False, redact=True)

    write_index(tmp_path, [result], "http://127.0.0.1:8080", redact=True)
    write_manifest(tmp_path, [result], "http://127.0.0.1:8080", args)
    zip_path = make_zip(tmp_path)

    assert (tmp_path / "index.html").is_file()
    assert (tmp_path / "snapshot_manifest.json").is_file()
    assert zip_path.is_file()
    with ZipFile(zip_path) as zf:
        names = set(zf.namelist())
    assert f"{tmp_path.name}/index.html" in names
    assert f"{tmp_path.name}/snapshot_manifest.json" in names


def test_redact_api_json_stays_valid_and_masks_domain_user() -> None:
    import json
    from scripts.maintenance.export_report_snapshots import _redact_text

    raw = json.dumps({"account": "EXAMPLE\\ivanov", "ip": "192.0.2.13"}, ensure_ascii=False)
    redacted = _redact_text(raw, kind="api")
    parsed = json.loads(redacted)

    assert parsed["account"] == "DOMAIN\\account_xxx"
    assert parsed["ip"] == "ip_xxx"
    assert "\x07" not in redacted


def test_review_backlog_is_created_from_page_lint(tmp_path: Path) -> None:
    from scripts.maintenance.export_report_snapshots import write_review_backlog

    result = CaptureResult(
        name="system_health",
        kind="html",
        source_url="http://127.0.0.1:8080/reports/system-health.html",
        output_file="system_health.html",
        status_code=200,
        ok=True,
        bytes=100,
        elapsed_ms=5,
        warnings=["найден raw JSON/pre-блок в пользовательском UI"],
    )
    (tmp_path / "system_health.html").write_text("<html><pre>{}</pre></html>", encoding="utf-8")

    review = write_review_backlog(tmp_path, [result])

    assert review["summary"]["warnings"] == 1
    assert (tmp_path / "snapshot_review.json").is_file()
    assert (tmp_path / "snapshot_review.html").is_file()
    assert (tmp_path / "snapshot_review_checklist.md").is_file()
