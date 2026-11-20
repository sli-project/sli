"""Split out of ``scripts.run_dc_log_pilot`` (plan 6.3): collection summary and importer output parsing.

Module-level names of ``run_dc_log_pilot`` are looked up through ``_src`` at
call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import scripts.run_dc_log_pilot as _src


def find_output_dir(output: str) -> Path | None:
    for line in output.splitlines():
        if line.startswith("Collection output:"):
            raw_path = line.split(":", 1)[1].strip()
            path = Path(raw_path)
            if not path.is_absolute():
                path = _src.ROOT / path
            return path
    return None


def load_summary(folder: Path) -> dict:
    path = folder / "collection-summary.json"
    return json.loads(path.read_text(encoding="utf-8-sig"))


def summarize_channel_status(summary: dict) -> dict:
    from server.sli.sources.collection_failure_policy import classify_collection_failure

    channels = summary.get("channels") or []

    def _is_limit_truncated(item: dict) -> bool:
        continuity = item.get("continuity")
        return bool(
            isinstance(continuity, dict)
            and continuity.get("truncated") is True
        )

    completed = [
        item for item in channels
        if item.get("status") == "completed" and not _is_limit_truncated(item)
    ]

    def _is_broken_partial(item: dict) -> bool:
        """A partial read that broke mid-stream, not one that merely timed out.

        The wire status is still `partial_timeout`; the collector reports the
        distinction in `partial_kind`.  Without this, a broken read was counted
        as a benign warning and its error never reached `errors`.
        """
        return item.get("partial_kind") == "failure" or item.get("cursor_commit_allowed") is False

    partial = [
        item for item in channels
        if (
            item.get("status") == "partial_timeout"
            and int(item.get("count") or 0) > 0
            and not _is_broken_partial(item)
        ) or (
            item.get("status") == "completed"
            and _is_limit_truncated(item)
        )
    ]
    fatal_failed = [
        item for item in channels
        if item.get("status") in ("failed", "timeout")
        or (item.get("status") == "partial_timeout" and int(item.get("count") or 0) <= 0)
        or (item.get("status") == "partial_timeout" and _is_broken_partial(item))
    ]
    warning = list(partial)
    timed_out = [item for item in channels if item.get("status") in ("timeout", "partial_timeout")]
    collected = completed + partial
    total_events = sum(int(item.get("count") or 0) for item in collected)
    errors = [
        f"{item.get('channel')}: {item.get('error')}"
        for item in fatal_failed
        if item.get("error")
    ]
    warnings = [
        f"{item.get('channel')}: {item.get('error')}"
        for item in warning
        if item.get("error")
    ]
    warnings.extend(
        f"{item.get('channel')}: bounded limit reached before source boundary"
        for item in warning
        if _is_limit_truncated(item)
    )
    decision = classify_collection_failure([
        summary.get("failure_code"),
        summary.get("error"),
        *(item.get("failure_code") for item in channels),
        *(item.get("error") for item in channels),
    ])
    terminal_block = bool(summary.get("terminal_block")) or decision.blocked
    failure_code = str(summary.get("failure_code") or decision.code or "") or None
    return {
        "channels_total": len(channels),
        "channels_completed": len(completed),
        "channels_partial": len(partial),
        "channels_failed": len(fatal_failed),
        "channels_timeout": len(timed_out),
        "events_collected": total_events,
        "errors": errors,
        "warnings": warnings,
        "all_failed": bool(channels) and not collected,
        "partial_failed": bool(collected) and bool(fatal_failed),
        "partial_warning": bool(warning),
        "terminal_block": terminal_block,
        "failure_code": failure_code,
        "import_allowed": not terminal_block,
        "retry_policy": "operator_recovery_required" if terminal_block else "bounded_transient",
    }


def write_collection_block_marker(output_dir: Path, summary: dict, channel_status: dict, *, server: str) -> Path:
    """Quarantine a non-retryable batch before any importer or cursor update."""
    marker = output_dir / "collection-blocked.json"
    payload = {
        "status": "blocked",
        "failure_code": channel_status.get("failure_code"),
        "failure_scope": "worker_identity",
        "retry_policy": "operator_recovery_required",
        "pipeline_disposition": "blocked_pre_import",
        "import_attempted": False,
        "cursor_advanced": False,
        "server": server,
        "started_at": summary.get("started_at"),
        "finished_at": summary.get("finished_at"),
        "operator_action": (
            "Восстановите Windows-контекст процесса сбора и выполните явную контрольную проверку; "
            "автоматический повтор и импорт этой папки запрещены."
        ),
    }
    marker.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    summary.update(payload)
    (output_dir / "collection-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return marker


def channel_file_stats(output_dir: Path, channel: str) -> dict[str, int]:
    safe_channel = re.sub(r'[\\/:*?"<>| ]+', '_', channel)
    path = output_dir / f"{safe_channel}.jsonl"
    count = 0
    latest_record_id = 0
    if not path.is_file():
        return {"count": 0, "latest_event_record_id": 0}
    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            count += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                latest_record_id = max(latest_record_id, int(record.get("record_id") or 0))
            except (TypeError, ValueError):
                pass
    return {"count": count, "latest_event_record_id": latest_record_id}


def log_channel_summaries(server: str, output_dir: Path, summary: dict, *, phase: str) -> None:
    for item in summary.get("channels") or []:
        channel = str(item.get("channel") or "")
        if not channel:
            continue
        stats = _src.channel_file_stats(output_dir, channel)
        status = str(item.get("status") or "unknown")
        _src.log_event(
            "runner",
            "channel_collection_status",
            "Channel collection status.",
            server=server,
            channel=channel,
            status=status,
            count=int(item.get("count") or stats["count"] or 0),
            partial_count=stats["count"] if status == "partial_timeout" else 0,
            latest_event_record_id=stats["latest_event_record_id"] or None,
            cursor_strategy=item.get("cursor_strategy"),
            cursor_fallback_reason=item.get("cursor_fallback_reason"),
            latest_available_record_id=item.get("latest_available_record_id"),
            error=item.get("error"),
            path=str(output_dir),
            collector_backend=item.get("collector_backend") or summary.get("collector_backend"),
            backend_reason=item.get("backend_reason") or summary.get("backend_reason"),
        )


def _load_json_object(value: str | None) -> dict[str, int]:
    if not value:
        return {}
    try:
        loaded = json.loads(value)
    except json.JSONDecodeError:
        return {}
    if not isinstance(loaded, dict):
        return {}
    result: dict[str, int] = {}
    for key, raw in loaded.items():
        try:
            result[str(key)] = int(raw)
        except (TypeError, ValueError):
            continue
    return result


def parse_import_stats(output: str) -> dict[str, dict[str, int]]:
    safe_to_channel = {re.sub(r'[\\/:*?"<>| ]+', '_', channel): channel for channel in [
        "Security",
        "System",
        "Directory Service",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "DNS Server",
    ]}
    stats: dict[str, dict[str, int]] = {}
    for line in output.splitlines():
        match = re.search(
            r"(?P<safe>[A-Za-z0-9_.-]+)\.jsonl: inserted=(?P<inserted>\d+), "
            r"skipped=(?P<skipped>\d+)"
            r"(?:, source_capture_continuity_persisted=(?P<continuity>[01]))?",
            line,
        )
        if not match:
            continue
        channel = safe_to_channel.get(match.group("safe"), match.group("safe").replace("_", " "))
        stats[channel] = {
            "inserted": int(match.group("inserted")),
            "skipped": int(match.group("skipped")),
            "source_capture_continuity_persisted": match.group("continuity") == "1",
        }
    return stats


def parse_import_profile(output: str) -> dict:
    for line in output.splitlines():
        if not line.startswith("import_profile="):
            continue
        try:
            value = json.loads(line.split("=", 1)[1])
        except (json.JSONDecodeError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}
    return {}
