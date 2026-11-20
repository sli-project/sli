from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts.maintenance.warm_tier_read_probe import (
    MAX_EXTERNAL_GROUP_BY_BYTES,
    MAX_QUERY_MEMORY_BYTES,
    MAX_QUERY_THREADS,
    MAX_RESULT_BYTES,
    SESSION_ANALYTICS_QUERY,
    build_command,
    run_probe,
)


NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


def test_probe_command_is_parameterized_bounded_and_read_only() -> None:
    command = build_command(NOW - timedelta(days=90), NOW)
    source = Path(
        "scripts/maintenance/warm_tier_read_probe.py"
    ).read_text(encoding="utf-8").lower()

    assert command[:4] == [
        "docker",
        "exec",
        "sli-warm-tier-step1",
        "clickhouse-client",
    ]
    assert command[command.index("--readonly") + 1] == "1"
    assert "--max_execution_time" in command
    assert command[command.index("--max_memory_usage") + 1] == str(
        MAX_QUERY_MEMORY_BYTES
    )
    assert command[command.index("--max_bytes_before_external_group_by") + 1] == str(
        MAX_EXTERNAL_GROUP_BY_BYTES
    )
    assert command[command.index("--max_threads") + 1] == str(MAX_QUERY_THREADS)
    assert "--max_result_rows" in command
    assert command[command.index("--max_result_bytes") + 1] == str(MAX_RESULT_BYTES)
    assert "{from_utc:datetime64" in SESSION_ANALYTICS_QUERY.lower()
    assert "{to_utc:datetime64" in SESSION_ANALYTICS_QUERY.lower()
    assert all(
        statement not in SESSION_ANALYTICS_QUERY.lower()
        for statement in ("insert ", "update ", "delete ", "drop ", "alter ", "truncate ")
    )
    assert "shell=true" not in source


def test_probe_rejects_unbounded_or_reversed_windows_before_docker() -> None:
    with pytest.raises(ValueError, match="365"):
        run_probe(NOW - timedelta(days=366), NOW)

    with pytest.raises(ValueError, match="before"):
        run_probe(NOW, NOW)
