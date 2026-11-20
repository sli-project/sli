"""GPO snapshot persistence, independent of AD plugin admission."""
from __future__ import annotations

from typing import Any

from server.sli.sources.gpo_v2_source import canonical_snapshot, redact_gpo_snapshot

def _store_gpo_v2_snapshot(cur: Any, *, domain_id: int, run_id: str, snapshot: dict[str, Any]) -> None:
    payload_text, payload_sha256 = canonical_snapshot(redact_gpo_snapshot(snapshot))
    cur.execute(
        """
        insert into gpo_report_v2_source_snapshots(
            domain_id, source_run_id, schema_version, collector_version,
            collection_status, source_started_at_utc, source_completed_at_utc,
            source_observed_at_utc, import_status, gpo_count, scope_count,
            link_count, setting_count, permission_count, wmi_filter_count,
            payload_json, payload_sha256
        ) values (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s::jsonb, decode(%s,'hex')
        )
        on conflict(domain_id,source_run_id) do nothing
        """,
        (
            domain_id,
            run_id,
            snapshot["schema_version"],
            snapshot["collector_version"],
            snapshot["collection_status"],
            snapshot["started_at"],
            snapshot["completed_at"],
            snapshot["observed_at"],
            "completed",
            len(snapshot["gpos"]),
            len(snapshot["scopes"]),
            len(snapshot["links"]),
            len(snapshot["settings"]),
            len(snapshot["permissions"]),
            len(snapshot["wmi_filters"]),
            payload_text,
            payload_sha256,
        ),
    )
