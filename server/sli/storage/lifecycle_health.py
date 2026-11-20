"""Safe diagnostics for live lifecycle workers awaiting a known condition."""

EXPECTED_BLOCK_REASONS = frozenset({
    "snapshot_history_migration_required",
    "source_rows_held_for_processing_or_evidence",
    "owner_storage_policy_changed",
    "history_source_link_details_missing",
    "history_source_archive_unavailable",
    "history_clickhouse_unavailable",
    "published_history_event_batch_incomplete",
    "retention_candidate_history_incomplete",
    "retention_candidate_history_not_published",
    "file_audit_history_unavailable",
    "file_audit_payload_held_or_unresolved",
    "file_audit_semantic_pending",
    "file_audit_evidence_held",
    "purge_lock_unavailable",
    "purge_statement_timeout",
})
WARNING_REASONS = EXPECTED_BLOCK_REASONS | frozenset({
    "ad_snapshot_history_coverage_partial",
    "ad_snapshot_history_backlog_remaining",
    "history_publication_backlog_remaining",
    "fact_history_copy_lock_held",
    "file_audit_retention_backlog_remaining",
    "warm_backlog_remaining",
    "storage_lifecycle_condition_pending",
})


def safe_warning_reason(value: object) -> str:
    return value if isinstance(value, str) and value in WARNING_REASONS else "storage_lifecycle_condition_pending"
