namespace Sli.Server.Vpn;

// Queries preserve the Python control read boundary. All values are positional parameters.
internal static class RadiusReconciliationSql
{
    public const string Sources = """
        select source_instance_id,organization_scope
        from acquisition_source_instances
        where source_kind='windows.nps.radius'
        order by source_instance_id
        """;
    public const string Subscriptions = """
        select subscription_id
        from acquisition_consumer_subscriptions
        where source_instance_id=$1
          and stream_id=$2
          and transport_binding=$3
        order by subscription_id
        """;
    public const string Cursor = """
        select revision
        from acquisition_stream_cursors
        where source_instance_id=$1
          and stream_id=$2
          and transport_binding=$3
        """;
    public const string Baseline = """
        select
          (
            select count(*)::bigint
            from radius_accounting_session_observations observation
            join core_evidence_manifests evidence
              on evidence.evidence_uid=observation.evidence_uid
            where evidence.source_instance_id=$1
              and evidence.stream_id=$2
              and evidence.transport_binding=$3
          ) as observations,
          (
            select count(*)::bigint
            from radius_session_projection_receipts receipt
            join radius_accounting_session_observations observation
              on observation.observation_id=receipt.observation_id
            join core_evidence_manifests evidence
              on evidence.evidence_uid=observation.evidence_uid
            where evidence.source_instance_id=$4
              and evidence.stream_id=$5
              and evidence.transport_binding=$6
              and receipt.outcome='identity_unresolved'
          ) as terminal_unresolved_receipts,
          (
            select count(*)::bigint
            from acquisition_delivery_outbox delivery
            where delivery.subscription_id=$7
              and delivery.delivery_state in ('queued','leased')
          ) as nonterminal_deliveries,
          to_regclass('radius_session_reconciliation_attempts') is not null as attempts_table,
          to_regclass('radius_session_identity_overlays') is not null as overlays_table,
          to_regrole('adlog_radius_session_reconciliation_writer') is not null as writer_role,
          (select rolcreaterole from pg_roles where rolname=current_user)
            as migration_role_can_create_role
        """;
    public const string Markers = """
        select version,name
        from schema_migrations
        where version between 61 and 80
        order by version
        """;
    public const string OutputCounts = """
        select
          (
            select count(*)::bigint
            from radius_session_reconciliation_attempts attempt
            join radius_accounting_session_observations observation
              on observation.observation_id=attempt.observation_id
            join core_evidence_manifests evidence
              on evidence.evidence_uid=observation.evidence_uid
            where evidence.source_instance_id=$1
              and evidence.stream_id=$2
              and evidence.transport_binding=$3
          ) as attempt_count,
          (
            select count(*)::bigint
            from radius_session_identity_overlays overlay
            join radius_accounting_session_observations observation
              on observation.observation_id=overlay.observation_id
            join core_evidence_manifests evidence
              on evidence.evidence_uid=observation.evidence_uid
            where evidence.source_instance_id=$4
              and evidence.stream_id=$5
              and evidence.transport_binding=$6
          ) as overlay_count
        """;
    public const string Terminal = """
        select observation.observation_id::text,observation.evidence_uid::text,
               observation.lifecycle_event,observation.timestamp_state,
               observation.observed_at_utc,evidence.cursor_start_byte_offset,
               evidence.canonical_record_sha256,evidence.object_sha256,
               evidence.object_size_bytes,evidence.batch_record_ordinal
        from radius_accounting_session_observations observation
        join core_evidence_manifests evidence
          on evidence.evidence_uid=observation.evidence_uid
        where evidence.source_instance_id=$1
          and evidence.stream_id=$2
          and evidence.transport_binding=$3
          and exists(
            select 1 from radius_session_projection_receipts receipt
            where receipt.observation_id=observation.observation_id
              and receipt.outcome='identity_unresolved'
          )
        order by evidence.cursor_start_byte_offset,observation.observation_id
        """;
    public const string LockedCursor = """
        select revision
        from acquisition_stream_cursors
        where source_instance_id=$1
          and stream_id=$2
          and transport_binding=$3
        for share
        """;
    public const string LockedBaseline = """
        select
          (
            select count(*)::bigint
            from radius_accounting_session_observations observation
            join core_evidence_manifests evidence
              on evidence.evidence_uid=observation.evidence_uid
            where evidence.source_instance_id=$1
              and evidence.stream_id=$2
              and evidence.transport_binding=$3
          ) as observations,
          (
            select count(*)::bigint
            from radius_session_projection_receipts receipt
            join radius_accounting_session_observations observation
              on observation.observation_id=receipt.observation_id
            join core_evidence_manifests evidence
              on evidence.evidence_uid=observation.evidence_uid
            where evidence.source_instance_id=$4
              and evidence.stream_id=$5
              and evidence.transport_binding=$6
              and receipt.outcome='identity_unresolved'
          ) as terminal_unresolved_receipts,
          (
            select count(*)::bigint
            from acquisition_delivery_outbox delivery
            where delivery.subscription_id=$7
              and delivery.delivery_state in ('queued','leased')
          ) as nonterminal_deliveries,
          to_regclass('radius_session_reconciliation_attempts') is not null as attempts_table,
          to_regclass('radius_session_identity_overlays') is not null as overlays_table,
          to_regrole('adlog_radius_session_reconciliation_writer') is not null as writer_role,
          (select rolcreaterole from pg_roles where rolname=current_user)
            as migration_role_can_create_role
        """;
    public const string ProjectionRequests = """
        select delivery.delivery_id,overlay.session_identity_key
        from acquisition_delivery_outbox delivery
        join radius_session_identity_overlays overlay
          on overlay.observation_id=delivery.observation_id
        where delivery.subscription_id=$1
          and delivery.delivery_state='delivered'
          and delivery.observation_id=any($2::uuid[])
        order by delivery.delivery_id
        """;
    public const string Postcondition = """
        select
          (
            select count(*)::bigint
            from radius_session_reconciliation_attempts attempt
            where attempt.observation_id=any($1::uuid[])
          ) as attempt_count,
          (
            select count(*) filter(where attempt.outcome='projected')::bigint
            from radius_session_reconciliation_attempts attempt
            where attempt.observation_id=any($2::uuid[])
          ) as projected_attempt_count,
          (
            select count(*) filter(where attempt.outcome='still_unresolved')::bigint
            from radius_session_reconciliation_attempts attempt
            where attempt.observation_id=any($3::uuid[])
          ) as still_unresolved_attempt_count,
          (
            select count(*)::bigint
            from radius_session_identity_overlays overlay
            where overlay.observation_id=any($4::uuid[])
          ) as overlay_count,
          (
            select count(*)::bigint
            from radius_vpn_session_projection projection
            where exists (
              select 1
              from radius_session_identity_overlays overlay
              where overlay.observation_id=any($5::uuid[])
                and overlay.session_identity_key=projection.session_identity_key
            )
          ) as projection_row_count,
          (
            select count(*)::bigint
            from radius_accounting_session_observations observation
            where observation.observation_id=any($6::uuid[])
              and observation.identity_state='unresolved'
          ) as original_unresolved_observation_count,
          (
            select count(*)::bigint
            from radius_session_projection_receipts receipt
            where receipt.observation_id=any($7::uuid[])
              and receipt.outcome='identity_unresolved'
          ) as original_unresolved_receipt_count
        """;
}
