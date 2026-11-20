namespace Sli.Server.Vpn;
internal static class RadiusConsumerSql
{
    public const string Quarantine = """
        update acquisition_delivery_outbox
        set delivery_state='quarantined',
            lease_token=null,lease_until=null,heartbeat_at=now(),
            last_error_code='maximum_attempts_exhausted',
            updated_at=now()
        where subscription_id=$1
          and attempt_count >= $2
          and (
            delivery_state='failed'
            or (
              delivery_state='leased'
              and lease_until<=now()
            )
          )
        """;
    public const string Delivery = """
        select delivery.delivery_id,delivery.observation_id,
               observation.identity_state,
               observation.timestamp_state,
               observation.session_identity_key
        from acquisition_delivery_outbox delivery
        join radius_accounting_session_observations observation
          on observation.observation_id=delivery.observation_id
        where delivery.delivery_id=$1
          and delivery.subscription_id=$2
          and delivery.delivery_state='leased'
          and delivery.lease_token=$3
          and delivery.lease_until>now()
        for update of delivery
        """;
    public const string Prior = """
        select outcome,projected_row_count
        from radius_session_projection_receipts
        where delivery_id=$1
        """;
    public const string Delivered = """
        update acquisition_delivery_outbox
        set delivery_state='delivered',delivered_at=now(),
            lease_token=null,lease_until=null,heartbeat_at=now(),
            last_error_code=null,updated_at=now()
        where delivery_id=$1 and delivery_state='leased'
          and lease_token=$2
        """;
    public const string Receipt = """
        insert into radius_session_projection_receipts(
          delivery_id,observation_id,outcome,
          projected_row_count,consumer_contract_id
        ) values($1,$2,$3,$4,$5)
        """;
    public const string ProjectionLock = """
        select pg_advisory_xact_lock(hashtext('radius-session-projection:'||$1))
        """;
    public const string OverlayReadable = """
        select coalesce(
          has_column_privilege(
            current_user,
            to_regclass('public.radius_session_identity_overlays'),
            'observation_id',
            'SELECT'
          ) and has_column_privilege(
            current_user,
            to_regclass('public.radius_session_identity_overlays'),
            'session_identity_key',
            'SELECT'
          ) and has_column_privilege(
            current_user,
            to_regclass('public.radius_session_identity_overlays'),
            'exact_principal_key',
            'SELECT'
          ),
          false
        )
        """;
    public const string ObservationsOverlay = """
        select observation.observation_id::text,
               observation.lifecycle_event,
               case
                 when overlay.observation_id is not null then 'exact'
                 else observation.identity_state
               end as identity_state,
               observation.timestamp_state,
               coalesce(
                 overlay.session_identity_key,
                 observation.session_identity_key
               ) as session_identity_key,
               coalesce(
                 overlay.exact_principal_key,
                 observation.exact_principal_key
               ) as exact_principal_key,
               observation.observed_at_utc,
               manifest.canonical_record_sha256
        from acquisition_delivery_outbox delivery
        join radius_accounting_session_observations observation
          on observation.observation_id=delivery.observation_id
        join core_evidence_manifests manifest
          on manifest.evidence_uid=observation.evidence_uid
        left join radius_session_identity_overlays overlay
          on overlay.observation_id=observation.observation_id
        where delivery.subscription_id=$1
          and coalesce(
            overlay.session_identity_key,
            observation.session_identity_key
          )=$2
          and observation.timestamp_state='ready'
          and (
            observation.identity_state='exact'
            or overlay.observation_id is not null
          )
          and (
            delivery.delivery_state='delivered'
            or delivery.delivery_id=$3
          )
        order by observation.observed_at_utc,
                 observation.observation_id
        limit $4
        """;
    public const string Observations = """
        select observation.observation_id::text,
               observation.lifecycle_event,
               observation.identity_state,
               observation.timestamp_state,
               observation.session_identity_key,
               observation.exact_principal_key,
               observation.observed_at_utc,
               manifest.canonical_record_sha256
        from acquisition_delivery_outbox delivery
        join radius_accounting_session_observations observation
          on observation.observation_id=delivery.observation_id
        join core_evidence_manifests manifest
          on manifest.evidence_uid=observation.evidence_uid
        where delivery.subscription_id=$1
          and observation.session_identity_key=$2
          and observation.timestamp_state='ready'
          and observation.identity_state='exact'
          and (
            delivery.delivery_state='delivered'
            or delivery.delivery_id=$3
          )
        order by observation.observed_at_utc,
                 observation.observation_id
        limit $4
        """;
    public const string DeleteProjection = """
        delete from radius_vpn_session_projection
        where session_identity_key=$1
        """;
    public const string InsertProjection = """
        insert into radius_vpn_session_projection(
          session_row_id,session_identity_key,exact_principal_key,
          generation,lifecycle_state,completeness,
          started_at_utc,last_observed_at_utc,stopped_at_utc,
          duration_seconds,observation_count,anomalies,
          read_model_contract_id,updated_at
        ) values(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now()
        )
        """;
}
