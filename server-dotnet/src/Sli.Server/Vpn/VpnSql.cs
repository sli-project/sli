// Event SQL has been retired. Disabled operation names retain the frozen model contracts;
// PostgresVpnStore and HTTP routes reject the module before opening storage.
namespace Sli.Server.Vpn;
internal static class VpnSql
{
    public const string SessionDomains = """
        select domain_id
                       from radius_vpn_session_coverage_v1
                       where domain_id>$1
                       order by domain_id
                       limit $2
        """;
    public const string Coverage = """
        select domain_id,total_delivery_count,queued_delivery_count,
               leased_delivery_count,failed_delivery_count,
               delivered_delivery_count,quarantined_delivery_count,
               projected_receipt_count,identity_unresolved_count,
               timestamp_unresolved_count,projected_session_count,
               history_available_from_utc,history_available_to_utc
        from radius_vpn_session_coverage_v1
        where domain_id=$1
        """;
    public const string Evidence = """
        select observation_id,lifecycle_event,identity_state,
                              timestamp_state,session_identity_key,
                              exact_principal_key,observed_at_utc,evidence_uid,
                              source_instance_id,stream_id,transport_binding,
                              object_reference,canonical_record_sha256,
                              object_sha256,object_size_bytes,verified_at_utc
                       from radius_vpn_session_evidence_observations_v1
                       where domain_id=$1 and session_row_id=$2
                       order by observed_at_utc,observation_id
                       limit $3
        """;
    public const string NpsEvents = "module_disabled:NpsEvents";
    public const string NpsCoverage = "module_disabled:NpsCoverage";
    public const string Identities = """
        select entity.id as entity_id,entity.display_name,domain_row.netbios_name,
                                      account.attributes_json->'attributes'->>'sam_account_name' as sam_account_name,
                                      account.attributes_json->'attributes'->>'department' as department
                               from entities_v2 entity join domains domain_row on domain_row.id=entity.domain_id
                               left join lateral (
                                   select current.attributes_json from ad_context_entity_versions current
                                   where current.entity_id=entity.id and current.source_section in ('directory_accounts','vpn_membership')
                                     and current.valid_to_utc is null
                                   order by case current.source_section when 'directory_accounts' then 0 else 1 end,
                                            current.last_observed_at_utc desc,current.id desc limit 1
                               ) account on true
                               where entity.id=any($1) and entity.domain_id=$2 and entity_v2_is_active(entity.id)
        """;
    public const string FailedEvents = "module_disabled:FailedEvents";
    public const string FailedCoverage = "module_disabled:FailedCoverage";
    public const string ConnectionFailedEvents = "module_disabled:ConnectionFailedEvents";
    public const string ConnectionFailedCollected = "module_disabled:ConnectionFailedCollected";
    public const string WindowsGrid = "module_disabled:WindowsGrid";
    public const string WindowsDomains = """
        select id as domain_id from domains
                        where id>$1 order by id limit $2
        """;
    public const string WindowsPresent = "module_disabled:WindowsPresent";
    public const string WindowsEvents = "module_disabled:WindowsEvents";
    public const string WindowsCoverage = "module_disabled:WindowsCoverage";
    public const string WindowsReview = "module_disabled:WindowsReview";
    public const string ConnectionSessions = """
        select session_row_id,entity_id,domain_id,generation,
                              lifecycle_state,completeness,started_at_utc,
                              last_observed_at_utc,stopped_at_utc,duration_seconds,
                              observation_count,anomalies,updated_at
                       from radius_vpn_session_rows_v1
                       where domain_id=$1 and started_at_utc is not null
                         and started_at_utc<$2
                         and (
                             (stopped_at_utc is not null and stopped_at_utc>$3)
                             or (stopped_at_utc is null and last_observed_at_utc>=$4)
                         )
                       order by started_at_utc,session_row_id limit $5
        """;
    public const string FullIdentities = """
        select entity.id as entity_id,entity.display_name,
                                  domain_row.netbios_name,
                                  account.attributes_json->'attributes'->>'sam_account_name' as sam_account_name,
                                  account.attributes_json->'attributes'->>'department' as department,
                                  case when account.attributes_json->'attributes'->>'enabled' in ('true','false')
                                       then (account.attributes_json->'attributes'->>'enabled')::boolean end as enabled,
                                  account.attributes_json->'attributes'->>'last_logon_utc' as last_logon_utc,
                                  exists(select 1 from ad_context_relation_versions privileged
                                         where privileged.source_entity_id=entity.id
                                           and privileged.valid_to_utc is null
                                           and privileged.relation_kind='member_of'
                                           and privileged.source_section='privileged_membership') as privileged
                           from entities_v2 entity
                           join domains domain_row on domain_row.id=entity.domain_id
                           left join lateral (
                               select current.attributes_json
                               from ad_context_entity_versions current
                               where current.entity_id=entity.id
                                 and current.source_section in ('directory_accounts','vpn_membership')
                                 and current.valid_to_utc is null
                               order by case current.source_section when 'directory_accounts' then 0 else 1 end,
                                        current.last_observed_at_utc desc,current.id desc
                               limit 1
                           ) account on true
                           where entity.id=any($1) and entity.domain_id=$2
                             and entity_v2_is_active(entity.id)
        """;
    public const string Entitlements = """
        select distinct source_entity.id as entity_id
                       from ad_context_relation_versions relation
                       join entities_v2 source_entity on source_entity.id=relation.source_entity_id
                       join storage_v2_entity_type entity_type on entity_type.id=source_entity.entity_type_id
                       where source_entity.domain_id=$1 and relation.valid_to_utc is null
                         and relation.relation_kind='member_of'
                         and relation.source_section='vpn_membership'
                         and entity_type.value='ad_user'
                         and entity_v2_is_active(source_entity.id)
                       order by source_entity.id limit $2
        """;
}
