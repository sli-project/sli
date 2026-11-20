namespace Sli.Server.Ad;

internal static class AdHistorySql
{
    internal static string ShortPowerShellRows => "with short_events as not materialized (" +
        Sli.Server.Storage.EventReports.EventReadService.ShortSource("$7") + "), " + """
        bounded_powershell as (
            select e.* from short_events e
            join servers server on server.id=e.server_id and server.domain_id=e.domain_id and server.role='domain_controller'
            where e.domain_id=$1 and e.event_id in (4103,4104) and e.channel=$2 and e.provider_name=$3
              and e.time_created_utc>=$4 and e.time_created_utc<$5
            order by e.time_created_utc,e.id,e.event_id,e.actor limit $6
        )
        select e.id as event_db_id,e.domain_id,e.server_id,e.channel,e.provider_name,e.event_id,e.time_created_utc,e.computer as domain_controller,
            e.day::text as day,e.event_count,e.actor,
            case when e.actor ilike 'S-1-%' then e.actor end as subject_user_sid,
            case when e.actor not ilike 'S-1-%' then e.actor end as subject_user_name,
            e.fields->>'User' as powershell_user_name,e.fields->>'CommandName' as powershell_command_name,
            case when $8 then e.fields->>'ScriptBlockText' end as powershell_script_block_text,
            case when login.id is not null then 'nearest_logon' end as origin_basis,
            login.id as origin_session_start_event_db_id,
            case login.method->>'LogonType' when '10' then 'rdp' when '2' then 'local' else 'logon' end as origin_kind,
            login.source as origin_source_ip
        from bounded_powershell e
        left join lateral (
            select a.id,a.source,a.method from short_events a
            where e.day is null and e.actor is not null and a.day is null and a.event_id=4624
              and a.domain_id=e.domain_id and a.server_id=e.server_id and lower(a.computer)=lower(e.computer)
              and a.channel='Security' and a.provider_name='Microsoft-Windows-Security-Auditing'
              and (lower(a.actor)=lower(e.actor)
                or lower(concat_ws('\',nullif(a.method#>>'{$principals,TargetDomainName}',''),
                     a.method#>>'{$principals,TargetUserName}'))=lower(e.actor))
            order by abs(extract(epoch from a.time_created_utc-e.time_created_utc)),a.time_created_utc desc,a.id
            limit 1
        ) login on true
        order by e.time_created_utc,e.id,e.event_id,e.actor
        """;

    internal static string ChangeRows(string kind, IConfiguration? config = null) =>
        kind == "account" ? AccountRows(config) : MembershipRows(config);
    private static string AccountRows(IConfiguration? config) => $"""
select event.id as event_db_id,event.domain_id,event.server_id,event.channel,event.provider_name,event.event_record_id,event.event_id,
                      event.time_created_utc,server.hostname as domain_controller,
                      event.subject_user_sid,event.subject_user_name,
                      coalesce(nullif(btrim(event.target_user_sid),''),
                               nullif(btrim(facts.account_target_sid),'')) as target_user_sid,
                      coalesce(nullif(btrim(event.target_user_name),''),
                               nullif(btrim(facts.account_target_name),'')) as target_user_name,
                      facts.account_name_before,facts.account_name_after,facts.result_code,
                      event.source_core_sha256,facts.source_facts_sha256
                 {AdColdFactsSql.Joins(config)}
                where event.domain_id=$1 and server.role='domain_controller'
                  and event.event_id=any($2)
                  and channel.value=$3 and provider.value=$4
                  and event.time_created_utc>=$5 and event.time_created_utc<$6
                order by event.time_created_utc,event.id
                limit $7
""";
    private static string MembershipRows(IConfiguration? config) => $"""
select event.id as event_db_id,event.domain_id,event.server_id,event.channel,event.provider_name,event.event_record_id,event.event_id,
                      event.time_created_utc,server.hostname as domain_controller,
                      event.subject_user_sid,event.subject_user_name,
                      event.target_user_sid,event.target_user_name,
                      facts.membership_member_sid,facts.membership_member_name,
                      controlled.context_evidence_id as controlled_group_context_evidence_id,
                      controlled.context_observed_at_utc as controlled_group_context_observed_at_utc,
                      event.source_core_sha256,facts.source_facts_sha256
                 {AdColdFactsSql.Joins(config)}
                 left join lateral (
                     select evidence.id as context_evidence_id,
                            context.last_observed_at_utc as context_observed_at_utc
                       from ad_context_entity_aliases alias
                       join ad_context_entity_versions context on context.entity_id=alias.entity_id
                       join ad_context_runs run on run.run_id=context.source_run_id
                       join ad_context_evidence evidence
                         on evidence.source_run_id=context.source_run_id
                        and evidence.locator_json->>'record_key'=context.attributes_json->>'record_key'
                      where alias.domain_id=event.domain_id
                        and alias.alias_type='object_sid'
                        and alias.normalized_value=lower(event.target_user_sid)
                        and context.source_section='privileged_membership'
                        and context.valid_to_utc is null
                        and run.status='completed'
                        and exists(
                            select 1
                              from jsonb_array_elements_text(
                                  coalesce(run.scope_json->'privileged_group_sids', '[]'::jsonb)
                              ) configured_group(sid)
                             where lower(configured_group.sid)=lower(event.target_user_sid)
                        )
                      order by context.last_observed_at_utc desc,evidence.id desc
                      limit 1
                 ) controlled on true
                where event.domain_id=$1 and server.role='domain_controller'
                  and event.event_id=any($2)
                  and channel.value=$3 and provider.value=$4
                  and event.time_created_utc>=$5 and event.time_created_utc<$6
                order by event.time_created_utc,event.id
                limit $7
""";
}
