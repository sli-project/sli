namespace Sli.Server.Entities;

public sealed partial class EntityReader
{
    static string ShortInterpretationActionsSql => EntityShortSql.Cte("@boundary","@id",daily:false)+"""
        select event.id as event_db_id,event.domain_id,event.server_id,event.channel,null::bigint as event_record_id,event.event_id,event.time_created_utc,
          server.hostname as source_host,event.outcome->>'keywords' as audit_keywords,
          coalesce(event.method#>>'{$principals,SubjectUserSid}',case when not event.method ? '$principals' and event.event_id not in(4624,4625,4771,4776) and event.actor ilike 'S-1-%' then event.actor end) as subject_user_sid,
          coalesce(event.method#>>'{$principals,SubjectUserName}',case when not event.method ? '$principals' and event.event_id not in(4624,4625,4771,4776) and event.actor not ilike 'S-1-%' then event.actor end) as subject_user_name,
          coalesce(event.method#>>'{$principals,TargetUserSid}',event.method#>>'{$principals,TargetSid}',case when not event.method ? '$principals' and principal.account ilike 'S-1-%' then principal.account end) as target_user_sid,
          coalesce(event.method#>>'{$principals,TargetUserName}',case when not event.method ? '$principals' and principal.account not ilike 'S-1-%' then principal.account end) as target_user_name,
          event.fields->>'MemberSid' as membership_member_sid,event.fields->>'MemberName' as membership_member_name,
          coalesce(event.fields->>'OldTargetUserName',event.fields->>'OldAccountName') as account_name_before,
          coalesce(event.fields->>'NewTargetUserName',event.fields->>'NewAccountName') as account_name_after,
          coalesce(event.outcome->>'ResultCode',event.outcome->>'Status',event.outcome->>'SubStatus') as result_code,
          null::text as source_core_sha256,null::text as source_facts_sha256
        from short_events event join servers server on server.id=event.server_id and server.domain_id=event.domain_id
        cross join lateral (select case when event.event_id in(4624,4625,4771,4776) then event.actor else event.target end as account) principal
        where event.id>0 and event.domain_id=@domain and server.role='domain_controller' and event.event_id=any(@ids) and event.channel='Security'
          and((event.event_id=1102 and event.provider_name='Microsoft-Windows-Eventlog') or(event.event_id<>1102 and event.provider_name='Microsoft-Windows-Security-Auditing'))
          and event.time_created_utc>=@start and event.time_created_utc<@end
        order by event.time_created_utc desc,event.id desc limit @limit
        """;
}
