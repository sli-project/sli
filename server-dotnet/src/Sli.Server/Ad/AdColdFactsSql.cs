using System.Globalization;
using Sli.Server.Entities;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Ad;

internal static class AdColdFactsSql
{
    // Adjacent report readers still call this admission hook. Ad always uses the new layer.
    internal static bool Enabled(IConfiguration? configuration) => true;

    // Individual reads share the retention boundary and routing identity with
    // the event reader. Daily authentication groups remain explicitly marked.
    internal static string Joins(IConfiguration? config = null, bool authentication = false)
    {
        string boundary = "timestamptz '" + EventReadService.ShortBoundary(config).ToString("O",CultureInfo.InvariantCulture) + "'";
        const string signIn = "s.event_id in (4624,4625,4771,4776)";
        string target = $"(case when {signIn} then s.actor else s.target end)";
        return $"""
            from (select s.*,
                0::bigint as channel_id,0::bigint as provider_id,null::bigint as event_record_id,
                null::bytea as source_core_sha256,
                case when {signIn} then s.method->'$principals'->>'SubjectUserSid'
                     when s.actor ilike 'S-1-%' then s.actor end as subject_user_sid,
                case when {signIn} then s.method->'$principals'->>'SubjectUserName'
                     when s.actor not ilike 'S-1-%' then s.actor end as subject_user_name,
                case when {target} ilike 'S-1-%' then {target} end as target_user_sid,
                case when {target} not ilike 'S-1-%' then {target} end as target_user_name,
                s.source as ip_address,null::text as workstation_name
              from ({EntityShortSql.Source(boundary, daily:authentication)}) s) event
            join servers server on server.id=event.server_id and server.domain_id=event.domain_id
            cross join lateral (select event.channel as value) channel
            cross join lateral (select event.provider_name as value) provider
            left join lateral (select event.outcome->>'keywords' as value) keywords on true
            left join lateral (select
                null::text as account_target_sid,null::text as account_target_name,
                event.fields->>'MemberSid' as membership_member_sid,event.fields->>'MemberName' as membership_member_name,
                event.fields->>'OldTargetUserName' as account_name_before,event.fields->>'NewTargetUserName' as account_name_after,
                coalesce(event.outcome->>'ResultCode',event.outcome->>'Status',event.outcome->>'SubStatus') as result_code,
                null::bytea as source_facts_sha256) facts on true
            """;
    }
}
