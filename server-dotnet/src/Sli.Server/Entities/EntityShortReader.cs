using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Entities;

public sealed partial class EntityReader
{
    DateTime Boundary => EventReadService.ShortBoundary(services.GetService<IConfiguration>()).UtcDateTime;

    Task<JsonArray> ShortEvidenceCandidates(int id, EntityReadOptions options, int limit, CancellationToken ct)
    {
        var args = new Dictionary<string,object> { ["id"]=id,["limit"]=limit,["boundary"]=Boundary };
        var filters = new List<string> { "e.channel is not null and e.provider_name is not null" };
        if(options.BeforeTime is not null) {
            filters.Add("(e.time_created_utc,coalesce(e.id,0),e.summary_key)<(@before,@before_id,@before_group)");
            args["before"]=DateTimeOffset.Parse(options.BeforeTime,CultureInfo.InvariantCulture).UtcDateTime;
            args["before_id"]=options.BeforeId!.Value; args["before_group"]=options.BeforeSummaryKey ?? "";
        }
        if(options.From is not null) {
            filters.Add("(case when e.day is null then e.time_created_utc>=@start else e.day>=(@start at time zone 'UTC')::date end)");
            args["start"]=DateTimeOffset.Parse(options.From,CultureInfo.InvariantCulture).UtcDateTime;
        }
        if(options.To is not null) { filters.Add("e.time_created_utc<@end"); args["end"]=DateTimeOffset.Parse(options.To,CultureInfo.InvariantCulture).UtcDateTime; }
        return Read(EntityShortSql.Cte("@boundary","@id") + $"""
            select e.id as event_db_id,s.id as server_id,e.domain_id,e.channel,e.summary_key
            from short_events e join servers s on s.id=e.server_id and s.domain_id=e.domain_id
            {(filters.Count==0 ? "" : "where "+string.Join(" and ",filters))}
            order by e.time_created_utc desc,coalesce(e.id,0) desc,e.summary_key desc limit @limit
            """,args,ct);
    }

    Task<JsonArray> ShortEvidence(int id, long[] eventIds, string[] summaryKeys, bool technical, bool security, int limit, bool objectFacade, CancellationToken ct)
    {
        string columns = "e.id as event_db_id,e.summary_key,s.hostname as server,e.channel";
        if(security) columns += ",e.event_id,e.time_created_utc as time_utc,to_char(e.day,'YYYY-MM-DD') as day,e.event_count,e.first_seen_utc,e.last_seen_utc";
        if(technical) columns += ",e.provider_name,link.link_role,1.0 as confidence";
        if(technical && security) columns += ",e.method#>>'{$principals,SubjectUserName}' as actor,e.method#>>'{$principals,TargetUserName}' as target";
        return Read(EntityShortSql.Cte("@boundary","@id") + $"""
            select distinct {columns},e.time_created_utc as sort_time_utc from short_events e
            join servers s on s.id=e.server_id and s.domain_id=e.domain_id
            cross join entity_keys keys
            cross join lateral public.short_event_entity_links339(e.event_id,e.actor,e.target,e.source,e.computer,e.method,e.fields) link
            where (e.id=any(@event_ids) or e.day is not null and e.summary_key=any(@summary_keys))
                and link.natural_key=any(keys.natural_keys)
            order by sort_time_utc desc,event_db_id desc,summary_key desc limit @limit
            """,new() { ["id"]=id,["event_ids"]=eventIds,["summary_keys"]=summaryKeys,["boundary"]=Boundary,["limit"]=limit },ct);
    }
}
