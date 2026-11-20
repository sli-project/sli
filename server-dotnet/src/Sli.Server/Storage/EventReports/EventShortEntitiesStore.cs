using System.Text.Json.Nodes;
using Sli.Server.Entities;

namespace Sli.Server.Storage.EventReports;

internal sealed partial class EventReadService
{
    async Task<JsonObject> ShortEntitiesAsync(long id,
        Func<string,IReadOnlyDictionary<string,object>,CancellationToken,Task<List<JsonObject>>> query,CancellationToken ct)
    {
        string cte="with short_events as ("+EntityShortSql.Source("@boundary",daily:false)+") ";
        var args=new Dictionary<string,object> { ["id"]=id,["boundary"]=ShortBoundary(config) };
        var events=await query(cte+"select e.id "+ShortJoins+" where e.id=@id and s.id is not null limit 1",args,ct);
        bool found=events.Count>0;
        var items=new JsonArray();
        if(found) {
            var rows=await query(cte+"""
                select distinct entity.id,kind.value as type,entity.natural_key,entity.display_name,link.link_role,1.0 as confidence
                from short_events e join servers s on s.id=e.server_id and s.domain_id=e.domain_id
                cross join lateral public.short_event_entity_links339(e.event_id,e.actor,e.target,e.source,e.computer,e.method,e.fields) link
                join entities_v2_active entity on entity.domain_id is null or entity.domain_id=e.domain_id
                cross join lateral public.entity_event_keys339(entity.id) keys
                join storage_v2_entity_type kind on kind.id=entity.entity_type_id
                where e.id=@id and link.natural_key=any(keys.natural_keys)
                order by entity.id,link.link_role limit 30
                """,args,ct);
            foreach(var row in rows) items.Add(row);
        }
        return new() { ["api_version"]="v1",["event_db_id"]=id,["event_found"]=found,
            ["evidence_status"]=found?items.Count>0?"present":"zero_extracted":"event_not_found",
            ["items"]=items,["limit"]=30,["warning"]=null };
    }
}
