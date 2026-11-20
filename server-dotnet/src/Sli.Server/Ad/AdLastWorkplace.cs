using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Diagnostics;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdLastWorkplace
{
    internal static async Task<Dictionary<(long,string),JsonObject>> ReadAsync(NpgsqlConnection db,long[] domains,string[] sids,CancellationToken ct,IConfiguration? config=null,AccessFacts? facts=null,AccessDecision? access=null,string action="view")
    {
        var result=new Dictionary<(long,string),JsonObject>();if(sids.Length==0||domains.Length==0)return result;
        var rows=await AdAccountEvents.ReadAsync(db,domains,[4624],new(DateTimeOffset.UtcNow.AddDays(-365),DateTimeOffset.UtcNow),ct,config);
        var selected=sids.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach(var row in rows.Where(r=>r.Text("logon_type") is "2" or "10" or "11").OrderByDescending(r=>r.Time("last_seen_utc"))) {
            if(row.Text("target_user_sid") is not {} sid||!selected.Contains(sid)||row.Text("workstation_name") is not {} name)continue;
            var key=(row.Int("domain_id"),sid.ToLowerInvariant());
            result.TryAdd(key,new JsonObject{["computer"]=name,["computer_id"]=null,["computer_guid"]=null,
                ["at_utc"]=AdInventoryRows.PythonIso(row.Time("last_seen_utc")),["kind"]=row.Text("logon_type")=="10"?"rdp":"local"});
        }
        return result;
    }

    internal static async Task<List<JsonObject>> NativeAsync(NpgsqlConnection db,long[] domains,string[] sids,AccessFacts? facts,AccessDecision? access,string action,CancellationToken ct)
    {
        if(facts is null||access is null||domains.Length==0||sids.Length==0)return [];
        // Keep action, fields and scope in one grant, as in the workstation reader.
        var scoped=access with{Reports=access.Reports.Where(r=>r.ReportKey=="workstations.logons").Select(r=>r with{
            Grants=r.Grants.Where(g=>g.AllowedActions.Contains(action)).Select(g=>g with{AllowedActions=new HashSet<string>{"view"}}).ToArray()}).ToArray()};
        WorkstationPredicate predicate;
        try{predicate=WorkstationAgentScope.Build(facts,scoped,reportKey:"workstations.logons",reportOnly:true);}
        catch(AgentControlException){return [];}
        await using(var save=new NpgsqlCommand("savepoint ad_optional_native_workplaces",db))await save.ExecuteNonQueryAsync(ct);
        try
        {
            await using var command=new NpgsqlCommand(WorkstationAgentReader.Resources+"""
                , authorized as (select distinct a.agent_key from registered a where
                """+predicate.Sql+"""
                )
                select to_jsonb(workplace)::text from (
                    select distinct on(e.domain_id,lower(o.observation->'facts'->>'relation_account_sid'))
                        e.domain_id,o.observation->'facts'->>'relation_account_sid' as sid,
                        e.display_name as computer_name,e.id as computer_id,null::text as computer_object_guid,
                        o.observed_at as observed_at_utc,o.observation->'facts'->>'logon_type' as logon_type
                    from sli_plugin_workstations.observations o join entities_v2 e on e.id=o.ad_computer_id
                    where o.agent_key in(select agent_key from authorized) and o.family='logons' and o.event_id=4624
                      and e.domain_id=any(@domains) and lower(o.observation->'facts'->>'relation_account_sid')=any(@sids)
                      and o.observation->'facts'->>'logon_type' in ('2','10','11') and o.observed_at<=now()
                    order by e.domain_id,lower(o.observation->'facts'->>'relation_account_sid'),o.observed_at desc,o.id desc
                ) workplace
                """,db);
            foreach(var parameter in predicate.Parameters)command.Parameters.Add(parameter);
            command.Parameters.AddWithValue("domains",domains);command.Parameters.AddWithValue("sids",sids);
            var rows=new List<JsonObject>();await using var reader=await command.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct))rows.Add(JsonNode.Parse(reader.GetString(0))!.AsObject());
            return rows;
        }
        catch(NpgsqlException)
        {await using var rollback=new NpgsqlCommand("rollback to savepoint ad_optional_native_workplaces",db);await rollback.ExecuteNonQueryAsync(ct);return [];}
    }
}
