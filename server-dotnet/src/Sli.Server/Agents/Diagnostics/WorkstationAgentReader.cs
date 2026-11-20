using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
namespace Sli.Server.Agents.Diagnostics;

public sealed class WorkstationAgentReader
{
    internal const string Resources = """
    with registered as (
    select coalesce(a.source_agent_id,a.id)::text as agent_key,a.id::text as transport_agent_id,
           coalesce(a.source_host_id,a.host_id)::text as source_instance_id,
           'core:' || encode(sha256(convert_to(
               '["device","sli.agent.key","agent-registry","' || coalesce(a.source_agent_id,a.id)::text || '"]', 'UTF8')), 'hex') as identity_key
    from sli_agents a
    where a.status<>'replaced' and exists(select 1 from jsonb_array_elements(a.assigned_modules) m
                 where m->>'module_id'='sli.workstations')
), devices as (
        select distinct a.agent_key,a.source_instance_id,r.entity_id,r.device_id,r.collection_scope_id
        from registered a join core_entity_scope_resources r
          on r.natural_key=a.identity_key and r.plugin_id='sli.workstations'
         and r.source_instance_id=a.source_instance_id
         and r.entity_type='device' and r.resolution='resolved'
    ), resources as (
        select a.agent_key,'sli.workstations'::text as plugin_id,a.source_instance_id,
               d.entity_id,d.device_id,d.collection_scope_id,null::text as ou_path,
               null::bigint as ad_computer_id
        from registered a left join devices d on d.agent_key=a.agent_key
        union all
        select d.agent_key,'sli.workstations',d.source_instance_id,
               e.id,e.natural_key,'ad-domain:' || e.domain_id::text,
               v.attributes_json->'attributes'->>'organizational_unit',e.id as ad_computer_id
        from devices d
        join lateral (
            select min(target_entity_id) as target_entity_id
            from core_entity_associations
            where source_entity_id=d.entity_id and relation='directory_computer'
            having count(distinct target_entity_id)=1
        ) association on true
        join entities_v2_active e on e.id=association.target_entity_id
        join storage_v2_entity_type t on t.id=e.entity_type_id and t.value='ad_computer'
        left join ad_context_entity_versions v on v.entity_id=e.id
          and v.source_section='directory_accounts' and v.valid_to_utc is null
        where (select count(distinct own.entity_id) from devices own where own.agent_key=d.agent_key)=1
          and (select count(distinct own.agent_key) from devices own where own.entity_id=d.entity_id)=1
          and not exists(select 1 from devices other join core_entity_associations link
              on link.source_entity_id=other.entity_id and link.relation='directory_computer'
              where link.target_entity_id=e.id and other.agent_key<>d.agent_key)
    )

""";
    public static (string? Selected,string? Cursor) Validate(string raw)
    {
        var query=AgentDiagnosticRules.Query(raw);
        if(query.Any(p=>p.Key is not("agent_key" or "cursor")||p.Value.Length!=1))throw new AgentControlException("workstation_request_invalid");
        string? Id(string key)=>query.TryGetValue(key,out var values)?AgentControlJson.Id(System.Text.Json.JsonSerializer.SerializeToElement(values[0])).ToString():null;
        try{return(Id("agent_key"),Id("cursor"));}
        catch(AgentControlException){throw new AgentControlException("workstation_request_invalid");}
    }
    public async Task<JsonObject> ReadAsync(NpgsqlConnection db,NpgsqlTransaction tx,AccessFacts facts,AccessDecision decision,string raw,CancellationToken ct)
    {
        var (selected,cursor)=Validate(raw);var scope=WorkstationAgentScope.Build(facts,decision);
        await using(var timeout=new NpgsqlCommand("set local statement_timeout = '5000ms'",db,tx))await timeout.ExecuteNonQueryAsync(ct);
        string sql=Resources+" select to_jsonb(f)::text from (select a.agent_key,s.status,s.last_seen,s.policy_revision,s.applied_policy_revision from registered a join sli_agents s on s.id::text=a.transport_agent_id where "+scope.Sql;
        if(selected is not null)sql+=" and a.agent_key=@selected";
        if(cursor is not null)sql+=" and a.agent_key>@cursor";
        sql+=" order by a.agent_key limit 101) f";
        await using var command=new NpgsqlCommand(sql,db,tx);
        foreach(var parameter in scope.Parameters)command.Parameters.Add(parameter);
        if(selected is not null)command.Parameters.AddWithValue("selected",selected);
        if(cursor is not null)command.Parameters.AddWithValue("cursor",cursor);
        var items=new JsonArray();
        await using(var rows=await command.ExecuteReaderAsync(ct))while(await rows.ReadAsync(ct))items.Add(AgentControlJson.Row(rows.GetString(0)));
        if(selected is not null&&items.Count==0)throw new AgentControlException("workstation_access_denied",403);
        bool more=items.Count>100;if(more)items.RemoveAt(100);
        return new JsonObject{["items"]=items,["has_more"]=more,["next_cursor"]=more?items[^1]!["agent_key"]!.DeepClone():null};
    }
}
