using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.Diagnostics;

public sealed class AgentDiagnosticsService(AgentLifecycleService lifecycle,IAgentControlAudit audit,TimeProvider clock)
{
    public async Task<JsonObject> RevocationsAsync(NpgsqlConnection db,NpgsqlTransaction tx,long after,CancellationToken ct)
    {
        await using(var gate=new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('sli-agent-revocations'))",db,tx))await gate.ExecuteNonQueryAsync(ct);
        await using var q=new NpgsqlCommand("select to_jsonb(f)::text from (select id,target as agent_id,details->>'serial' as serial,occurred_at as revoked_at from sli_agent_audit where action='revoke' and id>@after order by id limit 500) f",db,tx);
        q.Parameters.AddWithValue("after",after);var items=new JsonArray();
        await using(var r=await q.ExecuteReaderAsync(ct))while(await r.ReadAsync(ct))items.Add(AgentControlJson.Row(r.GetString(0)));
        return new JsonObject{["items"]=items,["next_cursor"]=items.Count>0?items[^1]!["id"]!.DeepClone():JsonValue.Create(after)};
    }
    public async Task<JsonObject> LocalUninstallAsync(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity agent,CancellationToken ct)
    {
        bool pending;
        await using(var q=new NpgsqlCommand("select command_id,state,requested_at from sli_agent_removals where agent_id=@id for update",db,tx))
        {
            q.Parameters.AddWithValue("id",agent.Id);await using var r=await q.ExecuteReaderAsync(ct);
            pending=await r.ReadAsync(ct)&&r.GetString(1)!="state_cleaned";
        }
        if(!pending)await lifecycle.RequestRemovalAsync(db,tx,JsonSerializer.SerializeToElement(new{operation_id=Guid.NewGuid(),agent_ids=new[]{agent.Id}}),"agent:"+agent.Id,ct);
        return await AgentClientControlService.RemovalCommandAsync(db,tx,agent,ct);
    }
    public async Task<JsonObject> RemovalResultAsync(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity agent,JsonNode? body,CancellationToken ct)
    {
        var result=AgentDiagnosticRules.RemovalResult(body);
        await using(var q=new NpgsqlCommand("select command_id,state,requested_at from sli_agent_removals where agent_id=@id for update",db,tx))
        {
            q.Parameters.AddWithValue("id",agent.Id);await using var r=await q.ExecuteReaderAsync(ct);
            if(!await r.ReadAsync(ct)||r.GetString(1)=="state_cleaned"||r.GetGuid(0)!=result.CommandId)throw new AgentControlException("agent_removal_replay",409);
        }
        await using(var q=new NpgsqlCommand("update sli_agent_removals set state=@state,reason=@reason,reported_at=clock_timestamp() where agent_id=@id",db,tx))
        {
            q.Parameters.AddWithValue("state",result.State);q.Parameters.AddWithValue("reason",NpgsqlDbType.Text,(object?)result.Reason??DBNull.Value);q.Parameters.AddWithValue("id",agent.Id);await q.ExecuteNonQueryAsync(ct);
        }
        await audit.AppendAsync(db,tx,"removal_result","agent:"+agent.Id,agent.Id.ToString(),new{command_id=result.CommandId,state=result.State,reason=result.Reason},ct);
        return new JsonObject{["state"]=result.State};
    }
    public async Task<JsonObject> WindowsAuditAsync(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity agent,JsonNode? body,CancellationToken ct)
    {
        JsonObject stored;
        await using(var q=new NpgsqlCommand("select to_jsonb(a)::text from sli_agents a where id=@id",db,tx))
        {q.Parameters.AddWithValue("id",agent.Id);stored=JsonNode.Parse((string?)await q.ExecuteScalarAsync(ct)??throw new InvalidOperationException("agent_identity_unavailable"))!.AsObject();}
        var change=AgentWindowsAuditReport.Prepare(stored,body,clock.GetUtcNow());
        if(change.Write)
        {
            await using var q=new NpgsqlCommand("update sli_agents set windows_audit=@state where id=@id",db,tx);
            q.Parameters.AddWithValue("state",NpgsqlDbType.Jsonb,change.State.ToJsonString());q.Parameters.AddWithValue("id",agent.Id);await q.ExecuteNonQueryAsync(ct);
        }
        return new JsonObject{["windows_audit"]=change.State};
    }
}
