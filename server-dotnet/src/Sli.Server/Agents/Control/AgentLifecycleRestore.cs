using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.Control;

public sealed partial class AgentLifecycleService
{
    public async Task<JsonElement> RestoreAsync(NpgsqlConnection db,NpgsqlTransaction tx,JsonElement payload,string actor,CancellationToken ct)
    {
        if(payload.ValueKind!=JsonValueKind.Object || !payload.EnumerateObject().Select(p=>p.Name).ToHashSet().SetEquals(["agent_id","current_agent_id"]))
            throw new AgentControlException("agent_restore_invalid");
        Guid old=AgentControlJson.Id(payload.GetProperty("agent_id")), current=AgentControlJson.Id(payload.GetProperty("current_agent_id"));
        if(old==current) throw new AgentControlException("agent_restore_invalid");
        // Same order as enrollment/startup: registry gate, import gates, registry rows.
        await using(var gate=new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('sli-agent-registration-reconcile'))",db,tx))
            await gate.ExecuteNonQueryAsync(ct);
        var ids=new[] { old,current }.OrderBy(id=>id).ToArray();
        foreach(var id in ids) await AgentManagementService.LockImportAsync(db,tx,id,ct);
        var agents=new Dictionary<Guid,(string Status,string Source,bool Conflict,bool Removing,bool Certificate,JsonArray Modules)>();
        await using(var read=new NpgsqlCommand("""
            select a.id,a.status,b.source_name,a.rights_probe ? 'identity_conflict',
                exists(select 1 from sli_agent_removals r where r.agent_id=a.id),
                exists(select 1 from sli_agent_certificates c where c.agent_id=a.id and c.revoked_at is null
                    and c.not_before<=clock_timestamp() and c.not_after>clock_timestamp()),a.assigned_modules::text
            from sli_agents a left join sli_agent_module_bindings b on b.agent_id=a.id and b.module_id='sli.windows.ad-dc'
            where a.id=any(@ids) order by a.id for update of a
            """,db,tx))
        {
            read.Parameters.AddWithValue("ids",ids);
            await using var rows=await read.ExecuteReaderAsync(ct);
            while(await rows.ReadAsync(ct)) agents[rows.GetGuid(0)]=(rows.GetString(1),rows.IsDBNull(2)?"":rows.GetString(2),rows.GetBoolean(3),rows.GetBoolean(4),rows.GetBoolean(5),JsonNode.Parse(rows.GetString(6))!.AsArray());
        }
        if(!agents.TryGetValue(old,out var previous) || !agents.TryGetValue(current,out var selected)
            || previous.Status!="replaced" || selected.Status!="active" || previous.Conflict || selected.Conflict
            || previous.Removing || selected.Removing || !previous.Certificate)
            throw new AgentControlException("agent_restore_conflict",409);
        var dc=await AgentEnrollmentService.ResolveDcAsync(db,tx,previous.Source,ct,old);
        var currentDc=await AgentEnrollmentService.ResolveDcAsync(db,tx,selected.Source,ct,current);
        if(dc is null || currentDc is null || dc.Value.Server!=currentDc.Value.Server)
            throw new AgentControlException("agent_restore_conflict",409);
        await using(var snapshots=new NpgsqlCommand("select pg_advisory_xact_lock(170,1); update sli_agent_snapshot_bindings set enabled=false where agent_id=@id",db,tx))
        { snapshots.Parameters.AddWithValue("id",current); await snapshots.ExecuteNonQueryAsync(ct); }
        // Restore only the old agent's enabled assignments, retaining their own identity and policy.
        foreach(var module in previous.Modules.OfType<JsonObject>().Where(m=>m["module_id"]?.GetValue<string>() is "sli.ad-snapshot" or "sli.gpo-snapshot"))
        {
            string name=module["module_id"]!.GetValue<string>(); var config=module["config"]?.AsObject() ?? new();
            bool enabled=module["enabled"]?.GetValue<bool>()==true && config["paused"]?.GetValue<bool>()!=true;
            await AgentSnapshotAssignment.ValidateAsync(db,tx,old,name,config,enabled,ct);
            await using var update=new NpgsqlCommand("update sli_agent_snapshot_bindings set enabled=@enabled where agent_id=@id and module_id=@module",db,tx);
            update.Parameters.AddWithValue("enabled",enabled); update.Parameters.AddWithValue("id",old); update.Parameters.AddWithValue("module",name); await update.ExecuteNonQueryAsync(ct);
        }
        await using(var update=new NpgsqlCommand("update sli_agents set status=case when id=@old then 'active' else 'replaced' end where id=any(@ids)",db,tx))
        { update.Parameters.AddWithValue("old",old); update.Parameters.AddWithValue("ids",ids); await update.ExecuteNonQueryAsync(ct); }
        await audit.AppendAsync(db,tx,"disable",actor,current.ToString(),new { reason="registration_replaced",replaced_by=old,tail_import=false },ct);
        await audit.AppendAsync(db,tx,"runtime_switch_complete",actor,old.ToString(),new { reason="registration_restored",replaced_agent_id=current },ct);
        return JsonSerializer.SerializeToElement(new { agent_id=old,current_agent_id=current,status="active" });
    }
}
