using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.Control;
namespace Sli.Server.Agents.Updates;
internal sealed record AgentUpdateMember(Guid Id,int Batch,string State,bool HadError,string AgentStatus,string? Reason=null);
internal sealed record AgentUpdatePlan(string Action,string? Reason,int Errors);
internal static partial class AgentUpdateWaves
{
    internal static AgentUpdatePlan Decide(IReadOnlyList<AgentUpdateMember> members,int batch,int threshold)
    {
        int errors=members.Count(m=>m.HadError);
        if(errors>threshold)return new("stopped","agent_update_error_threshold_exceeded",errors);
        if(members.Any(m=>m.AgentStatus!="active"))return new("stopped","agent_update_agent_inactive",errors);
        if(members.All(m=>m.State=="updated"))return new("completed",null,errors);
        return new(members.Where(m=>m.Batch<=batch).All(m=>m.State=="updated")?"issue":"wait",null,errors);
    }
    internal static async Task RecordAsync(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity identity,AgentUpdateInput result,IAgentControlAudit audit,CancellationToken ct)
    {
        // The caller acquired the source global rollout lock before the agent
        // and certificate locks. All result/audit/rollout writes stay in this TX.
        Guid waveId;string version,memberState;string? memberReason;int batch,threshold;bool shipped;
        await using(var command=new NpgsqlCommand("""
            select w.id,w.version,w.current_batch,w.error_threshold,m.state,m.reason,w.created_by from sli_agent_update_waves w
            join sli_agent_update_wave_members m on m.wave_id=w.id
            where m.agent_id=@agent and m.package_sha256=@package and m.state<>'queued' and w.status='running'
            """,db,tx)) {
            command.Parameters.AddWithValue("agent",identity.Id);command.Parameters.AddWithValue("package",result.Sha256);
            await using var reader=await command.ExecuteReaderAsync(ct);if(!await reader.ReadAsync(ct))return;
            waveId=reader.GetGuid(0);version=reader.GetString(1);batch=reader.GetInt32(2);threshold=reader.GetInt32(3);memberState=reader.GetString(4);memberReason=reader.IsDBNull(5)?null:reader.GetString(5);
            shipped=reader.GetString(6)==ShippedAgentUpdate.Actor;
        }
        bool success=result.Status=="updated" && result.Version==version;
        string state=success?"updated":"failed";string? reason=success?null:result.Status=="updated"?"agent_update_version_mismatch":result.Reason;
        if(memberState==state && memberReason==reason || shipped && memberState=="updated")return;
        await using(var command=new NpgsqlCommand("update sli_agent_update_wave_members set state=@state,reason=@reason,had_error=had_error or @error,reported_at=clock_timestamp() where wave_id=@wave and agent_id=@agent",db,tx)) {
            command.Parameters.AddWithValue("state",state);command.Parameters.AddWithValue("reason",NpgsqlDbType.Text,(object?)reason??DBNull.Value);
            command.Parameters.AddWithValue("error",!success);command.Parameters.AddWithValue("wave",waveId);command.Parameters.AddWithValue("agent",identity.Id);await command.ExecuteNonQueryAsync(ct);
        }
        string actor="agent:"+identity.Id.ToString("D"),target=waveId.ToString("D");
        await audit.AppendAsync(db,tx,"update_wave_result",actor,target,new { agent_id=identity.Id.ToString("D"),status=state,reason,version=result.Version },ct);
        // The automatic wave stays open for future check-ins. A failed or
        // disconnected member never blocks another agent's update.
        if(shipped) {
            if(success) {
                await using var inventory=new NpgsqlCommand("""
                    update sli_agents set rights_probe=jsonb_set(rights_probe,'{agent_version}',to_jsonb(cast(@version as text)),true)
                    where id=@agent and exists(select 1 from platform_settings where key='agents.shipped_update' and value=@package)
                    """,db,tx);
                inventory.Parameters.AddWithValue("version",version);inventory.Parameters.AddWithValue("agent",identity.Id);
                inventory.Parameters.AddWithValue("package",result.Sha256);
                await inventory.ExecuteNonQueryAsync(ct);
            }
            return;
        }
        var members=await MembersAsync(db,tx,waveId,ct);
        var plan=Decide(members,batch,threshold);
        if(plan.Action is "stopped" or "completed") {
            await FinishAsync(db,tx,waveId,result.Sha256,batch,plan.Action,plan.Reason,plan.Errors,actor,audit,ct);
        } else if(plan.Action=="issue") {
            await IssueAsync(db,tx,waveId,result.Sha256,batch+1,members,actor,audit,ct);
        }
    }
}
