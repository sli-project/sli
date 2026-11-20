using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.Control;
namespace Sli.Server.Agents.Updates;
internal static partial class AgentUpdateWaves
{
    internal static async Task<IReadOnlyList<AgentUpdateMember>> MembersAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid wave,CancellationToken ct)
    {
        var members=new List<AgentUpdateMember>();
        await using var command=new NpgsqlCommand("select m.agent_id,m.batch_number,m.state,m.had_error,a.status,m.reason from sli_agent_update_wave_members m join sli_agents a on a.id=m.agent_id where m.wave_id=@wave order by m.batch_number,m.agent_id",db,tx);
        command.Parameters.AddWithValue("wave",wave);await using var reader=await command.ExecuteReaderAsync(ct);
        while(await reader.ReadAsync(ct))members.Add(new(reader.GetGuid(0),reader.GetInt32(1),reader.GetString(2),reader.GetBoolean(3),reader.GetString(4),reader.IsDBNull(5)?null:reader.GetString(5)));return members;
    }
    internal static async Task<DateTimeOffset> FinishAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid wave,string package,int batch,string status,string? reason,int errors,string actor,IAgentControlAudit audit,CancellationToken ct)
    {
        DateTimeOffset finished;
        await using(var command=new NpgsqlCommand("update sli_agent_update_waves set status=@status,reason=@reason,finished_at=clock_timestamp() where id=@wave returning finished_at",db,tx)) {
            command.Parameters.AddWithValue("status",status);command.Parameters.AddWithValue("reason",NpgsqlDbType.Text,(object?)reason??DBNull.Value);command.Parameters.AddWithValue("wave",wave);
            finished=new DateTimeOffset((DateTime)(await command.ExecuteScalarAsync(ct))!);
        }
        await using(var command=new NpgsqlCommand("update sli_agent_update_policy set package_sha256=null where agent_id in (select agent_id from sli_agent_update_wave_members where wave_id=@wave) and package_sha256=@package",db,tx)) {
            command.Parameters.AddWithValue("wave",wave);command.Parameters.AddWithValue("package",package);await command.ExecuteNonQueryAsync(ct);
        }
        await using(var command=new NpgsqlCommand("update sli_agent_update_wave_members set reserved=false where wave_id=@wave",db,tx)) {
            command.Parameters.AddWithValue("wave",wave);await command.ExecuteNonQueryAsync(ct);
        }
        await audit.AppendAsync(db,tx,status=="completed"?"update_wave_complete":"update_wave_stop",actor,wave.ToString("D"),new { reason,errors,batch },ct);return finished;
    }
    internal static async Task IssueAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid wave,string package,int next,IReadOnlyList<AgentUpdateMember> members,string actor,IAgentControlAudit audit,CancellationToken ct)
    {
        var issued=members.Where(m=>m.Batch==next).ToArray();
        foreach(var member in issued) {
            await using(var command=new NpgsqlCommand("update sli_agent_update_wave_members set state='pending',issued_at=clock_timestamp() where wave_id=@wave and agent_id=@agent",db,tx)) {
                command.Parameters.AddWithValue("wave",wave);command.Parameters.AddWithValue("agent",member.Id);await command.ExecuteNonQueryAsync(ct);
            }
            await using(var command=new NpgsqlCommand("insert into sli_agent_update_policy(agent_id,package_sha256) values(@agent,@package) on conflict(agent_id) do update set package_sha256=excluded.package_sha256",db,tx)) {
                command.Parameters.AddWithValue("agent",member.Id);command.Parameters.AddWithValue("package",package);await command.ExecuteNonQueryAsync(ct);
            }
            await audit.AppendAsync(db,tx,"update_assign",actor,member.Id.ToString("D"),new { sha256=package,wave_id=wave.ToString("D"),batch=next },ct);
        }
        await using(var command=new NpgsqlCommand("update sli_agent_update_waves set current_batch=@batch where id=@wave",db,tx)) {
            command.Parameters.AddWithValue("batch",next);command.Parameters.AddWithValue("wave",wave);await command.ExecuteNonQueryAsync(ct);
        }
        await audit.AppendAsync(db,tx,"update_wave_batch",actor,wave.ToString("D"),new { batch=next,count=issued.Length },ct);
    }
}
