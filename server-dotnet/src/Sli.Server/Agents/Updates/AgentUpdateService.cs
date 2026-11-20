using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
namespace Sli.Server.Agents.Updates;

public sealed class AgentUpdateService(IAgentControlAudit audit)
{
    public async Task<FileStream> DownloadAsync(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity agent,string value,CancellationToken ct)
    {
        string package=AgentUpdateInput.Digest(JsonValue.Create(value));
        await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);
        await using var command=new NpgsqlCommand("select p.archive from sli_agent_update_packages p join sli_agent_update_policy a on a.package_sha256=p.sha256 where a.agent_id=@agent and p.sha256=@package",db,tx);
        command.Parameters.AddWithValue("agent",agent.Id);command.Parameters.AddWithValue("package",package);
        await using var reader=await command.ExecuteReaderAsync(System.Data.CommandBehavior.SequentialAccess,ct);
        if(!await reader.ReadAsync(ct))throw new AgentControlException("agent_package_not_assigned",404);
        await using var content=reader.GetStream(0);
        var options=new FileStreamOptions { Mode=FileMode.CreateNew,Access=FileAccess.ReadWrite,Share=FileShare.None,
            Options=FileOptions.Asynchronous|FileOptions.SequentialScan|FileOptions.DeleteOnClose };
        if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        var file=new FileStream(Path.Combine(Path.GetTempPath(),"sli-agent-package-"+Guid.NewGuid().ToString("N")+".tmp"),options);
        try {await content.CopyToAsync(file,ct);file.Position=0;return file;}
        catch {await file.DisposeAsync();throw;}
    }
    public async Task<JsonObject> ReportAsync(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity agent,JsonObject body,CancellationToken ct)
    {
        var result=AgentUpdateInput.Parse(body);
        await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);
        await using(var command=new NpgsqlCommand("""
            select p.sha256 from sli_agent_update_packages p where p.sha256=@package and
            (exists(select 1 from sli_agent_update_policy a where a.agent_id=@agent and a.package_sha256=p.sha256)
             or exists(select 1 from sli_agent_audit a where a.action='update_assign' and a.target=@target and a.details->>'sha256'=p.sha256))
            """,db,tx)) {
            command.Parameters.AddWithValue("package",result.Sha256);command.Parameters.AddWithValue("agent",agent.Id);command.Parameters.AddWithValue("target",agent.Id.ToString("D"));
            if(await command.ExecuteScalarAsync(ct) is null)throw new AgentControlException("agent_package_not_assigned",404);
        }
        bool inserted;
        await using(var command=new NpgsqlCommand("insert into sli_agent_update_results(agent_id,package_sha256,status,reason,version) values(@agent,@package,@status,@reason,@version) on conflict(agent_id,package_sha256,status,reason_key) do nothing returning agent_id",db,tx)) {
            command.Parameters.AddWithValue("agent",agent.Id);command.Parameters.AddWithValue("package",result.Sha256);command.Parameters.AddWithValue("status",result.Status);
            command.Parameters.AddWithValue("reason",NpgsqlDbType.Text,(object?)result.Reason??DBNull.Value);command.Parameters.AddWithValue("version",result.Version);inserted=await command.ExecuteScalarAsync(ct) is not null;
        }
        if(inserted)await audit.AppendAsync(db,tx,"update_result","agent:"+agent.Id.ToString("D"),result.Sha256,new { status=result.Status,reason=result.Reason },ct);
        await AgentUpdateWaves.RecordAsync(db,tx,agent,result,audit,ct);
        return new JsonObject { ["status"]="recorded" };
    }
}
