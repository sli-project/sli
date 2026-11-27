using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
namespace Sli.Server.Agents.Updates;

public sealed class AgentUpdateService(IAgentControlAudit audit)
{
    public async Task<FileStream> DownloadAsync(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity agent,string value,CancellationToken ct)
        => (await DownloadPackageAsync(db,tx,agent,value,ct)).Content;

    internal async Task<(FileStream Content, string ContentType)> DownloadPackageAsync(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity agent,string value,CancellationToken ct)
    {
        string package=AgentUpdateInput.Digest(JsonValue.Create(value));
        await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);
        await using var command=new NpgsqlCommand("""
            select coalesce(p.manifest->>'format'='msi',false),p.archive from sli_agent_update_packages p where p.sha256=@package and (
                exists(select 1 from sli_agent_update_policy a where a.agent_id=@agent and a.package_sha256=p.sha256)
                or (
                    exists(select 1 from sli_agent_update_wave_members m
                        join sli_agent_update_waves w on w.id=m.wave_id
                        where m.agent_id=@agent and w.package_sha256=p.sha256 and m.state in ('pending','failed')
                            and w.status='running' and w.created_by=@shipped
                            and w.package_sha256=(select value from platform_settings where key='agents.shipped_update'))
                    and exists(select 1 from platform_settings where key='agents.automatic_update' and value='automatic')
                    and not exists(select 1 from sli_agent_update_policy a where a.agent_id=@agent)
                    and not exists(select 1 from sli_agent_update_wave_members m where m.agent_id=@agent and m.reserved)
                ))
            """,db,tx);
        command.Parameters.AddWithValue("agent",agent.Id);command.Parameters.AddWithValue("package",package);
        command.Parameters.AddWithValue("shipped",ShippedAgentUpdate.Actor);
        await using var reader=await command.ExecuteReaderAsync(System.Data.CommandBehavior.SequentialAccess,ct);
        if(!await reader.ReadAsync(ct))throw new AgentControlException("agent_package_not_assigned",404);
        string contentType=reader.GetBoolean(0)?"application/octet-stream":"application/zip";
        var options=new FileStreamOptions { Mode=FileMode.CreateNew,Access=FileAccess.ReadWrite,Share=FileShare.None,
            Options=FileOptions.Asynchronous|FileOptions.SequentialScan|FileOptions.DeleteOnClose };
        if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        var file=new FileStream(Path.Combine(Path.GetTempPath(),"sli-agent-package-"+Guid.NewGuid().ToString("N")+".tmp"),options);
        try {
            await using(var content=reader.GetStream(1))await content.CopyToAsync(file,ct);
            await reader.DisposeAsync();
            if(contentType=="application/octet-stream") {
                await using var retry=new NpgsqlCommand("""
                    update sli_agent_update_wave_members m set state='pending',reason=null,reported_at=null,issued_at=clock_timestamp()
                    from sli_agent_update_waves w where w.id=m.wave_id and w.created_by=@shipped
                        and w.status='running' and m.agent_id=@agent and m.package_sha256=@package and m.state='failed'
                    """,db,tx);
                retry.Parameters.AddWithValue("shipped",ShippedAgentUpdate.Actor);
                retry.Parameters.AddWithValue("agent",agent.Id);
                retry.Parameters.AddWithValue("package",package);
                await retry.ExecuteNonQueryAsync(ct);
            }
            file.Position=0;return (file,contentType);
        }
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
