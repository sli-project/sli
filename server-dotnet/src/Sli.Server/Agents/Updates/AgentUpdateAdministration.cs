using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
namespace Sli.Server.Agents.Updates;

public sealed class AgentUpdateAdministration(IAgentControlAudit audit,IConfiguration configuration)
{
    public async Task<JsonElement> UploadAsync(NpgsqlConnection db,NpgsqlTransaction tx,byte[] raw,string actor,CancellationToken ct)
    {
        if(raw.Length is <1 or >268435456)throw new AgentControlException("agent_package_invalid");
        // Python bytes are immutable. Keep a private snapshot for verification
        // and the later asynchronous bytea INSERT, never reopen a package path.
        byte[] archive=(byte[])raw.Clone(),trust;
        try {
            string path=configuration["Sli:AgentUpdateTrustFile"]??Environment.GetEnvironmentVariable("SLI_AGENT_UPDATE_TRUST_FILE")??throw new IOException();
            await using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read,4096,FileOptions.Asynchronous);
            using var memory=new MemoryStream();byte[] buffer=new byte[4096];int read;
            while((read=await stream.ReadAsync(buffer,ct))!=0){if(memory.Length+read>65536)throw new IOException();await memory.WriteAsync(buffer.AsMemory(0,read),ct);}trust=memory.ToArray();
        }
        catch(Exception error) when(error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {throw new AgentControlException("agent_package_verification_failed");}
        var verified=AgentPackageVerifier.Verify(archive,trust);
        await using var command=new NpgsqlCommand("insert into sli_agent_update_packages(sha256,version,manifest,archive) values(@sha,@version,@manifest,@archive) on conflict(sha256) do nothing",db,tx);
        command.Parameters.AddWithValue("sha",verified.Sha256);command.Parameters.AddWithValue("version",verified.Manifest["version"]!.GetValue<string>());
        command.Parameters.AddWithValue("manifest",NpgsqlDbType.Jsonb,verified.Manifest.ToJsonString());command.Parameters.AddWithValue("archive",archive);await command.ExecuteNonQueryAsync(ct);
        await audit.AppendAsync(db,tx,"update_upload",actor,verified.Sha256,new { },ct);
        return JsonSerializer.SerializeToElement(new { sha256=verified.Sha256,version=verified.Manifest["version"]!.GetValue<string>() });
    }
    public async Task<JsonElement> ListPackagesAsync(NpgsqlConnection db,NpgsqlTransaction tx,string actor,CancellationToken ct)
    {
        var items=await Rows(db,tx,"select jsonb_build_object('sha256',sha256,'version',version,'manifest',manifest,'created_at',created_at)::text from sli_agent_update_packages order by created_at desc,sha256 limit 100",ct);
        var policies=await Rows(db,tx,"select jsonb_build_object('agent_id',agent_id,'package_sha256',package_sha256)::text from sli_agent_update_policy order by agent_id limit 100",ct);
        var results=await Rows(db,tx,"select jsonb_build_object('agent_id',agent_id,'package_sha256',package_sha256,'status',status,'reason',reason,'version',version,'observed_at',observed_at)::text from sli_agent_update_results order by observed_at desc limit 100",ct);
        await audit.AppendAsync(db,tx,"update_list",actor,"agent-packages",new { },ct);return AgentControlJson.Element(new JsonObject { ["items"]=items,["policies"]=policies,["results"]=results });
    }
    public async Task<JsonElement> AssignAsync(NpgsqlConnection db,NpgsqlTransaction tx,JsonElement payload,string actor,CancellationToken ct)
    {
        var body=AgentUpdateAdminInput.Body(payload,"agent_update_policy_invalid");
        if(body.Count!=2 || !body.ContainsKey("agent_id") || !body.ContainsKey("sha256"))throw new AgentControlException("agent_update_policy_invalid");
        Guid id=AgentUpdateAdminInput.Id(body["agent_id"]);await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);
        string? package=body["sha256"] is null?null:AgentUpdateInput.Digest(body["sha256"]);
        if(package is not null && !await Exists(db,tx,"select 1 from sli_agent_update_packages where sha256=@package",ct,("package",package)))throw new AgentControlException("agent_package_not_found",404);
        if(!await Exists(db,tx,"select id from sli_agents where id=@id and status='active' for update",ct,("id",id)))throw new AgentControlException("agent_not_found",404);
        await Unreserved(db,tx,[id],ct);
        await using var command=new NpgsqlCommand("insert into sli_agent_update_policy(agent_id,package_sha256) values(@agent,@package) on conflict(agent_id) do update set package_sha256=excluded.package_sha256",db,tx);
        command.Parameters.AddWithValue("agent",id);command.Parameters.AddWithValue("package",NpgsqlDbType.Text,(object?)package??DBNull.Value);await command.ExecuteNonQueryAsync(ct);
        await audit.AppendAsync(db,tx,"update_assign",actor,id.ToString("D"),new { sha256=package },ct);return JsonSerializer.SerializeToElement(new { status="assigned" });
    }
    public async Task<JsonElement> CreateWaveAsync(NpgsqlConnection db,NpgsqlTransaction tx,JsonElement payload,string actor,CancellationToken ct)
    {
        var input=AgentUpdateAdminInput.Wave(payload);await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);string version;
        await using(var release=new NpgsqlCommand("select version from sli_agent_update_packages where sha256=@package",db,tx)) {
            release.Parameters.AddWithValue("package",input.Sha256);version=(string?)await release.ExecuteScalarAsync(ct)??throw new AgentControlException("agent_package_not_found",404);
        }
        var ids=new List<Guid>();
        await using(var selection=new NpgsqlCommand(input.Group is null?"select id from sli_agents where id=any(@ids) and status='active' order by id for update":"""
            select a.id from sli_agents a where a.status='active' and exists(
              select 1 from sli_agent_group_approval_links c join sli_agent_group_requests r on r.id=c.request_id
              join sli_agent_enrollment_tokens t on t.id=c.enrollment_token_id
              where r.token_id=@group and r.status='approved' and t.used_at is not null
                and t.key_fingerprint=r.key_fingerprint and a.host_id=t.host_id
                and a.instance_name is not distinct from t.instance_name
                and exists(select 1 from sli_agent_audit e where e.action='issue' and e.actor='enrollment:' || t.id::text and e.target=a.id::text))
              order by a.id limit 1001 for update of a
            """,db,tx)) {
            if(input.Group is null)selection.Parameters.AddWithValue("ids",input.Ids!);else selection.Parameters.AddWithValue("group",input.Group.Value);
            await using var reader=await selection.ExecuteReaderAsync(ct);while(await reader.ReadAsync(ct))ids.Add(reader.GetGuid(0));
        }
        if(input.Group is not null && ids.Count is <1 or >1000)throw new AgentControlException("agent_update_wave_selection_invalid");
        if(input.Group is null && !ids.ToHashSet().SetEquals(input.Ids!))throw new AgentControlException("agent_not_found",404);
        Guid[] agents=ids.ToArray();await Unreserved(db,tx,agents,ct);
        if(await Exists(db,tx,"select 1 from sli_agent_update_policy where agent_id=any(@ids) and package_sha256 is not null",ct,("ids",agents)))throw new AgentControlException("agent_update_policy_conflict",409);
        if(await Exists(db,tx,"select 1 from sli_agent_update_wave_members where agent_id=any(@ids) and package_sha256=@package limit 1",ct,("ids",agents),("package",input.Sha256)) ||
            await Exists(db,tx,"select 1 from sli_agent_audit where action='update_assign' and target=any(@targets) and details->>'sha256'=@package limit 1",ct,("targets",agents.Select(i=>i.ToString("D")).ToArray()),("package",input.Sha256)))throw new AgentControlException("agent_update_package_already_attempted",409);
        Guid wave=Guid.NewGuid();
        await using(var create=new NpgsqlCommand("insert into sli_agent_update_waves(id,package_sha256,version,batch_size,error_threshold,group_token_id,created_by) values(@id,@package,@version,@size,@threshold,@group,@actor)",db,tx)) {
            create.Parameters.AddWithValue("id",wave);create.Parameters.AddWithValue("package",input.Sha256);create.Parameters.AddWithValue("version",version);create.Parameters.AddWithValue("size",input.BatchSize);create.Parameters.AddWithValue("threshold",input.Threshold);
            create.Parameters.AddWithValue("group",NpgsqlDbType.Uuid,(object?)input.Group??DBNull.Value);create.Parameters.AddWithValue("actor",actor);await create.ExecuteNonQueryAsync(ct);
        }
        for(int index=0;index<agents.Length;index++) {
            await using var member=new NpgsqlCommand("insert into sli_agent_update_wave_members(wave_id,agent_id,package_sha256,batch_number) values(@wave,@agent,@package,@batch)",db,tx);
            member.Parameters.AddWithValue("wave",wave);member.Parameters.AddWithValue("agent",agents[index]);member.Parameters.AddWithValue("package",input.Sha256);member.Parameters.AddWithValue("batch",index/input.BatchSize+1);await member.ExecuteNonQueryAsync(ct);
        }
        await audit.AppendAsync(db,tx,"update_wave_create",actor,wave.ToString("D"),new { sha256=input.Sha256,batch_size=input.BatchSize,error_threshold=input.Threshold,group_token_id=input.Group?.ToString("D"),count=agents.Length },ct);
        await AgentUpdateWaves.IssueAsync(db,tx,wave,input.Sha256,1,await AgentUpdateWaves.MembersAsync(db,tx,wave,ct),actor,audit,ct);
        return AgentControlJson.Element(await View(db,tx,await Wave(db,tx,wave,ct),ct));
    }
    public async Task<JsonElement> StopWaveAsync(NpgsqlConnection db,NpgsqlTransaction tx,JsonElement payload,string actor,CancellationToken ct)
    {
        var body=AgentUpdateAdminInput.Body(payload,"agent_update_wave_invalid");if(body.Count!=1 || !body.ContainsKey("wave_id"))throw new AgentControlException("agent_update_wave_invalid");
        Guid id=AgentUpdateAdminInput.Id(body["wave_id"]);await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);var wave=await Wave(db,tx,id,ct);
        if(wave["status"]!.GetValue<string>()=="running")await Finish(db,tx,wave,"agent_update_stopped_by_admin",actor,ct);
        return AgentControlJson.Element(await View(db,tx,wave,ct));
    }
    public async Task<JsonElement> ListWavesAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid? id,string actor,CancellationToken ct)
    {
        await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);List<JsonObject> waves;
        if(id is not null)waves=[await Wave(db,tx,id.Value,ct)];
        else waves=(await Rows(db,tx,"select to_jsonb(w)::text from sli_agent_update_waves w order by created_at desc,id limit 100",ct)).Select(n=>n!.AsObject()).ToList();
        foreach(var wave in waves)if(wave["status"]!.GetValue<string>()=="running" && (await AgentUpdateWaves.MembersAsync(db,tx,Guid.Parse(wave["id"]!.GetValue<string>()),ct)).Any(m=>m.AgentStatus!="active"))await Finish(db,tx,wave,"agent_update_agent_inactive",actor,ct);
        await audit.AppendAsync(db,tx,"update_wave_list",actor,id?.ToString("D")??"agent-update-waves",new { },ct);
        var items=new JsonArray();foreach(var wave in waves)items.Add(await View(db,tx,wave,ct));return AgentControlJson.Element(new JsonObject { ["items"]=items });
    }
    private async Task Finish(NpgsqlConnection db,NpgsqlTransaction tx,JsonObject wave,string reason,string actor,CancellationToken ct)
    {
        Guid id=Guid.Parse(wave["id"]!.GetValue<string>());int errors=(await AgentUpdateWaves.MembersAsync(db,tx,id,ct)).Count(m=>m.HadError);
        var finished=await AgentUpdateWaves.FinishAsync(db,tx,id,wave["package_sha256"]!.GetValue<string>(),wave["current_batch"]!.GetValue<int>(),"stopped",reason,errors,actor,audit,ct);
        wave["status"]="stopped";wave["reason"]=reason;wave["finished_at"]=AgentControlJson.Stamp(finished);
    }
    private static async Task<JsonObject> View(NpgsqlConnection db,NpgsqlTransaction tx,JsonObject wave,CancellationToken ct)
    {
        var members=await AgentUpdateWaves.MembersAsync(db,tx,Guid.Parse(wave["id"]!.GetValue<string>()),ct);var result=(JsonObject)wave.DeepClone();
        result["errors"]=members.Count(m=>m.HadError);result["confirmed"]=members.Count(m=>m.State=="updated");result["waiting_reason"]=wave["status"]!.GetValue<string>()=="running"?"agent_update_awaiting_version":null;
        result["members"]=new JsonArray(members.Select(m=>(JsonNode)new JsonObject { ["agent_id"]=m.Id.ToString("D"),["batch_number"]=m.Batch,["state"]=m.State,["reason"]=m.Reason,["had_error"]=m.HadError,["agent_status"]=m.AgentStatus }).ToArray());return result;
    }
    private static async Task<JsonObject> Wave(NpgsqlConnection db,NpgsqlTransaction tx,Guid id,CancellationToken ct)
    {await using var query=new NpgsqlCommand("select to_jsonb(w)::text from sli_agent_update_waves w where id=@id",db,tx);query.Parameters.AddWithValue("id",id);return Row((string?)await query.ExecuteScalarAsync(ct)??throw new AgentControlException("agent_update_wave_not_found",404));}
    private static async Task Unreserved(NpgsqlConnection db,NpgsqlTransaction tx,Guid[] ids,CancellationToken ct)
    {if(await Exists(db,tx,"select 1 from sli_agent_update_wave_members where agent_id=any(@ids) and reserved",ct,("ids",ids)))throw new AgentControlException("agent_update_wave_conflict",409);}
    private static async Task<bool> Exists(NpgsqlConnection db,NpgsqlTransaction tx,string sql,CancellationToken ct,params (string Key,object Value)[] parameters)
    {await using var query=new NpgsqlCommand(sql,db,tx);foreach(var (key,value) in parameters)query.Parameters.AddWithValue(key,value);return await query.ExecuteScalarAsync(ct) is not null;}
    private static async Task<JsonArray> Rows(NpgsqlConnection db,NpgsqlTransaction tx,string sql,CancellationToken ct)
    {var result=new JsonArray();await using var query=new NpgsqlCommand(sql,db,tx);await using var reader=await query.ExecuteReaderAsync(ct);while(await reader.ReadAsync(ct))result.Add(Row(reader.GetString(0)));return result;}
    private static JsonObject Row(string json)
    {
        var row=JsonNode.Parse(json)!.AsObject();foreach(string key in new[]{"created_at","observed_at","finished_at","issued_at","reported_at"})
            if(row[key] is JsonValue v && v.TryGetValue<string>(out var text))row[key]=AgentControlJson.Stamp(DateTimeOffset.Parse(text,CultureInfo.InvariantCulture));return row;
    }
}
