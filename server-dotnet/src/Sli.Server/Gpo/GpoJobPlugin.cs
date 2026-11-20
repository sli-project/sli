using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Jobs;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Gpo;

// Owns only ad.gpo.v2; the agent publisher remains the source writer.
public sealed class GpoJobPlugin : ICoreJobPlugin
{
    public void Register(CoreJobPluginCatalog catalog)
    {
        var handler = new CoreJobHandler((db,j,ct)=>StageAsync(new GpoJobStore(db),j,ct), (db,j,r,ct)=>PublishAsync(new GpoJobStore(db),j,r,ct));
        catalog.Add("sli.gpo","gpo-snapshot",handler,ScheduleAsync);
        catalog.Add("sli.gpo","gpo-acquisition",handler);
    }
    internal static (JsonObject Pinned,string Partition) Pin(JsonObject h,JsonObject s,string generation) =>
        (new JsonObject { ["generation"]=generation,["input_range"]=new JsonArray(s.Text("manifest_id")),["policy_revision"]=s["revision"]?.DeepClone(),["continuation"]=null,
            ["manifest_id"]=s["manifest_id"]?.DeepClone(),["snapshot_sha256"]=s["snapshot_sha256"]?.DeepClone(),["domain_id"]=s["domain_id"]?.DeepClone() },"ad-snapshot");
    static async Task ScheduleAsync(NpgsqlConnection db,CoreJobQueue q,CoreJobRegistry registry,string profile,CancellationToken ct)
    {
        var sources=new List<JsonObject>();
        await using(var cmd=new NpgsqlCommand("select public.read_ad_snapshot_job_sources_v1('sli.gpo')",db))
        await using(var reader=await cmd.ExecuteReaderAsync(ct))
            while(await reader.ReadAsync(ct)) sources.Add(JsonNode.Parse(reader.GetString(0))!.AsObject());
        foreach(var source in sources) foreach(var spec in CoreJobScheduler.Create(registry,profile,source,DateTimeOffset.UtcNow,Pin)) await q.EnqueueAsync(spec,ct);
    }
    internal static JsonObject Blocked(JsonObject j,string error,JsonObject? composition=null)
    {
        var r=new JsonObject { ["status"]="blocked",["output_contract"]=j["result_contract"]?.DeepClone(),["coverage_state"]="not_collected",["continuation"]=null,["evidence_refs"]=new JsonArray(),["error_code"]=error };
        if(composition is not null) r["composition"]=composition.DeepClone(); return r;
    }
    internal static async Task<JsonObject> StageAsync(IGpoJobStore store,JsonObject j,CancellationToken ct)
    {
        if(j.Text("job_type")=="acquire") return Blocked(j,OperatingSystem.IsWindows()?"acquisition_requires_agent":"acquisition_disabled_on_linux");
        if(!await store.EnabledAsync(ct)) return Blocked(j,"snapshot_plugin_disabled");
        var p=j["pinned_input"]!; var m=await store.ManifestAsync(p.Text("manifest_id"),ct); ValidateBinding(j,m);
        var families=m.Rows("members").Select(x=>x.Text("family")).ToHashSet();
        var composition=new JsonObject { ["version"]=1,["parts"]=new JsonArray() };
        if(families.Overlaps(["ad_context_base","computers_v6"])) composition["parts"]!.AsArray().Add("base_ad");
        if(!families.Overlaps(["gpo_v2","ad_gpo_governance"])) return Blocked(j,"snapshot_part_not_collected",composition);
        composition["parts"]!.AsArray().Add("gpo");
        var member=m.Rows("members").SingleOrDefault(x=>x.Text("family")=="gpo_v2")??throw new CoreJobContractException("snapshot_projection_failed");
        var payload=await store.SourceAsync(member.Text("source_id"),member.Text("payload_sha256"),ct);
        if(payload.Where(x=>x.Value is JsonArray).Sum(x=>x.Value!.AsArray().Count)>j["budget"]!.Number("max_records")) throw new CoreJobContractException("snapshot_record_budget_exceeded");
        var identity=new JsonObject { ["manifest_id"]=m["manifest_id"]!.DeepClone(),["manifest_sha256"]=m["manifest_sha256"]!.DeepClone(),["projection_key"]="ad.gpo.v2",["projection_version"]=1,
            ["family"]="gpo_v2",["source_id"]=member["source_id"]!.DeepClone(),["payload_sha256"]=member["payload_sha256"]!.DeepClone() };
        var projection=new JsonObject { ["input_sha256"]=Hash(identity),["output_sha256"]=Hash(payload),["output_identity"]=m.Text("manifest_id")+":ad.gpo.v2:v1" };
        return new JsonObject { ["status"]=m.Text("coverage_state")=="partial"?"partial":"success",["output_contract"]=j["result_contract"]?.DeepClone(),["coverage_state"]=m["coverage_state"]?.DeepClone()??JsonValue.Create("not_proven"),
            ["continuation"]=null,["error_code"]=null,["evidence_refs"]=new JsonArray("ad-snapshot:"+m.Text("manifest_id")),["projection_results"]=new JsonObject { ["ad.gpo.v2"]=projection },["composition"]=composition };
    }
    internal static void ValidateBinding(JsonObject j,JsonObject m)
    {
        var p=j["pinned_input"]!;
        if(m.Text("manifest_id")!=p.Text("manifest_id")||m.Text("manifest_sha256")!=p.Text("snapshot_sha256")||m.Number("domain_id")!=p.Number("domain_id")||j.Text("source_instance_id")!="ad-domain:"+p.Number("domain_id")) throw new CoreJobContractException("snapshot_input_changed");
    }
    internal static async Task PublishAsync(IGpoJobStore store,JsonObject j,JsonObject r,CancellationToken ct)
    {
        if(r.Text("status") is "blocked" or "cancelled") return;
        await store.FenceAsync(j,ct); var expected=await StageAsync(store,j,ct);
        if(!JsonNode.DeepEquals(expected["projection_results"],r["projection_results"])||!JsonNode.DeepEquals(expected["composition"],r["composition"])) throw new CoreJobContractException("snapshot_result_changed");
        var m=await store.ManifestAsync(j["pinned_input"]!.Text("manifest_id"),ct);var member=m.Rows("members").Single(x=>x.Text("family")=="gpo_v2");
        await store.PersistAsync(j,r["projection_results"]!["ad.gpo.v2"]!.AsObject(),await store.SourceAsync(member.Text("source_id"),member.Text("payload_sha256"),ct),ct);
    }
}
internal interface IGpoJobStore
{
    Task<bool> EnabledAsync(CancellationToken ct);
    Task<JsonObject> ManifestAsync(string id,CancellationToken ct);
    Task<JsonObject> SourceAsync(string id,string hash,CancellationToken ct);
    Task FenceAsync(JsonObject job,CancellationToken ct);
    Task PersistAsync(JsonObject job,JsonObject projection,JsonObject payload,CancellationToken ct);
}
internal sealed class GpoJobStore(NpgsqlConnection db) : IGpoJobStore
{
    public Task<bool> EnabledAsync(CancellationToken ct)
    {
        using var stream=typeof(GpoJobStore).Assembly.GetManifestResourceStream("Sli.Server.Workspace.declarations.json")!;
        return Task.FromResult(JsonNode.Parse(stream)!["navigation"]!["enabled_plugins"]!.AsArray().Any(x=>x!.GetValue<string>()=="sli.gpo"));
    }
    public async Task<JsonObject> ManifestAsync(string id,CancellationToken ct)
    {
        await using var cmd=new NpgsqlCommand("select jsonb_build_object('manifest_id',manifest_id::text,'domain_id',domain_id,'coverage_state',coverage_state,'manifest_sha256',encode(manifest_sha256,'hex')) from ad_snapshot_manifests where manifest_id=@id",db);
        cmd.Parameters.AddWithValue("id",Guid.Parse(id));var r=JsonNode.Parse((string?)await cmd.ExecuteScalarAsync(ct)??throw new CoreJobContractException("snapshot_input_changed"))!.AsObject();
        await using var members=new NpgsqlCommand("select jsonb_build_object('family',family,'source_id',source_id,'payload_sha256',encode(payload_sha256,'hex')) from ad_snapshot_manifest_sources where manifest_id=@id order by family",db);
        members.Parameters.AddWithValue("id",Guid.Parse(id));var rows=new JsonArray();await using var reader=await members.ExecuteReaderAsync(ct);while(await reader.ReadAsync(ct)) rows.Add(JsonNode.Parse(reader.GetString(0)));r["members"]=rows;return r;
    }
    public async Task<JsonObject> SourceAsync(string id,string hash,CancellationToken ct)
    {
        await using var cmd=new NpgsqlCommand("select payload_json,encode(payload_sha256,'hex') from gpo_report_v2_source_snapshots where source_run_id=@id",db);cmd.Parameters.AddWithValue("id",Guid.Parse(id));await using var reader=await cmd.ExecuteReaderAsync(ct);
        if(!await reader.ReadAsync(ct)||reader.GetString(1)!=hash) throw new CoreJobContractException("snapshot_input_changed");return JsonNode.Parse(reader.GetString(0))!.AsObject();
    }
    public async Task FenceAsync(JsonObject j,CancellationToken ct)
    {
        foreach(string key in new[]{"ad_log_reports_runtime_ad_snapshot_manifest_coordinator_worker","ad_log_reports_runtime_ad_context_snapshot_worker","ad_log_reports_runtime_computers_v6_source_worker","ad_log_reports_runtime_users_v2_snapshot_worker"})
        {
            await using var cmd=new NpgsqlCommand("select pg_try_advisory_lock(hashtext(@key))",db);cmd.Parameters.AddWithValue("key",key);if(await cmd.ExecuteScalarAsync(ct) is not true) throw new InvalidOperationException("legacy_snapshot_writer_busy");
        }
        await using var fence=new NpgsqlCommand("select set_config('sli.job_id',@id,true),set_config('sli.job_token',@token,true),set_config('sli.job_generation',@generation,true)",db);
        fence.Parameters.AddWithValue("id",j.Text("job_id"));fence.Parameters.AddWithValue("token",j.Text("lease_token"));fence.Parameters.AddWithValue("generation",j["lease_generation"]!.ToString());await fence.ExecuteNonQueryAsync(ct);
    }
    public async Task PersistAsync(JsonObject j,JsonObject p,JsonObject payload,CancellationToken ct)
    {
        Guid id=Guid.Parse(j["pinned_input"]!.Text("manifest_id"));string worker="core-job:"+j.Text("job_id");
        // Match legacy recovery: a completed receipt without its immutable output
        // must be claimed again, never accepted as a successful publication.
        await using(var repair=new NpgsqlCommand("""
            update ad_snapshot_projection_receipts receipt set status='failed',lease_owner=null,lease_expires_at=null,
              last_error='projection output readback missing',updated_at=now()
            where manifest_id=@id and projection_key='ad.gpo.v2' and projection_version=1 and status='completed'
              and not exists(select 1 from ad_snapshot_projection_outputs output where output.manifest_id=receipt.manifest_id
                and output.projection_key=receipt.projection_key and output.projection_version=receipt.projection_version)
            """,db)) { repair.Parameters.AddWithValue("id",id);await repair.ExecuteNonQueryAsync(ct); }
        await using(var claim=new NpgsqlCommand("""
            update ad_snapshot_projection_receipts set status='running',attempt_count=attempt_count+1,lease_owner=@worker,
                lease_expires_at=now()+interval '300 seconds',updated_at=now(),last_error=null
            where manifest_id=@id and projection_key='ad.gpo.v2' and projection_version=1 and attempt_count<4
              and (status in ('pending','failed') or (status='running' and lease_expires_at<=now()))
            """,db)) { claim.Parameters.AddWithValue("id",id);claim.Parameters.AddWithValue("worker",worker);await claim.ExecuteNonQueryAsync(ct); }
        await using(var insert=new NpgsqlCommand("""
            insert into ad_snapshot_projection_outputs(manifest_id,projection_key,projection_version,input_sha256,output_sha256,output_identity,payload_json)
            select @id,'ad.gpo.v2',1,@input,@output,@identity,@payload where exists (
              select 1 from ad_snapshot_projection_receipts where manifest_id=@id and projection_key='ad.gpo.v2' and projection_version=1 and status='running' and lease_owner=@worker)
            on conflict(manifest_id,projection_key,projection_version) do nothing
            """,db)) { Bind(insert);insert.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,payload.ToJsonString());insert.Parameters.AddWithValue("worker",worker);await insert.ExecuteNonQueryAsync(ct); }
        await using(var read=new NpgsqlCommand("select encode(input_sha256,'hex'),encode(output_sha256,'hex'),output_identity,payload_json from ad_snapshot_projection_outputs where manifest_id=@id and projection_key='ad.gpo.v2' and projection_version=1",db))
        {
            read.Parameters.AddWithValue("id",id);await using var reader=await read.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct)||reader.GetString(0)!=p.Text("input_sha256")||reader.GetString(1)!=p.Text("output_sha256")||reader.GetString(2)!=p.Text("output_identity")||Hash(JsonNode.Parse(reader.GetString(3)))!=p.Text("output_sha256")) throw new CoreJobContractException("snapshot_result_changed");
        }
        await using var finish=new NpgsqlCommand("""
            update ad_snapshot_projection_receipts set status='completed',lease_owner=null,lease_expires_at=null,input_sha256=@input,
              output_sha256=@output,output_identity=@identity,last_error=null,updated_at=now()
            where manifest_id=@id and projection_key='ad.gpo.v2' and projection_version=1 and
              ((status='running' and lease_owner=@worker) or (status='completed' and input_sha256=@input and output_sha256=@output and output_identity=@identity))
            """,db);Bind(finish);finish.Parameters.AddWithValue("worker",worker);if(await finish.ExecuteNonQueryAsync(ct)!=1) throw new InvalidOperationException("snapshot_projection_not_completed");
        void Bind(NpgsqlCommand c) { c.Parameters.AddWithValue("id",id);c.Parameters.AddWithValue("input",Convert.FromHexString(p.Text("input_sha256")));c.Parameters.AddWithValue("output",Convert.FromHexString(p.Text("output_sha256")));c.Parameters.AddWithValue("identity",p.Text("output_identity")); }
    }
}
