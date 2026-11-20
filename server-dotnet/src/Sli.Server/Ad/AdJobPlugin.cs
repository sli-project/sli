using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using CJ = Sli.Server.Jobs;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

// The shared host owns leases, child budgets, admission and the final transaction fence.
public sealed class AdJobPlugin : CJ.ICoreJobPlugin
{
    public static readonly string[] Handlers = ["ad-snapshot-manifest-coordinator", "ad-snapshot-projection", "ad-context-snapshot", "computers-v6-source", "users-report-v2-snapshot"];
    static readonly Dictionary<string, (string Key, string Family)> Projections = new()
    {
        [Handlers[0]] = ("ad.state", "ad_context_base"), [Handlers[1]] = ("ad.computers.v6", "computers_v6"), [Handlers[4]] = ("ad.users.v2", "users_v2")
    };
    public void Register(CJ.CoreJobPluginCatalog catalog)
    { foreach (string handler in Handlers) catalog.Add("sli.ad", handler, new(StageAsync, PublishAsync), ScheduleAsync); }
    public static (JsonObject Pinned, string Partition) Pin(JsonObject handler, JsonObject source, string generation)
    {
        var pin = new JsonObject { ["generation"] = generation, ["input_range"] = new JsonArray(source["manifest_id"]!.DeepClone()), ["policy_revision"] = source["revision"]!.DeepClone(), ["continuation"] = null };
        foreach (string k in new[] { "manifest_id", "snapshot_sha256", "domain_id" }) pin[k] = source[k]!.DeepClone();
        return (pin, "ad-snapshot");
    }
    static async Task ScheduleAsync(NpgsqlConnection db, CJ.CoreJobQueue queue, CJ.CoreJobRegistry registry, string profile, CancellationToken ct)
    {
        if (profile != "heavy") return;
        var sources = await ReadAsync(db, "select public.read_ad_snapshot_job_sources_v1('sli.ad')::text as source", ct);
        foreach (var source in sources)
            foreach (var spec in CJ.CoreJobScheduler.Create(registry, profile, JsonNode.Parse(source.Text("source")!)!.AsObject(), DateTimeOffset.UtcNow, Pin)) await queue.EnqueueAsync(spec, ct);
    }
    public static string Digest(JsonNode value) => Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(CanonicalJson.Serialize(value, false))));
    public static JsonObject Composition(IEnumerable<string> families)
    {
        var set = families.ToHashSet(StringComparer.Ordinal); var parts = new JsonArray();
        if (set.Contains("ad_context_base") || set.Contains("computers_v6")) parts.Add("base_ad");
        if (set.Contains("gpo_v2") || set.Contains("ad_gpo_governance")) parts.Add("gpo");
        return new JsonObject { ["version"] = 1, ["parts"] = parts };
    }
    public static JsonObject Project(JsonObject manifest, string key, string family, JsonNode payload, out JsonObject output)
    {
        var member = manifest["members"]!.AsArray().OfType<JsonObject>().Single(m => m.Text("family") == family);
        var input = new JsonObject { ["manifest_id"] = manifest["manifest_id"]!.DeepClone(), ["manifest_sha256"] = manifest["manifest_sha256"]!.DeepClone(), ["projection_key"] = key, ["projection_version"] = 1, ["family"] = family, ["source_id"] = member["source_id"]!.DeepClone(), ["payload_sha256"] = member["payload_sha256"]!.DeepClone() };
        output = (JsonObject)payload.DeepClone();
        var families = manifest["members"]!.AsArray().Select(m => m!.Text("family")!).ToHashSet();
        if (key == "ad.state" && families.Contains("ad_context_base") && families.Contains("computers_v6") && !families.Contains("gpo_v2") && !families.Contains("ad_gpo_governance")) output["composition"] = Composition(families);
        return Obj(new { input_sha256 = Digest(input), output_sha256 = Digest(output), output_identity = manifest.Text("manifest_id") + ":" + key + ":v1" });
    }
    static async Task<bool> Enabled(NpgsqlConnection db, CancellationToken ct)
    {
        await using var c = new NpgsqlCommand("select public.core_ad_job_plugin_enabled_v1('sli.ad')", db);
        return await c.ExecuteScalarAsync(ct) is true;
    }
    static JsonObject Blocked(JsonObject job, string code) => Obj(new { status = "blocked", output_contract = job.Text("result_contract"), coverage_state = "not_collected", continuation = (string?)null, evidence_refs = new string[0], error_code = code });
    static async Task<JsonObject> LoadManifest(NpgsqlConnection db, JsonObject job, CancellationToken ct)
    {
        var pin = job["pinned_input"]!; var id = Guid.Parse(pin.Text("manifest_id")!);
        var rows = await ReadAsync(db, "select manifest_id::text,domain_id,coverage_state,encode(manifest_sha256,'hex') as manifest_sha256 from ad_snapshot_manifests where manifest_id=$1", ct, id);
        if (rows.Count != 1 || rows[0].Text("manifest_sha256") != pin.Text("snapshot_sha256") || rows[0].Int("domain_id") != pin.Int("domain_id") || job.Text("source_instance_id") != "ad-domain:" + pin.Int("domain_id")) throw new CJ.CoreJobContractException("snapshot_input_changed");
        // The executor has column grants for this immutable header and member identity only.
        var manifest = rows[0]; manifest["members"] = Array(await ReadAsync(db, "select family,source_id,encode(payload_sha256,'hex') as payload_sha256 from ad_snapshot_manifest_sources where manifest_id=$1 order by family", ct, id));
        return manifest;
    }
    static async Task<JsonObject> LoadSource(NpgsqlConnection db, JsonObject manifest, string family, long maxRecords, CancellationToken ct)
    {
        var member = manifest["members"]!.AsArray().OfType<JsonObject>().Single(m => m.Text("family") == family);
        string sql = family switch
        {
            "users_v2" => "select payload_json::text as payload,encode(payload_sha256,'hex') as hash from users_report_v2_snapshots where snapshot_id=$1::bigint",
            "computers_v6" => "select payload_json::text as payload,encode(payload_sha256,'hex') as hash from computers_v6_source_snapshots where snapshot_uuid=$1::uuid",
            "ad_context_base" => "select jsonb_build_object('run_id',run_id::text,'domain_id',domain_id,'observed_at_utc',observed_at_utc,'status',status)::text as payload,encode(bundle_sha256,'hex') as hash from ad_context_runs where run_id=$1::uuid and status='completed'",
            _ => throw new CJ.CoreJobContractException("snapshot_input_invalid")
        };
        var rows = await ReadAsync(db, sql, ct, member.Text("source_id"));
        if (rows.Count != 1 || rows[0].Text("hash") != member.Text("payload_sha256")) throw new CJ.CoreJobContractException("snapshot_input_changed");
        var payload = JsonNode.Parse(rows[0].Text("payload")!)!.AsObject();
        if(family!="ad_context_base"&&Digest(payload)!=member.Text("payload_sha256"))throw new CJ.CoreJobContractException("snapshot_input_changed");
        if (payload.Select(p => p.Value).OfType<JsonArray>().Sum(a => a.Count) > maxRecords) throw new CJ.CoreJobContractException("snapshot_record_budget_exceeded");
        return payload;
    }
    public static async Task<JsonObject> StageAsync(NpgsqlConnection db, JsonObject job, CancellationToken ct)
    {
        if (job.Text("job_type") == "acquire") return Blocked(job, OperatingSystem.IsWindows() ? "acquisition_requires_agent" : "acquisition_disabled_on_linux");
        if (!await Enabled(db, ct)) return Blocked(job, "snapshot_plugin_disabled");
        var manifest = await LoadManifest(db, job, ct);
        var (key, family) = Projections[job.Text("handler_id")!];
        var payload = await LoadSource(db, manifest, family, job["budget"]!.Int("max_records"), ct);
        var projection = Project(manifest, key, family, payload, out _);
        return new JsonObject { ["status"] = manifest.Text("coverage_state") == "partial" ? "partial" : "success", ["output_contract"] = job["result_contract"]!.DeepClone(), ["coverage_state"] = manifest["coverage_state"]!.DeepClone(), ["continuation"] = null, ["error_code"] = null, ["evidence_refs"] = new JsonArray("ad-snapshot:" + manifest.Text("manifest_id")), ["projection_results"] = new JsonObject { [key] = projection }, ["composition"] = Composition(manifest["members"]!.AsArray().Select(m => m!.Text("family")!)) };
    }
    public static async Task PublishAsync(NpgsqlConnection db, JsonObject job, JsonObject staged, CancellationToken ct)
    {
        if (staged.Text("status") is "blocked" or "cancelled") return;
        if (!await Enabled(db, ct)) throw new CJ.CoreJobContractException("snapshot_plugin_disabled");
        foreach (string name in new[] { "ad_log_reports_runtime_ad_snapshot_manifest_coordinator_worker", "ad_log_reports_runtime_ad_context_snapshot_worker", "ad_log_reports_runtime_computers_v6_source_worker", "ad_log_reports_runtime_users_v2_snapshot_worker" })
        {
            await using var c = new NpgsqlCommand("select pg_try_advisory_lock(hashtext($1))", db); c.Parameters.AddWithValue(name);
            if (await c.ExecuteScalarAsync(ct) is not true) throw new InvalidOperationException("legacy_snapshot_writer_busy");
        }
        await ReadAsync(db, "select set_config('sli.job_id',$1,true),set_config('sli.job_token',$2,true),set_config('sli.job_generation',$3,true)", ct, job.Text("job_id"), job.Text("lease_token"), job["lease_generation"]!.ToString());
        var expected = await StageAsync(db, job, ct);
        if (!JsonNode.DeepEquals(expected["projection_results"], staged["projection_results"]) || !JsonNode.DeepEquals(expected["composition"], staged["composition"])) throw new CJ.CoreJobContractException("snapshot_result_changed");
        var manifest = await LoadManifest(db, job, ct); var (key, family) = Projections[job.Text("handler_id")!];
        var source = await LoadSource(db, manifest, family, job["budget"]!.Int("max_records"), ct);
        var result = Project(manifest, key, family, source, out var output);
        await PersistAsync(db, Guid.Parse(manifest.Text("manifest_id")!), key, result, output, ct);
    }
    internal static async Task PersistAsync(NpgsqlConnection db, Guid manifest, string key, JsonObject result, JsonObject output, CancellationToken ct)
    {
        var receipts=await ReadAsync(db,"select status,lease_owner,lease_expires_at,encode(input_sha256,'hex') as input_sha256,encode(output_sha256,'hex') as output_sha256,output_identity from ad_snapshot_projection_receipts where manifest_id=$1 and projection_key=$2 and projection_version=1 for update",ct,manifest,key);
        if(receipts.Count!=1)throw new CJ.CoreJobContractException("snapshot_projection_receipt_missing");
        var receipt=receipts[0];
        if(receipt.Text("status")=="running"&&AdInventoryRows.Date(receipt["lease_expires_at"]) is {} lease&&lease>DateTimeOffset.UtcNow)throw new InvalidOperationException("snapshot_projection_receipt_busy");
        if(receipt.Text("status")=="completed"&&new[]{"input_sha256","output_sha256","output_identity"}.Any(k=>receipt.Text(k)!=result.Text(k)))throw new CJ.CoreJobContractException("snapshot_projection_readback_mismatch");
        await using (var command = new NpgsqlCommand("""
            insert into ad_snapshot_projection_outputs(manifest_id,projection_key,projection_version,input_sha256,output_sha256,output_identity,payload_json)
            values($1,$2,1,decode($3,'hex'),decode($4,'hex'),$5,$6)
            on conflict(manifest_id,projection_key,projection_version) do nothing
            """, db))
        {
            foreach (object value in new object[] { manifest, key, result.Text("input_sha256")!, result.Text("output_sha256")!, result.Text("output_identity")! }) command.Parameters.Add(new() { Value = value });
            command.Parameters.Add(new() { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = CanonicalJson.Serialize(output) }); await command.ExecuteNonQueryAsync(ct);
        }
        var rows = await ReadAsync(db, "select encode(input_sha256,'hex') as input_sha256,encode(output_sha256,'hex') as output_sha256,output_identity,payload_json::text as payload from ad_snapshot_projection_outputs where manifest_id=$1 and projection_key=$2 and projection_version=1", ct, manifest, key);
        if (rows.Count != 1 || new[] { "input_sha256", "output_sha256", "output_identity" }.Any(k => rows[0].Text(k) != result.Text(k)) || Digest(JsonNode.Parse(rows[0].Text("payload")!)!) != result.Text("output_sha256")) throw new CJ.CoreJobContractException("snapshot_projection_readback_mismatch");
        await using var complete = new NpgsqlCommand("""
            update ad_snapshot_projection_receipts set status='completed',input_sha256=decode($3,'hex'),output_sha256=decode($4,'hex'),
            output_identity=$5,lease_owner=null,lease_expires_at=null,last_error=null,attempt_count=attempt_count+case when status='completed' then 0 else 1 end,updated_at=now()
            where manifest_id=$1 and projection_key=$2 and projection_version=1
            """, db);
        foreach (object value in new object[] { manifest, key, result.Text("input_sha256")!, result.Text("output_sha256")!, result.Text("output_identity")! }) complete.Parameters.Add(new() { Value = value });
        if (await complete.ExecuteNonQueryAsync(ct) != 1) throw new CJ.CoreJobContractException("snapshot_projection_receipt_missing");
    }
}
