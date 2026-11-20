using Sli.Server.Infrastructure;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Auth.Lifecycle.Security;
using static Sli.Server.Ad.AdJson;
using static Sli.Server.Ad.AdContextBundle;

namespace Sli.Server.Ad;

public static class AdSnapshotPublisher
{
    public static async Task<GpoPublicationResult> ProcessAsync(NpgsqlConnection worker, Guid cycle, CancellationToken ct)
    {
        await using var tx = await worker.BeginTransactionAsync(ct);
        await using (var role = new NpgsqlCommand("select current_user", worker, tx))
            if ((string?)await role.ExecuteScalarAsync(ct) != "adlog_context_worker") throw new InvalidOperationException("agent_snapshot_worker_role_required");
        var transport = await SnapshotTransportReader.ReadAsync(worker, tx, cycle, ct, SnapshotPolicy.Ad);
        if (transport is null) { await tx.CommitAsync(ct); return new(false, "pending", null); }
        if (!transport.PublicationPending) { await tx.CommitAsync(ct); return new(true, "published", null); }
        await tx.SaveAsync("ad_publication", ct);
        try
        {
            var families = SnapshotFamilyDecoder.Decode(transport);
            var bundles = AdSnapshotPreparation.Prepare(transport.Policy, families);
            var policy = SnapshotPolicy.Parse(SnapshotPolicy.Ad, transport.Policy);
            string slotText = transport.Rows[0].Payload.Text("slot_start_utc")!; var slot = DateTimeOffset.Parse(slotText, CultureInfo.InvariantCulture);
            Require(DateTimeOffset.Parse(policy.DueSlot(slot), CultureInfo.InvariantCulture) == slot, "agent_ad_schedule_unsupported");
            long domain = await GpoDomainLock.AcquireAsync(worker, tx, transport.DomainSid, transport.Policy.Text("domain_dns")!, ct);
            var entityIds = new Dictionary<string, long>();
            foreach (var bundle in bundles.Values)
            {
                var ids = await AdContextStore.ImportAsync(worker, tx, domain, bundle, ct);
                foreach (var r in bundle["records"]!.AsArray().OfType<JsonObject>().Where(r => r.Text("record_type") == "entity"))
                {
                    string guid = r["identity"]!.Text("object_guid")!; long id = ids[r.Text("record_key")!];
                    Require(!entityIds.TryGetValue(guid, out long existing) || existing == id, "agent_ad_identity_conflict"); entityIds[guid] = id;
                }
            }
            string dns = transport.Policy.Text("domain_dns")!; var users = AdUsersSnapshot.Build(bundles, domain, dns, entityIds);
            var computer = families["computers_v6"]; var observed = bundles["ad_context_base"].Time("observed_at_utc");
            string userSource = await StoreUsers(worker, domain, users, observed, ct);
            string computerSource = await StoreComputers(worker, domain, computer, observed, transport.Policy, ct);
            var members = new List<JsonObject>();
            foreach (var (family, bundle) in bundles)
            {
                var statuses = bundle["sections"]!.AsArray().Select(s => s!.Text("status")).ToArray();
                members.Add(Member(family, "sli.windows.ad-context", bundle.Text("run_id")!, observed, statuses.Contains("failed") ? "failed" : statuses.Any(s => s is "partial" or "skipped") ? "partial" : "complete", bundle.Text("bundle_sha256")!));
            }
            members.Add(Member("users_v2", "sli.users-report.v2", userSource, observed, users["metadata"]!.Text("collection_status")!, AdJobPlugin.Digest(users)));
            members.Add(Member("computers_v6", "sli.ad-computers.snapshot/2.0", computerSource, observed, computer["metadata"]!.Text("collection_status")!, AdJobPlugin.Digest(computer)));
            var manifest = Manifest(domain, transport.DomainSid, dns, slot, observed, transport.Policy, members);
            await StoreManifest(worker, manifest, ct);
            var exactBase=await ReadAsync(worker,"select jsonb_build_object('run_id',run_id::text,'domain_id',domain_id,'observed_at_utc',observed_at_utc,'status',status)::text as payload from ad_context_runs where run_id=$1 and status='completed'",ct,Guid.Parse(bundles["ad_context_base"].Text("run_id")!));
            Require(exactBase.Count==1,"agent_ad_manifest_readback_invalid");
            foreach (var (key, family, payload) in new[] { ("ad.state", "ad_context_base", JsonNode.Parse(exactBase[0].Text("payload")!)!.AsObject()), ("ad.users.v2", "users_v2", users), ("ad.computers.v6", "computers_v6", computer) })
            {
                var result = AdJobPlugin.Project(manifest, key, family, payload, out var output);
                await AdJobPlugin.PersistAsync(worker, Guid.Parse(manifest.Text("manifest_id")!), key, result, output, ct);
            }
            await Execute(worker, "update sli_agent_snapshot_cycles set publication_state='published',manifest_id=$1,published_at=clock_timestamp() where cycle_id=$2", ct, Guid.Parse(manifest.Text("manifest_id")!), cycle);
            await tx.ReleaseAsync("ad_publication", ct); await tx.CommitAsync(ct);
            return new(true, "published", null);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            await tx.RollbackAsync("ad_publication", ct);
            string code = error is ProtocolException p ? p.Code : "agent_ad_publication_failed";
            if(code=="agent_gpo_domain_not_bound")code="agent_ad_domain_not_bound";
            if (code == "agent_gpo_snapshot_superseded")
            {
                await Execute(worker, "update sli_agent_snapshot_cycles set publication_state='superseded',superseded_reason='agent_ad_snapshot_superseded',superseded_at=clock_timestamp() where cycle_id=$1", ct, cycle);
                await tx.CommitAsync(ct); return new(true, "superseded", "agent_ad_snapshot_superseded");
            }
            await tx.CommitAsync(ct); return new(true, "pending", code.StartsWith("agent_ad_", StringComparison.Ordinal) ? code : "agent_ad_publication_failed");
        }
    }
    internal static JsonObject Member(string family, string contract, string source, DateTimeOffset observed, string state, string hash) => Obj(new { family, contract_id = contract, source_id = source, observed_at_utc = Iso(observed), source_state = state, payload_sha256 = hash, reason_code = state == "complete" ? null : family+"_source_partial" });
    public static JsonObject Manifest(long domain, string sid, string dns, DateTimeOffset slot, DateTimeOffset observed, JsonObject policy, IEnumerable<JsonObject> sources)
    {
        bool standard = policy["schedule"]!.Text("timezone") == "Asia/Novosibirsk" && JsonNode.DeepEquals(policy["schedule"]!["hours"], new JsonArray(6, 18));
        string version = standard ? "sli.ad-snapshot-manifest/2.0" : "sli.ad-snapshot-manifest/3.0", zone = standard ? "Asia/Novosibirsk" : "UTC";
        string local = TimeZoneInfo.ConvertTime(slot, TimeZoneInfo.FindSystemTimeZoneById(zone)).ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture);
        var members = sources.OrderBy(m => m.Text("family"), StringComparer.Ordinal).ToArray();
        var identity = Obj(new { contract = version, domain_id = domain, slot = Iso(slot), schedule = new { timezone = zone, local_at = local }, members = members.Select(m => new { family = m.Text("family"), source_id = m.Text("source_id"), sha256 = m.Text("payload_sha256") }) });
        Guid id = AuthAudit.Uuid5(CanonicalJson.Serialize(identity, false));
        var manifest = Obj(new { contract_version = version, manifest_id = id.ToString("D"), domain_id = domain, domain_sid = sid, domain_dns = dns.ToLowerInvariant(), slot_start_utc = Iso(slot), assembled_at_utc = Iso(observed), coverage_state = members.All(m => m.Text("source_state") == "complete") ? "complete" : "partial", members, schedule_timezone = zone, scheduled_local_at = local });
        manifest["manifest_sha256"] = AdJobPlugin.Digest(manifest); return manifest;
    }
    internal static async Task<string> StoreUsers(NpgsqlConnection db, long domain, JsonObject users, DateTimeOffset observed, CancellationToken ct)
    {
        var scope = Obj(new { domain_ids = new[] { domain }, report_key = "ad.users.v2" });
        var bucket = new DateTimeOffset(observed.Year, observed.Month, observed.Day, observed.Hour >= 12 ? 12 : 0, 0, 0, TimeSpan.Zero);
        await Execute(db, """
            insert into users_report_v2_snapshots(domain_id,contract_id,scope_json,scope_sha256,bucket_start_utc,captured_at_utc,source_observed_at_utc,source_state,user_count,payload_json,payload_sha256)
            values($1,'sli.users-report.v2',$2,decode($3,'hex'),$4,$5,$5,$6,$7,$8,decode($9,'hex'))
            on conflict(domain_id,scope_sha256,source_observed_at_utc,contract_id,schema_version) do nothing
            """, ct, domain, scope, AdJobPlugin.Digest(scope), bucket, observed, users["metadata"]!.Text("collection_status")!, users["users"]!.AsArray().Count, users, AdJobPlugin.Digest(users));
        var rows = await ReadAsync(db, "select snapshot_id,encode(payload_sha256,'hex') as hash,payload_json::text as payload from users_report_v2_snapshots where domain_id=$1 and scope_sha256=decode($2,'hex') and source_observed_at_utc=$3 and contract_id='sli.users-report.v2'", ct, domain, AdJobPlugin.Digest(scope), observed);
        Require(rows.Count == 1 && rows[0].Text("hash") == AdJobPlugin.Digest(users)&&AdJobPlugin.Digest(JsonNode.Parse(rows[0].Text("payload")!)!)==rows[0].Text("hash"), "agent_ad_users_readback_invalid"); return rows[0].Int("snapshot_id").ToString(CultureInfo.InvariantCulture);
    }
    internal static async Task<string> StoreComputers(NpgsqlConnection db, long domain, JsonObject computers, DateTimeOffset observed, JsonObject policy, CancellationToken ct, bool referenceCollector = false)
    {
        var m = computers["metadata"]!; Guid id = Guid.Parse(m.Text("snapshot_id")!);
        var options = Obj(new { server = m.Text("query_dc"), search_base = m.Text("search_base"), skip_dns = policy["expensive_flags"]?["dns"]?.GetValue<bool>() != true, collect_ad_site = policy["expensive_flags"]?["ad_site"]?.GetValue<bool>() == true, collect_exact_last_logon = policy["expensive_flags"]?["exact_last_logon"]?.GetValue<bool>() == true });
        await Execute(db, """
            insert into computers_v6_source_snapshots(domain_id,snapshot_uuid,schema_version,source_started_at_utc,source_completed_at_utc,captured_at_utc,query_dc,search_base,collector_version,collector_sha256,collection_status,base_inventory_status,object_count,source_options_json,payload_json,payload_sha256,collector_exit_code)
            values($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,'observed',$11,$12,$13,decode($14,'hex'),0)
            on conflict(domain_id,snapshot_uuid) do nothing
            """, ct, domain, id, computers.Text("schema_version")!, m.Time("started_at"), observed, m.Text("query_dc")!, (object?)m.Text("search_base") ?? DBNull.Value, m.Text("collector_version")!, referenceCollector ? Convert.FromHexString("caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5") : SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("sli-agent/ad-snapshot/1")), m.Text("collection_status")!, computers["objects"]!.AsArray().Count, options, computers, AdJobPlugin.Digest(computers));
        var rows = await ReadAsync(db, "select encode(payload_sha256,'hex') as hash,object_count,payload_json::text as payload from computers_v6_source_snapshots where domain_id=$1 and snapshot_uuid=$2", ct, domain, id);
        Require(rows.Count == 1 && rows[0].Text("hash") == AdJobPlugin.Digest(computers) && rows[0].Int("object_count") == computers["objects"]!.AsArray().Count&&AdJobPlugin.Digest(JsonNode.Parse(rows[0].Text("payload")!)!)==rows[0].Text("hash"), "agent_ad_computers_readback_invalid"); return id.ToString("D");
    }
    static async Task StoreManifest(NpgsqlConnection db, JsonObject manifest, CancellationToken ct)
    {
        Guid id = Guid.Parse(manifest.Text("manifest_id")!);
        var prior = await ReadAsync(db, "select manifest_id::text,encode(manifest_sha256,'hex') as hash from ad_snapshot_manifests where domain_id=$1 and slot_start_utc=$2 and contract_version=$3", ct, manifest.Int("domain_id"), manifest.Time("slot_start_utc"), manifest.Text("contract_version"));
        if (prior.Count > 0) Require(prior.Count == 1 && prior[0].Text("manifest_id") == manifest.Text("manifest_id") && prior[0].Text("hash") == manifest.Text("manifest_sha256"), "agent_ad_manifest_readback_invalid");
        else
        {
            await Execute(db, "insert into ad_snapshot_manifests(manifest_id,domain_id,domain_sid,domain_dns,slot_start_utc,assembled_at_utc,contract_version,coverage_state,manifest_sha256) values($1,$2,$3,$4,$5,$6,$7,$8,decode($9,'hex'))", ct, id, manifest.Int("domain_id"), manifest.Text("domain_sid")!, manifest.Text("domain_dns")!, manifest.Time("slot_start_utc"), manifest.Time("assembled_at_utc"), manifest.Text("contract_version")!, manifest.Text("coverage_state")!, manifest.Text("manifest_sha256")!);
            foreach (var m in manifest["members"]!.AsArray()) await Execute(db, "insert into ad_snapshot_manifest_sources(manifest_id,family,contract_id,source_id,observed_at_utc,source_state,payload_sha256,reason_code) values($1,$2,$3,$4,$5,$6,decode($7,'hex'),$8)", ct, id, m!.Text("family")!, m.Text("contract_id")!, m.Text("source_id")!, m.Time("observed_at_utc"), m.Text("source_state")!, m.Text("payload_sha256")!, (object?)m.Text("reason_code") ?? DBNull.Value);
        }
        var readback=await ReadAsync(db,"select family,contract_id,source_id,observed_at_utc,source_state,encode(payload_sha256,'hex') as payload_sha256,reason_code from ad_snapshot_manifest_sources where manifest_id=$1 order by family",ct,id);
        Require(JsonNode.DeepEquals(manifest["members"],Array(readback)),"agent_ad_manifest_readback_invalid");
        foreach (string key in new[] { "ad.state", "ad.users.v2", "ad.computers.v6", "ad.gpo.v2" }) await Execute(db, "insert into ad_snapshot_projection_receipts(manifest_id,projection_key,projection_version,status) values($1,$2,1,'pending') on conflict(manifest_id,projection_key,projection_version) do nothing", ct, id, key);
    }
    static async Task Execute(NpgsqlConnection db, string sql, CancellationToken ct, params object[] args)
    {
        SqlArguments.Validate(args);
        await using var c = new NpgsqlCommand(sql, db);
        foreach (object arg in args) c.Parameters.Add(arg is JsonNode node ? new() { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = CanonicalJson.Serialize(node, false) } : new() { Value = arg });
        await c.ExecuteNonQueryAsync(ct);
    }
}
