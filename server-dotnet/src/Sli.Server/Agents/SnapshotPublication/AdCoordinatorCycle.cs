using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Gpo.SnapshotModel;
using Sli.Server.Ad;
using Sli.Server.Hosting;
using static Sli.Server.Ad.AdJson;
using NativePublisher = Sli.Server.Ad.AdSnapshotPublisher;

namespace Sli.Server.Agents.SnapshotPublication;

internal sealed class AdCoordinatorCycle(NpgsqlConnection db, string domainDns, bool gpoEnabled,
    Func<string, JsonObject?, CancellationToken, Task<JsonObject>> collect,
    Func<string, JsonObject, CancellationToken, Task> progress,
    Func<Guid, CancellationToken, Task<JsonObject>> retention)
{
    internal static JsonObject Schedule => new() { ["schedule"] = new JsonObject { ["timezone"] = "Asia/Novosibirsk", ["hours"] = new JsonArray(6, 18) }, ["expensive_flags"] = new JsonObject { ["dns"] = true, ["ad_site"] = true, ["exact_last_logon"] = true } };
    static void Require(bool ok, string code) { if (!ok) throw new WorkerFailure("coordinator", code); }
    internal async Task<JsonObject> RunAsync(DateTimeOffset slot, CancellationToken ct)
    {
        var domains = await ReadAsync(db, "select id,domain_sid,fqdn from domains where lower(fqdn)=lower($1) order by id", ct, domainDns.Trim());
        Require(domains.Count == 1, "coordinator_requires_one_exact_domain");
        var domain = domains[0]; long id = domain.Int("id");
        var existing = await ReadAsync(db, "select manifest_id::text from ad_snapshot_manifests where domain_id=$1 and slot_start_utc=$2 and contract_version='sli.ad-snapshot-manifest/2.0'", ct, id, slot);
        JsonObject manifest;
        bool replay = existing.Count > 0;
        if (replay) manifest = await ReadManifest(Guid.Parse(existing.Single().Text("manifest_id")!), ct);
        else {
            var bundles = new Dictionary<string, JsonObject>(); var members = new List<JsonObject>();
            var baseBundle = await Acquire("ad_context_base", null, domain, ct);
            AdCoordinatorAcquisition.QualifyBase(baseBundle);
            Require(baseBundle["scope"]!.Text("collection_profile") == "ad_snapshot_base_v1", "base_profile_mismatch");
            var entityIds = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            async Task Import(string family, JsonObject bundle) {
                await progress("importing", new() { ["family"] = family }, ct);
                await using var tx = await db.BeginTransactionAsync(ct);
                var ids = await Sli.Server.Ad.AdContextStore.ImportAsync(db, tx, id, bundle, ct);
                foreach (var r in bundle["records"]!.AsArray().OfType<JsonObject>().Where(r => r.Text("record_type") == "entity")) entityIds[r["identity"]!.Text("object_guid")!] = ids[r.Text("record_key")!];
                await tx.CommitAsync(ct);
                bundles.Add(family, bundle); members.Add(BundleMember(family, bundle));
            }
            await Import("ad_context_base", baseBundle);
            // Users are derived from the exact shared base, before the supplemental collections.
            var users = Sli.Server.Ad.AdUsersSnapshot.Build(bundles, id, domain.Text("fqdn")!, entityIds);
            string usersId;
            await using (var tx = await db.BeginTransactionAsync(ct)) { usersId = await NativePublisher.StoreUsers(db, id, users, baseBundle.Time("observed_at_utc"), ct); await tx.CommitAsync(ct); }
            members.Add(NativePublisher.Member("users_v2", "sli.users-report.v2", usersId, baseBundle.Time("observed_at_utc"), users["metadata"]!.Text("collection_status")!, AdJobPlugin.Digest(users)));
            var computers = await collect("computers_v6", baseBundle, ct);
            Sli.Server.Ad.AdSnapshotPreparation.ValidateComputers(computers);
            Require(computers["metadata"]!.Text("domain")?.Equals(domain.Text("fqdn"), StringComparison.OrdinalIgnoreCase) == true && computers["metadata"]!.Text("collection_status") != "failed", "computers_v6_base_inventory_not_observed");
            Require(baseBundle["records"]!.AsArray().Where(r => r!["identity"]?.Text("kind") == "ad_computer").Select(r => r!["identity"]!.Text("object_guid")!.ToLowerInvariant()).ToHashSet().SetEquals(computers["objects"]!.AsArray().Select(r => r!.Text("objectGuid")!.ToLowerInvariant())), "coordinator_base_identity_mismatch");
            string computersId;
            await using (var tx = await db.BeginTransactionAsync(ct)) { computersId = await NativePublisher.StoreComputers(db, id, computers, computers["metadata"]!.Time("completed_at"), Schedule, ct, true); await tx.CommitAsync(ct); }
            members.Add(NativePublisher.Member("computers_v6", "sli.ad-computers.snapshot/2.0", computersId, computers["metadata"]!.Time("completed_at"), computers["metadata"]!.Text("collection_status")!, AdJobPlugin.Digest(computers)));
            foreach (string family in AdCoordinatorAcquisition.Families.Skip(1)) {
                if (family == "ad_gpo_governance") {
                    if (!gpoEnabled) continue;
                    var raw = await collect(family, null, ct); var snapshot = raw["gpo_v2_snapshot"]!.AsObject();
                    GpoSnapshotValidator.Validate(System.Text.Json.JsonSerializer.SerializeToElement(snapshot));
                    var clean = (JsonObject)raw.DeepClone(); clean.Remove("gpo_v2_snapshot");
                    var bundle = GpoGovernanceBundle.Normalize(clean, snapshot); ValidateDomain(bundle, domain);
                    await using var tx = await db.BeginTransactionAsync(ct);
                    await GpoGovernanceStore.ImportAsync(db, tx, bundle, ct); await tx.CommitAsync(ct);
                    members.Add(BundleMember(family, bundle));
                    var source = await ReadAsync(db, "select source_run_id::text,schema_version,source_observed_at_utc,collection_status,encode(payload_sha256,'hex') as hash from gpo_report_v2_source_snapshots where source_run_id=$1 and domain_id=$2 and import_status='completed'", ct, Guid.Parse(bundle.Text("run_id")!), id);
                    Require(source.Count == 1, "gpo_v2_exact_source_readback_missing");
                    members.Add(NativePublisher.Member("gpo_v2", source[0].Text("schema_version")!, source[0].Text("source_run_id")!, source[0].Time("source_observed_at_utc"), source[0].Text("collection_status")!, source[0].Text("hash")!));
                } else await Import(family, await Acquire(family, null, domain, ct));
            }
            var assembled = members.Max(m => m.Time("observed_at_utc"));
            manifest = NativePublisher.Manifest(id, domain.Text("domain_sid")!, domain.Text("fqdn")!, slot, assembled, Schedule, members);
            await VerifySources(manifest, ct);
            await progress("publishing_manifest", new() { ["slot_start_utc"] = Iso(slot) }, ct);
            await using (var tx = await db.BeginTransactionAsync(ct)) { await AdSnapshotManifest.PublishAsync(db, tx, manifest, ct); await tx.CommitAsync(ct); }
            var readback = await ReadManifest(Guid.Parse(manifest.Text("manifest_id")!), ct);
            Require(JsonNode.DeepEquals(manifest, readback), "manifest_publication_database_readback_mismatch");
        }
        ValidateDomain(new() { ["domain"] = new JsonObject { ["sid"] = manifest["domain_sid"]!.DeepClone(), ["dns_name"] = manifest["domain_dns"]!.DeepClone() } }, domain);
        Require(manifest.Time("slot_start_utc") == slot, "existing_manifest_slot_mismatch");
        var payloads = await VerifySources(manifest, ct);
        await progress("projecting", new() { ["manifest_id"] = manifest["manifest_id"]!.DeepClone() }, ct);
        var results = new JsonObject();
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            foreach (var (key, family) in new[] { ("ad.state", "ad_context_base"), ("ad.users.v2", "users_v2"), ("ad.computers.v6", "computers_v6"), ("ad.gpo.v2", "gpo_v2") }) {
                if (!payloads.TryGetValue(family, out var payload)) continue;
                var projection = AdJobPlugin.Project(manifest, key, family, payload, out var output);
                await AdJobPlugin.PersistAsync(db, Guid.Parse(manifest.Text("manifest_id")!), key, projection, output, ct); results[key] = projection;
            }
            await tx.CommitAsync(ct);
        }
        await progress("history_publication", new() { ["manifest_id"] = manifest["manifest_id"]!.DeepClone() }, ct);
        var history = await retention(Guid.Parse(manifest.Text("manifest_id")!), ct);
        return new JsonObject { ["status"] = replay ? "replayed_existing" : "published", ["slot_start_utc"] = Iso(slot), ["manifest_id"] = manifest["manifest_id"]!.DeepClone(), ["manifest_sha256"] = manifest["manifest_sha256"]!.DeepClone(), ["source_contacted"] = !replay, ["replayed"] = replay ? 1 : 0, ["coverage_state"] = manifest["coverage_state"]!.DeepClone(), ["composition"] = AdJobPlugin.Composition(payloads.Keys), ["projection_results"] = results, ["retention_execution"] = history };
    }
    async Task<JsonObject> Acquire(string family, JsonObject? basis, JsonObject domain, CancellationToken ct) {
        var bundle = Sli.Server.Ad.AdContextBundle.Normalize(await collect(family, basis, ct)); ValidateDomain(bundle, domain);
        Require(bundle["sections"]!.AsArray().Select(s => s!.Text("name")).ToHashSet().SetEquals(Sections(family)), "source_family_section_mismatch"); return bundle;
    }
    static string[] Sections(string family) => family switch { "ad_context_base" => AdCoordinatorAcquisition.BaseSections, "ad_privileged_membership" => ["privileged_membership"], "ad_vpn_membership" => ["vpn_membership"], "ad_domain_posture" => ["domain_posture"], "ad_domain_health" => ["domain_health"], "ad_gpo_governance" => ["gpo_governance"], _ => throw new WorkerFailure("coordinator", "unsupported_ad_snapshot_family") };
    static void ValidateDomain(JsonObject bundle, JsonObject domain) => Require(bundle["domain"]!.Text("sid")?.Equals(domain.Text("domain_sid"), StringComparison.OrdinalIgnoreCase) == true && bundle["domain"]!.Text("dns_name")?.Equals(domain.Text("fqdn"), StringComparison.OrdinalIgnoreCase) == true, "requested_domain_does_not_match_configured_domain");
    static JsonObject BundleMember(string family, JsonObject bundle) {
        var states = bundle["sections"]!.AsArray().Select(s => s!.Text("status")).ToArray();
        return NativePublisher.Member(family, "sli.windows.ad-context", bundle.Text("run_id")!, bundle.Time("observed_at_utc"), states.Contains("failed") ? "failed" : states.Any(s => s is "partial" or "skipped") ? "partial" : "complete", bundle.Text("bundle_sha256")!);
    }
    async Task<JsonObject> ReadManifest(Guid id, CancellationToken ct) {
        var rows = await ReadAsync(db, "select manifest_id::text,domain_id,domain_sid,domain_dns,slot_start_utc,assembled_at_utc,contract_version,coverage_state,schedule_timezone,to_char(scheduled_local_at,'YYYY-MM-DD\"T\"HH24:MI:SS') as scheduled_local_at,encode(manifest_sha256,'hex') as manifest_sha256 from ad_snapshot_manifests where manifest_id=$1", ct, id);
        Require(rows.Count == 1, "existing_manifest_missing"); var manifest = rows[0];
        manifest["members"] = Array(await ReadAsync(db, "select family,contract_id,source_id,observed_at_utc,source_state,encode(payload_sha256,'hex') as payload_sha256,reason_code from ad_snapshot_manifest_sources where manifest_id=$1 order by family", ct, id));
        var copy = (JsonObject)manifest.DeepClone(); copy.Remove("manifest_sha256");
        Require(AdJobPlugin.Digest(copy) == manifest.Text("manifest_sha256"), "existing_manifest_hash_mismatch");
        Require(manifest.Text("schedule_timezone") == "Asia/Novosibirsk" && manifest.Text("scheduled_local_at") == AdCoordinatorLoop.LocalAt(manifest.Time("slot_start_utc")), "existing_manifest_schedule_header_mismatch");
        Require(JsonNode.DeepEquals(manifest, NativePublisher.Manifest(manifest.Int("domain_id"), manifest.Text("domain_sid")!, manifest.Text("domain_dns")!, manifest.Time("slot_start_utc"), manifest.Time("assembled_at_utc"), Schedule, manifest["members"]!.AsArray().OfType<JsonObject>())), "existing_manifest_identity_mismatch");
        return manifest;
    }
    async Task<Dictionary<string, JsonObject>> VerifySources(JsonObject manifest, CancellationToken ct) {
        var members = manifest["members"]!.AsArray().OfType<JsonObject>().ToDictionary(m => m.Text("family")!);
        var required = AdCoordinatorAcquisition.Families.Where(f => f != "ad_gpo_governance").Concat(["users_v2", "computers_v6"]).ToHashSet();
        Require(required.SetEquals(members.Keys) || required.Concat(["ad_gpo_governance", "gpo_v2"]).ToHashSet().SetEquals(members.Keys), "existing_manifest_family_set_mismatch");
        var payloads = new Dictionary<string, JsonObject>(); long domain = manifest.Int("domain_id");
        foreach (var (family, member) in members) {
            string sql = family switch {
                "users_v2" => "select contract_id,payload_json::text as payload,encode(payload_sha256,'hex') as hash,source_observed_at_utc as observed,source_state as state from users_report_v2_snapshots where snapshot_id=$1::bigint and domain_id=$2",
                "computers_v6" => "select 'sli.ad-computers.snapshot/2.0'::text as contract_id,payload_json::text as payload,encode(payload_sha256,'hex') as hash,captured_at_utc as observed,collection_status as state,base_inventory_status from computers_v6_source_snapshots where snapshot_uuid=$1::uuid and domain_id=$2",
                "gpo_v2" => "select schema_version as contract_id,payload_json::text as payload,encode(payload_sha256,'hex') as hash,source_observed_at_utc as observed,collection_status as state from gpo_report_v2_source_snapshots where source_run_id=$1::uuid and domain_id=$2 and import_status='completed'",
                _ => "select source_pack_id as contract_id,jsonb_build_object('run_id',run_id::text,'domain_id',domain_id,'observed_at_utc',observed_at_utc,'status',status)::text as payload,encode(bundle_sha256,'hex') as hash,observed_at_utc as observed from ad_context_runs where run_id=$1::uuid and domain_id=$2 and status='completed'"
            };
            var rows = await ReadAsync(db, sql, ct, member.Text("source_id"), domain);
            Require(rows.Count == 1 && rows[0].Text("hash") == member.Text("payload_sha256") && rows[0].Time("observed") == member.Time("observed_at_utc") && rows[0].Text("contract_id") == member.Text("contract_id"), "existing_manifest_source_mismatch");
            var row = rows[0]; var payload = JsonNode.Parse(row.Text("payload")!)!.AsObject();
            if (family is "users_v2" or "computers_v6" or "gpo_v2") Require(AdJobPlugin.Digest(payload) == member.Text("payload_sha256") && row.Text("state") == member.Text("source_state"), "existing_manifest_source_mismatch");
            else {
                var sections = await ReadAsync(db, "select section_name as name,status,error_code from ad_context_sections where run_id=$1::uuid order by section_name", ct, member.Text("source_id"));
                Require(sections.Select(s => s.Text("name")).ToHashSet().SetEquals(Sections(family)), "existing_manifest_family_section_mismatch");
                var states = sections.Select(s => s.Text("status")).ToArray();
                Require((states.Contains("failed") ? "failed" : states.Any(s => s is "partial" or "skipped") ? "partial" : "complete") == member.Text("source_state"), "existing_manifest_source_mismatch");
                if (family == "ad_context_base") {
                    var evidence = await ReadAsync(db, "select locator_json->>'record_key' as record_key from ad_context_evidence where source_run_id=$1::uuid and evidence_type='data_quality'", ct, member.Text("source_id"));
                    var quality = new JsonArray(); foreach (var e in evidence) { var parts = (e.Text("record_key") ?? "").Split(':', 3); if (parts.Length == 3 && parts[0] == "dq") quality.Add(Obj(new { record_type = "data_quality", section = parts[1], code = parts[2] })); }
                    AdCoordinatorAcquisition.QualifyBase(new() { ["sections"] = Array(sections), ["records"] = quality });
                }
            }
            if (family == "computers_v6") Require(row.Text("base_inventory_status") == "observed" && member.Text("source_state") != "failed", "existing_manifest_required_base_not_usable");
            payloads[family] = payload;
        }
        Require(manifest.Text("coverage_state") == (members.Values.All(m => m.Text("source_state") == "complete") ? "complete" : "partial"), "existing_manifest_coverage_mismatch");
        return payloads;
    }
}
