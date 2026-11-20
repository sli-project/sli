using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using static Sli.Server.Agents.SnapshotPublication.AdContextBundle;
using static Sli.Server.Agents.SnapshotPublication.AdContextStore;

namespace Sli.Server.Agents.SnapshotPublication;

public static class AdSnapshotPublisher
{
    public static async Task<GpoPublicationResult> ProcessAsync(NpgsqlConnection db, Guid cycleId, CancellationToken ct)
    {
        await using var tx = await db.BeginTransactionAsync(ct);
        await using (var role = new NpgsqlCommand("select current_user", db, tx))
            if (await role.ExecuteScalarAsync(ct) as string != "adlog_context_worker") throw new InvalidOperationException("agent_snapshot_worker_role_required");
        var transport = await SnapshotTransportReader.ReadAsync(db, tx, cycleId, ct, Sli.Agent.Core.SnapshotPolicy.Ad);
        if (transport is null) { await tx.CommitAsync(ct); return new(false, "pending", null); }
        if (!transport.PublicationPending) { await tx.CommitAsync(ct); return new(true, "published", null); }
        await tx.SaveAsync("ad_publication", ct);
        try {
            using var admission = Sli.Server.Agents.Control.AgentAssignmentPluginAdmission.Enter("sli.ad", Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"), Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
            var prepared = AdPublicationPreparation.Prepare(transport.Policy, SnapshotFamilyDecoder.Decode(transport));
            long domain;
            await using (var c = Command(db, tx, "select pg_advisory_xact_lock(hashtext('sli_agent_ad_snapshot'),hashtext(@sid))", ("sid", transport.DomainSid))) await c.ExecuteNonQueryAsync(ct);
            await using (var c = Command(db, tx, "select id from domains where domain_sid=@sid and lower(fqdn)=@dns for update", ("sid", transport.DomainSid), ("dns", Text(transport.Policy["domain_dns"]))))
                domain = Convert.ToInt64(await c.ExecuteScalarAsync(ct) ?? throw new ProtocolException("agent_ad_domain_not_bound"));
            foreach (var bundle in prepared.Bundles.Values) await ImportAsync(db, tx, domain, bundle, ct);
            var ids = new Dictionary<string, long>();
            string[] guids = prepared.Bundles.Values.SelectMany(b => b["records"]!.AsArray()).Where(r => Text(r!["record_type"]) == "entity").Select(r => Text(r!["identity"]!["object_guid"])).Distinct().ToArray();
            await using (var c = Command(db, tx, "select alias_value,entity_id from ad_context_entity_aliases where domain_id=@domain and alias_type='object_guid' and normalized_value=any(@guids)", ("domain", domain), ("guids", guids))) {
                await using var r = await c.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) ids[r.GetString(0).ToLowerInvariant()] = Convert.ToInt64(r.GetValue(1));
            }
            Require(ids.Keys.ToHashSet().SetEquals(guids));
            var users = AdUsersSnapshot.Build(prepared, domain, Text(transport.Policy["domain_dns"]), ids);
            string usersId = await AdSourceSnapshots.UsersAsync(db, tx, domain, users, ct), computersId = await AdSourceSnapshots.ComputersAsync(db, tx, domain, prepared.Computers, transport.Policy, ct);
            var sources = new List<JsonObject>();
            foreach (var (family, b) in prepared.Bundles) {
                var states = b["sections"]!.AsArray().Select(s => Text(s!["status"])).ToArray(); string state = states.Contains("failed") ? "failed" : states.Any(s => s is "partial" or "skipped") ? "partial" : "complete";
                sources.Add(AdSnapshotManifest.Member(family, Text(b["source_pack_id"]), Text(b["run_id"]), Text(b["observed_at_utc"]), state, Text(b["bundle_sha256"])));
            }
            string observed = Text(prepared.Bundles["ad_context_base"]["observed_at_utc"]);
            sources.Add(AdSnapshotManifest.Member("users_v2", "sli.users-report.v2", usersId, observed, Text(users["metadata"]!["collection_status"]), Convert.ToHexStringLower(GpoIdentityWriter.Hash(users, false))));
            sources.Add(AdSnapshotManifest.Member("computers_v6", "sli.ad-computers.snapshot/2.0", computersId, observed, Text(prepared.Computers["metadata"]!["collection_status"]), Convert.ToHexStringLower(GpoIdentityWriter.Hash(prepared.Computers, false))));
            var manifest = AdSnapshotManifest.Build(domain, transport.DomainSid, Text(transport.Policy["domain_dns"]), transport.SlotStartUtc!, transport.Policy, observed, sources);
            await AdSnapshotManifest.PublishAsync(db, tx, manifest, ct);
            await AdSnapshotProjections.PublishAsync(db, tx, manifest, users, prepared.Computers, ct);
            await Execute(db, tx, "update sli_agent_snapshot_cycles set publication_state='published',manifest_id=@manifest,published_at=clock_timestamp() where cycle_id=@cycle", ct, ("manifest", Guid.Parse(Text(manifest["manifest_id"]))), ("cycle", cycleId));
            await tx.CommitAsync(ct); return new(true, "published", null);
        }
        catch (Exception error) when (error is not OperationCanceledException) {
            await tx.RollbackAsync("ad_publication", ct);
            string code = error is ProtocolException p ? p.Code : "agent_ad_publication_failed";
            if (code == "agent_ad_snapshot_superseded") {
                await Execute(db, tx, "update sli_agent_snapshot_cycles set publication_state='superseded',superseded_reason=@reason,superseded_at=clock_timestamp() where cycle_id=@cycle", ct, ("reason", code), ("cycle", cycleId));
                await tx.CommitAsync(ct); return new(true, "superseded", code);
            }
            await tx.CommitAsync(ct);
            return new(true, "pending", code is "agent_ad_required_families_missing" or "agent_ad_base_incomplete" or "agent_ad_exact_logon_incomplete" or "agent_ad_scope_incomplete" or "agent_ad_membership_incomplete" or "agent_ad_schedule_unsupported" or "agent_ad_domain_not_bound" or "agent_ad_projection_pending" ? code : "agent_ad_publication_failed");
        }
    }
}
