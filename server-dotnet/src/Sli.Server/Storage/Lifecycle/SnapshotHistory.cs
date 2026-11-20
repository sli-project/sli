using System.Data;
using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Storage.Lifecycle.LifecyclePostgres;

namespace Sli.Server.Storage.Lifecycle;

internal sealed class SnapshotHistory(NpgsqlDataSource source, Func<string, string?> get, Func<NpgsqlDataSource> deletion)
{
    static readonly string[] Families = ["users_v2", "computers_v6", "gpo_v2"];
    string step = "connect";
    internal async Task<JsonObject> RunAsync(bool apply, DateTime now, int limit, CancellationToken ct)
    {
        try { return await RunCycleAsync(apply, now, limit, ct); }
        catch (Exception error) {
            // Only constants defined in this class cross the diagnostic boundary.
            error.Data["snapshot_history_step"] = step;
            throw;
        }
    }
    async Task<JsonObject> RunCycleAsync(bool apply, DateTime now, int limit, CancellationToken ct)
    {
        await using var db = await source.OpenConnectionAsync(ct); await using var tx = await db.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        step = "migration_check";
        var migrations = await Rows(db, tx, "select version from schema_migrations where (version=195 and name='ad_snapshot_history_composition') or (version=200 and name='agent_gpo_change_history') or (version=204 and name='agent_gpo_history_slot_timestamp')", ct);
        bool Has(int v) => migrations.Any(r => LifecycleJson.Number(r, "version") == v);
        if (!Has(195) || Has(200) && !Has(204)) throw new LifecycleBlocked("snapshot_history_migration_required");
        step = "snapshot_lock";
        await Execute(db, tx, "select pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_history_v1'))", ct);
        step = "manifest_pending";
        var pending = await Rows(db, tx, """
            select m.manifest_id from ad_snapshot_manifests m where exists(
              select 1 from ad_snapshot_manifest_sources s where s.manifest_id=m.manifest_id and s.family=any(@families)
                and not exists(select 1 from ad_snapshot_history_confirmations h where h.manifest_id=m.manifest_id and h.family=s.family))
            order by m.slot_start_utc,m.manifest_id limit @limit
            """, ct, ("families", Families), ("limit", limit));
        long records = 0;
        foreach (var row in pending) records += await PublishManifest(db, tx, Guid.Parse(LifecycleJson.Text(row, "manifest_id")), ct);
        List<JsonObject> gpo = [];
        if (Has(200)) {
            step = "gpo_pending";
            gpo = await Rows(db, tx, """
                select c.cycle_id from sli_agent_snapshot_cycles c where c.module_id='sli.gpo-snapshot' and c.publication_state='published'
                  and not exists(select 1 from ad_snapshot_history_confirmations h where h.manifest_id=c.cycle_id and h.family='gpo_v2')
                order by c.slot_start_utc,c.cycle_id limit @limit
                """, ct, ("limit", limit));
            foreach (var row in gpo) records += await PublishAgentGpo(db, tx, Guid.Parse(LifecycleJson.Text(row, "cycle_id")), ct);
        }
        step = "history_days";
        var setting = await Rows(db, tx, "select value from public.storage_lifecycle_setting_v319", ct);
        string configured = setting.Count > 0 ? LifecycleJson.Text(setting[0], "value") : get("SLI_AD_SNAPSHOT_HISTORY_DAYS") ?? "365";
        if (!int.TryParse(configured, NumberStyles.None, CultureInfo.InvariantCulture, out int days) || days is < 7 or > 3650) throw new LifecycleBlocked("ad_snapshot_history_days_must_be_7_to_3650");
        step = "coverage";
        var coverage = await Rows(db, tx, """
            select exists(select 1 from ad_snapshot_manifests m where m.coverage_state='partial'
              or not exists(select 1 from ad_snapshot_manifest_sources s where s.manifest_id=m.manifest_id and s.family='gpo_v2')) as partial
            """, ct);
        step = "confirmation_commit";
        await tx.CommitAsync(ct);
        var result = new JsonObject { ["status"] = pending.Count == limit || gpo.Count == limit ? "partial" : "ok", ["manifests_published"] = pending.Count,
            ["records_published"] = records, ["gpo_cycles_published"] = gpo.Count, ["coverage_state"] = coverage[0]["partial"]!.GetValue<bool>() ? "partial" : "complete",
            ["deleted_records"] = 0L, ["history_days"] = days };
        if (apply) {
            step = "retention_connect";
            await using var purge = await deletion().OpenConnectionAsync(ct);
            step = "postgres_history_expiry";
            var partitions = await Rows(purge, null, "select public.expire_ad_snapshot_change_partitions(@cutoff) as count", ct, ("cutoff", now.AddDays(-days)));
            result["deleted_postgres_partitions"] = partitions[0]["count"]?.DeepClone();
            step = "confirmation_expiry";
            var expired = await Rows(purge, null, "select public.expire_storage_lifecycle_confirmations_v319(@cutoff) as count", ct, ("cutoff", now.AddDays(-days)));
            result["deleted_confirmations"] = expired[0]["count"]?.DeepClone();
        }
        return result;
    }
    internal async Task<long> PublishManifest(NpgsqlConnection db, NpgsqlTransaction tx, Guid id, CancellationToken ct)
    {
        step = "manifest_current";
        var current = (await Rows(db, tx, "select manifest_id,domain_id,slot_start_utc,coverage_state from ad_snapshot_manifests where manifest_id=@id", ct, ("id", id))).SingleOrDefault()
            ?? throw new LifecycleBlocked("snapshot_history_manifest_missing");
        long domain = LifecycleJson.Number(current, "domain_id"); DateTime slot = DateTime.Parse(LifecycleJson.Text(current, "slot_start_utc"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);
        step = "manifest_previous";
        var previous = (await Rows(db, tx, "select manifest_id,coverage_state from ad_snapshot_manifests where domain_id=@domain and slot_start_utc<@slot order by slot_start_utc desc limit 1", ct, ("domain", domain), ("slot", slot))).SingleOrDefault();
        step = "manifest_sources";
        var members = await Rows(db, tx, "select family,source_id,observed_at_utc,encode(payload_sha256,'hex') as hash from ad_snapshot_manifest_sources where manifest_id=@id order by family", ct, ("id", id));
        var oldMembers = previous is null ? [] : await Rows(db, tx, "select family,source_id,encode(payload_sha256,'hex') as hash from ad_snapshot_manifest_sources where manifest_id=@id order by family", ct, ("id", Guid.Parse(LifecycleJson.Text(previous, "manifest_id"))));
        long count = 0;
        foreach (string family in Families) {
            var member = members.SingleOrDefault(r => LifecycleJson.Text(r, "family") == family);
            if (member is null) continue;
            step = "manifest_confirmation_lookup";
            if ((await Rows(db, tx, "select 1 from ad_snapshot_history_confirmations where manifest_id=@id and family=@family", ct, ("id", id), ("family", family))).Count > 0) continue;
            var oldMember = oldMembers.SingleOrDefault(r => LifecycleJson.Text(r, "family") == family);
            var payload = await Payload(db, tx, family, member, ct);
            var oldPayload = oldMember is null ? null : await Payload(db, tx, family, oldMember, ct);
            count += await PublishPair(db, tx, id, oldMember is null ? null : Guid.Parse(LifecycleJson.Text(previous!, "manifest_id")), domain, family, slot,
                DateTimeOffset.Parse(LifecycleJson.Text(member, "observed_at_utc"), CultureInfo.InvariantCulture), payload, oldPayload,
                LifecycleJson.Text(member, "hash"), oldMember?["hash"]?.ToString(),
                LifecycleJson.Text(current, "coverage_state") == "complete" && (previous is null || LifecycleJson.Text(previous, "coverage_state") == "complete"), ct);
        }
        return count;
    }
    async Task<JsonObject> Payload(NpgsqlConnection db, NpgsqlTransaction tx, string family, JsonObject member, CancellationToken ct, long? domain = null)
    {
        step = "source_payload";
        string sql = family switch {
            "users_v2" => "select payload_json,encode(payload_sha256,'hex') as hash from users_report_v2_snapshots where snapshot_id=cast(@source as bigint)",
            "computers_v6" => "select payload_json,encode(payload_sha256,'hex') as hash from computers_v6_source_snapshots where snapshot_uuid=cast(@source as uuid)",
            "gpo_v2" => "select payload_json,encode(payload_sha256,'hex') as hash from gpo_report_v2_source_snapshots where source_run_id=cast(@source as uuid)" + (domain.HasValue ? " and domain_id=@domain and import_status='completed'" : ""),
            _ => throw new LifecycleBlocked("snapshot_history_family_invalid")
        };
        var rows = await Rows(db, tx, sql, ct, ("source", LifecycleJson.Text(member, "source_id")), ("domain", domain ?? 0));
        if (rows.Count != 1 || LifecycleJson.Text(rows[0], "hash") != LifecycleJson.Text(member, "hash") || rows[0]["payload_json"] is not JsonObject payload || LifecycleJson.Hash(payload).ToLowerInvariant() != LifecycleJson.Text(member, "hash")) throw new LifecycleBlocked("snapshot_history_source_hash_mismatch");
        return payload;
    }
    internal async Task<long> PublishAgentGpo(NpgsqlConnection db, NpgsqlTransaction tx, Guid id, CancellationToken ct)
    {
        step = "gpo_current";
        var current = (await Rows(db, tx, """
            select c.cycle_id,c.agent_id,c.slot_start_utc,c.policy,s.domain_id,s.source_observed_at_utc,s.source_run_id::text as source_id,encode(s.payload_sha256,'hex') as hash
            from sli_agent_snapshot_cycles c join gpo_report_v2_source_snapshots s on s.source_run_id=c.gpo_source_run_id
            join domains d on d.id=s.domain_id and d.domain_sid=c.domain_sid and d.domain_sid=c.policy->>'domain_sid' and lower(d.fqdn)=c.policy->>'domain_dns'
            where c.cycle_id=@id and c.module_id='sli.gpo-snapshot' and c.publication_state='published' and s.import_status='completed'
            """, ct, ("id", id))).SingleOrDefault() ?? throw new LifecycleBlocked("snapshot_history_gpo_cycle_missing");
        long domain = LifecycleJson.Number(current, "domain_id"); DateTime slot = DateTime.Parse(LifecycleJson.Text(current, "slot_start_utc"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);
        step = "gpo_previous";
        var previous = (await Rows(db, tx, """
            select c.cycle_id,c.policy,c.publication_state,s.domain_id,s.source_run_id::text as source_id,encode(s.payload_sha256,'hex') as hash
            from sli_agent_snapshot_cycles c left join gpo_report_v2_source_snapshots s on s.source_run_id=c.gpo_source_run_id and s.import_status='completed' and s.domain_id=@domain
            where c.agent_id=@agent and c.module_id='sli.gpo-snapshot' and c.slot_start_utc<@slot order by c.slot_start_utc desc,c.cycle_id desc limit 1
            """, ct, ("domain", domain), ("agent", Guid.Parse(LifecycleJson.Text(current, "agent_id"))), ("slot", LifecycleJson.Text(current, "slot_start_utc")))).SingleOrDefault();
        if (previous is not null && (LifecycleJson.Text(previous, "publication_state") != "published" || previous["domain_id"]?.ToString() != domain.ToString(CultureInfo.InvariantCulture) ||
            new[] { "source_instance_id", "domain_sid", "domain_dns", "scope" }.Any(k => !JsonNode.DeepEquals(previous["policy"]?[k], current["policy"]?[k])))) previous = null;
        var payload = await Payload(db, tx, "gpo_v2", current, ct, domain); var oldPayload = previous is null ? null : await Payload(db, tx, "gpo_v2", previous, ct, domain);
        return await PublishPair(db, tx, id, previous is null ? null : Guid.Parse(LifecycleJson.Text(previous, "cycle_id")), domain, "gpo_v2", slot,
            DateTimeOffset.Parse(LifecycleJson.Text(current, "source_observed_at_utc"), CultureInfo.InvariantCulture), payload, oldPayload, LifecycleJson.Text(current, "hash"), previous?["hash"]?.ToString(), true, ct);
    }
    async Task<long> PublishPair(NpgsqlConnection db, NpgsqlTransaction tx, Guid id, Guid? previousId, long domain, string family, DateTime slot, DateTimeOffset sourceObserved,
        JsonObject payload, JsonObject? oldPayload, string hash, string? oldHash, bool coverageComplete, CancellationToken ct)
    {
        step = "changes_extract";
        var values = new List<(string? Before, string? After)>();
        var changes = oldPayload is null ? [] : SnapshotChanges.Extract(family, oldPayload, payload,
            (before, after) => values.Add((SnapshotChangeStore.Value(before), SnapshotChangeStore.Value(after))));
        var identity = new JsonObject { ["manifest_id"] = id.ToString("D"), ["previous_manifest_id"] = previousId?.ToString("D"), ["domain_id"] = domain, ["family"] = family,
            ["source_sha256"] = hash, ["previous_sha256"] = oldHash, ["version"] = 1 };
        string batch = LifecycleJson.Hash(identity).ToLowerInvariant();
        var records = changes.Select(change => new JsonObject { ["batch_id"] = batch,
            ["record_id"] = LifecycleJson.Hash(new JsonArray(JsonValue.Create(batch), change.DeepClone())).ToLowerInvariant(), ["domain_id"] = domain, ["family"] = family,
            ["observed_at"] = LifecycleJson.Stamp(slot), ["payload_json"] = LifecycleJson.Canonical(change) }).ToArray();
        var display = new List<JsonObject>();
        if (oldPayload is not null && family == "users_v2") {
            display = Ad.AdSnapshotChanges.CompareUsers(payload, oldPayload);
            foreach (var row in display) row["observed_at_utc"] = payload["metadata"]?["observed_at"]?.DeepClone();
        }
        if (oldPayload is not null && family == "computers_v6") {
            var names = await Rows(db, tx, "select fqdn from public.domains where id=@domain", ct, ("domain", domain));
            display = Ad.AdSnapshotChanges.CompareComputers(payload, oldPayload, domain, names.Single()["fqdn"]?.ToString(), sourceObserved);
        }
        step = "postgres_changes_insert";
        await SnapshotChangeStore.WriteAsync(db, tx, id, batch, domain, family, slot, records, values, display,
            oldPayload?["metadata"]?["observed_at"]?.ToString(), payload["metadata"]?["observed_at"]?.ToString(), ct);
        var sequence = new JsonArray(records.OrderBy(r => LifecycleJson.Text(r, "record_id"), StringComparer.Ordinal).Select(r => (JsonNode)new JsonArray(r["record_id"]!.DeepClone(), r["payload_json"]!.DeepClone())).ToArray());
        bool complete = oldPayload is not null && SnapshotChanges.Complete(oldPayload) && SnapshotChanges.Complete(payload) && SnapshotChanges.Comparable(oldPayload, payload) && coverageComplete;
        (string Key, object Value)[] parameters = [("id", id), ("family", family), ("domain", domain),
            ("previous", (object?)previousId?.ToString("D") ?? DBNull.Value), ("hash", hash),
            ("oldHash", (object?)oldHash ?? DBNull.Value), ("batch", batch), ("records", LifecycleJson.Hash(sequence).ToLowerInvariant()),
            ("count", records.Length), ("observed", slot), ("coverage", complete ? "complete" : "partial")];
        step = "confirmation_insert";
        await Execute(db, tx, """
            insert into ad_snapshot_history_confirmations(manifest_id,family,domain_id,previous_manifest_id,source_sha256,previous_sha256,
              batch_id,records_sha256,record_count,observed_at,coverage_state)
            values(@id,@family,@domain,cast(@previous as uuid),@hash,@oldHash,@batch,@records,@count,@observed,@coverage)
            on conflict(manifest_id,family) do nothing
            """, ct, parameters);
        step = "confirmation_readback";
        var confirmed = await Rows(db, tx, """
            select 1 from ad_snapshot_history_confirmations where manifest_id=@id and family=@family and domain_id=@domain
              and previous_manifest_id is not distinct from cast(@previous as uuid) and source_sha256=@hash
              and previous_sha256 is not distinct from @oldHash and batch_id=@batch and records_sha256=@records
              and record_count=@count and observed_at=@observed and coverage_state=@coverage
            """, ct, parameters);
        if (confirmed.Count != 1) throw new LifecycleBlocked("snapshot_history_confirmation_readback_mismatch");
        return records.Length;
    }
}
