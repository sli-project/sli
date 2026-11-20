using Sli.Server.Infrastructure;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.SnapshotPublication;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdContextStore
{
    static async Task Execute(NpgsqlConnection db, string sql, CancellationToken ct, params object[] args)
    {
        SqlArguments.Validate(args);
        await using var command = new NpgsqlCommand(sql, db);
        foreach (object arg in args) command.Parameters.Add(arg is JsonNode node ? new() { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = node.ToJsonString() } : new() { Value = arg });
        await command.ExecuteNonQueryAsync(ct);
    }
    public static async Task<Dictionary<string, long>> ImportAsync(NpgsqlConnection db, NpgsqlTransaction tx, long domain, JsonObject bundle, CancellationToken ct)
    {
        Guid run = Guid.Parse(bundle.Text("run_id")!); var stamp = bundle.Time("observed_at_utc");
        bool replay = await GpoRunLedger.StartAsync(db, tx, domain, bundle, ct);
        var records = bundle["records"]!.AsArray().OfType<JsonObject>().ToArray();
        var entities = records.Where(r => r.Text("record_type") == "entity").ToArray();
        var ids = new Dictionary<string, long>();
        var aliases = await ReadAsync(db, """
            select alias.alias_type,alias.normalized_value,alias.entity_id,entity.domain_id,kind.value as kind
            from ad_context_entity_aliases alias join entities_v2 entity on entity.id=alias.entity_id
            join storage_v2_entity_type kind on kind.id=entity.entity_type_id
            where alias.domain_id=$1 and ((alias.alias_type='object_guid' and alias.normalized_value=any($2))
            or (alias.alias_type='object_sid' and alias.normalized_value=any($3)))
            """, ct, domain, entities.Select(r => r["identity"]!.Text("object_guid")!.ToLowerInvariant()).Distinct().ToArray(), entities.Select(r => r["identity"]!.Text("object_sid")?.ToLowerInvariant()).Where(s => s is not null).Distinct().ToArray());
        var exact = await ReadAsync(db, "select entity.id,entity.natural_key,kind.value as kind,entity.domain_id from entities_v2 entity join storage_v2_entity_type kind on kind.id=entity.entity_type_id where entity.natural_key=any($1)", ct, (object)entities.Select(r => r.Text("record_key")!).ToArray());
        var aliasIndex=aliases.ToDictionary(a=>(a.Text("alias_type")!,a.Text("normalized_value")!.ToLowerInvariant()));
        var exactIndex=exact.ToDictionary(e=>(e.Text("natural_key")!,e.Text("kind")!));
        var importedGuids=new Dictionary<string,JsonObject>(StringComparer.OrdinalIgnoreCase);
        var legacyRows=await ReadAsync(db,"select entity.id as entity_id,entity.domain_id,kind.value as kind,lower(details.attributes_json->>'sid') as sid from entities_v2 entity join entity_details_v2 details on details.entity_id=entity.id join storage_v2_entity_type kind on kind.id=entity.entity_type_id where entity.domain_id=$1 and lower(details.attributes_json->>'sid')=any($2)",ct,domain,entities.Select(r=>r["identity"]!.Text("object_sid")?.ToLowerInvariant()).Where(s=>s is not null).Distinct().ToArray());
        var legacyIndex=legacyRows.GroupBy(r=>r.Text("sid")!).Where(g=>g.Count()==1).ToDictionary(g=>g.Key,g=>g.Single());
        foreach (var record in entities)
        {
            var identity = record["identity"]!; string key = record.Text("record_key")!, guid = identity.Text("object_guid")!, kind = identity.Text("kind")!;
            var byGuid = aliasIndex.GetValueOrDefault(("object_guid",guid.ToLowerInvariant()));
            var bySid = aliasIndex.GetValueOrDefault(("object_sid",identity.Text("object_sid")?.ToLowerInvariant()??""));
            var found = bySid ?? exactIndex.GetValueOrDefault((key,kind));
            if (found is null && identity.Text("object_sid") is {} sid)
            {
                found=legacyIndex.GetValueOrDefault(sid.ToLowerInvariant());
            }
            long? existing = found is null ? null : found.Int(found["entity_id"] is null ? "id" : "entity_id");
            if (found is not null) AdContextBundle.Require(found.Int("domain_id") == domain && found.Text("kind") == kind && (byGuid is null || byGuid.Int("entity_id") == existing), "agent_ad_identity_conflict");
            var sameGuid = importedGuids.TryGetValue(guid,out var priorRecord)?new[]{priorRecord}:[];
            if (sameGuid.Length > 0)
            {
                foreach (var prior in sameGuid) AdContextBundle.Require(prior["identity"]!.Text("kind") == kind && (prior["identity"]!.Text("object_sid") is null || identity.Text("object_sid") is null || string.Equals(prior["identity"]!.Text("object_sid"), identity.Text("object_sid"), StringComparison.OrdinalIgnoreCase)) && (existing is null || existing == ids[prior.Text("record_key")!]), "agent_ad_identity_conflict");
                existing = ids[sameGuid[0].Text("record_key")!];
            }
            if (replay) { AdContextBundle.Require(byGuid is not null, "agent_ad_import_identity_missing"); ids[key] = byGuid!.Int("entity_id"); continue; }
            long id = await GpoIdentityWriter.StoreAsync(db, tx, domain, run, record, existing, ct, kind); ids[key] = id;
            importedGuids[guid]=record;
            await GpoEntityObservation.WriteAsync(db, tx, id, run, bundle, record, ct);
        }
        if (replay) return ids;
        foreach (var s in bundle["sections"]!.AsArray())
            await Execute(db, "insert into ad_context_sections(run_id,section_name,status,record_count,duration_ms,error_code) values($1,$2,$3,$4,$5,$6)", ct, run, s!.Text("name")!, s.Text("status")!, s.Int("record_count"), s.Int("duration_ms"), (object?)s.Text("error_code") ?? DBNull.Value);
        foreach (var record in records.Where(r => r.Text("record_type") != "entity"))
        {
            if (record.Text("record_type") == "relation")
            {
                var semantic = (JsonObject)record.DeepClone(); semantic.Remove("observed_at_utc"); byte[] hash = GpoIdentityWriter.Hash(semantic, false);
                var prior = await ReadAsync(db, "select id,encode(content_sha256,'hex') as hash from ad_context_relation_versions where domain_id=$1 and relation_key=$2 and valid_to_utc is null", ct, domain, record.Text("record_key"));
                if (prior.Count > 0 && prior[0].Text("hash") == Convert.ToHexStringLower(hash)) await Execute(db, "update ad_context_relation_versions set last_observed_at_utc=greatest(last_observed_at_utc,$1) where id=$2", ct, stamp, prior[0].Int("id"));
                else
                {
                    if (prior.Count > 0) await Execute(db, "update ad_context_relation_versions set valid_to_utc=$1 where id=$2", ct, stamp, prior[0].Int("id"));
                    await Execute(db, "insert into ad_context_relation_versions(relation_key,relation_kind,source_entity_id,target_entity_id,source_section,domain_id,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id) values($1,$2,$3,$4,$5,$6,$7,$7,$8,$9,$10)", ct, record.Text("record_key")!, record.Text("relation_kind")!, ids[record.Text("source_record_key")!], ids[record.Text("target_record_key")!], record.Text("section")!, domain, stamp, hash, record, run);
                }
            }
            await Execute(db, "insert into ad_context_evidence(evidence_key,evidence_type,source_pack_id,source_run_id,observed_at_utc,locator_json,integrity_sha256) values($1,$2,$3,$4,$5,$6,$7) on conflict(evidence_key) do nothing", ct, $"adctx:{run:D}:{record.Text("record_key")}", record.Text("record_type") == "relation" ? "relation_observation" : "data_quality", bundle.Text("source_pack_id")!, run, stamp, Obj(new { run_id = run.ToString("D"), record_key = record.Text("record_key"), section = record.Text("section") }), GpoIdentityWriter.Hash(record, false));
        }
        if (bundle.Text("mode") is "full" or "reconcile") foreach (var s in bundle["sections"]!.AsArray().Where(s => s!.Text("status") == "complete"))
        {
            string section = s!.Text("name")!;
            if (section is "directory_accounts" or "directory_group_graph" or "directory_exact_logon")
                await Execute(db, "update ad_context_entity_versions version set valid_to_utc=$1 from entities_v2 entity where version.entity_id=entity.id and entity.domain_id=$2 and version.source_section=$3 and version.valid_to_utc is null and not(version.entity_id=any($4))", ct, stamp, domain, section, entities.Where(r => r.Text("section") == section).Select(r => ids[r.Text("record_key")!]).ToArray());
            if (section == "directory_group_graph")
                await Execute(db, "update ad_context_relation_versions set valid_to_utc=$1 where domain_id=$2 and source_section=$3 and valid_to_utc is null and not(relation_key=any($4))", ct, stamp, domain, section, records.Where(r => r.Text("record_type") == "relation" && r.Text("section") == section).Select(r => r.Text("record_key")!).ToArray());
            if (section is "privileged_membership" or "vpn_membership")
            {
                var rootSids = bundle["scope"]![section == "privileged_membership" ? "privileged_group_sids" : "vpn_group_sids"]!.AsArray().Select(n => n!.ToString()).ToHashSet(StringComparer.OrdinalIgnoreCase);
                var targets = entities.Where(r => r["identity"]!.Text("kind") == "ad_group" && rootSids.Contains(r["identity"]!.Text("object_sid") ?? "")).Select(r => ids[r.Text("record_key")!]).Concat(records.Where(r => r.Text("record_type") == "relation" && r.Text("section") == section).Select(r => ids[r.Text("target_record_key")!])).Distinct().ToArray();
                await Execute(db, "update ad_context_relation_versions set valid_to_utc=$1 where domain_id=$2 and source_section=$3 and target_entity_id=any($4) and valid_to_utc is null and not(relation_key=any($5))", ct, stamp, domain, section, targets, records.Where(r => r.Text("record_type") == "relation" && r.Text("section") == section).Select(r => r.Text("record_key")!).ToArray());
            }
        }
        await Execute(db, "update ad_context_runs set status='completed',completed_at=now() where run_id=$1", ct, run);
        return ids;
    }
}
