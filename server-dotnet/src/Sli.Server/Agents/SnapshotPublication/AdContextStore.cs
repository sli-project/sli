using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;
using static Sli.Server.Agents.SnapshotPublication.AdContextBundle;

namespace Sli.Server.Agents.SnapshotPublication;

internal static class AdContextStore
{
    internal static NpgsqlCommand Command(NpgsqlConnection db, NpgsqlTransaction tx, string sql, params (string Key, object? Value)[] values)
    {
        var c = new NpgsqlCommand(sql, db, tx);
        foreach (var (key, value) in values) {
            if (value is null) c.Parameters.AddWithValue(key, NpgsqlDbType.Unknown, DBNull.Value);
            else c.Parameters.AddWithValue(key, value);
        }
        return c;
    }
    internal static async Task Execute(NpgsqlConnection db, NpgsqlTransaction tx, string sql, CancellationToken ct, params (string Key, object? Value)[] values)
    { await using var c = Command(db, tx, sql, values); await c.ExecuteNonQueryAsync(ct); }
    internal static DateTime Time(JsonNode? n) => DateTimeOffset.Parse(Text(n), System.Globalization.CultureInfo.InvariantCulture).UtcDateTime;

    internal static async Task ImportAsync(NpgsqlConnection db, NpgsqlTransaction tx, long domain, JsonObject bundle, CancellationToken ct)
    {
        Guid run = Guid.Parse(Text(bundle["run_id"])); byte[] hash = Convert.FromHexString(Text(bundle["bundle_sha256"])); DateTime stamp = Time(bundle["observed_at_utc"]);
        await using (var c = Command(db, tx, "select bundle_sha256,status from ad_context_runs where run_id=@run", ("run", run))) {
            await using var r = await c.ExecuteReaderAsync(ct);
            if (await r.ReadAsync(ct)) { Require(((byte[])r.GetValue(0)).AsSpan().SequenceEqual(hash) && r.GetString(1) == "completed"); return; }
        }
        string[] sectionNames = bundle["sections"]!.AsArray().Select(s => Text(s!["name"])).ToArray();
        await using (var c = Command(db, tx, """
            select max(run.observed_at_utc) from ad_context_runs run join ad_context_sections s using(run_id)
            where run.domain_id=@domain and run.source_pack_id=@pack and run.status='completed' and s.section_name=any(@sections)
            """, ("domain", domain), ("pack", Text(bundle["source_pack_id"])), ("sections", sectionNames))) {
            if (await c.ExecuteScalarAsync(ct) is DateTime latest && stamp < latest) throw new ProtocolException("agent_ad_snapshot_superseded");
        }
        await Execute(db, tx, """
            insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,scope_json,status)
            values(@run,@pack,@version,@domain,@mode,@stamp,@hash,@scope::jsonb,'importing')
            """, ct, ("run", run), ("pack", Text(bundle["source_pack_id"])), ("version", Text(bundle["source_pack_version"])), ("domain", domain), ("mode", Text(bundle["mode"])), ("stamp", stamp), ("hash", hash), ("scope", bundle["scope"]!.ToJsonString()));
        foreach (var s in bundle["sections"]!.AsArray())
            await Execute(db, tx, "insert into ad_context_sections(run_id,section_name,status,record_count,duration_ms,error_code) values(@run,@name,@status,@count,@duration,@error)", ct,
                ("run", run), ("name", Text(s!["name"])), ("status", Text(s["status"])), ("count", s["record_count"]!.GetValue<int>()), ("duration", s["duration_ms"]!.GetValue<long>()), ("error", Optional(s["error_code"])));
        var records = bundle["records"]!.AsArray().Select(r => r!.AsObject()).ToArray();
        var entities = records.Where(r => Text(r["record_type"]) == "entity").ToArray();
        var resolved = await ResolveAsync(db, tx, domain, entities, ct);
        var ids = new Dictionary<string, long>(); var observed = new Dictionary<string, (long Id, string Kind, string? Sid)>();
        foreach (var record in entities) {
            string guid = Text(record["identity"]!["object_guid"]), kind = Text(record["identity"]!["kind"]); string? sid = Optional(record["identity"]!["object_sid"]);
            long? existing = resolved.GetValueOrDefault(Text(record["record_key"])); if (existing == 0) existing = null;
            if (observed.TryGetValue(guid, out var prior)) {
                Require(prior.Kind == kind && (prior.Sid is null || sid is null || UnicodeCaseFold.Fold(prior.Sid) == UnicodeCaseFold.Fold(sid)) && (existing is null || existing == prior.Id));
                existing = prior.Id; sid = prior.Sid ?? sid;
            }
            long id = await GpoIdentityWriter.StoreAsync(db, tx, domain, run, record, existing, ct, kind);
            observed[guid] = (id, kind, sid); ids[Text(record["record_key"])] = id;
            await ObserveAsync(db, tx, domain, run, record, id, null, ct);
        }
        foreach (var record in records.Where(r => Text(r["record_type"]) == "relation"))
            await ObserveAsync(db, tx, domain, run, record, ids[Text(record["source_record_key"])], ids[Text(record["target_record_key"])], ct);
        foreach (var record in records) await EvidenceAsync(db, tx, run, bundle, record, ct);
        if (Text(bundle["mode"]) is "full" or "reconcile") {
            foreach (var s in bundle["sections"]!.AsArray().Where(s => Text(s!["status"]) == "complete")) {
                string section = Text(s!["name"]);
                if (section is "directory_accounts" or "directory_group_graph" or "directory_exact_logon")
                    await Execute(db, tx, """
                        update ad_context_entity_versions v set valid_to_utc=@stamp from entities_v2 e
                        where v.entity_id=e.id and e.domain_id=@domain and v.source_section=@section and v.valid_to_utc is null and not (v.entity_id=any(@seen))
                        """, ct, ("stamp", stamp), ("domain", domain), ("section", section), ("seen", entities.Where(r => Text(r["section"]) == section).Select(r => ids[Text(r["record_key"])]).Distinct().ToArray()));
                if (section is "directory_group_graph" or "privileged_membership" or "vpn_membership") {
                    var relations = records.Where(r => Text(r["record_type"]) == "relation" && Text(r["section"]) == section).ToArray();
                    var targetIds = new HashSet<long>(relations.Select(r => ids[Text(r["target_record_key"])]));
                    if (section != "directory_group_graph") {
                        string key = section == "privileged_membership" ? "privileged_group_sids" : "vpn_group_sids";
                        var sids = bundle["scope"]![key]!.AsArray().Select(Text).Select(UnicodeCaseFold.Fold).ToHashSet();
                        foreach (var r in entities.Where(r => Text(r["identity"]!["kind"]) == "ad_group" && sids.Contains(UnicodeCaseFold.Fold(Optional(r["identity"]!["object_sid"]) ?? "")))) targetIds.Add(ids[Text(r["record_key"])]);
                    }
                    await Execute(db, tx, """
                        update ad_context_relation_versions set valid_to_utc=@stamp where domain_id=@domain and source_section=@section
                          and valid_to_utc is null and not (relation_key=any(@seen)) and (@graph or target_entity_id=any(@targets))
                        """, ct, ("stamp", stamp), ("domain", domain), ("section", section), ("seen", relations.Select(r => Text(r["record_key"])).ToArray()), ("graph", section == "directory_group_graph"), ("targets", targetIds.ToArray()));
                }
            }
        }
        await Execute(db, tx, "update ad_context_runs set status='completed',completed_at=now() where run_id=@run", ct, ("run", run));
    }

    private static async Task<Dictionary<string, long>> ResolveAsync(NpgsqlConnection db, NpgsqlTransaction tx, long domain, JsonObject[] records, CancellationToken ct)
    {
        var aliases = new Dictionary<(string Type, string Value), (long Id, string Kind)>();
        await using (var c = Command(db, tx, """
            select a.alias_type,a.normalized_value,a.entity_id,t.value from ad_context_entity_aliases a
            join entities_v2 e on e.id=a.entity_id join storage_v2_entity_type t on t.id=e.entity_type_id
            where a.domain_id=@domain and ((a.alias_type='object_guid' and a.normalized_value=any(@guids)) or (a.alias_type='object_sid' and a.normalized_value=any(@sids)))
            """, ("domain", domain), ("guids", records.Select(r => Text(r["identity"]!["object_guid"])).Distinct().ToArray()), ("sids", records.Select(r => UnicodeCaseFold.Fold(Optional(r["identity"]!["object_sid"]) ?? "")).Distinct().ToArray()))) {
            await using var r = await c.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct)) aliases[(r.GetString(0), r.GetString(1))] = (Convert.ToInt64(r.GetValue(2)), r.GetString(3));
        }
        var result = new Dictionary<string, long>();
        foreach (var record in records) {
            string guid = Text(record["identity"]!["object_guid"]), sid = UnicodeCaseFold.Fold(Optional(record["identity"]!["object_sid"]) ?? ""), kind = Text(record["identity"]!["kind"]), key = Text(record["record_key"]);
            aliases.TryGetValue(("object_guid", guid), out var byGuid);
            if (aliases.TryGetValue(("object_sid", sid), out var bySid)) { Require(bySid.Kind == kind && (byGuid.Id == 0 || byGuid.Id == bySid.Id)); result[key] = bySid.Id; continue; }
            // A renamed record may reuse a GUID even before a SID is available.
            if (byGuid.Id != 0) { Require(byGuid.Kind == kind); result[key] = byGuid.Id; continue; }
            await using var c = Command(db, tx, """
                select e.id,t.value from entities_v2 e join storage_v2_entity_type t on t.id=e.entity_type_id
                left join entity_details_v2 d on d.entity_id=e.id
                where (t.value=@kind and e.natural_key=@key) or (e.domain_id=@domain and @sid<>'' and lower(d.attributes_json->>'sid')=@sid)
                order by (e.natural_key=@key) desc,e.id limit 2
                """, ("kind", kind), ("key", key), ("domain", domain), ("sid", sid));
            var matches = new List<(long Id, string Kind)>(); await using var reader = await c.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) matches.Add((Convert.ToInt64(reader.GetValue(0)), reader.GetString(1)));
            if (matches.Count == 1) { Require(matches[0].Kind == kind); result[key] = matches[0].Id; }
        }
        return result;
    }

    private static async Task ObserveAsync(NpgsqlConnection db, NpgsqlTransaction tx, long domain, Guid run, JsonObject record, long source, long? target, CancellationToken ct)
    {
        bool relation = target is not null; string section = Text(record["section"]), key = Text(record["record_key"]); DateTime stamp = Time(record["observed_at_utc"]);
        var semantic = (JsonObject)record.DeepClone(); semantic.Remove("observed_at_utc"); byte[] hash = GpoIdentityWriter.Hash(semantic, false);
        string table = relation ? "ad_context_relation_versions" : "ad_context_entity_versions";
        long? version = null; bool same = false;
        await using (var c = Command(db, tx, relation ? "select id,content_sha256 from ad_context_relation_versions where domain_id=@domain and relation_key=@key and valid_to_utc is null" : "select id,content_sha256 from ad_context_entity_versions where entity_id=@entity and source_section=@section and valid_to_utc is null", ("domain", domain), ("key", key), ("entity", source), ("section", section))) {
            await using var r = await c.ExecuteReaderAsync(ct);
            if (await r.ReadAsync(ct)) { version = Convert.ToInt64(r.GetValue(0)); same = ((byte[])r.GetValue(1)).AsSpan().SequenceEqual(hash); }
        }
        if (version is not null) await Execute(db, tx, same ? $"update {table} set last_observed_at_utc=greatest(last_observed_at_utc,@stamp) where id=@id" : $"update {table} set valid_to_utc=@stamp where id=@id", ct, ("stamp", stamp), ("id", version));
        if (same) return;
        await Execute(db, tx, relation ? """
            insert into ad_context_relation_versions(relation_key,relation_kind,source_entity_id,target_entity_id,source_section,domain_id,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
            values(@key,'member_of',@entity,@target,@section,@domain,@stamp,@stamp,@hash,@record::jsonb,@run)
            """ : """
            insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
            values(@entity,@section,@stamp,@stamp,@hash,@record::jsonb,@run)
            """, ct, ("entity", source), ("target", target), ("section", section), ("domain", domain), ("stamp", stamp), ("hash", hash), ("record", record.ToJsonString()), ("run", run), ("key", key));
    }

    private static Task EvidenceAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid run, JsonObject bundle, JsonObject record, CancellationToken ct)
    {
        string key = Text(record["record_key"]); var locator = new JsonObject { ["run_id"] = run.ToString("D"), ["record_key"] = key, ["section"] = Text(record["section"]) };
        return Execute(db, tx, """
            insert into ad_context_evidence(evidence_key,evidence_type,source_pack_id,source_run_id,observed_at_utc,locator_json,integrity_sha256)
            values(@key,@type,@pack,@run,@stamp,@locator::jsonb,@hash) on conflict(evidence_key) do nothing
            """, ct, ("key", $"adctx:{run:D}:{key}"), ("type", Text(record["record_type"]) switch { "entity" => "entity_observation", "relation" => "relation_observation", _ => "data_quality" }), ("pack", Text(bundle["source_pack_id"])), ("run", run), ("stamp", Time(record["observed_at_utc"])), ("locator", locator.ToJsonString()), ("hash", GpoIdentityWriter.Hash(record, false)));
    }
}
