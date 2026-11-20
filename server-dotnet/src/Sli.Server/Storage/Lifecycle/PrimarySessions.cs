using System.Text.Json.Nodes;

namespace Sli.Server.Storage.Lifecycle;

// Observed pairs and coverage are deliberately separate: agent capture does not
// declare continuity. A pair can be closed, but is never evidence of completeness.
internal sealed class PrimarySessions(LifecycleClickHouse ch)
{
    const string Columns = "revision,state,server_id,domain_id,channel_id,logon_time_utc,logoff_time_utc,duration_s,logon_id,logon_source_id,logoff_source_id,previous_revision_sha256,revision_sha256,batch_identity,payload_json";
    internal const string ReadColumns = "lower(hex(session_uid)) AS session_uid_hex," + Columns;

    internal static string Digest(JsonObject revision)
    {
        var value = (JsonObject)revision.DeepClone();
        foreach (string key in new[] { "revision_sha256", "published_at_utc", "latest_revision", "revision_rows", "event_id", "placement", "lifecycle_revision_sha256", "placement_revision", "placement_batch" }) value.Remove(key);
        // UInt64 JSON transport can be quoted; normalize scalar types for hashing.
        foreach (string key in new[] { "revision", "server_id", "domain_id", "channel_id", "duration_s", "logon_source_id", "logoff_source_id" })
            if (value[key] is not null) value[key] = LifecycleJson.Number(value, key);
        return LifecycleJson.Hash(value).ToLowerInvariant();
    }
    internal static JsonObject VerifyRevision(JsonObject row)
    {
        if (LifecycleJson.Text(row, "revision_sha256") != Digest(row)) throw new InvalidDataException("primary_session_revision_mismatch");
        var payload = JsonNode.Parse(LifecycleJson.Text(row, "payload_json"))!.AsObject();
        foreach (var (key, idKey) in new[] { ("logon", "logon_source_id"), ("logoff", "logoff_source_id") }) {
            if (row[idKey] is null && payload[key] is null) continue;
            if (payload[key] is not JsonObject fact || fact["id"]?.ToString() != row[idKey]?.ToString() ||
                new[] { "server_id", "domain_id", "channel_id" }.Any(k => fact[k]?.ToString() != row[k]?.ToString()) || LifecycleJson.Text(fact, "normalized_hash").Length != 64)
                throw new InvalidDataException("primary_session_source_mismatch");
        }
        return payload;
    }

    static string Signature(JsonObject row) => string.Join('\0', row.Where(p => p.Key != "published_at_utc").OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => p.Key + "=" + (p.Value?.ToString() ?? "<null>")));
    static string BatchDigest(List<JsonObject> revisions,List<JsonObject> placements) => LifecycleJson.Hash(new JsonObject {
        ["revisions"]=new JsonArray(revisions.Select(Signature).Order(StringComparer.Ordinal).Select(s=>(JsonNode)JsonValue.Create(s)!).ToArray()),
        ["placements"]=new JsonArray(placements.Select(Signature).Order(StringComparer.Ordinal).Select(s=>(JsonNode)JsonValue.Create(s)!).ToArray()) }).ToLowerInvariant();

    async Task VerifyBatchesAsync(IEnumerable<JsonObject> rows,CancellationToken ct)
    {
        foreach(string batch in rows.Select(r=>LifecycleJson.Text(r,"batch_identity")).Distinct()) {
            var args=new Dictionary<string,string>{["batch"]=batch};
            var markers=await ch.RowsAsync("SELECT batch_identity,revision_count,placement_count,content_sha256 FROM sli_warm.primary_session_batches WHERE batch_identity={batch:String}",ct,args);
            if(markers.Count!=1)throw new InvalidDataException("primary_session_publication_missing_or_duplicate");
            var revisions=await ch.RowsAsync("SELECT "+ReadColumns+" FROM sli_warm.session_lifecycle_revisions WHERE batch_identity={batch:String} LIMIT 1001",ct,args);
            var placements=await ch.RowsAsync("SELECT event_id,revision,lower(hex(session_uid)) AS session_uid_hex,placement,lifecycle_revision_sha256,batch_identity FROM sli_warm.event_session_placement_revisions WHERE batch_identity={batch:String} LIMIT 2001",ct,args);
            if(revisions.Count>1000||placements.Count>2000||revisions.Count!=LifecycleJson.Number(markers[0],"revision_count")||placements.Count!=LifecycleJson.Number(markers[0],"placement_count")||BatchDigest(revisions,placements)!=LifecycleJson.Text(markers[0],"content_sha256"))throw new InvalidDataException("primary_session_publication_mismatch");
        }
    }

    // Verify historical placement against the latest published revision.
    internal async Task<Dictionary<long, JsonObject>> ReadPlacementsAsync(long[] ids, CancellationToken ct, Action<long, string>? invalidPlacement = null)
    {
        if (ids.Length == 0) return [];
        if (ids.Length > 1000) throw new ArgumentOutOfRangeException(nameof(ids));
        var rows = await ch.RowsAsync(PrimarySessionRead.Select(ReadColumns, PrimarySessionRead.SourceIds(ids)), ct);
        var invalidBatches = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var batch in rows.GroupBy(r => LifecycleJson.Text(r, "batch_identity"))) {
            try { await VerifyBatchesAsync(batch, ct); }
            catch (InvalidDataException error) when (invalidPlacement is not null) { invalidBatches.Add(batch.Key, error.Message); }
        }
        var placements = await ch.RowsAsync("SELECT event_id,revision,lower(hex(session_uid)) AS session_uid_hex,placement,lifecycle_revision_sha256,batch_identity FROM sli_warm.event_session_placement_revisions WHERE event_id IN (" + LifecycleClickHouse.Ids(ids) + ") AND batch_identity IN (SELECT batch_identity FROM sli_warm.primary_session_batches PREWHERE batch_identity IN (SELECT batch_identity FROM sli_warm.event_session_placement_revisions WHERE event_id IN (" + LifecycleClickHouse.Ids(ids) + ")) GROUP BY batch_identity HAVING count()=1)", ct);
        var result = new Dictionary<long, JsonObject>();
        foreach (long id in ids.Distinct()) {
            try {
                foreach (var sessionRow in rows.Where(r => new[] { "logon_source_id", "logoff_source_id" }.Any(k => r[k] is not null && LifecycleJson.Number(r, k) == id)))
                    if (invalidBatches.TryGetValue(LifecycleJson.Text(sessionRow, "batch_identity"), out string? reason)) throw new InvalidDataException(reason);
                var latest = placements.Where(p => LifecycleJson.Number(p, "event_id") == id).OrderByDescending(p => LifecycleJson.Number(p, "revision")).ToArray();
                if (latest.Length == 0) continue;
                var placement = latest[0];
                if (latest.Count(p => LifecycleJson.Number(p, "revision") == LifecycleJson.Number(placement, "revision")) != 1) throw new InvalidDataException("primary_session_placement_conflict");
                var matches = rows.Where(r => r["session_uid_hex"]?.ToString() == placement["session_uid_hex"]?.ToString() && r["revision"]?.ToString() == placement["revision"]?.ToString() && r["revision_sha256"]?.ToString() == placement["lifecycle_revision_sha256"]?.ToString() && r["batch_identity"]?.ToString() == placement["batch_identity"]?.ToString()).ToArray();
                if (matches.Length != 1) throw new InvalidDataException("primary_session_placement_revision_missing");
                var row = matches[0]; var payload = VerifyRevision(row);
                if(LifecycleJson.Text(placement,"placement")!=(LifecycleJson.Text(row,"state")=="closed"?"closed_session":"incomplete_session"))throw new InvalidDataException("primary_session_placement_state_mismatch");
                if (!new[] { "logon", "logoff" }.Any(k => payload[k]?["id"]?.ToString() == id.ToString(System.Globalization.CultureInfo.InvariantCulture))) throw new InvalidDataException("primary_session_placement_source_missing");
                result.Add(id, row);
            } catch (InvalidDataException error) when (invalidPlacement is not null) { invalidPlacement(id, error.Message); }
        }
        return result;
    }

}
