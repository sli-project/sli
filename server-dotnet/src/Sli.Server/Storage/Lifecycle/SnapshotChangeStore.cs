using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Storage.Lifecycle.LifecyclePostgres;

namespace Sli.Server.Storage.Lifecycle;

internal static class SnapshotChangeStore
{
    internal static bool PostgresReads(IConfiguration config) => Sli.Server.Storage.EventReports.EventReadService.ShortReads(config);

    static string Short(string text) => string.Concat(text.Replace('\0', '\uFFFD').EnumerateRunes().Take(2048).Select(r => r.ToString()));
    internal static string? Value(JsonNode? value) => value is null ? null : Short(
        value is JsonValue scalar && scalar.TryGetValue<string>(out var text) ? text : value.ToJsonString());

    static JsonNode? Bounded(JsonNode? value) => value switch {
        JsonObject obj => new JsonObject(obj.Select(p => KeyValuePair.Create(p.Key, Bounded(p.Value)))),
        JsonArray array => new JsonArray(array.Select(Bounded).ToArray()),
        JsonValue scalar when scalar.TryGetValue<string>(out var text) => JsonValue.Create(Short(text)),
        _ => value?.DeepClone()
    };

    internal static async Task<List<JsonObject>> ReadAsync(NpgsqlConnection db, string batch, long domain, string family, DateTimeOffset observed, CancellationToken ct, bool includeValues = false)
        => await Rows(db, null, """
            select record_id,payload_json,
                   case when @include_values then before_value end as before_value,
                   case when @include_values then after_value end as after_value
            from public.ad_snapshot_change_history
            where batch_id=@batch and domain_id=@domain and family=@family and observed_at=@observed and record_kind='history'
            order by record_id collate "C"
            """, ct, ("batch", batch), ("domain", domain), ("family", family), ("observed", observed), ("include_values", includeValues));

    internal static async Task WriteAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid manifest, string batch, long domain, string family, DateTime observed,
        JsonObject[] history, List<(string? Before, string? After)> values, List<JsonObject> display, string? from, string? to, CancellationToken ct)
    {
        await Execute(db, tx, "select public.create_ad_snapshot_change_partition(@observed)", ct, ("observed", observed));
        var rows = new List<JsonObject>();
        for (int i = 0; i < history.Length; i++) rows.Add(new JsonObject {
            ["record_id"] = history[i]["record_id"]!.DeepClone(), ["record_kind"] = "history", ["ordinal"] = i,
            ["payload_json"] = history[i]["payload_json"]!.DeepClone(), ["before_value"] = values[i].Before, ["after_value"] = values[i].After });
        var pairs = new JsonArray();
        for (int i = 0; i < display.Count; i++) {
            var item = Bounded(display[i])!.AsObject();
            foreach (string key in new[] { "before", "after" })
                if (item[key] is JsonArray or JsonObject && item[key]!.ToJsonString().EnumerateRunes().Count() > 2048) item[key] = Value(item[key]);
            string payload = LifecycleJson.Canonical(item), id = LifecycleJson.Hash(new JsonArray(batch, "changes", item)).ToLowerInvariant();
            rows.Add(new JsonObject { ["record_id"] = id, ["record_kind"] = "changes", ["ordinal"] = i, ["payload_json"] = payload,
                ["before_value"] = Value(item["before"]), ["after_value"] = Value(item["after"]) });
            pairs.Add(new JsonArray(id, payload));
        }
        // Even a pair with zero changes has a verified header. It remains readable
        // after the seven-day source ring expires, without inventing source data.
        var header = new JsonObject { ["count"] = display.Count, ["records_sha256"] = LifecycleJson.Hash(pairs).ToLowerInvariant(), ["from_utc"] = from, ["to_utc"] = to };
        rows.Add(new JsonObject { ["record_id"] = LifecycleJson.Hash(new JsonArray(batch, "changes_header", header.DeepClone())).ToLowerInvariant(),
            ["record_kind"] = "changes_header", ["ordinal"] = 0, ["payload_json"] = LifecycleJson.Canonical(header) });
        foreach (var part in rows.Chunk(1000)) {
            await Execute(db, tx, """
                insert into public.ad_snapshot_change_history(observed_at,record_id,batch_id,manifest_id,domain_id,family,record_kind,ordinal,payload_json,before_value,after_value)
                select @observed,r.record_id,@batch,@manifest,@domain,@family,r.record_kind,r.ordinal,r.payload_json,r.before_value,r.after_value
                from jsonb_to_recordset(cast(@rows as jsonb)) r(record_id text,record_kind text,ordinal integer,payload_json text,before_value text,after_value text)
                on conflict(observed_at,record_kind,record_id) do nothing
                """, ct, ("observed", observed), ("batch", batch), ("manifest", manifest), ("domain", domain), ("family", family),
                ("rows", LifecycleJson.Canonical(new JsonArray(part.Select(r => (JsonNode)r.DeepClone()).ToArray()))));
        }
        var actual = await Rows(db, tx, """
            select record_id,record_kind,ordinal,payload_json,before_value,after_value from public.ad_snapshot_change_history
            where batch_id=@batch and manifest_id=@manifest and domain_id=@domain and family=@family and observed_at=@observed
            """, ct, ("batch", batch), ("manifest", manifest), ("domain", domain), ("family", family), ("observed", observed));
        string Key(JsonObject r) => r["record_kind"] + ":" + r["record_id"];
        if (actual.Count != rows.Count || !actual.OrderBy(Key, StringComparer.Ordinal).Zip(rows.OrderBy(Key, StringComparer.Ordinal)).All(p =>
            new[] { "record_id", "record_kind", "ordinal", "payload_json", "before_value", "after_value" }.All(k => p.First[k]?.ToString() == p.Second[k]?.ToString())))
            throw new LifecycleBlocked("snapshot_history_postgres_readback_mismatch");
    }

    internal static async Task<(List<JsonObject> Items, JsonObject Header)?> DisplayAsync(NpgsqlConnection db, Guid manifest, long domain, string family, CancellationToken ct)
    {
        var records = await Rows(db, null, """
            select record_id,record_kind,payload_json,batch_id from public.ad_snapshot_change_history
            where manifest_id=@manifest and domain_id=@domain and family=@family and record_kind in ('changes','changes_header')
            order by record_kind,ordinal,record_id collate "C"
            """, ct, ("manifest", manifest), ("domain", domain), ("family", family));
        if (records.Count == 0) return null;
        var headers = records.Where(r => r["record_kind"]!.ToString() == "changes_header").ToArray();
        if (headers.Length != 1) throw new InvalidDataException("snapshot_history_report_readback_mismatch");
        var pairs = new JsonArray(); var items = new List<JsonObject>(); JsonObject? header = null;
        foreach (var record in records) {
            var payload = JsonNode.Parse(record["payload_json"]!.GetValue<string>())!.AsObject();
            if (LifecycleJson.Hash(new JsonArray(record["batch_id"]!.DeepClone(), record["record_kind"]!.DeepClone(), payload.DeepClone())).ToLowerInvariant() != record["record_id"]!.ToString())
                throw new InvalidDataException("snapshot_history_record_hash_mismatch");
            if (record["record_kind"]!.ToString() == "changes_header") header = payload;
            else { items.Add(payload); pairs.Add(new JsonArray(record["record_id"]!.DeepClone(), record["payload_json"]!.DeepClone())); }
        }
        if (header!["count"]!.GetValue<int>() != items.Count || header["records_sha256"]!.ToString() != LifecycleJson.Hash(pairs).ToLowerInvariant())
            throw new InvalidDataException("snapshot_history_report_readback_mismatch");
        return (items, header);
    }
}
