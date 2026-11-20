using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Storage.Lifecycle;

// Store the complete PG row and its ordered evidence links, not just event facts.
internal sealed class FileAuditHistory(LifecycleClickHouse ch, IDisposable? owner = null) : IDisposable
{
    internal const string ReferencePrefix = "file-audit-history:";
    internal static FileAuditHistory? Configured(IConfiguration? config)
    {
        var settings = Sli.Server.Storage.History.HistoryConfiguration.For(config);
        if (!settings.HasPort) return null;
        var client = settings.CreateClient();
        return new(new LifecycleClickHouse(client,settings.Endpoint),client);
    }
    public void Dispose() => owner?.Dispose();
    internal const string Table = "sli_history.file_audit_observations";
    internal async Task EnsureSchemaAsync(CancellationToken ct) => await ch.ExecuteAsync("""
        CREATE TABLE IF NOT EXISTS sli_history.file_audit_observations (
          evidence_key String,agent_id String,source_instance_id String,core_evidence_ref String,
          payload_json String,payload_sha256 String)
        ENGINE=ReplacingMergeTree ORDER BY evidence_key
        SETTINGS fsync_after_insert=1,fsync_part_directory=1
        """,ct);

    internal static JsonObject Record(JsonObject payload)
    {
        var row = payload["observation"]!.AsObject();
        if (!Regex.IsMatch(row["evidence_key"]!.ToString(),"^[a-f0-9]{64}$") || payload["links"] is not JsonArray)
            throw new LifecycleBlocked("file_audit_history_payload_invalid");
        return new() { ["evidence_key"] = row["evidence_key"]!.DeepClone(), ["agent_id"] = row["agent_id"]!.DeepClone(),
            ["source_instance_id"] = row["source_instance_id"]!.DeepClone(), ["core_evidence_ref"] = row["core_evidence_ref"]!.DeepClone(),
            ["payload_json"] = LifecycleJson.Canonical(payload), ["payload_sha256"] = LifecycleJson.Hash(payload) };
    }
    internal static JsonObject Decode(JsonObject record)
    {
        try {
            var payload = JsonNode.Parse(record["payload_json"]!.ToString())!.AsObject();
            if (!JsonNode.DeepEquals(Record(payload),record)) throw new LifecycleBlocked("file_audit_history_readback_mismatch");
            return payload;
        } catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException or ArgumentException or NullReferenceException) {
            throw new LifecycleBlocked("file_audit_history_payload_invalid");
        }
    }
    internal async Task PreserveAsync(JsonObject payload, CancellationToken ct)
    {
        var schema = await ch.RowsAsync("SELECT engine,sorting_key,partition_key,create_table_query FROM system.tables WHERE database='sli_history' AND name='file_audit_observations'",ct);
        if (schema.Count != 1 || LifecycleJson.Text(schema[0],"engine") != "ReplacingMergeTree" || LifecycleJson.Text(schema[0],"sorting_key") != "evidence_key"
            || LifecycleJson.Text(schema[0],"partition_key") is not ("" or "tuple()")
            || !Durable(LifecycleJson.Text(schema[0],"create_table_query"))) throw new LifecycleBlocked("file_audit_history_durability_unverified");
        var expected = Record(payload);
        var p = new Dictionary<string,string> { ["key"] = expected["evidence_key"]!.ToString() };
        string sql = "SELECT * FROM " + Table + " FINAL WHERE evidence_key={key:String} LIMIT 2";
        var found = await ch.RowsAsync(sql,ct,p);
        if (found.Count == 0) {
            await ch.InsertAsync(Table,[expected],ct);
            found = await ch.RowsAsync(sql,ct,p);
        }
        if (found.Count != 1 || !JsonNode.DeepEquals(Decode(found[0]),payload)) throw new LifecycleBlocked("file_audit_history_readback_mismatch");
    }
    internal static bool Durable(string ddl) => !Regex.IsMatch(ddl,@"\bTTL\b",RegexOptions.IgnoreCase)
        && new[] { "fsync_after_insert","fsync_part_directory" }.All(k => Regex.IsMatch(ddl,@"\b"+k+@"\s*=\s*1\b"));

    internal async Task<List<JsonObject>> ReadAsync(JsonObject root, string[] keys, CancellationToken ct)
    {
        var p = new Dictionary<string,string> { ["agent"] = root["agent_id"]!.ToString(), ["source"] = root["source_instance_id"]!.ToString(),
            ["keys"] = LifecycleClickHouse.StringArray(keys) };
        var rows = await ch.RowsAsync("SELECT * FROM " + Table + " FINAL WHERE agent_id={agent:String} AND source_instance_id={source:String} AND evidence_key IN {keys:Array(String)}",ct,p);
        var payloads = rows.Select(Decode).ToList();
        foreach (var payload in payloads) {
            var row = payload["observation"]!;
            if (row["agent_id"]!.ToString() != p["agent"] || row["source_instance_id"]!.ToString() != p["source"] || !keys.Contains(row["evidence_key"]!.ToString()) || !InScope(root,row.AsObject()))
                throw new LifecycleBlocked("file_audit_history_scope_mismatch");
        }
        if (payloads.Count != keys.Length || payloads.Select(p => p["observation"]!["evidence_key"]!.ToString()).Distinct().Count() != keys.Length)
            throw new LifecycleBlocked("file_audit_history_readback_incomplete");
        return payloads;
    }
    internal static bool InScope(JsonObject root, JsonObject observation) => root["collection_scope_id"]!.ToString() == observation["collection_scope_id"]!.ToString()
        || observation["normalized"]?["scopes"] is JsonArray scopes && scopes.Any(s => s?["collection_scope_id"]?.ToString() == root["collection_scope_id"]!.ToString());

}
