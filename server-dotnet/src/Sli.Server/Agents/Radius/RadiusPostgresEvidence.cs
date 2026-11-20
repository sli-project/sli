using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace Sli.Server.Agents.Radius;

// Pure validation from stage9_radius_postgres_migrate.py. This does not execute
// migrations or collect evidence and never connects to a database or source.
internal static class RadiusPostgresEvidence
{
    private static void Require(bool valid,string code) { if(!valid) throw new InvalidOperationException(code); }
    private static bool Equal(JsonNode? node,string json)=>JsonNode.DeepEquals(node,JsonNode.Parse(json));
    private static bool Flag(JsonNode? node,bool value)=>JsonNode.DeepEquals(node,JsonValue.Create(value));
    private static string? Text(JsonNode? node)=>node is JsonValue v && v.TryGetValue<string>(out var s)?s:null;

    internal static void ValidatePreflight(JsonObject evidence,JsonObject live,byte[] forward,byte[] rollback)
    {
        Require(Text(evidence["status"])=="ready","preflight is not ready");
        Require(Equal(evidence["blockers"],"[]"),"preflight contains blockers");
        var migration=evidence["migration"] as JsonObject ?? new();
        Require(Equal(migration["version"],"58"),"preflight migration version mismatch");
        Require(Text(migration["execution_contract"])=="single_file_058_only","preflight execution contract mismatch");
        Require(Equal(migration["excluded_from_automatic_sequence"],"[56,57]"),"preflight does not exclude migrations 056/057");
        Require(Text(migration["forward_sha256"])==Convert.ToHexStringLower(SHA256.HashData(forward))
            && Text(migration["rollback_sha256"])==Convert.ToHexStringLower(SHA256.HashData(rollback)),"migration files changed after preflight");
        Require(Text(live["status"])=="ready" && Equal(live["blockers"],"[]"),"live preflight is no longer ready");
        foreach(string key in new[]{"identity","schema","privileges"})
            Require(JsonNode.DeepEquals(live[key] ?? new JsonObject(),evidence[key] ?? new JsonObject()),$"database {key} changed after preflight");
    }

    internal static JsonObject AcceptedDisposable(JsonObject value)
    {
        const string error="disposable_058_evidence_invalid";
        var evidence=value["evidence"] as JsonObject ?? new();
        var registration=evidence["registration"] as JsonObject ?? new();
        var first=evidence["evidence_first"] as JsonObject ?? new();
        Require(Text(value["status"])=="passed" && Flag(value["production_database_changed"],false)
            && Flag(value["radius_source_contacted"],false) && Flag(value["runtime_enabled"],false) && Flag(value["disposable_schema_cleaned"],true)
            && Equal(evidence["migration"],"""{"marker":true,"worker_role":true,"evidence_insert":true,"evidence_delete":false,"cursor_update":true}""")
            && Flag(registration["registered_disabled_first"],true) && Flag(registration["disposable_manual_enable_only"],true)
            && new[]{"source_instance_id","subscription_id","stream_id","transport_binding"}.All(k=>!string.IsNullOrEmpty(Sli.Server.Compatibility.PythonText.Strip(Text(registration[k]) ?? "")))
            && first["published_objects"] is JsonValue count && count.TryGetValue<int>(out var n) && n>0
            && Equal(first["database_manifest_rows_before_commit"],"0") && Flag(first["orphan_retry_is_idempotent"],true) && Flag(first["payload_in_result"],false),error);
        Require(evidence["injected_failures"] is JsonArray failures && failures.Count==3
            && failures.All(f=>f is JsonObject && Flag(f["rolled_back"],true))
            && failures.Select(f=>Text(f!["phase"])).ToHashSet().SetEquals(["evidence","outbox","cache"]),error);
        Require(Equal(evidence["commit"],"""{"evidence_rows":2,"observation_rows":1,"outbox_rows":1,"class_cache_rows":1,"cursor_revision":1,"cursor_byte_offset":200}""")
            && Flag(evidence["stale_replay_rejected"],true) && Flag(evidence["persisted_state_rollback_guarded"],true)
            && Equal(evidence["clean_rollback"],"""{"marker":false,"foundation_table":false,"worker_role":false}"""),error);
        return value;
    }
}
