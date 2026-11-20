using System.Text.Json.Nodes;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

// Projections of the maintenance summaries: retain decisions and measured
// values while leaving detailed tables and full cleanup plans out of bundles.
internal static class OperationsStorageCompact
{
    internal static JsonObject Health(JsonObject result)
    {
        var pressure = result["disk_pressure"];
        var disk = pressure?["disk"];
        var postgres = result["postgres_operations"];
        var database = postgres?["database"];
        var project = result["project_overview"];
        var scan = project?["scan"];
        var cleanup = result["cleanup_preview"];
        var last = result["last_cleanup"] as JsonObject;
        return new()
        {
            ["status"] = Copy(result["status"]), ["warnings"] = Copy(result["warnings"]) ?? new JsonArray(),
            ["disk"] = new JsonObject
            {
                ["free_bytes"] = Copy(disk?["free_bytes"]), ["free_human"] = Copy(disk?["free_human"]),
                ["free_percent"] = Copy(disk?["free_percent"]), ["collection_allowed"] = Copy(pressure?["collection_allowed"]),
                ["blocking_free_human"] = Copy(pressure?["blocking_threshold"]?["free_human"])
            },
            ["postgres"] = new JsonObject
            {
                ["status"] = Copy(postgres?["status"]), ["connectivity_status"] = Copy(postgres?["connectivity_status"]),
                ["metrics_status"] = Copy(postgres?["metrics_status"]), ["database_name"] = Copy(database?["database_name"]),
                ["database_bytes"] = Copy(database?["database_bytes"]), ["database_human"] = Copy(database?["database_human"]),
                ["checked_at"] = Copy(database?["checked_at"])
            },
            ["project"] = new JsonObject
            {
                ["files_human"] = Copy(project?["project_files_human"]), ["database_human"] = Copy(project?["database_human"]),
                ["total_human"] = Copy(project?["total_human"]), ["scan_complete"] = Copy(scan?["complete_project_tree"]),
                ["scan_errors"] = Copy(scan?["errors"]), ["scan_error_paths"] = Copy(scan?["error_paths"]) ?? new JsonArray()
            },
            ["cleanup_preview"] = new JsonObject { ["total_candidates"] = Copy(cleanup?["total_candidates"]), ["total_human"] = Copy(cleanup?["total_human"]) },
            ["last_cleanup"] = last is { Count: > 0 } ? new JsonObject
            { ["status"] = Copy(last["status"]), ["mode"] = Copy(last["mode"]), ["generated_at_utc"] = Copy(last["generated_at_utc"]) } : null,
            ["safety"] = new JsonObject { ["read_only"] = true, ["cleanup_executed"] = false, ["vacuum_executed"] = false }
        };
    }

    internal static JsonObject Cleanup(JsonObject result)
    {
        var actions = result["actions"] as JsonArray ?? [];
        var categories = new JsonObject();
        foreach (var action in actions)
        {
            string category = S(action?["category"]);
            if (category.Length == 0) category = "unknown";
            var bucket = categories[category] as JsonObject ?? new JsonObject { ["count"] = 0, ["bytes"] = 0L };
            if (categories[category] is null) categories[category] = bucket;
            bucket["count"] = (int)N(bucket["count"]) + 1;
            bucket["bytes"] = N(bucket["bytes"]) + N(action?["size_bytes"]);
        }
        foreach (var category in categories) category.Value!["human"] = Human(N(category.Value["bytes"]));
        var compact = new JsonObject();
        foreach (string key in new[] { "status", "mode", "category", "generated_at_utc", "duration_ms", "deep", "limit", "root", "min_age_hours", "total_candidates", "total_bytes", "total_human", "scan", "safety" })
            compact[key] = Copy(result[key]);
        compact["by_category"] = categories;
        compact["actions_sample"] = A(actions.Take(10));
        compact["actions_omitted"] = Math.Max(0, actions.Count - 10);
        compact["applied"] = Copy(result["applied"]) ?? new JsonArray();
        compact["errors"] = Copy(result["errors"]) ?? new JsonArray();
        return compact;
    }
}
