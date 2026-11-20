using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Agents.Radius;

public sealed class PluginWorkerBoundaryException(string code) : ArgumentException(code);

// Source: server/sli/sources/plugin_worker_boundaries.py. Validation is source-only:
// it never provisions principals, starts workers, or contacts a source or database.
public static class PluginWorkerBoundaries
{
    private static JsonElement Get(JsonElement obj, string key) =>
        obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(key, out var value) ? value : default;
    private static string Text(JsonElement value) => value.ValueKind == JsonValueKind.String ? value.GetString()! : "";
    private static bool Is(JsonElement obj, string key, string expected) =>
        Get(obj, key).ValueKind == JsonValueKind.String && Text(Get(obj, key)) == expected;
    private static bool Bool(JsonElement obj, string key, bool expected) =>
        Get(obj, key).ValueKind == (expected ? JsonValueKind.True : JsonValueKind.False);
    private static bool Null(JsonElement obj, string key) => Get(obj, key).ValueKind is JsonValueKind.Null or JsonValueKind.Undefined;
    private static void Require(bool condition, string code)
    {
        if (!condition) throw new PluginWorkerBoundaryException(code);
    }

    public static JsonObject Validate(JsonElement value)
    {
        var version = Get(value, "schema_version");
        Require(version.ValueKind == JsonValueKind.True ||
            (version.ValueKind == JsonValueKind.Number && version.TryGetDouble(out double n) && n == 1), "schema_version_invalid");
        foreach (var (key, expected) in new[] {
            ("contract_id", "sli.plugin-worker-boundaries.v1"),
            ("status", "prepared_source_contract_with_external_blockers"),
            ("architecture_decision_id", "sli.plugin-architecture.v2"),
            ("plugin_id", "sli.remote-access") })
            Require(Is(value, key, expected), key + "_invalid");
        foreach (string key in new[] { "runtime_enabled", "autostart_enabled", "source_contact_allowed", "production_configuration_changed" })
            Require(Bool(value, key, false), key + "_must_be_false");

        var isolation = Get(value, "isolation_model");
        Require(isolation.ValueKind == JsonValueKind.Object && isolation.EnumerateObject().Any() &&
            isolation.EnumerateObject().All(p => p.Value.ValueKind == JsonValueKind.True), "isolation_model_incomplete");
        var cells = Get(value, "execution_cells");
        Require(cells.ValueKind == JsonValueKind.Array && cells.GetArrayLength() == 2, "exact_execution_cells_required");
        var indexed = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var cell in cells.EnumerateArray())
        {
            Require(cell.ValueKind == JsonValueKind.Object, "execution_cell_object_required");
            string id = Text(Get(cell, "cell_id"));
            Require((id is "radius-acquisition" or "radius-session-observation") && indexed.TryAdd(id, cell), "execution_cell_id_invalid");
        }

        var summaries = new JsonArray();
        foreach (string id in new[] { "radius-acquisition", "radius-session-observation" })
        {
            bool acquisition = id == "radius-acquisition";
            string handler = acquisition ? "stage9-radius-manual-worker" : "stage9-radius-session-consumer-manual";
            string role = acquisition ? "adlog_radius_accounting_worker" : "adlog_radius_session_consumer";
            string other = acquisition ? "radius-session-observation" : "radius-acquisition";
            string[] expectedNetwork = acquisition
                ? ["plugin_postgres_exact_endpoint", "radius_accounting_read_endpoint"]
                : ["plugin_postgres_exact_endpoint"];
            var cell = indexed[id];
            Require(Is(cell, "component_id", id), id + "_component_invalid");
            Require(Is(cell, "handler_id", handler), id + "_handler_invalid");
            var argv = Get(cell, "runtime_argv");
            Require(argv.ValueKind == JsonValueKind.Array && argv.GetArrayLength() == 1 && Text(argv[0]) == "--internal", id + "_runtime_argv_invalid");

            var windows = Get(cell, "windows_boundary");
            Require(windows.ValueKind == JsonValueKind.Object && Is(windows, "principal_kind", "domain_gmsa") &&
                Null(windows, "exact_principal") && Null(windows, "windows_service_name") && Null(windows, "service_sid") &&
                Is(windows, "provisioning_state", "unprovisioned") && Is(windows, "must_be_distinct_from", other), id + "_windows_boundary_invalid");
            var filesystem = Get(cell, "filesystem_boundary");
            Require(filesystem.ValueKind == JsonValueKind.Object && Null(filesystem, "dedicated_working_directory") &&
                Bool(filesystem, "working_directory_acl_proven", false) && Bool(filesystem, "project_tree_write_allowed", false) &&
                Bool(filesystem, "shared_plugin_working_directory_allowed", false), id + "_filesystem_boundary_invalid");
            var network = Get(cell, "network_boundary");
            var capabilities = Get(network, "allowed_capabilities");
            Require(capabilities.ValueKind == JsonValueKind.Array && capabilities.EnumerateArray().All(c => c.ValueKind == JsonValueKind.String) &&
                capabilities.EnumerateArray().Select(Text).ToHashSet(StringComparer.Ordinal).SetEquals(expectedNetwork) &&
                Bool(network, "default_deny", true) && Bool(network, "administrative_share_allowed", false) &&
                Bool(network, "remote_registry_allowed", false) && Bool(network, "firewall_rules_proven", false), id + "_network_boundary_invalid");
            var postgres = Get(cell, "postgres_boundary");
            Require(postgres.ValueKind == JsonValueKind.Object && Is(postgres, "membership_role", role) && Null(postgres, "login_role") &&
                Is(postgres, "credential_scope", "plugin_postgres") && Is(postgres, "credential_materialization", "SLI_PLUGIN_PG_DSN") &&
                Bool(postgres, "admin_environment_allowed", false) && Bool(postgres, "runtime_login_proven", false), id + "_postgres_boundary_invalid");
            var process = Get(cell, "process_boundary");
            Require(process.ValueKind == JsonValueKind.Object && Bool(process, "job_object_required", true) &&
                Null(process, "normal_resource_profile_id") && Bool(process, "normal_resource_profile_proven", false), id + "_process_boundary_invalid");
            summaries.Add(new JsonObject {
                ["cell_id"] = id, ["handler_id"] = handler,
                ["network_capabilities"] = new JsonArray(expectedNetwork.Select(c => (JsonNode?)JsonValue.Create(c)).ToArray()),
                ["ready"] = false
            });
        }

        var source = Get(indexed["radius-acquisition"], "source_preconditions");
        var sourceNetwork = Get(indexed["radius-acquisition"], "network_boundary");
        Require(source.ValueKind == JsonValueKind.Object && Bool(source, "dedicated_read_only_share_configured", true) &&
            Bool(source, "static_timezone_descriptor_replaces_remote_registry", true) && Bool(source, "timezone_drift_check_accepted", false) &&
            Bool(source, "timezone_owner_assumption_active", true) && Is(sourceNetwork, "source_endpoint", "192.0.2.15") &&
            Is(sourceNetwork, "source_transport", "dedicated_read_only_smb_share"), "radius_source_preconditions_invalid");
        var consumer = Get(indexed["radius-session-observation"], "network_boundary");
        Require(Null(consumer, "source_endpoint") && Is(consumer, "source_transport", "none"), "consumer_source_network_forbidden");

        var prohibited = Get(value, "prohibited_environment_names");
        string[] expectedProhibited = ["ADLOG_PG_DSN", "ADLOG_PG_ADMIN_USER", "ADLOG_PG_ADMIN_PASSWORD"];
        Require(prohibited.ValueKind == JsonValueKind.Array && prohibited.EnumerateArray().All(p => p.ValueKind == JsonValueKind.String) &&
            prohibited.EnumerateArray().Select(Text).SequenceEqual(expectedProhibited), "prohibited_environment_names_invalid");
        var blockers = Get(value, "blockers");
        Require(blockers.ValueKind == JsonValueKind.Array && blockers.GetArrayLength() == 6, "exact_blockers_required");
        var seen = new List<JsonElement>();
        foreach (var blocker in blockers.EnumerateArray())
        {
            Require(blocker.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array) &&
                !seen.Any(previous => EqualBlocker(previous, blocker)), "exact_blockers_required");
            seen.Add(blocker);
        }
        return new JsonObject {
            ["contract_id"] = "sli.plugin-worker-boundaries.v1", ["plugin_id"] = "sli.remote-access",
            ["cell_count"] = summaries.Count, ["cells"] = summaries, ["ready_for_live_runtime"] = false,
            ["blockers"] = JsonNode.Parse(blockers.GetRawText())
        };
    }

    private static bool EqualBlocker(JsonElement a, JsonElement b)
    {
        // Python considers boolean and numeric keys equal (True == 1, False == 0).
        static double? Number(JsonElement x) => x.ValueKind switch {
            JsonValueKind.True => 1, JsonValueKind.False => 0,
            JsonValueKind.Number when x.TryGetDouble(out double n) => n, _ => null
        };
        return Number(a) is double n && Number(b) is double m ? n == m : JsonElement.DeepEquals(a, b);
    }
}
