using System.Text.Json.Nodes;

namespace Sli.Server.Sources;

public sealed class PluginIsolationFixtureError(string code) : ArgumentException(code);

// Frozen source: server/sli/sources/plugin_isolation_fixture.py.
// An offline transition model only; never registered as a runtime plugin service.
public sealed class PluginIsolationFixture
{
    private readonly JsonObject core;
    private readonly JsonObject plugins = new();
    private static readonly string[] Scenarios =
    [
        "independent_disable", "failure_isolation", "resource_exhaustion_isolation",
        "independent_upgrade_and_rollback", "detach_without_core_or_peer_outage",
        "read_and_report_parity_before_ownership_cutover"
    ];

    public PluginIsolationFixture(JsonObject config)
    {
        core = (JsonObject)config["core"]!.DeepClone();
        foreach (var item in (JsonArray)config["plugins"]!)
        {
            var plugin = (JsonObject)item!.DeepClone();
            plugin["rollback_versions"] = new JsonArray();
            plugins[Text(plugin["plugin_id"])!] = plugin;
        }
    }

    public static PluginIsolationFixture FromConfig() => new(Load());

    public static JsonObject Load(string? path = null)
    {
        var value = path is null ? ReadResource("Sli.Server.Sources.isolation-fixture.json")
            : JsonNode.Parse(File.ReadAllText(path));
        if (value is not JsonObject config) throw new PluginIsolationFixtureError("isolation_fixture_object_required");
        var expected = new JsonObject
        {
            ["schema_version"] = 1, ["contract_id"] = "sli.plugin-isolation-fixture.v1",
            ["status"] = "prepared_fixture_only", ["architecture_decision_id"] = "sli.plugin-architecture.v2",
            ["fixture_only"] = true, ["runtime_enabled"] = false, ["source_contact_allowed"] = false,
            ["database_access_allowed"] = false, ["process_control_allowed"] = false,
            ["autostart_enabled"] = false, ["production_read_path_cutover"] = false
        };
        foreach (var (key, item) in expected)
            Require(JsonNode.DeepEquals(config[key], item), $"isolation_fixture_{key}_invalid");
        var scenarios = new JsonArray(Scenarios.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
        var architecture = ReadResource("Sli.Installation.plugin_architecture_v2.json")!;
        Require(JsonNode.DeepEquals(architecture["decision_id"], config["architecture_decision_id"])
            && Text(architecture["status"]) == "owner_accepted_design_boundary"
            && JsonNode.DeepEquals(architecture["stage10_acceptance_requires"], scenarios),
            "isolation_fixture_architecture_mismatch");
        Require(JsonNode.DeepEquals(config["required_scenarios"], scenarios), "isolation_fixture_scenarios_invalid");
        Require(JsonNode.DeepEquals(config["core"], new JsonObject
        { ["health"] = "healthy_fixture", ["runtime"] = "running_fixture" }), "isolation_fixture_core_invalid");
        if (config["plugins"] is not JsonArray { Count: 2 } items)
            throw new PluginIsolationFixtureError("isolation_fixture_plugins_invalid");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in items)
        {
            if (item is not JsonObject plugin) throw new PluginIsolationFixtureError("isolation_fixture_plugin_object_required");
            var id = Text(plugin["plugin_id"]);
            Require(id is "sli.remote-access" or "sli.windows.ad-dc" && seen.Add(id), "isolation_fixture_plugin_id_invalid");
            Require(Text(plugin["package_version"])?.EndsWith("-fixture", StringComparison.Ordinal) == true,
                "isolation_fixture_version_invalid");
            foreach (var key in new[] { "package_lifecycle", "desired_activation", "observed_health", "component_runtime", "queue_state", "dataset_state" })
                Require(Text(plugin[key])?.EndsWith("_fixture", StringComparison.Ordinal) == true,
                    $"isolation_fixture_plugin_state_invalid:{id}:{key}");
            foreach (var key in new[] { "detach_reader_ready", "read_report_parity" })
                Require(IsTrue(plugin[key]), $"isolation_fixture_guard_missing:{id}:{key}");
            Require(plugin["immutable_evidence_refs"] is JsonArray { Count: > 0 } refs
                && refs.All(r => Text(r)?.StartsWith("fixture-evidence:", StringComparison.Ordinal) == true)
                && refs.Select(Text).Distinct(StringComparer.Ordinal).Count() == refs.Count,
                $"isolation_fixture_evidence_invalid:{id}");
        }
        Require(seen.SetEquals(["sli.remote-access", "sli.windows.ad-dc"]), "isolation_fixture_plugin_set_invalid");
        Require(config["explicitly_not_proven"] is JsonArray { Count: >= 7 }, "isolation_fixture_limitations_required");
        return config;
    }

    public JsonObject Snapshot() => new() { ["core"] = core.DeepClone(), ["plugins"] = plugins.DeepClone() };

    public void Disable(string id)
    {
        var plugin = Plugin(id);
        plugin["desired_activation"] = "disabled_fixture";
        plugin["component_runtime"] = "stopped_fixture";
        plugin["observed_health"] = "disabled_fixture";
    }

    public void InjectFailure(string id)
    {
        var plugin = Plugin(id);
        plugin["observed_health"] = "failed_fixture";
        plugin["component_runtime"] = "failed_fixture";
        plugin["dataset_state"] = "blocked_fixture";
    }

    public void InjectResourceExhaustion(string id)
    {
        var plugin = Plugin(id);
        plugin["observed_health"] = "resource_exhausted_fixture";
        plugin["component_runtime"] = "terminated_fixture";
        plugin["queue_state"] = "quarantined_fixture";
        plugin["dataset_state"] = "blocked_fixture";
    }

    public void Upgrade(string id, string? version)
    {
        var plugin = Plugin(id);
        Require(DisabledAndDrained(plugin), "upgrade_requires_disabled_drained_plugin");
        Require(version?.EndsWith("-fixture", StringComparison.Ordinal) == true, "upgrade_fixture_version_required");
        ((JsonArray)plugin["rollback_versions"]!).Add(plugin["package_version"]!.DeepClone());
        plugin["package_version"] = version;
    }

    public void Rollback(string id)
    {
        var plugin = Plugin(id);
        var versions = (JsonArray)plugin["rollback_versions"]!;
        Require(versions.Count > 0, "rollback_version_missing");
        plugin["package_version"] = versions[^1]!.DeepClone();
        versions.RemoveAt(versions.Count - 1);
    }

    public void Detach(string id)
    {
        var plugin = Plugin(id);
        Require(DisabledAndDrained(plugin) && IsTrue(plugin["detach_reader_ready"]) && IsTrue(plugin["read_report_parity"]),
            "detach_preconditions_not_met");
        plugin["package_lifecycle"] = "detached_fixture";
        plugin["dataset_state"] = "retained_read_only_fixture";
    }

    public JsonObject PlanOwnershipCutover(string id)
    {
        Require(IsTrue(Plugin(id)["read_report_parity"]), "read_report_parity_required");
        return new() { ["eligible"] = true, ["executed"] = false, ["production_read_path_cutover"] = false };
    }

    private JsonObject Plugin(string id) => plugins[id] as JsonObject
        ?? throw new PluginIsolationFixtureError("isolation_fixture_plugin_not_found");
    private static bool DisabledAndDrained(JsonObject plugin) => Text(plugin["desired_activation"]) == "disabled_fixture"
        && Text(plugin["component_runtime"]) == "stopped_fixture" && Text(plugin["queue_state"]) == "drained_fixture";
    private static string? Text(JsonNode? node) => node is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
    private static bool IsTrue(JsonNode? node) => node is JsonValue value && value.TryGetValue<bool>(out var flag) && flag;
    private static void Require(bool condition, string code)
    {
        if (!condition) throw new PluginIsolationFixtureError(code);
    }
    private static JsonNode? ReadResource(string name)
    {
        using var stream = typeof(PluginIsolationFixture).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException("isolation_fixture_resource_missing");
        return JsonNode.Parse(stream);
    }
}
