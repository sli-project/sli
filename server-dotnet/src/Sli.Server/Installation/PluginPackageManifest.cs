using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Server.Operations;

namespace Sli.Server.InstallationSetup;

// Reviewed v2 package metadata, retained alongside the v3 installation contracts.
// Handler resources are hashed as data and are never loaded or executed as code.
internal static class PluginPackageManifest
{
    const string ManifestPath = "plugin_packages/sli.remote-access.json";
    static readonly HashSet<string> Forbidden = new(StringComparer.OrdinalIgnoreCase)
        { "argv", "command", "dsn", "entrypoint", "html", "import_path", "javascript", "password", "secret", "sql" };
    static readonly (string Id, string Resource)[] Handlers = [
        ("stage9-radius-manual-worker", "stage9_radius_manual_worker.py"),
        ("stage9-radius-session-consumer-manual", "stage9_radius_session_consumer_manual.py")
    ];
    static string Text(JsonNode? value) => value is JsonValue scalar && scalar.TryGetValue<string>(out var text) ? text : "";
    static void Require(bool valid, string error)
    {
        if (!valid) throw new InvalidDataException(error);
    }
    static bool Set(IEnumerable<string> actual, params string[] expected) => actual.ToHashSet(StringComparer.Ordinal).SetEquals(expected);
    static bool Equal(JsonNode? actual, string expected) => JsonNode.DeepEquals(actual, JsonNode.Parse(expected));
    static void RejectExecutableMaterial(JsonNode? value)
    {
        if (value is JsonObject obj)
            foreach (var (key, item) in obj)
            {
                Require(!Forbidden.Contains(key), "executable_or_sensitive_manifest_key:" + key);
                RejectExecutableMaterial(item);
            }
        else if (value is JsonArray array)
            foreach (var item in array) RejectExecutableMaterial(item);
    }
    static Dictionary<string, JsonObject> ComponentMap(JsonNode? items, string kind)
    {
        if (items is not JsonArray { Count: > 0 } array) throw new InvalidDataException("components_required:" + kind);
        var result = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        foreach (var item in array)
        {
            if (item is not JsonObject component) throw new InvalidDataException("component_object_required:" + kind);
            string id = Text(component["component_id"]);
            Require(id.Length > 0 && !result.ContainsKey(id), "component_id_invalid:" + kind);
            Require(Text(component["state"]).Length > 0, "component_state_invalid:" + id);
            result.Add(id, component);
        }
        return result;
    }
    static string Hash(string resource)
    {
        using var stream = typeof(InstallationPackages).Assembly.GetManifestResourceStream("Sli.Installation." + resource.Replace('/', '.'))
            ?? throw new InvalidDataException("manifest_handler_allowlist_mismatch");
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    public static JsonObject LoadAndValidateRemoteAccess() => ValidateRemoteAccess(InstallationPackages.Contract(ManifestPath));

    public static JsonObject ValidateRemoteAccess(JsonObject manifest)
    {
        RejectExecutableMaterial(manifest);
        var expected = JsonNode.Parse("""
            {"schema_version":2,"manifest_id":"sli.remote-access.package.v1",
             "status":"accepted_supervised_production_metadata","architecture_decision_id":"sli.plugin-architecture.v2",
             "plugin_id":"sli.remote-access","plugin_version":"0.1.0","delivery":"bundled_reviewed",
             "trust":"bundled_reviewed_only","lifecycle_actions_enabled":false,"runtime_enabled":true,
             "autostart_enabled":true,"source_contact_allowed":true,"production_read_path_cutover":false}
            """)!.AsObject();
        foreach (var (key, value) in expected)
            Require(JsonNode.DeepEquals(manifest[key], value), "manifest_" + key + "_invalid");
        Require(Equal(manifest["core_api"], """{"minimum":"1.0.0","maximum_exclusive":"2.0.0"}"""), "manifest_core_api_invalid");

        if (manifest["components"] is not JsonObject components || !Set(components.Select(p => p.Key),
                "source_packs", "adapters", "workers", "datasets", "reports", "resource_profiles"))
            throw new InvalidDataException("manifest_component_groups_invalid");
        var packs = ComponentMap(components["source_packs"], "source_packs");
        var adapters = ComponentMap(components["adapters"], "adapters");
        var workers = ComponentMap(components["workers"], "workers");
        var datasets = ComponentMap(components["datasets"], "datasets");
        var reports = ComponentMap(components["reports"], "reports");
        Require(Set(packs.Keys, "sli.windows.vpn-radius"), "manifest_source_pack_set_invalid");
        Require(Set(adapters.Keys, "radius-accounting-database-compatible-v1"), "manifest_adapter_set_invalid");
        Require(Set(workers.Keys, "radius-acquisition", "radius-session-observation"), "manifest_worker_set_invalid");
        Require(Set(datasets.Keys, "vpn.sessions") && Set(reports.Keys, "vpn.audit", "vpn.connections"), "manifest_product_component_set_invalid");
        Require(Set(workers.Values.Select(w => Text(w["handler_id"])), Handlers.Select(h => h.Id).ToArray()), "manifest_handler_allowlist_mismatch");
        Require(Equal(components["resource_profiles"], """["stage9-radius-manual-bounded-v1"]"""), "manifest_resource_profile_invalid");

        if (manifest["production_runtime"] is not JsonObject runtime) throw new InvalidDataException("manifest_production_runtime_invalid");
        Require(Text(runtime["host_script"]) == "scripts/runtime/remote_access_plugin_host.py", "manifest_production_runtime_mismatch");
        if (runtime["components"] is not JsonObject runtimeComponents || !Set(runtimeComponents.Select(p => p.Key), workers.Keys.ToArray()))
            throw new InvalidDataException("manifest_production_runtime_mismatch");
        foreach (var (id, name) in runtimeComponents)
        {
            // Operations declares the active supervised components; retired workers are absent.
            var registered = OperationsService.Components.FirstOrDefault(c => c.Name == Text(name));
            Require(registered is not null && registered.Plugin == id, "manifest_production_runtime_mismatch");
        }

        var architecture = InstallationPackages.Contract("plugin_architecture_v2.json");
        Require(JsonNode.DeepEquals(architecture["decision_id"], manifest["architecture_decision_id"]), "manifest_architecture_mismatch");
        Require(manifest["required_worker_boundaries"] is JsonArray boundaries && Set(boundaries.Select(Text),
            "windows_identity", "job_object", "working_directory_acl", "network_policy", "component_secret_handle",
            "allowlisted_handler", "postgres_role", "db_timeouts", "runtime_identity"), "manifest_worker_boundaries_invalid");
        var management = InstallationPackages.Contract("stage10_plugin_management_v1.json");
        var remote = management["plugins"]!.AsArray().OfType<JsonObject>().FirstOrDefault(p => Text(p["plugin_id"]) == Text(manifest["plugin_id"]));
        Require(remote is not null && Equal(remote["source_pack_ids"], """["sli.windows.vpn-radius"]"""), "manifest_management_mismatch");
        var pack = InstallationPackages.Contract("source_packs/radius.json");
        var registration = InstallationPackages.Contract("stage9_radius_registration_v1.json");
        var profiles = InstallationPackages.Contract("stage10_plugin_resource_profiles_v1.json");
        var isolation = InstallationPackages.Contract("stage10_plugin_postgresql_isolation_v1.json");
        Require(Text(pack["pack_id"]) == "sli.windows.vpn-radius"
            && JsonNode.DeepEquals(pack["version"], packs["sli.windows.vpn-radius"]["component_version"])
            && adapters.ContainsKey(Text(registration["source"]?["adapter_binding"]))
            && workers.ContainsKey(Text(registration["subscription"]?["consumer_component_id"]))
            && JsonNode.DeepEquals(isolation["plugin_id"], manifest["plugin_id"]), "manifest_registered_components_mismatch");
        var profileIds = profiles["profiles"]!.AsArray().OfType<JsonObject>().Select(p => Text(p["profile_id"])).ToHashSet(StringComparer.Ordinal);
        Require(components["resource_profiles"]!.AsArray().All(p => profileIds.Contains(Text(p))), "manifest_profile_not_registered");
        Require(Equal(manifest["migrations"], """{"compatibility_existing":[58,59,60,61,62,63,64,65],"core_prerequisites":[66],"plugin_owned_prepared":[67]}"""), "manifest_migrations_invalid");
        Require(manifest["explicitly_not_proven"] is JsonArray, "manifest_limitations_required");

        var hashes = new JsonObject();
        foreach (var (id, resource) in Handlers) hashes[id] = Hash(resource);
        return new JsonObject {
            ["manifest_id"] = manifest["manifest_id"]!.DeepClone(), ["plugin_id"] = manifest["plugin_id"]!.DeepClone(),
            ["plugin_version"] = manifest["plugin_version"]!.DeepClone(),
            ["component_count"] = packs.Count + adapters.Count + workers.Count + datasets.Count + reports.Count,
            ["handler_hashes"] = hashes, ["manifest_sha256"] = Hash(ManifestPath)
        };
    }
}
