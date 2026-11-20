using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Sources;

public sealed class PluginContractException(string code) : Exception(code);

// Frozen sources/plugin_contract_v1.py: pure P0B contract validation only.
// This model has no database, source-contact, process or runtime activation entry point.
public static class PluginContractV1
{
    static readonly string[] StateAxes = ["package_lifecycle", "desired_activation", "observed_health", "component_runtime", "migration_state", "source_state", "queue_state", "dataset_state"];
    // db_timeouts is a historical declaration in v1, never an applied runtime timeout.
    static readonly string[] Boundaries = ["windows_identity", "job_object", "working_directory_acl", "network_policy", "component_secret_handle", "allowlisted_handler", "postgres_role", "db_timeouts", "runtime_identity"];
    static readonly string[] RequiredLabels = ["resource_groups", "row_sensitivity", "field_visibility_categories", "evidence_access_requirement", "producer_contract_version", "label_policy_version", "provenance"];
    static readonly string[] Prohibitions = ["postgresql_migration", "clickhouse_migration", "worker_activation", "windows_service_change", "windows_firewall_change", "source_contact", "nps_radius_inventory", "product_runtime_ownership_transfer", "autostart", "webhook_write_lifecycle", "destructive_purge"];

    internal static string Text(JsonNode? value) => value?.ToString() ?? "";
    internal static long Number(JsonNode? value) => long.Parse(Truthy(value) ? Text(value) : "0", CultureInfo.InvariantCulture);
    internal static bool Truthy(JsonNode? value) => value switch
    {
        null => false, JsonArray a => a.Count > 0, JsonObject o => o.Count > 0,
        JsonValue v when v.TryGetValue<bool>(out var b) => b,
        JsonValue v when v.TryGetValue<string>(out var s) => s.Length > 0,
        _ => Text(value) is not ("0" or "0.0")
    };
    static JsonObject Object(JsonNode? value) => value as JsonObject ?? new();
    static JsonArray Array(JsonNode? value) => value as JsonArray ?? new();
    static string[] Strings(JsonNode? value) => Array(value).Select(Text).ToArray();
    static JsonArray JsonStrings(IEnumerable<string> values) => new(values.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
    static void RequireEqual(JsonObject source, string key, JsonNode expected)
    {
        if (!JsonNode.DeepEquals(source[key], expected))
            throw new PluginContractException($"{key}_must_equal_{(expected.ToString() == "false" ? "False" : expected.ToString() == "true" ? "True" : expected.ToString())}");
    }
    static void RequireSet(JsonObject source, string key, string[] expected, string? error = null)
    {
        if (source[key] is not JsonArray || !Strings(source[key]).ToHashSet(StringComparer.Ordinal).SetEquals(expected))
            throw new PluginContractException(error ?? key + "_contract_mismatch");
    }
    public static string CanonicalHash(JsonNode value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson.Serialize(value, ensureAscii: false))));

    public static JsonObject ValidateDecisionRecord(JsonObject record)
    {
        RequireEqual(record, "schema_version", JsonValue.Create(1)!);
        RequireEqual(record, "decision_id", JsonValue.Create("sli.plugin-architecture.v1")!);
        RequireEqual(record, "status", JsonValue.Create("accepted_for_p0a_p0b_fixture_only")!);
        RequireEqual(record, "package_model", JsonValue.Create("bundled_reviewed")!);
        var acquisition = Object(record["acquisition"]);
        if (!new HashSet<string>(Strings(acquisition["source_identity_excludes"]), StringComparer.Ordinal)
            .IsSupersetOf(["plugin_id", "component_version", "subscription_selector", "display_name", "credential_generation", "adapter_version"]))
            throw new PluginContractException("consumer_or_mutable_source_identity_allowed");
        RequireSet(acquisition, "cursor_owner_fields", ["source_instance_id", "stream_id", "transport_binding"]);
        RequireEqual(acquisition, "existing_windows_stream_policy", JsonValue.Create("full_channel_then_core_evidence_then_subscription_routing")!);
        var routing = Object(record["routing"]);
        RequireEqual(routing, "kind", JsonValue.Create("compiled_subscription_registry")!);
        RequireEqual(routing, "fan_out", JsonValue.Create(true)!);
        if (!Strings(routing["selector_fields"]).Contains("event_key")) throw new PluginContractException("event_key_selector_required");
        var axes = Strings(record["state_axes"]);
        if (axes.Length != axes.Distinct(StringComparer.Ordinal).Count() || !axes.ToHashSet(StringComparer.Ordinal).SetEquals(StateAxes))
            throw new PluginContractException("orthogonal_state_axes_required");
        var execution = Object(record["execution"]);
        RequireEqual(execution, "sandbox_claimed", JsonValue.Create(false)!);
        RequireSet(execution, "required_boundaries", Boundaries, "worker_boundary_contract_mismatch");
        var contracts = Object(record["contracts"]);
        RequireEqual(contracts, "owner", JsonValue.Create("core_contract_registry")!);
        RequireEqual(contracts, "authority", JsonValue.Create("one_authoritative_producer_per_contract_and_partition")!);
        RequireEqual(contracts, "required_feedback_cycles", JsonValue.Create(false)!);
        var storage = Object(record["storage"]);
        RequireEqual(storage, "raw_owner", JsonValue.Create("core")!);
        RequireEqual(storage, "canonical_evidence_owner", JsonValue.Create("core")!);
        RequireEqual(storage, "authentication_session_warm", JsonValue.Create("core_hosted_compatibility")!);
        RequireSet(Object(record["access"]), "required_labels", RequiredLabels, "information_flow_labels_incomplete");
        var prohibited = Strings(record["prohibited_until_separate_owner_decision"]).ToHashSet(StringComparer.Ordinal);
        if (!prohibited.IsSupersetOf(Prohibitions)) throw new PluginContractException("p0b_prohibition_missing");
        return new() { ["decision_id"] = record["decision_id"]!.DeepClone(), ["decision_hash"] = CanonicalHash(record),
            ["state_axes"] = JsonStrings(axes), ["prohibited_actions"] = JsonStrings(prohibited.Order(StringComparer.Ordinal)) };
    }

    static void ValidateWorker(JsonObject worker, JsonObject decision)
    {
        if (new[] { "worker_instance_id", "component_id", "component_version", "source_instance_id", "process_generation" }.Any(k => !Truthy(worker[k])))
            throw new PluginContractException("worker_runtime_identity_incomplete");
        RequireSet(worker, "boundaries", Strings(Object(decision["execution"])["required_boundaries"]), "worker_boundaries_incomplete");
    }

    public static JsonObject ValidateFixture(JsonObject fixture, JsonObject decision)
    {
        string id = Text(fixture["fixture_id"]), archetype = Text(fixture["archetype"]);
        if (id.Length == 0 || !Strings(decision["p0b_archetypes"]).Contains(archetype)) throw new PluginContractException("unknown_fixture_archetype");
        RequireEqual(fixture, "runtime_enabled", JsonValue.Create(false)!);
        var package = Object(fixture["package"]);
        RequireEqual(package, "delivery", JsonValue.Create("bundled_reviewed")!);
        if (!Text(package["handler_id"]).EndsWith("fixture-handler", StringComparison.Ordinal)) throw new PluginContractException("allowlisted_fixture_handler_required");
        if (fixture["states"] is not JsonObject states) throw new PluginContractException("fixture_states_required");
        if (!states.Select(p => p.Key).ToHashSet(StringComparer.Ordinal).SetEquals(Strings(decision["state_axes"]))) throw new PluginContractException("fixture_state_axes_mismatch");
        var storage = Object(fixture["storage"]);
        RequireEqual(storage, "raw_owner", JsonValue.Create("core")!);
        RequireEqual(storage, "canonical_evidence_owner", JsonValue.Create("core")!);
        RequireEqual(storage, "derived_backend", JsonValue.Create("postgresql")!);
        var reader = Object(fixture["detach_reader"]);
        if (Text(reader["kind"]) is not ("core_immutable_snapshot" or "reviewed_read_only_compatibility_reader")) throw new PluginContractException("detach_reader_required");
        foreach (string key in new[] { "source_contact", "jobs_enabled", "write_rights" }) RequireEqual(reader, key, JsonValue.Create(false)!);
        List<string> checks = ["runtime_disabled", "bundled_reviewed", "orthogonal_states"];
        if (archetype == "shared_bounded_pull")
        {
            var source = Object(fixture["source_instance"]);
            if (source.ContainsKey("plugin_id") || !Truthy(source["endpoint_identity"])) throw new PluginContractException("source_identity_must_be_consumer_neutral");
            var streams = Array(fixture["streams"]); var subscriptions = Array(fixture["subscriptions"]);
            if (streams.Count != 1 || subscriptions.Count < 2) throw new PluginContractException("shared_stream_requires_two_consumers");
            var stream = streams[0]!.AsObject();
            RequireEqual(stream, "collection_policy", JsonValue.Create("full_channel")!);
            if (subscriptions.Any(s => !JsonNode.DeepEquals(s!["stream_id"], stream["stream_id"]))) throw new PluginContractException("subscription_stream_mismatch");
            if (subscriptions.Select(s => Text(s!["delivery_position"])).Distinct(StringComparer.Ordinal).Count() != 1) throw new PluginContractException("fixture_delivery_positions_must_start_equal");
            if (subscriptions.Select(s => Text(s!["subscription_id"])).Distinct(StringComparer.Ordinal).Count() != subscriptions.Count) throw new PluginContractException("subscription_identity_collision");
            ValidateWorker(Object(fixture["worker"]), decision);
            checks.AddRange(["consumer_neutral_source", "full_channel", "independent_subscriptions"]);
        }
        else if (archetype == "snapshot_generation")
        {
            if (SnapshotStatus(Object(fixture["snapshot"])) != "complete") throw new PluginContractException("snapshot_fixture_not_complete");
            checks.AddRange(["snapshot_complete", "atomic_publish"]);
        }
        else
        {
            var transport = Object(fixture["transport"]);
            RequireEqual(transport, "source_contact", JsonValue.Create(false)!);
            foreach (string key in new[] { "offset_semantics", "gap_semantics", "replay_semantics" })
                if (!Truthy(transport[key])) throw new PluginContractException(key + "_required");
            ValidateWorker(Object(fixture["worker"]), decision);
            checks.AddRange(["continuous_declared_not_started", "gap_semantics"]);
        }
        return new() { ["fixture_id"] = id, ["archetype"] = archetype, ["fixture_hash"] = CanonicalHash(fixture), ["checks"] = JsonStrings(checks) };
    }

    public static string[] RouteEvent(JsonObject fixture, JsonObject record) => Array(fixture["subscriptions"])
        .Where(s => Text(s!["stream_id"]) == Text(record["stream_id"])
            && UnicodeCaseFold.Fold(Text(s["provider"])) == UnicodeCaseFold.Fold(Text(record["provider"]))
            && Strings(s["event_keys"]).Contains(Text(record["event_key"]))
            && Number(s["schema_version"]) == Number(record["schema_version"]))
        .Select(s => Text(s!["subscription_id"])).Order(StringComparer.Ordinal).ToArray();

    public static string SnapshotStatus(JsonObject snapshot)
    {
        var expected = Array(snapshot["expected_pages"]).Select(p => CanonicalJson.Serialize(p)).ToArray();
        var received = Array(snapshot["received_pages"]).Select(p => CanonicalJson.Serialize(p)).ToArray();
        if (expected.Distinct().Count() != expected.Length || received.Distinct().Count() != received.Length) return "invalid";
        if (!Truthy(snapshot["manifest_verified"]) || !Truthy(snapshot["atomic_publish"])) return "partial";
        return expected.Length > 0 && expected.ToHashSet().SetEquals(received) ? "complete" : "partial";
    }

    public static JsonObject ValidateAuthorityRegistrations(IEnumerable<JsonObject> registrations)
    {
        var authoritative = new Dictionary<(string, string, string, string), List<(long Start, long End)>>();
        int shadows = 0;
        foreach (var item in registrations)
        {
            var fields = new[] { "contract_id", "organization", "authority_kind", "authority_partition_id" }.Select(k => Text(item[k])).ToArray();
            if (fields.Any(string.IsNullOrEmpty)) throw new PluginContractException("authority_partition_identity_incomplete");
            if (Text(item["mode"]) == "shadow") { shadows++; continue; }
            if (Text(item["mode"]) != "authoritative") throw new PluginContractException("producer_mode_invalid");
            long start = Number(item["valid_from"]), end = Number(item["valid_to"]);
            if (end <= start) throw new PluginContractException("authority_interval_invalid");
            var key = (fields[0], fields[1], fields[2], fields[3]);
            if (!authoritative.TryGetValue(key, out var intervals)) authoritative[key] = intervals = [];
            if (intervals.Any(old => start < old.End && old.Start < end)) throw new PluginContractException("authority_partition_overlap");
            intervals.Add((start, end));
        }
        return new() { ["authority_partition_count"] = authoritative.Count, ["authoritative_interval_count"] = authoritative.Values.Sum(v => v.Count), ["shadow_count"] = shadows };
    }

    public static JsonObject InheritAccessLabel(IEnumerable<JsonObject> inputs, JsonObject fieldVisibilityCategories, string producerContractVersion)
    {
        var items = inputs.ToArray();
        if (items.Length == 0) throw new PluginContractException("mandatory_input_labels_required");
        var groups = new JsonArray(); bool evidenceRequired = false; int maximum = 0;
        var provenance = new HashSet<string>(StringComparer.Ordinal);
        string[] sensitivities = ["internal", "restricted", "confidential"];
        foreach (var item in items)
        {
            if (item["resource_groups"] is not JsonArray { Count: > 0 } resourceGroups) throw new PluginContractException("resource_groups_required");
            foreach (var group in resourceGroups) groups.Add(group?.DeepClone());
            int sensitivity = System.Array.IndexOf(sensitivities, Text(item["row_sensitivity"]));
            if (sensitivity < 0) throw new PluginContractException("row_sensitivity_invalid");
            maximum = Math.Max(maximum, sensitivity);
            evidenceRequired |= Truthy(item["evidence_access_requirement"]);
            provenance.UnionWith(Strings(item["provenance"]));
        }
        return new() { ["resource_groups"] = groups, ["row_sensitivity"] = sensitivities[maximum], ["field_visibility_categories"] = fieldVisibilityCategories.DeepClone(),
            ["evidence_access_requirement"] = evidenceRequired, ["producer_contract_version"] = producerContractVersion, ["label_policy_version"] = 1,
            ["provenance"] = JsonStrings(provenance.Order(StringComparer.Ordinal)) };
    }

    public static string SemanticProjectionHash(JsonObject value) => CanonicalHash(new JsonObject(value
        .Where(p => p.Key is not ("producer_id" or "producer_version" or "observed_at"))
        .Select(p => new KeyValuePair<string, JsonNode?>(p.Key, p.Value?.DeepClone()))));
}
