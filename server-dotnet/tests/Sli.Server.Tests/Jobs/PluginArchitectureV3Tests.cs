using System.Text.Json.Nodes;
using Sli.Server.InstallationSetup;
using Sli.Server.Jobs;
using Xunit;

namespace Sli.Server.Tests.Jobs;

// Parity with tests/sources/test_plugin_architecture_v3.py, using the schemas
// embedded in the server for job registration and plugin settings validation.
public sealed class PluginArchitectureV3Tests
{
    [Fact]
    public void V3_is_a_proposed_manifest_schema_without_runtime_configuration()
    {
        var schema = CoreJobRegistry.Schema;
        Assert.Equal(3, schema["schema_version"]!.GetValue<int>());
        Assert.Equal("sli.plugin-architecture.v3", schema["decision_id"]!.GetValue<string>());
        Assert.Equal("sli.plugin-architecture.v2", schema["supersedes"]!.GetValue<string>());
        Assert.Equal("proposed", schema["status"]!.GetValue<string>());
        Assert.Equal("https://json-schema.org/draft/2020-12/schema", schema["$schema"]!.GetValue<string>());
        Assert.Equal("object", schema["type"]!.GetValue<string>());
        Assert.False(schema["additionalProperties"]!.GetValue<bool>());
        RequiredIncludes(schema, "plugin_id", "plugin_version", "core_api", "handlers", "data", "navigation");

        var properties = schema["properties"]!.AsObject();
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"const":false}"""), properties["own_permanent_workers"]));
        Assert.Equal("bundled_reviewed_only", properties["trust"]!["const"]!.GetValue<string>());
        foreach (string field in new[] { "workers", "production_runtime", "runtime_enabled", "autostart_enabled" })
            Assert.False(schema.ContainsKey(field), field);
        foreach (string field in new[] { "workers", "production_runtime", "command", "dsn" })
            Assert.False(properties.ContainsKey(field), field);
    }

    [Theory]
    [InlineData("plugin_architecture_v3.json")]
    [InlineData("plugin_settings_schema_v1.json")]
    public void Schemas_have_resolvable_local_references_and_required_properties(string filename)
    {
        var schema = InstallationPackages.Contract(filename);
        foreach (var node in Nodes(schema))
        {
            if (node["$ref"] is JsonNode reference)
            {
                string target = reference.GetValue<string>();
                Assert.StartsWith("#/$defs/", target);
                Assert.True(schema["$defs"]!.AsObject().ContainsKey(target["#/$defs/".Length..]), target);
            }

            // A properties map can itself contain a property named "required".
            if (node["type"] is not JsonValue type || !type.TryGetValue<string>(out var name) || name != "object")
                continue;
            if (node.ContainsKey("required"))
            {
                var required = Assert.IsType<JsonArray>(node["required"]);
                var fields = required.Select(x => x!.GetValue<string>()).ToArray();
                Assert.Equal(fields.Length, fields.Distinct(StringComparer.Ordinal).Count());
                var properties = node["properties"]!.AsObject();
                Assert.All(fields, field => Assert.True(properties.ContainsKey(field), field));
            }

            Assert.True(node.ContainsKey("additionalProperties"));
            var additional = node["additionalProperties"];
            Assert.True(node.ContainsKey("properties") || additional is JsonObject);
            Assert.True(additional is JsonObject ||
                additional is JsonValue value && value.TryGetValue<bool>(out bool allowed) && !allowed);
        }
    }

    [Fact]
    public void V3_defines_jobs_results_scope_and_agent_receipts()
    {
        var definitions = CoreJobRegistry.Schema["$defs"]!.AsObject();
        foreach (string name in new[] { "job", "result", "budget", "access_scope", "entity_observation", "agent_envelope", "receipt" })
            Assert.True(definitions.ContainsKey(name), name);
        RequiredIncludes(definitions["job"]!.AsObject(),
            "idempotency_key", "input_sha256", "handler_version", "manifest_sha256", "budget", "partition_key");
        RequiredIncludes(definitions["result"]!.AsObject(),
            "job_id", "lease_token", "lease_generation", "result_sha256", "continuation");
        // These are declarations in the shared proposed schema, not runtime limits.
        RequiredIncludes(definitions["budget"]!.AsObject(),
            "wall_seconds", "cpu_seconds", "memory_bytes", "max_records", "max_result_bytes", "max_db_connections");
        Assert.Equal(new[] { "none", "restricted", "all" },
            definitions["access_scope"]!["properties"]!["mode"]!["enum"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"$ref":"#/$defs/id"}"""),
            definitions["scope_clause"]!["properties"]!["plugin_ids"]!["items"]));
        RequiredIncludes(definitions["agent_envelope"]!.AsObject(),
            "agent_id", "source_instance_id", "generation", "cursor_before", "cursor_after", "policy_revision", "payload_sha256");
        RequiredIncludes(definitions["receipt"]!.AsObject(),
            "packet_id", "payload_sha256", "committed_cursor", "status");
    }

    private static void RequiredIncludes(JsonObject schema, params string[] fields)
    {
        var required = schema["required"]!.AsArray().Select(x => x!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        Assert.All(fields, field => Assert.Contains(field, required));
    }

    private static IEnumerable<JsonObject> Nodes(JsonNode? value)
    {
        if (value is JsonObject obj)
        {
            yield return obj;
            foreach (var child in obj)
                foreach (var node in Nodes(child.Value))
                    yield return node;
        }
        else if (value is JsonArray array)
        {
            foreach (var child in array)
                foreach (var node in Nodes(child))
                    yield return node;
        }
    }
}
