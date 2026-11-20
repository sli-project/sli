using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class PluginWorkerBoundaryTests
{
    private static JsonObject Contract()
    {
        using var stream = typeof(PluginWorkerBoundaryTests).Assembly.GetManifestResourceStream(
            "Sli.Server.Tests.Agents.stage10_plugin_worker_boundaries_v1.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }

    private static JsonObject Validate(JsonObject value) =>
        PluginWorkerBoundaries.Validate(JsonSerializer.SerializeToElement(value));

    [Fact]
    public void TwoDistinctCellsAreRequiredAndNotLive()
    {
        var contract = Contract();
        string before = contract.ToJsonString();
        var result = Validate(contract);
        Assert.Equal("sli.plugin-worker-boundaries.v1", result["contract_id"]!.GetValue<string>());
        Assert.Equal("sli.remote-access", result["plugin_id"]!.GetValue<string>());
        Assert.Equal(2, result["cell_count"]!.GetValue<int>());
        Assert.False(result["ready_for_live_runtime"]!.GetValue<bool>());
        var cells = result["cells"]!.AsArray();
        Assert.Equal(new[] { "radius-acquisition", "radius-session-observation" },
            cells.Select(cell => cell!["cell_id"]!.GetValue<string>()).ToArray());
        Assert.Equal(new[] { "stage9-radius-manual-worker", "stage9-radius-session-consumer-manual" },
            cells.Select(cell => cell!["handler_id"]!.GetValue<string>()).ToArray());
        Assert.All(cells, cell => Assert.False(cell!["ready"]!.GetValue<bool>()));
        Assert.Equal(new[] { "plugin_postgres_exact_endpoint", "radius_accounting_read_endpoint" },
            cells[0]!["network_capabilities"]!.AsArray().Select(c => c!.GetValue<string>()).ToArray());
        Assert.True(JsonNode.DeepEquals(contract["blockers"], result["blockers"]));
        Assert.Equal(before, contract.ToJsonString());
    }

    [Fact]
    public void ConsumerHasNoSourceNetworkCapability()
    {
        var result = Validate(Contract());
        var consumer = Assert.Single(result["cells"]!.AsArray(),
            cell => cell!["cell_id"]!.GetValue<string>() == "radius-session-observation");
        Assert.Equal(new[] { "plugin_postgres_exact_endpoint" },
            consumer!["network_capabilities"]!.AsArray().Select(c => c!.GetValue<string>()).ToArray());
    }

    // All seven fail-closed mutations from tests/sources/test_plugin_worker_boundaries.py.
    [Theory]
    [InlineData("runtime", "runtime_enabled_must_be_false")]
    [InlineData("missing-cell", "exact_execution_cells_required")]
    [InlineData("consumer-source-capability", "radius-session-observation_network_boundary_invalid")]
    [InlineData("same-principal", "radius-acquisition_windows_boundary_invalid")]
    [InlineData("admin-share", "radius-acquisition_network_boundary_invalid")]
    [InlineData("admin-environment", "radius-acquisition_postgres_boundary_invalid")]
    [InlineData("resource-profile-proven", "radius-acquisition_process_boundary_invalid")]
    public void WeakerOrAmbiguousBoundaryFailsClosed(string mutation, string code)
    {
        var value = Contract();
        var cells = value["execution_cells"]!.AsArray();
        var acquisition = cells[0]!;
        switch (mutation)
        {
            case "runtime": value["runtime_enabled"] = true; break;
            case "missing-cell": cells.RemoveAt(1); break;
            case "consumer-source-capability":
                cells[1]!["network_boundary"]!["allowed_capabilities"]!.AsArray().Add("radius_accounting_read_endpoint"); break;
            case "same-principal": acquisition["windows_boundary"]!["must_be_distinct_from"] = "radius-acquisition"; break;
            case "admin-share": acquisition["network_boundary"]!["administrative_share_allowed"] = true; break;
            case "admin-environment": acquisition["postgres_boundary"]!["admin_environment_allowed"] = true; break;
            case "resource-profile-proven": acquisition["process_boundary"]!["normal_resource_profile_proven"] = true; break;
            default: throw new ArgumentException("unknown_test_mutation");
        }
        Assert.Equal(code, Assert.Throws<PluginWorkerBoundaryException>(() => Validate(value)).Message);
    }

    // The port also preserves the remaining fail-closed guards of the source validator.
    [Theory]
    [InlineData("schema_version", "2", "schema_version_invalid")]
    [InlineData("contract_id", "null", "contract_id_invalid")]
    [InlineData("autostart_enabled", "true", "autostart_enabled_must_be_false")]
    [InlineData("source_contact_allowed", "0", "source_contact_allowed_must_be_false")]
    [InlineData("production_configuration_changed", "null", "production_configuration_changed_must_be_false")]
    [InlineData("isolation_model", "{}", "isolation_model_incomplete")]
    [InlineData("isolation_model", "{\"default_deny_outbound_network\":false}", "isolation_model_incomplete")]
    [InlineData("execution_cells.1", "null", "execution_cell_object_required")]
    [InlineData("execution_cells.1.cell_id", "\"radius-acquisition\"", "execution_cell_id_invalid")]
    [InlineData("execution_cells.0.component_id", "\"other\"", "radius-acquisition_component_invalid")]
    [InlineData("execution_cells.0.handler_id", "\"other\"", "radius-acquisition_handler_invalid")]
    [InlineData("execution_cells.0.runtime_argv", "[]", "radius-acquisition_runtime_argv_invalid")]
    [InlineData("execution_cells.0.windows_boundary", "null", "radius-acquisition_windows_boundary_invalid")]
    [InlineData("execution_cells.0.filesystem_boundary.project_tree_write_allowed", "true", "radius-acquisition_filesystem_boundary_invalid")]
    [InlineData("execution_cells.0.network_boundary", "null", "radius-acquisition_network_boundary_invalid")]
    [InlineData("execution_cells.0.postgres_boundary.membership_role", "\"adlog_radius_session_consumer\"", "radius-acquisition_postgres_boundary_invalid")]
    [InlineData("execution_cells.0.process_boundary.job_object_required", "false", "radius-acquisition_process_boundary_invalid")]
    [InlineData("execution_cells.0.source_preconditions.timezone_owner_assumption_active", "false", "radius_source_preconditions_invalid")]
    [InlineData("execution_cells.0.network_boundary.source_endpoint", "\"192.0.2.16\"", "radius_source_preconditions_invalid")]
    [InlineData("execution_cells.1.network_boundary.source_endpoint", "\"192.0.2.15\"", "consumer_source_network_forbidden")]
    [InlineData("execution_cells.1.network_boundary.source_transport", "\"dedicated_read_only_smb_share\"", "consumer_source_network_forbidden")]
    [InlineData("prohibited_environment_names", "[]", "prohibited_environment_names_invalid")]
    [InlineData("blockers", "[]", "exact_blockers_required")]
    [InlineData("blockers", "[\"a\",\"b\",\"c\",\"d\",\"e\",\"e\"]", "exact_blockers_required")]
    public void InvalidContractSectionsFailWithSourceError(string path, string replacement, string code)
    {
        var value = Contract();
        string[] parts = path.Split('.');
        JsonNode parent = value;
        foreach (string part in parts[..^1])
            parent = parent is JsonArray array ? array[int.Parse(part)]! : parent[part]!;
        if (parent is JsonArray cells) cells[int.Parse(parts[^1])] = JsonNode.Parse(replacement);
        else parent[parts[^1]] = JsonNode.Parse(replacement);
        Assert.Equal(code, Assert.Throws<PluginWorkerBoundaryException>(() => Validate(value)).Message);
    }

    [Fact]
    public void CellAndCapabilityOrderingDoNotChangeTheSummary()
    {
        var value = Contract();
        var expected = Validate(value);
        var cells = value["execution_cells"]!.AsArray();
        var acquisition = cells[0]!;
        cells.RemoveAt(0);
        cells.Add(acquisition);
        acquisition["network_boundary"]!["allowed_capabilities"] = new JsonArray(
            "radius_accounting_read_endpoint", "plugin_postgres_exact_endpoint", "radius_accounting_read_endpoint");
        Assert.True(JsonNode.DeepEquals(expected, Validate(value)));
    }
}
