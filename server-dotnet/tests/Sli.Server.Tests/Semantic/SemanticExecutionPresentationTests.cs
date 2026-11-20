using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Parity vectors from tests/semantic/test_semantic_execution_presentation.py.
[Collection("Semantic producer environment")]
public sealed class SemanticExecutionPresentationTests : IDisposable
{
    private readonly Dictionary<string, string?> previous;

    public SemanticExecutionPresentationTests()
    {
        var values = new Dictionary<string, string?>
        {
            ["ADLOG_SEMANTIC_PRODUCTION_ENABLED"] = "1",
            ["ADLOG_SEMANTIC_RUNTIME_MODE"] = SemanticRuntimeSettings.FactsMode,
            ["ADLOG_SEMANTIC_NORMALIZATION_ENABLED"] = "1",
            ["ADLOG_SEMANTIC_ASSEMBLY_ENABLED"] = "1",
            ["ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED"] = null,
            ["ADLOG_SEMANTIC_CORRELATION_ENABLED"] = null,
            ["ADLOG_SEMANTIC_RISK_ENGINE_ENABLED"] = null,
            ["ADLOG_SEMANTIC_FINDING_CREATION_ENABLED"] = null
        };
        previous = values.ToDictionary(p => p.Key, p => Environment.GetEnvironmentVariable(p.Key));
        foreach (var pair in values) Environment.SetEnvironmentVariable(pair.Key, pair.Value);
    }

    public void Dispose()
    {
        foreach (var pair in previous) Environment.SetEnvironmentVariable(pair.Key, pair.Value);
    }

    private static async Task<JsonObject> Read(string mode = SemanticRuntimeSettings.FactsMode,
        bool stale = false, bool admitted = true, string? reportedMode = SemanticRuntimeSettings.FactsMode,
        bool findings = false, bool registered = true)
    {
        Environment.SetEnvironmentVariable("ADLOG_SEMANTIC_PRODUCTION_ENABLED", admitted ? "1" : null);
        Environment.SetEnvironmentVariable("ADLOG_SEMANTIC_RUNTIME_MODE", mode);
        foreach (string stage in new[] { "CORRELATION", "RISK_ENGINE", "FINDING_CREATION" })
            Environment.SetEnvironmentVariable("ADLOG_SEMANTIC_" + stage + "_ENABLED", findings ? "1" : null);
        var heartbeat = new JsonObject
        {
            ["status"] = "idle",
            ["heartbeat_at"] = SemanticJson.Stamp(stale ? DateTimeOffset.UtcNow.AddDays(-1) : DateTimeOffset.UtcNow),
            ["expected_interval_seconds"] = 70,
            ["details_json"] = new JsonObject
            {
                ["runtime_mode"] = reportedMode,
                ["finding_creation"] = mode == SemanticRuntimeSettings.FindingsMode
            }
        };
        return await SemanticWorkspace.ExecutionAsync(
            new SemanticEndpointTests.Database { Heartbeat = registered ? heartbeat : null },
            TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Active_facts_worker_does_not_require_risk()
    {
        var result = await Read();
        Assert.Equal("active", result.Text("state"));
        Assert.Equal("facts-v1", result.Text("runtime_mode"));
        Assert.False(result.Flag("finding_path_live"));
        Assert.False(result["feature_chain"].Flag("risk_engine"));
        Assert.False(result["feature_chain"].Flag("finding_creation"));
    }

    [Fact]
    public async Task Stale_facts_worker_is_not_live()
    {
        var result = await Read(stale: true);
        Assert.Equal("stale", result["worker"].Text("state"));
        Assert.Equal("enabled_without_worker", result.Text("state"));
        Assert.False(result.Flag("finding_path_live"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("findings-v1")]
    [InlineData("unknown-v1")]
    public async Task Facts_requires_matching_observed_worker_mode(string? reportedMode)
    {
        var result = await Read(reportedMode: reportedMode);
        Assert.Equal("active", result["worker"].Text("state"));
        Assert.Equal(reportedMode, result["worker"].Text("runtime_mode"));
        Assert.Equal("enabled_without_worker", result.Text("state"));
        Assert.False(result.Flag("finding_path_live"));
    }

    [Fact]
    public async Task Unadmitted_flags_cannot_claim_active_execution()
    {
        var result = await Read(admitted: false);
        Assert.Equal("active", result["worker"].Text("state"));
        Assert.Equal("disabled", result.Text("state"));
        Assert.Null(result["runtime_mode"]);
        Assert.False(result.Flag("finding_path_live"));
    }

    [Fact]
    public async Task Unknown_mode_cannot_claim_active_execution()
    {
        var result = await Read(mode: "invented-v1", reportedMode: "invented-v1");
        Assert.Equal("active", result["worker"].Text("state"));
        Assert.Equal("partially_enabled", result.Text("state"));
        Assert.Null(result["runtime_mode"]);
        Assert.False(result.Flag("finding_path_live"));
    }

    [Fact]
    public async Task Finding_flag_alone_does_not_claim_live_publication()
    {
        var result = await Read(stale: true, findings: true);
        Assert.True(result["feature_chain"].Flag("finding_creation"));
        Assert.Equal("partially_enabled", result.Text("state"));
        Assert.False(result.Flag("finding_path_live"));
    }

    [Theory]
    [InlineData(false, true, "active", true)]
    [InlineData(true, true, "enabled_without_worker", false)]
    [InlineData(false, false, "enabled_without_worker", false)]
    public async Task Admitted_findings_publication_requires_a_live_worker(bool stale, bool registered,
        string state, bool live)
    {
        var result = await Read(mode: SemanticRuntimeSettings.FindingsMode, reportedMode: SemanticRuntimeSettings.FindingsMode,
            findings: true, stale: stale, registered: registered);
        Assert.Equal(state, result.Text("state"));
        Assert.Equal(live, result.Flag("finding_path_live"));
    }
}
