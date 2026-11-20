using Sli.Server.Storage;
using Sli.Server.Tests.Operations;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Behavioral vectors from tests/storage/test_postgres_import_pipeline.py.
public sealed class PostgresImportPipelineTests
{
    [Fact]
    public async Task Explicit_source_identity_reaches_the_postgres_importer()
    {
        int calls = 0;
        var ct = TestContext.Current.CancellationToken;
        var result = await PostgresImportPipeline.RunAsync("postgres", "Corp.Example.Test.", "Forest.Example.Test.",
            (domain, forest, token) => {
                calls++;
                Assert.Equal("corp.example.test", domain);
                Assert.Equal("forest.example.test", forest);
                Assert.Equal(ct, token);
                return Task.FromResult((0, "total_inserted=1", ""));
            }, ct);
        Assert.Equal(1, calls);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("total_inserted=1", result.Stdout);
        Assert.Equal("", result.Stderr);
        Assert.Equal("postgres", result.Backend);
        Assert.Equal(0, result.Retries);
        Assert.True(result.QueueWaitMs >= 0);
    }

    [Theory]
    [InlineData("DC1.Corp.Example.Test.", null, null, "corp.example.test", "corp.example.test")]
    [InlineData("DC1", "Corp.Example.Test.", "Forest.Example.Test.", "corp.example.test", "forest.example.test")]
    [InlineData("DC1.Corp.Example.Test.", "", "", "corp.example.test", "corp.example.test")]
    public void Domain_derivation_and_single_domain_forest_match_the_reference(
        string address, string? domain, string? forest, string expectedDomain, string expectedForest)
    {
        Assert.Equal((expectedDomain, expectedForest), PostgresImportPipeline.ResolveSourceIdentity(address, domain, forest));
    }

    [Theory]
    [InlineData("EXAMPLE", null, "domain_placeholder_forbidden")]
    [InlineData("example.invalid", null, "domain_placeholder_forbidden")]
    [InlineData("corp.example.test", "example.invalid", "forest_placeholder_forbidden")]
    public void Importer_placeholders_are_rejected(string domain, string? forest, string error)
    {
        Assert.Equal(error, Assert.Throws<ArgumentException>(() =>
            PostgresImportPipeline.ResolveSourceIdentity("dc1.corp.example.test", domain, forest)).Message);
    }

    [Fact]
    public void Deriving_a_domain_requires_a_fqdn()
    {
        Assert.Equal("connect_address_must_be_fqdn", Assert.Throws<ArgumentException>(() =>
            PostgresImportPipeline.ResolveSourceIdentity("DC1")).Message);
    }

    [Theory]
    [InlineData(null, "example.test", "postgres_source_identity_required")]
    [InlineData("example.test", null, "postgres_source_identity_required")]
    [InlineData("EXAMPLE", "example.test", "domain_placeholder_forbidden")]
    [InlineData("example.test", "example.invalid", "forest_placeholder_forbidden")]
    [InlineData("corp..example.test", "example.test", "domain_must_be_fqdn")]
    public async Task Invalid_identity_is_rejected_before_dispatch(string? domain, string? forest, string error)
    {
        int calls = 0;
        var exception = await Assert.ThrowsAsync<ArgumentException>(() => PostgresImportPipeline.RunAsync(
            "postgres", domain, forest, (_, _, _) => { calls++; return Task.FromResult((0, "", "")); }, TestContext.Current.CancellationToken));
        Assert.Equal(error, exception.Message);
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task Non_postgres_backend_never_dispatches()
    {
        int calls = 0;
        var error = await Assert.ThrowsAsync<ArgumentException>(() => PostgresImportPipeline.RunAsync(
            "unsupported", "example.test", "example.test", (_, _, _) => { calls++; return Task.FromResult((0, "", "")); }, TestContext.Current.CancellationToken));
        Assert.Equal("non_postgres_backend_forbidden: unsupported", error.Message);
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData("corp..example.test")]
    [InlineData("-corp.example.test")]
    [InlineData("corp-.example.test")]
    [InlineData("corp_example.test")]
    public void Malformed_dns_labels_are_rejected(string domain)
    {
        Assert.Equal("domain_must_be_fqdn", Assert.Throws<ArgumentException>(() =>
            PostgresImportPipeline.ResolveSourceIdentity("DC1", domain)).Message);
    }

    [Fact]
    public async Task Queue_serializes_imports_and_releases_after_import_failure()
    {
        var ct = TestContext.Current.CancellationToken;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        bool secondEntered = false;
        var first = PostgresImportPipeline.RunAsync("postgres", "example.test", "example.test", async (_, _, _) => {
            entered.SetResult();
            await release.Task.WaitAsync(ct);
            throw new InvalidOperationException("synthetic_import_failure");
        }, ct);
        await entered.Task.WaitAsync(ct);
        var second = PostgresImportPipeline.RunAsync("postgres", "example.test", "example.test", (_, _, _) => {
            secondEntered = true;
            return Task.FromResult((75, "", "synthetic_import_failure"));
        }, ct);
        try { Assert.False(secondEntered); Assert.False(second.IsCompleted); }
        finally { release.TrySetResult(); }
        Assert.Equal("synthetic_import_failure", (await Assert.ThrowsAsync<InvalidOperationException>(() => first)).Message);
        var result = await second;
        Assert.True(secondEntered);
        Assert.Equal(75, result.ExitCode);
        Assert.Equal("", result.Stdout);
        Assert.Equal("synthetic_import_failure", result.Stderr);
        Assert.Equal("postgres", result.Backend);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Runtime_status_exposes_postgres_pipeline_state(bool failed)
    {
        using var app = await OperationsEndpointTests.Start();
        if (failed) app.Queries.FailContaining = "select 1 as ok";
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/runtime/status");
        Assert.Equal(200, (int)response.StatusCode);
        var body = await OperationsEndpointTests.Body(response);
        Assert.Equal("postgres", (string?)body["active_backend"]);
        Assert.Equal(!failed, (bool)body["collection"]!["postgres_importer_available"]!);
        Assert.Equal(failed ? "failed" : "ready", (string?)body["collection"]!["postgres_pipeline_status"]);
        Assert.DoesNotContain("private-db-password-and-AD-data", body.ToJsonString());
    }
}
