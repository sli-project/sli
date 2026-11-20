using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Domains;
using Sli.Server.InstallationSetup;
using Sli.Server.Reporting.V2;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

public sealed class DomainArchivePolicyTests
{
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-09T00:00:00Z");
    static DomainItem Domain(long id, string? observed = null, bool archived = false,
        string? manifest = null, string? published = null, string? events = null) =>
        new(id, $"domain-{id}.example.test", archived, new(null, published, null, manifest, observed, events, null));

    [Fact]
    public void SavedNonarchivePreferenceWinsRegardlessOfAge()
    {
        var rows = new[] { Domain(1, "2000-01-01T00:00:00Z"), Domain(2, "2026-01-01T00:00:00Z") };
        Assert.Equal(1, ReportV2Metadata.ChooseDomain(rows, "DOMAIN-1.EXAMPLE.TEST", Now)!.Id);
    }

    [Fact]
    public void ArchivedPreferenceUsesObservationInsteadOfPublicationOrEvents()
    {
        var rows = new[] { Domain(1, "2026-01-01T00:00:00Z", true), Domain(2, "2025-01-01T00:00:00Z"),
            Domain(3, published: "2026-02-01T00:00:00Z", events: "2026-02-01T00:00:00Z") };
        Assert.Equal(2, ReportV2Metadata.ChooseDomain(rows, "domain-1.example.test", Now)!.Id);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("bad")]
    [InlineData("2999-01-01T00:00:00Z")]
    [InlineData("2026-01-01T00:00:00")]
    public void UnknownInvalidFutureOrNaiveObservationCannotInventDefault(string? observed) =>
        Assert.Null(ReportV2Metadata.ChooseDomain([Domain(1, observed)], null, Now));

    [Fact]
    public void EmptyOrOnlyArchivedDomainsHaveNoDefault()
    {
        Assert.Null(ReportV2Metadata.ChooseDomain([], null, Now));
        Assert.Null(ReportV2Metadata.ChooseDomain([Domain(1, "2025-01-01T00:00:00Z", true)], null, Now));
    }

    [Fact]
    public void UnknownCompletedObservationDoesNotFallBackToManifestClock() =>
        Assert.Null(ReportV2Metadata.ChooseDomain([Domain(1, manifest: "2026-01-01T00:00:00Z")], null, Now));

    [Fact]
    public void CompletedObservationNeedsNoPublishedManifest() =>
        Assert.Equal(1, ReportV2Metadata.ChooseDomain([Domain(1, "2025-01-01T00:00:00Z")], null, Now)!.Id);

    [Theory]
    [InlineData("null")]
    [InlineData("0")]
    [InlineData("\"true\"")]
    [InlineData("[]")]
    [InlineData("{}")]
    public async Task NonbooleanArchiveValueIsRejectedBeforeDatabaseAccess(string value)
    {
        await using var f = new InstallationFixture(); await f.StartAsync();
        var result = await f.SendAsync("POST", "/api/v1/setup/domains/domain-1.example.test", "{\"is_archived\":" + value + "}");
        Assert.Equal(400, result.Status);
        Assert.Equal("domain_archive_must_be_boolean", (string?)result.Body["error"]);
        Assert.Empty(f.Database.Calls);
        Assert.Equal(0, f.Database.Commits);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task ArchiveMutationLocksNormalizesAndAuditsBeforeCommit(bool archived, bool previous)
    {
        await using var f = new InstallationFixture();
        f.Database.Override = (sql, _) => sql.Contains("for update", StringComparison.Ordinal)
            ? new(new JsonObject { ["is_archived"] = previous }) : null;
        await f.StartAsync();
        var result = await f.SendAsync("POST", "/api/v1/setup/domains/Domain-1.Example.Test", JsonSerializer.Serialize(new { is_archived = archived }));
        Assert.Equal(200, result.Status);
        Assert.True(JsonNode.DeepEquals(JsonSerializer.SerializeToNode(new {
            fqdn = "domain-1.example.test", is_archived = archived, previous_is_archived = previous }), result.Body["item"]));
        Assert.All(f.Database.Calls, c => Assert.True(c.Write));
        var locked = Assert.Single(f.Database.Calls, c => c.Sql.Contains("for update", StringComparison.Ordinal));
        Assert.Equal("domain-1.example.test", locked.Args[0]);
        Assert.DoesNotContain(f.Database.Calls, c => c.Sql.Contains("netbios_name", StringComparison.Ordinal));
        var update = Assert.Single(f.Database.Calls, c => c.Sql.StartsWith("update domains", StringComparison.Ordinal));
        Assert.Equal(new object?[] { archived, "domain-1.example.test" }, update.Args);
        var audit = f.Database.Calls[^1];
        Assert.Contains("insert into access_audit_v4", audit.Sql);
        Assert.Equal("domain-1.example.test", audit.Args[4]);
        var details = JsonNode.Parse((string)audit.Args[5]!)!;
        Assert.Equal(archived, (bool)details["is_archived"]!);
        Assert.Equal(previous, (bool)details["previous_is_archived"]!);
        Assert.Equal(1, f.Database.Commits);
    }

    [Fact]
    public async Task FailedArchiveAuditCannotCommitMutation()
    {
        await using var f = new InstallationFixture();
        f.Database.Override = (sql, _) => sql.Contains("insert into access_audit_v4", StringComparison.Ordinal)
            ? throw new InvalidOperationException("synthetic-audit-failure") : null;
        await f.StartAsync();
        var result = await f.SendAsync("POST", "/api/v1/setup/domains/domain-1.example.test", "{\"is_archived\":true}");
        Assert.Equal(500, result.Status);
        Assert.Equal(0, f.Database.Commits);
        Assert.Equal(1, f.Database.Rollbacks);
        Assert.DoesNotContain("synthetic-audit-failure", result.Body.ToJsonString());
    }

    [Fact]
    public async Task EffectiveDefaultKeepsStoredPreferenceAndOnlyReads()
    {
        await using var f = new InstallationFixture();
        f.Database.Settings["reports.domain_fqdn"] = "domain-1.example.test";
        f.Database.Override = (sql, _) => sql.StartsWith("select is_archived", StringComparison.Ordinal)
            ? ScriptDatabase.Rows("[{\"is_archived\":true}]")
            : sql.Contains("from domains d join lateral", StringComparison.Ordinal)
                ? ScriptDatabase.Rows("[{\"fqdn\":\"domain-2.example.test\"}]") : null;
        await f.StartAsync();
        var result = await f.SendAsync("GET", "/api/v1/platform-settings");
        Assert.Equal(200, result.Status);
        var setting = Assert.Single(result.Body["items"]!.AsArray(), s => (string?)s!["key"] == "reports.domain_fqdn")!;
        Assert.Equal("domain-1.example.test", (string?)setting["value"]);
        Assert.Equal("domain-2.example.test", (string?)setting["effective_value"]);
        Assert.Equal("domain-1.example.test", f.Database.Settings["reports.domain_fqdn"]);
        Assert.All(f.Database.Calls, c => { Assert.False(c.Write); Assert.StartsWith("select", c.Sql.TrimStart()); });
        var observed = Assert.Single(f.Database.Calls, c => c.Sql.Contains("from domains d join lateral", StringComparison.Ordinal));
        Assert.Contains("status='completed'", observed.Sql);
        Assert.Contains("max(observed_at_utc)", observed.Sql);
        Assert.Contains("not d.is_archived", observed.Sql);
        Assert.Contains("observed.observed_at_utc<=now()", observed.Sql);
        Assert.Contains("order by observed.observed_at_utc desc,d.id", observed.Sql);
    }

    [Fact]
    public async Task AutomaticDefaultDnsIsValidatedBeforeUse()
    {
        await using var f = new InstallationFixture();
        f.Database.Override = (sql, _) => sql.Contains("from domains d join lateral", StringComparison.Ordinal)
            ? ScriptDatabase.Rows("[{\"fqdn\":\"bad'name.example.test\"}]") : null;
        await f.StartAsync();
        var service = f.Host.Services.GetRequiredService<InstallationService>();
        var error = await Assert.ThrowsAsync<InstallationException>(() => service.SettingsAsync(TestContext.Current.CancellationToken));
        Assert.Equal("value_must_be_dns_name", error.Message);
        Assert.Equal(0, f.Database.Commits);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(null)]
    public async Task RecommendationCannotReplaceNonarchiveOrUnregisteredPreference(bool? archived)
    {
        await using var f = new InstallationFixture();
        f.Database.Override = (sql, _) => sql.StartsWith("select is_archived", StringComparison.Ordinal)
            ? archived is null ? new() : new(new JsonObject { ["is_archived"] = archived.Value })
            : throw new InvalidOperationException("recommendation must not read candidates");
        await f.StartAsync();
        var service = f.Host.Services.GetRequiredService<InstallationService>();
        Assert.Null(await service.SuggestedDomainAsync("domain-1.example.test", TestContext.Current.CancellationToken));
        Assert.Single(f.Database.Calls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0.0)]
    [InlineData(-1.0)]
    public async Task UnknownFreshnessPolicyDoesNotEvenReadDatabase(double? window)
    {
        await using var f = new InstallationFixture(); await f.StartAsync();
        var service = f.Host.Services.GetRequiredService<InstallationService>();
        Assert.Null(await service.SuggestedDomainAsync("domain-1.example.test", TestContext.Current.CancellationToken, window));
        Assert.Empty(f.Database.Calls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("2000-01-01T00:00:00Z")]
    [InlineData("2999-01-01T00:00:00Z")]
    [InlineData("2026-01-01T00:00:00")]
    public async Task RecommendationRejectsUntrustedOrOldObservation(string? observed)
    {
        await using var f = new InstallationFixture();
        RecommendationRows(f, observed);
        await f.StartAsync();
        var service = f.Host.Services.GetRequiredService<InstallationService>();
        Assert.Null(await service.SuggestedDomainAsync("domain-1.example.test", TestContext.Current.CancellationToken));
    }

    static void RecommendationRows(InstallationFixture f, object? observed)
    {
        f.Database.Override = (sql, _) => sql.StartsWith("select is_archived", StringComparison.Ordinal)
            ? ScriptDatabase.Rows("[{\"is_archived\":true}]")
            : sql.Contains("from domains d", StringComparison.Ordinal)
                ? new(new JsonObject { ["id"] = 2, ["display_name"] = "domain-2.example.test", ["fqdn"] = "domain-2.example.test",
                    ["is_archived"] = false, ["observed_at_utc"] = JsonSerializer.SerializeToNode(observed) }) : null;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RecommendationUsesCompletedObservationAndOnlyReads(bool typedDate)
    {
        await using var f = new InstallationFixture();
        var observed = DateTimeOffset.UtcNow.AddMinutes(-1);
        RecommendationRows(f, typedDate ? observed : observed.ToString("O"));
        await f.StartAsync();
        var service = f.Host.Services.GetRequiredService<InstallationService>();
        Assert.Equal("domain-2.example.test", await service.SuggestedDomainAsync("domain-1.example.test", TestContext.Current.CancellationToken));
        Assert.All(f.Database.Calls, c => { Assert.False(c.Write); Assert.StartsWith("select", c.Sql.TrimStart()); });
        var query = Assert.Single(f.Database.Calls, c => c.Sql.Contains("from ad_context_runs", StringComparison.Ordinal));
        Assert.Contains("status='completed'", query.Sql);
        Assert.Contains("max(", query.Sql);
        Assert.Equal(0, f.Database.Commits);
        Assert.Empty(f.Database.Settings);
    }
}
