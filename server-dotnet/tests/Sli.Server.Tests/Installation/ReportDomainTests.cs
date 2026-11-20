using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.InstallationSetup;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

[CollectionDefinition("Report domain environment", DisableParallelization = true)]
public sealed class ReportDomainEnvironmentCollection;

[Collection("Report domain environment")]
public sealed class ReportDomainTests
{
    const string Key = "reports.domain_fqdn";
    static CancellationToken Ct => TestContext.Current.CancellationToken;

    // Source: tests/core/test_report_domain.py. Environment changes are restored
    // even on failure and this collection runs without concurrent test classes.
    [Theory]
    [InlineData("ADLOG_REPORT_DOMAIN_FQDN", null)]
    [InlineData("ADLOG_REPORT_DOMAIN_FQDN", "   ")]
    [InlineData("ADLOG_REPORT_DOMAIN_FQDN", "env.example.test")]
    [InlineData("SLI_INSTALL_DOMAIN", "env.example.test")]
    [InlineData("REPORT_DOMAIN", "env.example.test")]
    [InlineData("DEFAULT_DOMAIN", "env.example.test")]
    public async Task MissingDatabaseDomainNeverUsesEnvironmentOrBuiltInDefault(string name, string? value)
    {
        string? previous = Environment.GetEnvironmentVariable(name);
        try
        {
            Environment.SetEnvironmentVariable(name, value);
            await using var f = new InstallationFixture();
            f.Database.Override = (_, _) => new JsonArray();
            await f.StartAsync();
            var service = f.Host.Services.GetRequiredService<InstallationService>();
            foreach (var read in new Func<Task<string>>[] { () => service.GetSettingAsync(Key, Ct), () => service.ReportDomainAsync(Ct) })
            {
                var error = await Assert.ThrowsAsync<InstallationException>(read);
                Assert.Equal("report_domain_not_configured", error.Message);
                Assert.Equal(503, error.Status);
                Assert.False((Exception)error is ArgumentException);
            }
            var response = await f.SendAsync("GET", "/api/v1/platform-settings");
            Assert.Equal(200, response.Status);
            var setting = Assert.Single(response.Body["items"]!.AsArray().OfType<JsonObject>(), s => s["key"]!.GetValue<string>() == Key);
            Assert.Equal("not_configured", setting["source"]!.GetValue<string>());
            Assert.Equal("", setting["value"]!.GetValue<string>());
            Assert.Equal("unknown", setting["effective_state"]!.GetValue<string>());
            Assert.Null(setting["effective_value"]);
            Assert.Equal(0, f.Database.Commits);
        }
        finally { Environment.SetEnvironmentVariable(name, previous); }
    }

    [Fact]
    public async Task StoredDomainIsNormalizedAndWinsOverEnvironment()
    {
        const string name = "ADLOG_REPORT_DOMAIN_FQDN";
        string? previous = Environment.GetEnvironmentVariable(name);
        try
        {
            Environment.SetEnvironmentVariable(name, " Corp.Example.TEST ");
            await using var f = new InstallationFixture();
            f.Database.Settings[Key] = " DB.Example.TEST ";
            await f.StartAsync();
            var service = f.Host.Services.GetRequiredService<InstallationService>();
            Assert.Equal("db.example.test", await service.GetSettingAsync(Key, Ct));
            Assert.Equal("db.example.test", await service.ReportDomainAsync(Ct));
            Assert.Contains(f.Database.Calls, c => c.Sql.StartsWith("select is_archived", StringComparison.Ordinal)
                && Equals(c.Args[0], "db.example.test"));
            Assert.Equal(" DB.Example.TEST ", f.Database.Settings[Key]);
            Assert.Equal(0, f.Database.Commits);
        }
        finally { Environment.SetEnvironmentVariable(name, previous); }
    }

    [Theory]
    [InlineData("example")]
    [InlineData("a'b.test")]
    [InlineData("a b.test")]
    [InlineData("-a.test")]
    [InlineData("a.test;drop")]
    [InlineData("a..test")]
    public async Task UnsafeStoredDomainIsRejectedBeforeDomainQuery(string value)
    {
        await using var f = new InstallationFixture();
        f.Database.Settings[Key] = value;
        await f.StartAsync();
        var service = f.Host.Services.GetRequiredService<InstallationService>();
        var error = await Assert.ThrowsAsync<InstallationException>(() => service.ReportDomainAsync(Ct));
        Assert.Equal("value_must_be_dns_name", error.Message);
        Assert.Equal(400, error.Status);
        Assert.DoesNotContain(f.Database.Calls, c => c.Sql.Contains("from domains", StringComparison.Ordinal));
        Assert.Equal(0, f.Database.Commits);
    }
}
