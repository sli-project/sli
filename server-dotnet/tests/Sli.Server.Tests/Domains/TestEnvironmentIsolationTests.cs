using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class TestEnvironmentIsolationTests
{
    [Fact]
    public void Safe_environment_uses_only_unreachable_Postgres_and_disables_background_work()
    {
        var env = SafeTestEnvironment.Create(new Dictionary<string, string?>());
        Assert.Equal("postgres", env["ADLOG_DB_BACKEND"]);
        Assert.Equal(SafeTestEnvironment.UnreachablePgDsn, env["ADLOG_PG_DSN"]);
        var pg = new NpgsqlConnectionStringBuilder(env["ConnectionStrings__Sli"]);
        Assert.EndsWith(".invalid", pg.Host);
        Assert.Equal("sli_test_unreachable", pg.Database);
        Assert.Equal("sli_test", pg.Username);
        Assert.Equal("1", env["ADLOG_DISABLE_SCHEDULER"]);
        Assert.Equal("false", env["ADLOG_CONTINUOUS_RECOVERY"]);
        Assert.Equal("", env["ADLOG_ENABLE_POSTGRES_COLLECTION"]);

        var config = new ConfigurationManager();
        config.AddInMemoryCollection(env.Select(pair => KeyValuePair.Create(pair.Key.Replace("__", ":"), pair.Value)));
        config.AddInstalledEnvironment();
        Assert.Equal(SafeTestEnvironment.UnreachableConnectionString, config.GetConnectionString("Sli"));
        _ = new PostgresConnectionFactory(config); // No implicit identity or operator DSN required.
    }

    [Fact]
    public void Sanitized_environment_drops_poisoned_settings_and_preserves_OS_variables()
    {
        var poisoned = new Dictionary<string, string?>
        {
            ["PATH"] = "trusted-path", ["SYSTEMROOT"] = "synthetic-system-root",
            ["DOTNET_HOST_PATH"] = "synthetic-dotnet-host",
            ["ADLOG_DB_BACKEND"] = "postgres", ["ADLOG_PG_DSN"] = "host=db.example.test dbname=operator user=operator",
            ["ADLOG_ENABLE_POSTGRES_COLLECTION"] = "1", ["ADLOG_DC_CONNECT_MAP"] = "DC1=dc.example.test",
            ["PGPASSWORD"] = "synthetic-password", ["PGHOST"] = "db.example.test",
            ["PYTHONPATH"] = "synthetic-injection", ["PYTEST_ADDOPTS"] = "--lf",
            ["ConnectionStrings__Sli"] = "Host=db.example.test;Database=operator;Username=operator",
            ["Sli__PostgresConnectionString"] = "synthetic-operator-dsn",
            ["ADLOG_PG_DSN_FILE"] = "synthetic-operator-secret-file",
            ["SLI_DEPLOYMENT_MODE"] = "native"
        };
        var before = poisoned.ToArray();
        var env = SafeTestEnvironment.Create(poisoned);

        Assert.Equal("trusted-path", env["PATH"]);
        Assert.Equal("synthetic-system-root", env["SYSTEMROOT"]);
        Assert.Equal("synthetic-dotnet-host", env["DOTNET_HOST_PATH"]);
        Assert.Equal("postgres", env["ADLOG_DB_BACKEND"]);
        Assert.Equal(SafeTestEnvironment.UnreachablePgDsn, env["ADLOG_PG_DSN"]);
        Assert.Equal(SafeTestEnvironment.UnreachableConnectionString, env["ConnectionStrings__Sli"]);
        Assert.Equal("1", env["ADLOG_DISABLE_SCHEDULER"]);
        Assert.Equal("false", env["ADLOG_CONTINUOUS_RECOVERY"]);
        Assert.Equal("", env["ADLOG_ENABLE_POSTGRES_COLLECTION"]);
        foreach (string name in new[] { "ADLOG_DC_CONNECT_MAP", "PGPASSWORD", "PGHOST", "PYTHONPATH",
            "PYTEST_ADDOPTS", "Sli__PostgresConnectionString", "ADLOG_PG_DSN_FILE", "SLI_DEPLOYMENT_MODE" })
            Assert.False(env.ContainsKey(name), name);
        Assert.Equal(before, poisoned.ToArray());
    }

    [Theory]
    [InlineData("pgpassword")]
    [InlineData("pgservicefile")]
    [InlineData("adlog_dc_connect_map")]
    [InlineData("sLi__PostgresConnectionString")]
    [InlineData("ConnectionStrings:Sli")]
    [InlineData("ASPNETCORE_URLS")]
    [InlineData("Kestrel__Certificates__Default__Path")]
    [InlineData("CREDENTIALS_DIRECTORY")]
    [InlineData("DOTNET_STARTUP_HOOKS")]
    public void Child_process_environment_is_sanitized_case_insensitively(string name)
    {
        var start = new ProcessStartInfo();
        start.Environment.Clear();
        start.Environment["PATH"] = "trusted-path";
        start.Environment[name] = "synthetic-poison";
        SafeTestEnvironment.Apply(start);
        Assert.False(start.Environment.ContainsKey(name), name);
        Assert.Equal("trusted-path", start.Environment["PATH"]);
        Assert.Equal(SafeTestEnvironment.UnreachableConnectionString, start.Environment["ConnectionStrings__Sli"]);
    }
}
