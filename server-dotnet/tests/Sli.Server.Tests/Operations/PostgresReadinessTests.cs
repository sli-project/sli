using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Compatibility;
using Sli.Server.Operations;
using Sli.Server.Reporting;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class PostgresReadinessTests
{
    static Dictionary<string, string?> Settings(string? dsn = "") => new()
    {
        ["ConnectionStrings:Sli"] = dsn,
        ["Sli:PostgresConnectionString"] = "",
        ["Sli:Operations:ADLOG_PG_DSN"] = ""
    };

    [Theory]
    [InlineData("postgresql://example_user:example_password@192.0.2.1:5432/example_db", "example_password", "example_user", "192.0.2.1")]
    [InlineData("host=192.0.2.1 password=secret dbname=example_db", "secret", null, "192.0.2.1")]
    [InlineData("host='db host' password='quoted secret' dbname=example_db", "quoted secret", null, "db host")]
    [InlineData("host = 192.0.2.1 password = spaced-secret dbname = example_db", "spaced-secret", null, "192.0.2.1")]
    [InlineData("postgresql://example_user:example%40password@[2001:db8::1]:5432/example_db", "example@password", "example_user", "2001:db8::1")]
    [InlineData("host=db user=example_user password=secret sslpassword=cert-secret", "cert-secret", "example_user", "db")]
    public async Task DsnPasswordsAreMaskedAndNonsecretIdentitySurvives(string dsn, string secret, string? user, string host)
    {
        using var app = await OperationsEndpointTests.Start(settings: Settings(dsn));
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/db/status?connect=false");
        var body = await OperationsEndpointTests.Body(response);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True((bool)body["postgres"]!["configured"]!);
        string redacted = (string)body["postgres"]!["dsn"]!;
        Assert.DoesNotContain(secret, redacted);
        Assert.DoesNotContain("example%40password", redacted);
        var fields = LibpqKeywordDsn.Parse(redacted);
        Assert.Equal("***", fields["password"]);
        Assert.Equal(host, fields["host"]);
        if (user is not null) Assert.Equal(user, fields["user"]);
        if (dsn.Contains("sslpassword")) Assert.Equal("***", fields["sslpassword"]);
        Assert.Equal(0, app.Queries.Reads);
    }

    [Fact]
    public async Task SslPasswordIsMaskedWithoutAnOrdinaryPassword()
    {
        using var app = await OperationsEndpointTests.Start(settings: Settings("host=db sslpassword=cert-secret"));
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/db/status?connect=false");
        var body = await OperationsEndpointTests.Body(response);
        var fields = LibpqKeywordDsn.Parse((string)body["postgres"]!["dsn"]!);
        Assert.Equal("***", fields["sslpassword"]);
        Assert.False(fields.ContainsKey("password"));
        Assert.DoesNotContain("cert-secret", body.ToJsonString());
    }

    [Theory]
    [InlineData("host='unterminated password=must-not-leak")]
    [InlineData("unsupported=must-not-leak")]
    [InlineData("postgresql://example_user:must-not-leak%ZZ@db/example_db")]
    public async Task InvalidOrUnsupportedDsnFailsClosed(string dsn)
    {
        using var app = await OperationsEndpointTests.Start(settings: Settings(dsn));
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/db/status?connect=false");
        var body = await OperationsEndpointTests.Body(response);
        Assert.Equal("<invalid PostgreSQL DSN>", (string?)body["postgres"]!["dsn"]);
        Assert.DoesNotContain("must-not-leak", body.ToJsonString());
        Assert.Equal(0, app.Queries.Reads);
    }

    [Fact]
    public async Task NativeConnectionStringMasksItsPassword()
    {
        using var app = await OperationsEndpointTests.Start(settings: Settings("Host=db;Database=example_db;Username=example_user;Password=\"quoted;secret\""));
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/db/status?connect=false");
        var body = await OperationsEndpointTests.Body(response);
        var fields = new Npgsql.NpgsqlConnectionStringBuilder((string)body["postgres"]!["dsn"]!);
        Assert.Equal("***", fields.Password);
        Assert.Equal("db", fields.Host);
        Assert.DoesNotContain("quoted;secret", body.ToJsonString());
    }

    [Theory]
    [InlineData("false")]
    [InlineData("true")]
    public async Task NoDsnReturnsWarningWithoutReadingDatabaseOrLeaking(string connect)
    {
        using var app = await OperationsEndpointTests.Start(settings: Settings());
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/db/status?connect=" + connect);
        var body = await OperationsEndpointTests.Body(response);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("db0_readiness", (string?)body["mode"]);
        Assert.Equal("postgres", (string?)body["active_backend"]);
        Assert.Equal("warn", (string?)body["status"]);
        Assert.False((bool)body["postgres"]!["configured"]!);
        Assert.Null(body["postgres"]!["dsn"]);
        Assert.False((bool)body["safety"]!["backend_switched"]!);
        Assert.False((bool)body["safety"]!["migration_running"]!);
        Assert.False((bool)body["safety"]!["cursor_or_watermark_changed"]!);
        Assert.Equal("warn", (string?)body["checks"]!["dsn"]!["status"]);
        Assert.Equal(0, app.Queries.Reads);
    }

    [Theory]
    [InlineData("")]
    [InlineData("host=db password=fixture-secret")]
    public async Task OfflineReadinessChecksSchemaAndNeverChangesData(string dsn)
    {
        using var app = await OperationsEndpointTests.Start(settings: Settings(dsn));
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/db/status?view=readiness&connect=false");
        var body = await OperationsEndpointTests.Body(response);
        Assert.Equal("DB-0.1", (string?)body["stage"]);
        Assert.Contains((string?)body["status"], new[] { "ok", "warn" });
        foreach (string key in new[] { "switch_backend", "migrate_data", "move_cursor_or_watermark" })
            Assert.False((bool)body["safety"]![key]!);
        Assert.Equal("ok", (string?)body["checks"]!["schema_file"]!["status"]);
        Assert.Equal(0, app.Queries.Reads);
        Assert.DoesNotContain("fixture-secret", body.ToJsonString());
    }

    [Fact]
    public async Task OfflineReadinessDoesNotReportAMissingSchemaAsHealthy()
    {
        var settings = Settings();
        settings["Sli:ProjectRoot"] = Path.Combine(Path.GetTempPath(), "sli-readiness-" + Guid.NewGuid().ToString("N"));
        using var app = await OperationsEndpointTests.Start(settings: settings);
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/db/status?view=readiness&connect=false");
        var body = await OperationsEndpointTests.Body(response);
        Assert.Equal("failed", (string?)body["status"]);
        Assert.Equal("failed", (string?)body["checks"]!["schema_file"]!["status"]);
        Assert.Equal(0, app.Queries.Reads);
    }

    [Theory]
    [InlineData(false, "ok", 3)]
    [InlineData(true, "failed", 1)]
    public async Task ConfiguredConnectionStillReportsRealProbeOutcomeWithoutExceptionText(bool fail, string status, int reads)
    {
        using var app = await OperationsEndpointTests.Start(settings: Settings("Host=db;Database=example_db;Username=example_user;Password=fixture-secret"));
        app.Queries.Fail = fail;
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/db/status");
        var body = await OperationsEndpointTests.Body(response);
        Assert.Equal(status, (string?)body["status"]);
        Assert.Equal(status, (string?)body["checks"]!["connection"]!["status"]);
        Assert.Equal(reads, app.Queries.Reads);
        Assert.DoesNotContain("private-db", body.ToJsonString());
        Assert.DoesNotContain("fixture-secret", body.ToJsonString());
        Assert.All(app.Queries.Calls, call => Assert.StartsWith("select", call.Sql));
    }

    [Fact]
    public void CanonicalSchemaContainsCoreTablesAndPostgresSyntax()
    {
        var files = new OperationsFiles(new ConfigurationBuilder().Build());
        string text = File.ReadAllText(Path.Combine(files.Root, "config", "postgres_schema.sql")).ToLowerInvariant();
        foreach (string table in new[] { "schema_migrations", "log_sources", "collection_channel_state", "collector_channel_runs", "collector_stage_metrics", "events", "findings", "ai_api_runs" })
            Assert.Contains("create table if not exists " + table, text);
        Assert.DoesNotContain("datetime('now')", text);
        Assert.DoesNotContain("insert or ignore", text);
        Assert.Contains("on conflict", text);
    }

    [Fact]
    public void DatabaseStatusReportKeepsItsTitleAndNavigationBookmark()
    {
        Assert.Contains(ReportDatasetCatalog.Data["legacy_dynamic"]!.AsArray(), n => (string?)n == "db-status.html");
        Assert.Equal("DB Backend Status", (string?)ReportDatasetCatalog.Data["legacy_metadata"]!["db-status.html"]!["title"]);
        var nav = LegacyWorkspaceModels.Navigation(new ConfigurationBuilder().Build());
        Assert.Contains(nav["items"]!.AsArray(), n => ((string?)n?["url"])?.Split('?')[0] == "/reports/db-status.html");
    }
}
