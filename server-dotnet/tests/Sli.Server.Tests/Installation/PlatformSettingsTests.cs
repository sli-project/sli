using System.Text.Json.Nodes;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

[CollectionDefinition("Platform settings environment", DisableParallelization = true)]
public sealed class PlatformSettingsEnvironmentCollection { }

[Collection("Platform settings environment")]
public sealed class PlatformSettingsTests
{
    const string Prefix = "/api/v1/platform-settings";
    const string Report = "reports.domain_fqdn";
    static string T(JsonNode? value) => value?.GetValue<string>() ?? "";
    static JsonObject Setting(JsonNode body, string key) => body["items"]!.AsArray().OfType<JsonObject>().Single(item => T(item["key"]) == key);
    static bool Upsert(string sql) => sql.Contains("insert into platform_settings", StringComparison.Ordinal);
    static bool Audit(string sql) => sql.Contains("insert into access_audit_v4", StringComparison.Ordinal);

    // Environment is process-wide; this collection runs without parallel tests and restores it.
    sealed class EnvironmentScope(params (string Name, string? Value)[] values) : IDisposable
    {
        readonly (string Name, string? Value)[] previous = values.Select(v => (v.Name, Environment.GetEnvironmentVariable(v.Name))).ToArray();
        public void Apply()
        {
            foreach (var (name, value) in values) Environment.SetEnvironmentVariable(name, value);
        }
        public void Dispose()
        {
            foreach (var (name, value) in previous) Environment.SetEnvironmentVariable(name, value);
        }
    }

    [Fact]
    public async Task StoredReportDomainWinsOverEnvironmentAndPreservesAttribution()
    {
        using var environment = new EnvironmentScope(("ADLOG_REPORT_DOMAIN_FQDN", "env.example.test")); environment.Apply();
        await using var f = new InstallationFixture(); f.Database.Settings[Report] = "Corp.Example.TEST"; await f.StartAsync();
        var result = await f.SendAsync("GET", Prefix); Assert.Equal(200, result.Status);
        var item = Setting(result.Body, Report);
        Assert.Equal("corp.example.test", T(item["value"])); Assert.Equal("corp.example.test", T(item["effective_value"]));
        Assert.Equal("available", T(item["effective_state"])); Assert.Equal("database", T(item["source"]));
        Assert.Equal("alice", T(item["updated_by"])); Assert.Equal("2026-01-01 00:00:00+00", T(item["updated_at"]));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task UnsetOrUnavailableReportDomainNeverUsesEnvironmentOrDefault(bool databaseUnavailable, bool withEnvironment)
    {
        using var environment = new EnvironmentScope(("ADLOG_REPORT_DOMAIN_FQDN", withEnvironment ? "env.example.test" : null),
            ("SLI_INSTALL_DOMAIN", withEnvironment ? "install.example.test" : null)); environment.Apply();
        await using var f = new InstallationFixture();
        if (databaseUnavailable) f.Database.Override = (_, _) => throw new InvalidOperationException("synthetic database unavailable");
        await f.StartAsync(); var result = await f.SendAsync("GET", Prefix); Assert.Equal(200, result.Status);
        var item = Setting(result.Body, Report);
        Assert.Equal("not_configured", T(item["source"])); Assert.Equal("", T(item["value"])); Assert.Equal("", T(item["environment"]));
        Assert.Null(item["effective_value"]); Assert.Equal(databaseUnavailable ? "unavailable" : "unknown", T(item["effective_state"]));
        Assert.Null(item["updated_by"]); Assert.Null(item["updated_at"]);
    }

    [Theory]
    [InlineData("ad.snapshot_history_days", "SLI_AD_SNAPSHOT_HISTORY_DAYS", "365", "730", "180")]
    [InlineData("workstations.evidence_retention_days", "SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS", "90", "180", "120")]
    public async Task DeclaredFallbacksResolveDatabaseThenEnvironmentThenDefault(string key, string variable, string defaultValue, string overrideValue, string storedValue)
    {
        using var environment = new EnvironmentScope((variable, null)); environment.Apply();
        await using var f = new InstallationFixture(); await f.StartAsync();
        async Task Check(string expected, string source)
        {
            var result = await f.SendAsync("GET", Prefix); Assert.Equal(200, result.Status);
            var item = Setting(result.Body, key); Assert.Equal(expected, T(item["value"])); Assert.Equal(source, T(item["source"]));
        }
        await Check(defaultValue, "default");
        Environment.SetEnvironmentVariable(variable, overrideValue); await Check(overrideValue, "environment");
        f.Database.Settings[key] = storedValue; await Check(storedValue, "database");
        f.Database.Settings.Clear(); Environment.SetEnvironmentVariable(variable, null); await Check(defaultValue, "default");
    }

    [Theory]
    [InlineData("ad.password_max_age_days", "365")]
    [InlineData("ad.inactivity_days", "90")]
    public async Task AdPolicyOverrideIsNormalizedAndAuditedWithPreviousDefault(string key, string defaultValue)
    {
        await using var f = new InstallationFixture(); await f.StartAsync();
        var initial = await f.SendAsync("GET", Prefix); Assert.Equal(200, initial.Status);
        Assert.Equal(defaultValue, T(Setting(initial.Body, key)["value"])); Assert.Equal("default", T(Setting(initial.Body, key)["source"]));
        var result = await f.SendAsync("POST", Prefix + "/" + key, "{\"value\":\" 120 \"}"); Assert.Equal(200, result.Status);
        Assert.Equal("120", T(result.Body["item"]!["value"])); Assert.Equal("database", T(result.Body["item"]!["source"]));
        AssertChange(f.Database, key, defaultValue, "120");
    }

    static void AssertChange(ScriptDatabase database, string key, string? previous, string value)
    {
        var writes = database.Calls.Where(c => c.Write).ToArray();
        var upsert = Assert.Single(writes, c => Upsert(c.Sql)); Assert.Equal(new object?[] { key, value, "alice" }, upsert.Args);
        Assert.Contains("on conflict(key) do update", upsert.Sql, StringComparison.Ordinal);
        var audit = Assert.Single(writes, c => Audit(c.Sql)); Assert.Equal("platform_setting_update", audit.Args[2]);
        Assert.Equal("platform_setting", audit.Args[3]); Assert.Equal(key, audit.Args[4]);
        var details = JsonNode.Parse((string)audit.Args[5]!)!;
        Assert.Equal(previous, details["previous"]?.GetValue<string>()); Assert.Equal(value, T(details["value"]));
        Assert.True(Array.FindIndex(writes, c => Upsert(c.Sql)) < Array.FindIndex(writes, c => Audit(c.Sql)));
        Assert.True(Audit(writes[^1].Sql)); Assert.Equal(1, database.Commits); Assert.Equal(0, database.Rollbacks);
        Assert.Equal(value, database.Settings[key]);
    }

    [Fact]
    public async Task ReportDomainWriteChecksRegistrationAndAuditsNormalizedValue()
    {
        using var environment = new EnvironmentScope(("ADLOG_REPORT_DOMAIN_FQDN", "env.example.test")); environment.Apply();
        await using var f = new InstallationFixture(); await f.StartAsync();
        var result = await f.SendAsync("POST", Prefix + "/" + Report, "{\"value\":\" Corp.Example.TEST \"}"); Assert.Equal(200, result.Status);
        Assert.Equal("corp.example.test", T(result.Body["item"]!["value"]));
        var registration = f.Database.Calls.First(c => c.Write);
        Assert.StartsWith("select id from domains where lower(fqdn)=", registration.Sql);
        Assert.Equal(new object?[] { "corp.example.test" }, registration.Args);
        AssertChange(f.Database, Report, null, "corp.example.test");
    }

    [Fact]
    public async Task UnregisteredReportDomainIsRejectedBeforeUpsertOrAudit()
    {
        await using var f = new InstallationFixture();
        f.Database.Override = (sql, _) => sql.StartsWith("select id from domains", StringComparison.Ordinal) ? new JsonArray() : null;
        await f.StartAsync(); var result = await f.SendAsync("POST", Prefix + "/" + Report, "{\"value\":\"unknown.example.test\"}");
        Assert.Equal(400, result.Status); Assert.Equal("report_domain_not_registered", T(result.Body["error"]));
        Assert.StartsWith("select id from domains", Assert.Single(f.Database.Calls, c => c.Write).Sql);
        Assert.Empty(f.Database.Settings); Assert.Equal(0, f.Database.Commits);
    }

    public static TheoryData<string, string, string> InvalidValues
    {
        get
        {
            var result = new TheoryData<string, string, string>();
            foreach (string value in new[] { "", "example", "a'b.test", "a b.test" }) result.Add(Report, value, "value_must_be_dns_name");
            foreach (string value in new[] { "3651", "365.0" }) result.Add("ad.snapshot_history_days", value, "ad_snapshot_history_days_must_be_7_to_3650");
            foreach (string key in new[] { "ad.password_max_age_days", "ad.inactivity_days" })
                foreach (string value in new[] { "", "0", "3651", "-1", "1.5", "true", "1e2", "９０" }) result.Add(key, value, "value_must_be_days_1_3650");
            foreach (string suffix in SprayDefaults.Keys)
                foreach (string value in new[] { "", "0", "745", "-1", "1.5", "1e2", "１２" }) result.Add("windows_auth.distributed_" + suffix, value, "value_must_be_integer_1_744");
            return result;
        }
    }
    [Theory, MemberData(nameof(InvalidValues))]
    public async Task InvalidSettingValuesAreRejectedBeforeDatabaseAccess(string key, string value, string error)
    {
        await using var f = new InstallationFixture(); await f.StartAsync();
        var result = await f.SendAsync("POST", Prefix + "/" + key, new JsonObject { ["value"] = value }.ToJsonString());
        Assert.Equal(400, result.Status); Assert.Equal(error, T(result.Body["error"]));
        Assert.Empty(f.Database.Calls); Assert.Equal(0, f.Database.Commits);
    }

    [Theory]
    [InlineData("reports.unknown", "alice", "unknown_setting", 404)]
    [InlineData(Report, "", "actor_required", 400)]
    public async Task UnknownSettingsAndMissingActorsAreRefused(string key, string actor, string error, int status)
    {
        await using var f = new InstallationFixture { Principal = new("session", 1, "admin", actor) }; await f.StartAsync();
        var result = await f.SendAsync("POST", Prefix + "/" + key, "{\"value\":\"corp.example.test\"}");
        Assert.Equal(status, result.Status); Assert.Equal(error, T(result.Body["error"])); Assert.Empty(f.Database.Calls);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("3650")]
    public async Task AdPolicyAcceptsBothBoundaries(string value)
    {
        await using var f = new InstallationFixture(); await f.StartAsync();
        var result = await f.SendAsync("POST", Prefix + "/ad.inactivity_days", new JsonObject { ["value"] = value }.ToJsonString());
        Assert.Equal(200, result.Status); Assert.Equal(value, T(result.Body["item"]!["value"]));
        AssertChange(f.Database, "ad.inactivity_days", "90", value);
    }

    static readonly Dictionary<string, string> SprayDefaults = new() { ["window_hours"] = "24", ["min_accounts"] = "10", ["min_sources"] = "5", ["max_failures_per_account"] = "3" };
    [Theory]
    [InlineData("window_hours")]
    [InlineData("min_accounts")]
    [InlineData("min_sources")]
    [InlineData("max_failures_per_account")]
    public async Task DistributedSprayDefaultsStoredOverridesAndUpperBoundary(string suffix)
    {
        string key = "windows_auth.distributed_" + suffix;
        await using var f = new InstallationFixture(); await f.StartAsync();
        var initial = await f.SendAsync("GET", Prefix); Assert.Equal(200, initial.Status);
        Assert.Equal(SprayDefaults[suffix], T(Setting(initial.Body, key)["value"])); Assert.Equal("default", T(Setting(initial.Body, key)["source"]));
        f.Database.Settings[key] = " 12 ";
        var stored = await f.SendAsync("GET", Prefix); Assert.Equal(200, stored.Status);
        Assert.Equal("12", T(Setting(stored.Body, key)["value"])); Assert.Equal("database", T(Setting(stored.Body, key)["source"]));
        var result = await f.SendAsync("POST", Prefix + "/" + key, "{\"value\":\"744\"}"); Assert.Equal(200, result.Status);
        Assert.Equal("744", T(result.Body["item"]!["value"])); AssertChange(f.Database, key, "12", "744");
    }

    [Theory]
    [InlineData(1, 400)]
    [InlineData(3, 200)]
    public async Task LogonPolicyVersionUsesLockedCurrentRowBeforeWritingAndAuditing(int version, int status)
    {
        const string key = "workstations.logon_policy", previous = "{\"policies\":[],\"version\":2}";
        await using var f = new InstallationFixture();
        // The ordinary read is deliberately stale: version validation must use the locked row.
        f.Database.Settings[key] = "{\"policies\":[],\"version\":1}";
        f.Database.Override = (sql, _) => sql.EndsWith("for update", StringComparison.Ordinal) ? ScriptDatabase.Rows("[{\"value\":\"{\\\"policies\\\":[],\\\"version\\\":2}\"}]") : null;
        await f.StartAsync();
        var result = await f.SendAsync("POST", Prefix + "/" + key, new JsonObject { ["value"] = $"{{\"version\":{version},\"policies\":[]}}" }.ToJsonString());
        Assert.Equal(status, result.Status);
        var writes = f.Database.Calls.Where(c => c.Write).ToArray();
        Assert.StartsWith("select pg_advisory_xact_lock(hashtext(", writes[0].Sql); Assert.Equal(new object?[] { key }, writes[0].Args);
        Assert.EndsWith("for update", writes[1].Sql); Assert.Equal(new object?[] { key }, writes[1].Args);
        if (status == 400)
        {
            Assert.Equal("workstation_logon_policy_invalid", T(result.Body["error"])); Assert.Equal(2, writes.Length);
            Assert.Equal(0, f.Database.Commits); Assert.Equal(1, f.Database.Rollbacks);
            Assert.Equal("{\"policies\":[],\"version\":1}", f.Database.Settings[key]);
        }
        else
        {
            Assert.True(Upsert(writes[2].Sql)); AssertChange(f.Database, key, previous, "{\"policies\":[],\"version\":3}");
        }
    }
}
