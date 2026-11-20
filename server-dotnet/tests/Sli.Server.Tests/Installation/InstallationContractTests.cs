using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Auth;
using Sli.Server.InstallationSetup;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

public sealed class InstallationContractTests
{
    static JsonObject O(string text) => JsonNode.Parse(text)!.AsObject();
    static JsonArray A(string text) => JsonNode.Parse(text)!.AsArray();
    static string T(JsonNode? n) => InstallationPackages.Text(n);
    public static TheoryData<string> HealthVectors
    {
        get
        {
            using var stream = typeof(InstallationContractTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Installation.collection-source-vectors.json")!;
            var result = new TheoryData<string>(); foreach (var vector in JsonNode.Parse(stream)!.AsArray()) result.Add(vector!.ToJsonString()); return result;
        }
    }
    static JsonNode? Comparable(JsonNode? n, JsonNode? scenario, string key = "")
    {
        if (n is JsonObject obj && scenario is JsonObject fields)
            return new JsonObject(obj.Where(p => fields.ContainsKey(p.Key))
                .Select(p => new KeyValuePair<string, JsonNode?>(p.Key, Comparable(p.Value, fields[p.Key], p.Key))));
        if (n is JsonArray array && scenario is JsonArray expected)
            return new JsonArray(array.Select((v, index) => Comparable(v, index < expected.Count ? expected[index] : null)).ToArray());
        if ((key.EndsWith("_at", StringComparison.Ordinal) || key.EndsWith("_utc", StringComparison.Ordinal) || key == "last_seen")
            && DateTimeOffset.TryParse(T(n), out var stamp)) return JsonValue.Create(stamp.UtcDateTime.Ticks);
        return n?.DeepClone();
    }
    [Theory, MemberData(nameof(HealthVectors))]
    public void CollectionPreservesIndependentContactImportAndCompletenessStates(string json)
    {
        var v = O(json); var agents = v["agents"]!.AsArray(); var streams = v["streams"]!.AsArray();
        var actual = SetupCollectionHealth.View(agents, streams, DateTimeOffset.Parse(T(v["now"])), v["diagnostics_available"]!.GetValue<bool>());
        var expected = v["expected"];
        Assert.True(JsonNode.DeepEquals(Comparable(expected, expected), Comparable(actual, expected)), T(v["name"]) + "\n" + actual.ToJsonString());
        Assert.True(JsonNode.DeepEquals(v["bindings"], SetupCollectionHealth.Bindings(agents)), T(v["name"]) + " bindings");
        Assert.True(JsonNode.DeepEquals(v["requested"], SetupCollectionHealth.Requested(agents)), T(v["name"]) + " requested");
    }
    [Theory]
    [InlineData("reports.domain_fqdn", " EXAMPLE.test ", "example.test")]
    [InlineData("ad.snapshot_history_days", "0007", "7")]
    [InlineData("workstations.evidence_retention_days", "3650", "3650")]
    [InlineData("ad.password_max_age_days", " 001 ", "1")]
    [InlineData("windows_auth.distributed_min_sources", "0744", "744")]
    public void SettingNormalizationMatchesLegacy(string key, string raw, string expected) => Assert.Equal(expected, InstallationSettings.Normalize(key, raw));
    [Theory]
    [InlineData("reports.domain_fqdn", "localhost", "value_must_be_dns_name")]
    [InlineData("ad.snapshot_history_days", "6", "ad_snapshot_history_days_must_be_7_to_3650")]
    [InlineData("workstations.evidence_retention_days", "0", "workstation_retention_days_invalid")]
    [InlineData("ad.password_max_age_days", "1e2", "value_must_be_days_1_3650")]
    [InlineData("windows_auth.distributed_min_sources", "745", "value_must_be_integer_1_744")]
    [InlineData("windows_auth.distributed_min_sources", "١٢", "value_must_be_integer_1_744")]
    [InlineData("security.working_time", "{}", "working_time_invalid")]
    [InlineData("workstations.logon_policy", "{\"version\":true,\"policies\":[]}", "workstation_logon_policy_invalid")]
    [InlineData("ad.service_account_exceptions", "[\"bad\"]", "ad_service_account_exceptions_invalid")]
    public void SettingValidationErrorsMatchLegacy(string key, string raw, string expected) => Assert.Equal(expected, Assert.Throws<InstallationException>(() => InstallationSettings.Normalize(key, raw)).Message);
    [Theory]
    [InlineData("sli.ad")]
    [InlineData("sli.gpo")]
    [InlineData("sli.workstations")]
    [InlineData("sli.file-audit")]
    [InlineData("sli.sigma")]
    [InlineData("sli.remote-access")]
    public async Task EveryBundledSettingsSchemaLoadsAndOwnsOnlyItsDeclaredKeys(string id)
    {
        await using var f = new InstallationFixture(); await f.StartAsync();
        var result = await f.SendAsync("GET", "/api/plugins/" + id + "/settings"); Assert.Equal(200, result.Status);
        var properties = result.Body["schema"]!["properties"]!.AsObject();
        Assert.Equal(properties.Select(p => p.Key).Order(), result.Body["values"]!.AsObject().Select(p => p.Key).Order());
        Assert.Equal(properties.Select(p => p.Key).Order(), result.Body["sources"]!.AsObject().Select(p => p.Key).Order());
        var denied = await f.SendAsync("PUT", "/api/plugins/" + id + "/settings", "{\"key\":\"security.working_time\",\"value\":{}}");
        Assert.Equal(400, denied.Status); Assert.Equal("invalid_plugin_setting_value", T(denied.Body["error"])); Assert.Empty(f.Database.Settings);
    }
    [Fact]
    public async Task TypedSettingsPreserveStoredLegacyExceptionRepresentation()
    {
        await using var f = new InstallationFixture(); f.Database.Settings["ad.service_account_exceptions"] = "[\"S-1-5-21-1-2-3-4\"]"; await f.StartAsync();
        var result = await f.SendAsync("GET", "/api/plugins/sli.ad/settings");
        Assert.Equal(200, result.Status); Assert.Equal("S-1-5-21-1-2-3-4", T(result.Body["values"]!["ad.service_account_exceptions"]![0]));
        Assert.Equal("database", T(result.Body["sources"]!["ad.service_account_exceptions"])); Assert.Equal("[\"S-1-5-21-1-2-3-4\"]", f.Database.Settings["ad.service_account_exceptions"]);
    }
    [Fact]
    public async Task ExceptionAttributionCannotBeForgedAndRetainsPreviousAuthor()
    {
        await using var f = new InstallationFixture();
        f.Database.Settings["ad.service_account_exceptions"] = "[{\"sid\":\"S-1-5-21-1-2-3-4\",\"excluded_by\":\"original\",\"excluded_at\":\"2026-01-01T00:00:00Z\"}]";
        await f.StartAsync();
        var result = await f.SendAsync("PUT", "/api/plugins/sli.ad/settings", """
            {"key":"ad.service_account_exceptions","value":[{"sid":"S-1-5-21-1-2-3-4","excluded_by":"forged","excluded_at":"forged"},{"sid":"S-1-5-21-1-2-3-5","excluded_by":"forged"}]}
            """);
        Assert.Equal(200, result.Status); var entries = result.Body["value"]!.AsArray();
        Assert.Equal("original", T(entries[0]!["excluded_by"])); Assert.Equal("2026-01-01T00:00:00Z", T(entries[0]!["excluded_at"]));
        Assert.Equal("alice", T(entries[1]!["excluded_by"])); Assert.True(DateTimeOffset.TryParse(T(entries[1]!["excluded_at"]), out _));
        var audit = Assert.Single(f.Database.Calls, c => c.Sql.Contains("insert into access_audit_v4", StringComparison.Ordinal));
        Assert.Equal("{\"plugin_id\":\"sli.ad\",\"key\":\"ad.service_account_exceptions\"}", audit.Args[5]);
    }
    const string Calendar = """{"timezone":"UTC","weekdays":[0,1,2,3,4],"start":"09:00","end":"18:00","excluded_dates":[],"exceptions":[]}""";
    const string Policy = """{"version":2,"policies":[{"scope":{"kind":"station","station_id":"host"},"timezone":"UTC","weekdays":[0],"start":"09:00","end":"18:00","include_cached_interactive":false}]}""";
    [Fact]
    public void CalendarAndPolicyAreCanonicalAndVersionsCannotBeReused()
    {
        string normalized = InstallationSettings.WorkingTime(Calendar); Assert.StartsWith("{\"end\":", normalized);
        string policy = InstallationSettings.LogonPolicy(Policy); Assert.StartsWith("{\"policies\":", policy);
        InstallationSettings.CheckPolicyVersion(policy, Policy);
        Assert.Throws<InstallationException>(() => InstallationSettings.CheckPolicyVersion(policy.Replace("09:00", "10:00", StringComparison.Ordinal), Policy));
        InstallationSettings.CheckPolicyVersion(policy.Replace("\"version\":2", "\"version\":3", StringComparison.Ordinal), Policy);
        foreach (string invalid in new[] { Calendar.Replace("UTC", "MadeUp/Timezone", StringComparison.Ordinal), Calendar.Replace("[0,1,2,3,4]", "[0,0]", StringComparison.Ordinal), Calendar.Replace("18:00", "09:00", StringComparison.Ordinal), Calendar.Replace("\"excluded_dates\":[]", "\"excluded_dates\":[\"2026-02-30\"]", StringComparison.Ordinal) })
            Assert.Throws<InstallationException>(() => InstallationSettings.WorkingTime(invalid));
    }
    [Theory]
    [InlineData("{\"is_archived\":true}", 200, null)]
    [InlineData("{\"is_archived\":1}", 400, "domain_archive_must_be_boolean")]
    [InlineData("{\"is_archived\":true,\"netbios_name\":\"x\"}", 400, "domain_archive_update_fields_invalid")]
    public async Task ArchivingOnlyChangesSelectionMetadata(string body, int expected, string? error)
    {
        await using var f = new InstallationFixture(); await f.StartAsync(); var result = await f.SendAsync("POST", "/api/v1/setup/domains/example.test", body);
        Assert.Equal(expected, result.Status);
        if (error is not null) Assert.Equal(error, T(result.Body["error"]));
        else { Assert.True(result.Body["item"]!["is_archived"]!.GetValue<bool>()); Assert.DoesNotContain(f.Database.Calls, c => c.Sql.Contains("delete", StringComparison.OrdinalIgnoreCase)); }
    }
    [Theory]
    [InlineData("POST", "/api/v1/setup/domains", "{\"fqdn\":\"example.test\"}", "domain_already_exists")]
    [InlineData("POST", "/api/v1/setup/domains/example.test", "{\"netbios_name\":\"taken\"}", "netbios_already_exists")]
    public async Task DuplicateDomainsAndNetbiosAreConflicts(string method, string route, string body, string error)
    {
        await using var f = new InstallationFixture();
        if (error == "netbios_already_exists") f.Database.Override = (sql, args) => sql.Contains("where upper(netbios_name)", StringComparison.Ordinal) ? A("[{\"found\":1}]") : null;
        await f.StartAsync(); var result = await f.SendAsync(method, route, body); Assert.Equal(409, result.Status); Assert.Equal(error, T(result.Body["error"])); Assert.Equal(0, f.Database.Commits);
    }
    [Fact]
    public async Task FirstDcMutationImportsFileTargetsInTheSameTransaction()
    {
        await using var f = new InstallationFixture();
        File.WriteAllText(Path.Combine(f.Root, "config", "domain_controllers.json"), "{\"domain_controllers\":[{\"hostname\":\"old\",\"connect_address\":\"old.example.test\",\"owner_confirmed_ip\":\"192.0.2.10\"}]}");
        f.Database.Override = (sql, _) => sql == "select id,lower(fqdn) as fqdn from domains" ? A("[{\"id\":1,\"fqdn\":\"example.test\"}]") : null;
        await f.StartAsync(); var result = await f.SendAsync("POST", "/api/v1/setup/domain-controllers", "{\"hostname\":\"new.example.test\",\"domain\":\"example.test\"}");
        Assert.Equal(201, result.Status); Assert.Equal(1, f.Database.Commits);
        var imported = Assert.Single(f.Database.Calls, c => c.Sql.Contains("'file_import'", StringComparison.Ordinal)); Assert.True(imported.Write); Assert.Equal("old", imported.Args[0]); Assert.Equal(1L, imported.Args[2]);
        var audit = Assert.Single(f.Database.Calls, c => c.Sql.Contains("insert into access_audit_v4", StringComparison.Ordinal)); Assert.Equal(1, O((string)audit.Args[5]!)["imported_from_file"]!.GetValue<int>());
        Assert.DoesNotContain("192.0.2.10", result.Body.ToJsonString());
    }
    [Fact]
    public async Task DcReadFallsBackToFileAndNeverExposesConfirmedIp()
    {
        await using var f = new InstallationFixture();
        File.WriteAllText(Path.Combine(f.Root, "config", "domain_controllers.json"), "{\"domain_controllers\":[{\"hostname\":\"old\",\"connect_address\":\"old.example.test\",\"owner_confirmed_ip\":\"192.0.2.10\"}]}");
        f.Database.Override = (sql, _) => sql.Contains("from domain_controller_targets t", StringComparison.Ordinal) ? new JsonArray() : null;
        await f.StartAsync(); var result = await f.SendAsync("GET", "/api/v1/setup/domain-controllers");
        Assert.Equal(200, result.Status); Assert.Equal("file", T(result.Body["source"])); Assert.True(result.Body["items"]![0]!["dns_readback"]!.GetValue<bool>());
        Assert.DoesNotContain("192.0.2.10", result.Body.ToJsonString());
    }
    [Fact]
    public async Task SetupDegradesSectionsIndependentlyAndNeverStartsCollection()
    {
        await using var f = new InstallationFixture();
        f.Database.Override = (sql, _) => sql.Contains("from sli_agents a", StringComparison.Ordinal) ? throw new InvalidOperationException("private-registry-detail") : null;
        await f.StartAsync(); var result = await f.SendAsync("GET", "/api/v1/setup/status");
        Assert.Equal(200, result.Status); Assert.Equal("unavailable", T(result.Body["agent_collection"]!["state"])); Assert.Single(result.Body["domains"]!.AsArray());
        Assert.Equal(5, result.Body["steps"]!.AsArray().Count); Assert.Equal(5, result.Body["sources"]!.AsArray().Count); Assert.DoesNotContain("private-registry-detail", result.Body.ToJsonString());
        Assert.DoesNotContain(f.Database.Calls, c => c.Sql.Contains("insert ", StringComparison.OrdinalIgnoreCase) || c.Sql.Contains("update ", StringComparison.OrdinalIgnoreCase));
    }
    [Fact]
    public async Task UiTamperingAndDescriptorExtensionsFailClosed()
    {
        await using var f = new InstallationFixture(); await f.StartAsync();
        string directory = Path.Combine(f.Root, "ui", "sli.ad"); File.AppendAllText(Path.Combine(directory, "entry.js"), "//changed");
        foreach (string route in new[] { "/api/v1/ui/plugins/sli.ad/descriptor", "/api/v1/ui/plugins/sli.ad/assets/HASH/entry.js" })
        { var result = await f.SendAsync("GET", route); Assert.Equal(503, result.Status); Assert.Equal("plugin_ui_integrity_failed", T(result.Body["error"])); }
        f.WriteUi(); var descriptor = O(File.ReadAllText(Path.Combine(directory, "descriptor.json"))); descriptor["html"] = "<script>bad</script>"; File.WriteAllText(Path.Combine(directory, "descriptor.json"), descriptor.ToJsonString());
        var invalid = await f.SendAsync("GET", "/api/v1/ui/plugins/sli.ad/descriptor"); Assert.Equal(503, invalid.Status); Assert.Equal("plugin_ui_invalid_descriptor", T(invalid.Body["error"]));
    }
    [Theory]
    [InlineData("../entry.js")]
    [InlineData("a/../entry.js")]
    [InlineData("a\\entry.js")]
    [InlineData("C:\\entry.js")]
    [InlineData("/entry.js")]
    public void UiPathTraversalIsRejected(string relative) => Assert.Throws<InstallationException>(() => InstallationPackages.LocalFile(Path.GetTempPath(), relative));
    [Fact]
    public async Task UiAndSetupRespectTheDrainingFence()
    {
        await using var f = new InstallationFixture(); string runtime = Path.Combine(f.Root, "runtime"); Directory.CreateDirectory(Path.Combine(runtime, "sli.ad"));
        File.WriteAllText(Path.Combine(runtime, "sli.ad", "draining.json"), "{}"); f.Configuration["Sli:PluginRuntimeDirectory"] = runtime; await f.StartAsync();
        var ui = await f.SendAsync("GET", "/api/v1/ui/plugins/sli.ad/descriptor"); Assert.Equal(503, ui.Status); Assert.Equal("plugin_ui_updating", T(ui.Body["error"]));
        var setup = await f.SendAsync("POST", "/api/v1/setup/domain-controllers", "{\"hostname\":\"dc2.example.test\",\"domain\":\"example.test\"}");
        Assert.Equal(500, setup.Status); Assert.Equal("internal_server_error", T(setup.Body["error"])); Assert.Empty(f.Database.Calls);
    }
    [Fact]
    public async Task UiLoadsTheActiveGenerationInsteadOfTheBundledAsset()
    {
        await using var f = new InstallationFixture(); string runtime = Path.Combine(f.Root, "runtime"), generation = new('a', 64);
        string ui = Path.Combine(runtime, "sli.ad", "versions", generation, "ui"); Directory.CreateDirectory(ui);
        File.Copy(Path.Combine(f.Root, "ui", "sli.ad", "descriptor.json"), Path.Combine(ui, "descriptor.json")); File.WriteAllBytes(Path.Combine(ui, "entry.js"), f.Asset);
        File.WriteAllText(Path.Combine(runtime, "sli.ad", "active.json"), "{\"generation\":\"" + generation + "\"}"); File.Delete(Path.Combine(f.Root, "ui", "sli.ad", "entry.js"));
        f.Configuration["Sli:PluginRuntimeDirectory"] = runtime; await f.StartAsync();
        var result = await f.SendAsync("GET", "/api/v1/ui/plugins/sli.ad/assets/HASH/entry.js"); Assert.Equal(200, result.Status);
    }
    [Fact]
    public async Task SetupUsesConfirmedCurrentStreamsAndReportsCollectionEnabled()
    {
        using var stream = typeof(InstallationContractTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Installation.collection-source-vectors.json")!;
        var vector = JsonNode.Parse(stream)!.AsArray()[0]!.DeepClone().AsObject();
        await using var f = new InstallationFixture();
        f.Database.Override = (sql, _) => sql.Contains("from sli_agents a", StringComparison.Ordinal) ? vector["agents"]!.DeepClone().AsArray()
            : sql.Contains("with requested as materialized", StringComparison.Ordinal) ? vector["streams"]!.DeepClone().AsArray() : null;
        // Freeze-relative timestamps are shifted to the request's current time.
        var baseline = DateTimeOffset.Parse(T(vector["now"]));
        void Shift(JsonNode? node)
        {
            if (node is JsonArray array) foreach (var child in array) Shift(child);
            if (node is not JsonObject obj) return;
            foreach (string key in obj.Select(p => p.Key).ToArray())
            {
                if (DateTimeOffset.TryParse(T(obj[key]), out var stamp)) obj[key] = (DateTimeOffset.UtcNow + (stamp - baseline)).ToString("o");
                else Shift(obj[key]);
            }
        }
        Shift(vector["agents"]); Shift(vector["streams"]);
        await f.StartAsync(); var result = await f.SendAsync("GET", "/api/v1/setup/status");
        Assert.Equal(200, result.Status); Assert.Equal("current", T(result.Body["agent_collection"]!["state"]));
        Assert.True(result.Body["collection"]!["collection_enabled"]!.GetValue<bool>()); Assert.Equal(1, result.Body["collection"]!["channels"]!.GetValue<int>());
        Assert.Equal("done", T(result.Body["steps"]![2]!["state"])); Assert.Equal("done", T(result.Body["steps"]![4]!["state"]));
    }
    [Fact]
    public async Task InvalidStoredPluginSettingsAreUnavailableAndErrorsAreLocalized()
    {
        await using var f = new InstallationFixture(); f.Database.Settings["ad.inactivity_days"] = "invalid"; await f.StartAsync();
        f.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en");
        var result = await f.SendAsync("GET", "/api/plugins/sli.ad/settings"); Assert.Equal(503, result.Status);
        Assert.Equal("plugin_settings_unavailable", T(result.Body["error"])); Assert.Equal("Settings could not load — try again.", T(result.Body["message"]!["text"]));
        var missing = await f.SendAsync("GET", "/api/plugins/missing/settings"); Assert.Equal(404, missing.Status); Assert.Equal("plugin_settings_not_found", T(missing.Body["message"]!["code"]));
    }
    [Theory]
    [InlineData("/api/plugins/settings", 404, "plugin_settings_not_found")]
    [InlineData("/api/plugins/bad/id/settings", 404, "plugin_settings_not_found")]
    [InlineData("/api/v1/ui/plugins/sli.ad/unrecognized", 404, "not_found")]
    [InlineData("/api/v1/ui/plugins/sli.ad/assets/hash", 404, "not_found")]
    public async Task MalformedPluginPathsNeverFallThroughTo501(string path, int status, string error)
    {
        await using var f = new InstallationFixture(); await f.StartAsync(); var result = await f.SendAsync("GET", path);
        Assert.Equal(status, result.Status); Assert.Equal(error, T(result.Body["error"]));
    }
}
