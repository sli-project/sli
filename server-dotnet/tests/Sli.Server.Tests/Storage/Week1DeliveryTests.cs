using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using Sli.Server.Auth;
using Sli.Server.Compatibility;
using Sli.Server.Operations;
using Sli.Server.Problems;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Operations;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Behavioral vectors from tests/storage/test_week1_4_delivery.py.
public sealed class Week1DeliveryTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void Operations_configuration_reads_retention_and_health_from_yaml()
    {
        using var state = new StorageLifecycleTests.State();
        Directory.CreateDirectory(Path.Combine(state.Path, "config"));
        File.WriteAllText(Path.Combine(state.Path, "config", "adlog_config.yaml"),
            "retention:\n  raw_retention_days: 7\nhealth:\n  lag_warn_minutes: 45\n");
        var environment = new Dictionary<string, string?>();
        var config = new LifecycleConfiguration(state.Path, environment.GetValueOrDefault);
        Assert.Equal("7", config.Get("ADLOG_RAW_RETENTION_DAYS"));
        Assert.Equal("45", config.Get("ADLOG_HEALTH_LAG_WARN_MINUTES"));
        environment["ADLOG_RAW_RETENTION_DAYS"] = "9";
        environment["ADLOG_HEALTH_LAG_WARN_MINUTES"] = "60";
        Assert.Equal("9", config.Get("ADLOG_RAW_RETENTION_DAYS"));
        Assert.Equal("60", config.Get("ADLOG_HEALTH_LAG_WARN_MINUTES"));
    }

    sealed class UnavailableFiles(IConfiguration config) : OperationsFiles(config)
    {
        internal override IReadOnlyList<FileInfo> Inventory(string relative, int maxEntries, TimeSpan budget) => throw new IOException("synthetic inventory failure");
    }

    static OperationsService RetentionService(string root, bool unavailable = false)
    {
        Directory.CreateDirectory(Path.Combine(root, "config"));
        File.WriteAllText(Path.Combine(root, "config", "adlog_config.yaml"), "retention:\n  log_retention_days: 1\n");
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = Path.Combine(root, "data") }).Build();
        return new(new OperationsEndpointTests.Queries(), unavailable ? new UnavailableFiles(config) : new OperationsFiles(config), new OperationsCatalog(), new OperationsJobs(), TimeProvider.System);
    }

    static string OldLog(string root)
    {
        string directory = Path.Combine(root, "data", "logs"); Directory.CreateDirectory(directory);
        string old = Path.Combine(directory, "old.log"); File.WriteAllText(old, "must remain");
        File.SetLastWriteTimeUtc(old, DateTime.UtcNow.AddDays(-5));
        File.WriteAllText(Path.Combine(directory, "recent.log"), "recent");
        return old;
    }

    [Fact]
    public async Task Retention_defaults_to_dry_run_and_only_plans_old_logs()
    {
        using var state = new StorageLifecycleTests.State(); string old = OldLog(state.Path);
        var result = await RetentionService(state.Path).ApplyRetentionAsync(ct: Ct);
        Assert.Equal("dry_run", result["mode"]!.ToString());
        Assert.Equal("ok", result["status"]!.ToString());
        Assert.Equal(1, result["total_candidates"]!.GetValue<int>());
        Assert.True(result["legacy_planner_retired"]!.GetValue<bool>());
        Assert.False(result["apply_supported"]!.GetValue<bool>());
        Assert.Empty(result["deleted"]!.AsArray()); Assert.Empty(result["errors"]!.AsArray());
        Assert.Equal("must remain", File.ReadAllText(old));
        Assert.True(File.Exists(Path.Combine(state.Path, "data", "logs", "recent.log")));
    }

    [Fact]
    public async Task Legacy_retention_apply_is_blocked_and_preserves_candidate_contents()
    {
        using var state = new StorageLifecycleTests.State(); string old = OldLog(state.Path);
        var result = await RetentionService(state.Path).ApplyRetentionAsync(apply: true, ct: Ct);
        Assert.Equal("blocked", result["status"]!.ToString());
        Assert.Equal("blocked", result["mode"]!.ToString());
        Assert.False(result["apply_supported"]!.GetValue<bool>());
        Assert.True(result["legacy_planner_retired"]!.GetValue<bool>());
        Assert.Equal(1, result["total_candidates"]!.GetValue<int>());
        Assert.Empty(result["deleted"]!.AsArray());
        Assert.Equal("legacy_retention_apply_disabled", Assert.Single(result["errors"]!.AsArray())!["code"]!.ToString());
        Assert.Equal("must remain", File.ReadAllText(old));
    }

    [Fact]
    public async Task Unavailable_inventory_is_not_reported_as_a_successful_empty_retention_plan()
    {
        using var state = new StorageLifecycleTests.State(); string old = OldLog(state.Path);
        var result = await RetentionService(state.Path, unavailable: true).ApplyRetentionAsync(ct: Ct);
        Assert.Equal("unavailable", result["status"]!.ToString()); Assert.Null(result["total_candidates"]);
        Assert.False(result["apply_supported"]!.GetValue<bool>()); Assert.Empty(result["deleted"]!.AsArray());
        Assert.Equal("must remain", File.ReadAllText(old));
    }

    sealed class StoryEvents : ILegacyHttpReader
    {
        public LegacyQuery? Query;
        public Task<JsonObject> ReadAsync(string path, LegacyQuery query, CancellationToken ct)
        {
            Assert.Equal("/api/events/search", path); Query = query;
            var items = new JsonArray();
            foreach (var (id, eventId, time, subject, ip, host, message) in new[] {
                (5, 4740, "08:20:00", "DC1$", "192.0.2.2", "WS01", "account locked"),
                (4, 4724, "08:10:00", "admin", "192.0.2.11", "WS02", "password reset"),
                (3, 4672, "08:06:00", "alice", "192.0.2.2", "WS01", "special privileges"),
                (2, 4624, "08:05:00", "alice", "192.0.2.2", "WS01", "successful logon"),
                (1, 4625, "08:00:00", "alice", "192.0.2.2", "WS01", "bad password") })
                items.Add(new JsonObject { ["id"] = id, ["event_id"] = eventId, ["time_created_utc"] = "2026-07-07T" + time + "Z",
                    ["subject"] = subject, ["target"] = "alice", ["ip_address"] = ip, ["workstation_name"] = host,
                    ["server"] = "dc1.example.test", ["channel"] = "Security", ["summary"] = message });
            return Task.FromResult(new JsonObject { ["items"] = items, ["returned_count"] = 5, ["total"] = 5, ["total_is_exact"] = true, ["has_more"] = false });
        }
    }

    sealed class Findings : IProblemRepository
    {
        public string? Query; public int Limit;
        public Task<JsonObject> LegacyFindingsAsync(string query, int limit, CancellationToken ct)
        {
            Query = query; Limit = limit;
            return Task.FromResult(JsonNode.Parse("""{"backend":"postgres","items":[{"id":1,"title":"Неудачный вход","severity":"high","status":"new","target":"alice","evidence_count":1},{"id":2,"title":"Сброс пароля","severity":"high","status":"new","target":"alice","evidence_count":1}],"summary":[]}""")!.AsObject());
        }
        public Task<JsonObject> FindingsAsync(FindingQuery q, ProblemAccess a, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> StatusAsync(long id, FindingStatusInput input, string actor, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> RiskAsync(long id, RiskInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> ResponsiblesAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> RiskAuditAsync(long id, long? before, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> WatchListAsync(RegistryQuery q, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> WatchSaveAsync(string? id, WatchInput input, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> DecoyListAsync(RegistryQuery q, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> DecoySaveAsync(string? id, DecoyInput input, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
    }

    [Fact]
    public async Task Investigation_links_the_five_event_story_and_two_related_findings()
    {
        var events = new StoryEvents(); var findings = new Findings();
        var result = await new LegacyInvestigationReader(events, findings).ReadAsync(new QueryCollection(new Dictionary<string, StringValues> {
            ["q"] = "alice", ["time_from"] = "2026-07-01T00:00:00Z" }), Ct);
        Assert.Equal(5, long.Parse(result["summary"]!["total_events"]!.ToString()));
        Assert.Equal(5, long.Parse(result["summary"]!["chain_events"]!.ToString()));
        Assert.Equal(2, result["summary"]!["findings"]!.GetValue<int>());
        Assert.Equal(new[] { 4740, 4724, 4672, 4624, 4625 }, result["timeline"]!["chain"]!.AsArray().Select(n => n!["event_id"]!.GetValue<int>()));
        Assert.Equal(new[] { "lockouts", "passwords", "privileges", "logons", "failed_logons" }, result["timeline"]!["chain"]!.AsArray().Select(n => n!["category"]!.ToString()));
        Assert.Equal(new[] { "Неудачный вход", "Сброс пароля" }, result["findings"]!["items"]!.AsArray().Select(n => n!["title"]!.ToString()));
        Assert.Equal("alice", findings.Query); Assert.Equal(50, findings.Limit);
        Assert.Equal("alice", events.Query!.Filters["q"]!.ToString());
        Assert.Equal(DateTimeOffset.Parse("2026-07-01T00:00:00Z"), DateTimeOffset.Parse(events.Query.Filters["time_from"]!.ToString()));
        foreach (int eventId in new[] { 4625, 4624, 4672, 4724, 4740 })
            Assert.Contains(events.Query.Filters["event_ids"]!.AsArray(), n => n!.GetValue<int>() == eventId);
        Assert.Equal("2026-07-01T00:00:00Z", result["data_quality"]!["time_from"]!.ToString());
        Assert.Equal("desc", events.Query.Filters["order"]!.ToString());
        Assert.True(events.Query.Filters["include_internal_evidence"]!.GetValue<bool>());
        string html = await RenderInvestigation(result);
        Assert.Contains("Рабочее место расследования", html);
        Assert.Contains("Цепочка событий", html);
        Assert.Contains("Связанные findings", html);
        Assert.Contains("password reset", html);
        Assert.Contains("Сброс пароля", System.Net.WebUtility.HtmlDecode(html));
    }

    static async Task<string> RenderInvestigation(JsonObject data)
    {
        var context = new DefaultHttpContext(); using var body = new MemoryStream(); context.Response.Body = body;
        await LegacyRender.HtmlAsync(context, "/reports/investigation.html", data, Ct);
        Assert.Equal("text/html; charset=utf-8", context.Response.ContentType);
        return System.Text.Encoding.UTF8.GetString(body.ToArray());
    }

    [Fact]
    public async Task Investigation_report_escapes_event_and_finding_text()
    {
        var data = await new LegacyInvestigationReader(new StoryEvents(), new Findings()).ReadAsync(
            new QueryCollection(new Dictionary<string, StringValues> { ["q"] = "alice" }), Ct);
        data["timeline"]!["chain"]![0]!["summary"] = "<script>event</script>";
        data["findings"]!["items"]![0]!["title"] = "<script>finding</script>";
        string html = await RenderInvestigation(data);
        Assert.Contains("&lt;script&gt;event&lt;/script&gt;", html);
        Assert.Contains("&lt;script&gt;finding&lt;/script&gt;", html);
        Assert.DoesNotContain("<script>", html);
    }
}
