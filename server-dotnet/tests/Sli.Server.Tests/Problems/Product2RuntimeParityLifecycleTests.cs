using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Compatibility;
using Sli.Server.Infrastructure;
using Sli.Server.Operations;
using Sli.Server.Problems;
using Sli.Server.Tests.Agents;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Problems;

// Behavioral vectors from tests/semantic/test_pg_product2_runtime_parity_lifecycle.py.
public sealed class Product2RuntimeParityLifecycleTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject O(string text) => JsonNode.Parse(text)!.AsObject();
    static readonly DateTimeOffset Now = new(2026, 7, 10, 0, 0, 0, TimeSpan.Zero);
    sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }

    [Fact]
    public async Task FindingHttpLifecyclePersistsAuditAssignmentReasonAndCloseReopenInPostgres()
    {
        await using var pg = new SqlPostgresFixture(); await pg.StartAsync(Ct);
        var connections = new Connections(pg.Pg.ConnectionString);
        await using var db = await connections.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            insert into findings(id,fingerprint,rule_code,title,severity) values(1,'fixture','fixture','fixture finding','high');
            """, Ct);
        var repo = new ProblemRepository(connections, new Clock());
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        using var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config);
            s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new ProblemEndpointTests.Authentication());
            s.AddSingleton<Sli.Server.Access.IAccessFactsRepository>(new ProblemEndpointTests.FactsReader(true));
            s.AddSingleton<IProblemRepository>(repo); s.AddSingleton<TimeProvider>(new Clock());
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapProblemLifecycle()); })).StartAsync(Ct);
        using var client = host.GetTestClient(); client.BaseAddress = new("https://localhost");
        async Task<JsonObject> Send(string body, HttpStatusCode status = HttpStatusCode.OK)
        {
            using var content = new StringContent(body, Encoding.UTF8, "application/json");
            using var response = await client.PostAsync("/api/findings/1/status", content, Ct);
            string text = await response.Content.ReadAsStringAsync(Ct);
            Assert.True(response.StatusCode == status, text);
            return O(text);
        }
        var review = await Send("""{"status":"review","note":"manual triage","assigned_to":"soc-team","status_reason":"needs evidence review","changed_by":"spoofed"}""");
        Assert.Equal("ok", (string?)review["status"]); Assert.Equal("postgres", (string?)review["backend"]); Assert.True((bool)review["changed"]!);
        var finding = review["finding"]!;
        Assert.Equal("review", (string?)finding["status"]); Assert.Equal("soc-team", (string?)finding["assigned_to"]);
        Assert.NotNull(finding["updated_at"]!.GetValue<string>());
        var history = Assert.Single(finding["status_history"]!.AsArray())!;
        Assert.Equal("new", (string?)history["old_status"]); Assert.Equal("review", (string?)history["new_status"]);
        Assert.Equal("alice", (string?)history["changed_by"]); Assert.Equal("manual triage", (string?)history["note"]);
        var same = await Send("""{"status":"review"}""");
        Assert.False((bool)same["changed"]!); Assert.Equal("soc-team", (string?)same["finding"]!["assigned_to"]);
        Assert.Equal("needs evidence review", (string?)same["finding"]!["status_reason"]); Assert.Single(same["finding"]!["status_history"]!.AsArray());
        var error = await Send("""{"status":"repeated"}""", HttpStatusCode.Conflict);
        Assert.Equal("invalid_transition", (string?)error["error"]);
        var closed = await Send("""{"status":"closed","note":"fixture resolution"}""");
        Assert.False(string.IsNullOrEmpty((string?)closed["finding"]!["closed_at"]));
        var reopened = await Send("""{"status":"active","note":"fixture new evidence"}""");
        Assert.Null(reopened["finding"]!["closed_at"]); Assert.Equal(3, reopened["finding"]!["status_history"]!.AsArray().Count);

        async Task Reset(string status = "new")
        {
            await using var command = new NpgsqlCommand("delete from finding_status_history; update findings set status=@status,assigned_to='fixture-team',status_reason='fixture reason',closed_at=null", db);
            command.Parameters.AddWithValue("status", status); await command.ExecuteNonQueryAsync(Ct);
        }
        foreach (var (assignment, owner, count) in new (string, string?, int)[] {
            ("", "fixture-team", 0), (",\"assigned_to\":null", null, 1), (",\"assigned_to\":\"\"", null, 1),
            (",\"assigned_to\":\" fixture-other-team \"", "fixture-other-team", 1) })
        {
            await Reset();
            var result = await Send("{\"status\":\"new\"" + (assignment.Length == 0 ? "" : ",\"status_reason\":\"fixture reason\"") + assignment + "}");
            Assert.False((bool)result["changed"]!); finding = result["finding"]!;
            Assert.Equal(owner, (string?)finding["assigned_to"]); Assert.Equal("fixture reason", (string?)finding["status_reason"]);
            Assert.Equal(count, finding["status_history"]!.AsArray().Count);
            if (count > 0) {
                history = finding["status_history"]![0]!;
                Assert.Equal("new", (string?)history["old_status"]); Assert.Equal("new", (string?)history["new_status"]); Assert.Equal("alice", (string?)history["changed_by"]);
            }
        }
        await Reset();
        var note = await Send("""{"status":"new","assigned_to":"soc-team","note":"Передано дежурной смене"}""");
        Assert.False((bool)note["changed"]!); Assert.Equal("soc-team", (string?)note["finding"]!["assigned_to"]);
        Assert.Equal("Передано дежурной смене", (string?)note["finding"]!["status_history"]![0]!["note"]);
        foreach (string? comment in new string?[] { null, "fixture comment" }) {
            await Reset("review");
            var body = new JsonObject { ["status"] = "review", ["status_reason"] = " updated fixture reason ", ["note"] = comment };
            var result = await Send(body.ToJsonString()); finding = result["finding"]!;
            Assert.False((bool)result["changed"]!); Assert.Equal("updated fixture reason", (string?)finding["status_reason"]);
            Assert.Equal("fixture-team", (string?)finding["assigned_to"]);
            history = Assert.Single(finding["status_history"]!.AsArray())!;
            Assert.Equal("review", (string?)history["old_status"]); Assert.Equal("review", (string?)history["new_status"]);
            Assert.Equal("alice", (string?)history["changed_by"]); Assert.Equal(comment ?? "updated fixture reason", (string?)history["note"]);
            body.Remove("note"); var unchanged = await Send(body.ToJsonString());
            Assert.True(JsonNode.DeepEquals(finding["status_history"], unchanged["finding"]!["status_history"]));
        }
        await VerifyAiRoundTrip(connections);
    }

    static async Task VerifyAiRoundTrip(Connections connections)
    {
        var package = O("""{"provider":"openai_api","model":"gpt-test","prompt_version":"v1","redaction_level":"strict","api_key":"synthetic-do-not-persist","redaction_mapping":{"fixture":"synthetic-private"},"payload":{"events":[{}]}}""");
        var recorder = new AiRunRepository(connections, new Clock());
        var config = new ConfigurationBuilder().Build();
        using var rows = new PostgresLegacyRows(connections);
        var reader = new LegacyHttpReader( null!, NullLogger<LegacyHttpReader>.Instance);
        foreach (var (called, warnings, status) in new[] { (true, false, "completed"), (false, false, "prepared"), (true, true, "completed_with_validation_warnings") }) {
            var result = new JsonObject { ["status"] = "completed", ["ai_call_performed"] = called, ["validation_errors"] = warnings ? new JsonArray("fixture warning") : new JsonArray() };
            long id = await recorder.RecordAsync(package, result, new(), Ct); Assert.True(id > 0);
            var stored = await rows.QueryAsync("select * from ai_api_runs where id=@p0", [id], 0, Ct);
            var item = Assert.Single(stored)!;
            Assert.Equal(id, (long)item["id"]!); Assert.Equal(status, (string?)item["status"]); Assert.Equal(called, (bool)item["ai_call_performed"]!);
            Assert.True(DateTimeOffset.TryParse((string?)item["created_at"], out _));
            if (called) Assert.Equal(Now, DateTimeOffset.Parse((string)item["completed_at"]!)); else Assert.Null(item["completed_at"]);
            Assert.DoesNotContain("synthetic-do-not-persist", stored.ToJsonString()); Assert.DoesNotContain("synthetic-private", stored.ToJsonString());
            var disabled = await Assert.ThrowsAsync<LegacyInputException>(() => reader.ReadAsync("/api/ai/runs", new(new()), Ct));
            Assert.Equal("module_disabled", disabled.Message);
        }
    }

    sealed class Search : ILegacyHttpReader
    {
        public Task<JsonObject> ReadAsync(string path, LegacyQuery query, CancellationToken ct) => Task.FromResult(new JsonObject {
            ["total"] = 25, ["items"] = new JsonArray(Enumerable.Range(0, 10).Select(_ => (JsonNode)new JsonObject { ["event_id"] = 4624, ["time_created_utc"] = "2026-07-10T00:00:00Z" }).ToArray()) });
    }
    [Fact]
    public async Task InvestigationExposesEvidenceFirstTruncationAndLimitations()
    {
        var reader = new LegacyInvestigationReader(new Search(), new ProblemEndpointTests.Repository());
        var result = await reader.ReadAsync(new QueryCollection(new Dictionary<string, StringValues> { ["q"] = "user", ["limit"] = "10", ["scope"] = "important" }), Ct);
        var quality = result["data_quality"]!;
        Assert.Equal("postgres", (string?)quality["backend"]); Assert.Equal("evidence-first", (string?)quality["evidence_policy"]);
        Assert.True((bool)quality["truncated"]!); Assert.True(quality["limitations"]!.AsArray().Count >= 2);
        Assert.Equal(25L, (long)quality["total_events"]!); Assert.Equal(10, (int)quality["returned_events"]!);
    }

    sealed class Metrics(bool activity) : IOperationsQueries
    {
        public List<string> Sql = [];
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        {
            Sql.Add(sql); Assert.StartsWith("select ", sql.TrimStart(), StringComparison.OrdinalIgnoreCase);
            JsonArray rows = sql.Contains("pg_database_size") ? new(O("""{"database_name":"adlog_reports","database_bytes":1073741824,"checked_at":"2026-07-10T00:00:00Z"}""")) :
                sql.Contains("pg_stat_user_tables") ? new(O("""{"table_name":"events","live_rows":1000,"dead_rows":10,"total_bytes":2048,"last_analyze":null,"last_autoanalyze":null,"last_vacuum":null,"last_autovacuum":null}""")) :
                sql.Contains("pg_stat_activity") && activity ? new(O("""{"pid":1,"user_name":"u","duration_seconds":120,"query_preview":"select * from events where target_user_name='synthetic-private-user' and event_record_id=123456789"}""")) : [];
            return Task.FromResult(rows);
        }
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task PostgresMetricsAreReadOnlyAndRedactQueryLiterals(bool activity)
    {
        var config = new ConfigurationBuilder().Build(); var queries = new Metrics(activity);
        var service = new OperationsService(queries, new OperationsFiles(config), new OperationsCatalog(), new OperationsJobs(), new Clock());
        var result = await service.PostgresAsync(20, Ct);
        Assert.Equal(activity ? "warn" : "ok", (string?)result["status"]); Assert.Equal("1.0 GB", (string?)result["database"]!["database_human"]);
        Assert.Equal("events", (string?)result["tables"]![0]!["table_name"]);
        Assert.True((bool)result["safety"]!["read_only"]!); Assert.False((bool)result["safety"]!["vacuum_executed"]!); Assert.False((bool)result["safety"]!["analyze_executed"]!);
        Assert.Equal(3, queries.Sql.Count);
        if (activity) {
            string preview = (string)result["long_running_queries"]![0]!["query_preview"]!;
            Assert.DoesNotContain("synthetic-private-user", preview); Assert.DoesNotContain("123456789", preview);
            Assert.Contains("<redacted>", preview); Assert.Contains("<number>", preview);
        } else Assert.Empty(result["long_running_queries"]!.AsArray());
    }
}
