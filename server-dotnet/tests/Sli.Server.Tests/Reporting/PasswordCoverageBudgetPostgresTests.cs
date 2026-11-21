using System.Diagnostics;
using System.Net;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Sli.Server.Tests.Semantic;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class PasswordCoverageBudgetPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task ProblemsQueueStaysWithinBudgetWithPopulatedPasswordCheckpoints()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddHours(-16).AddMinutes(-3).ToUnixTimeSeconds());
        var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: start, eventKinds: [4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        await using var source = new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", worker);
        var scope = PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        var connections = new ReaderConnections(fixture);
        await using (var app = await connections.OpenAsync(ct))
        await using (var bind = new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')::text", app)) {
            bind.Parameters.AddWithValue("agent", ShortEventAdmissionPostgresTests.Agent);
            Assert.Equal("configured", JsonNode.Parse((string)(await bind.ExecuteScalarAsync(ct))!)!["status"]!.GetValue<string>());
        }

        await PasswordFirstBatchPostgresTests.SeedBacklog(owner, ct, total: 100_000, spacing: TimeSpan.FromHours(16).TotalSeconds / 99_999,
            noise: true, clients: 50, accountCount: 2_000);
        await using (var shape = new NpgsqlCommand("""
            select count(*), count(distinct method#>>'{$principals,IpAddress}'),
                count(distinct method#>>'{$principals,TargetUserName}'), count(distinct computer)
            from event_hot where event_kind=4625
            """, owner)) {
            await using var counts = await shape.ExecuteReaderAsync(ct);
            Assert.True(await counts.ReadAsync(ct));
            Assert.Equal(new long[] { 100_000, 50, 2_000, 1 }, Enumerable.Range(0, 4).Select(counts.GetInt64));
        }

        var producer = new PasswordProducer();
        foreach (string kind in new[] { "brute", "spray" }) {
            var attempt = await producer.RunAsync(worker, new PasswordRule(scope, kind), ct);
            Assert.False(attempt.Failed, attempt.Diagnostic?.ToJsonString());
            Assert.True(attempt.Revision > 0, attempt.Status);
        }

        long domain;
        await using (var domainQuery = new NpgsqlCommand("select id from domains where fqdn='example.test'", owner))
            domain = (long)(await domainQuery.ExecuteScalarAsync(ct))!;
        await using (var profile = new NpgsqlCommand("""
            load 'auto_explain';
            set auto_explain.log_min_duration='50ms';
            set auto_explain.log_analyze=on;
            set auto_explain.log_buffers=on;
            set auto_explain.log_nested_statements=on;
            set auto_explain.log_timing=off;
            set role adlog_user;
            explain (analyze,buffers,timing off)
                select to_jsonb(row) from (select public.read_password_detection_coverage(@domains::bigint[]) as coverage) row
            """, owner) { CommandTimeout = 0 }) {
            profile.Parameters.AddWithValue("domains", new[] { domain });
            output.WriteLine("Former queue coverage statement, with nested plans in the PostgreSQL log");
            await using var plan = await profile.ExecuteReaderAsync(ct);
            while (await plan.ReadAsync(ct)) output.WriteLine(plan.GetString(0));
        }
        string log = await fixture.Pg.DiagnosticsAsync(ct);
        int nested = log.IndexOf("Query Text: ", StringComparison.Ordinal);
        if (nested >= 0) output.WriteLine(log[nested..]);

        var repository = new ProblemRepository(connections, TimeProvider.System);
        var reader = new SecurityProblemsReader(repository, new NoEvidence());
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), new ReportDefinitionRegistry().Get("security.problems")!, nativeReader: reader);
        const string endpoint = "/api/v2/reports/security.problems/";
        var elapsed = Stopwatch.StartNew();
        using (var response = await host.Client.GetAsync(endpoint + "data", ct)) {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var result = await ReportFixture.Body(response);
            elapsed.Stop();
            Assert.NotNull(result["items"]);
            Assert.Null(result["coverage"]!["password_detection"]);
        }
        output.WriteLine($"Problems data endpoint {elapsed.Elapsed.TotalMilliseconds:F1} ms");
        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(2), $"Problems data took {elapsed.Elapsed.TotalMilliseconds:F1} ms");

        // The fixture opens a dedicated PostgreSQL login before setting the app role.
        await PostCollectionPostgres.Sql(owner, """
            reset role;
            alter role postgres set session_preload_libraries='auto_explain';
            alter role postgres set auto_explain.log_min_duration=0;
            alter role postgres set auto_explain.log_analyze=on;
            alter role postgres set auto_explain.log_buffers=on;
            alter role postgres set auto_explain.log_timing=off;
            """, ct);
        using (var profiled = await host.Client.GetAsync(endpoint + "data", ct))
            Assert.Equal(HttpStatusCode.OK, profiled.StatusCode);
        string queueLog = await fixture.Pg.DiagnosticsAsync(ct);
        output.WriteLine("Problems data plans after removing the coverage call");
        output.WriteLine(queueLog[log.Length..]);
        await PostCollectionPostgres.Sql(owner, "alter role postgres reset session_preload_libraries", ct);

        elapsed.Restart();
        using var summary = await host.Client.GetAsync(endpoint + $"password-coverage?domain={domain}", ct);
        Assert.Equal(HttpStatusCode.OK, summary.StatusCode);
        var coverage = (await ReportFixture.Body(summary))["coverage"]!["password_detection"]!;
        output.WriteLine($"Separate password coverage endpoint {elapsed.Elapsed.TotalMilliseconds:F1} ms");
        Assert.Equal("observed", coverage["availability"]!.ToString());
        Assert.Collection(coverage["rows"]!.AsArray(), row => Assert.NotNull(row!["last_completed_at"]), row => Assert.NotNull(row!["last_completed_at"]));
    }

    private sealed class ReaderConnections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }

    private sealed class NoEvidence : ISecurityProblemEvidence
    {
        public Task<JsonObject> PageAsync(ReportQueryContext c, long id, JsonObject? cursor, CancellationToken ct) =>
            throw new InvalidOperationException("unexpected evidence read");
    }
}
