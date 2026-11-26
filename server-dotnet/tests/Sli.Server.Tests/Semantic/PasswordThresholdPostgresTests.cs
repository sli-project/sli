using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Problems;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordThresholdPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Previous_maximum_accepts_the_threshold_migration_and_rollback()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 417);
        string path = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/418_password_threshold_rules.sql");
        await fixture.Pg.ApplyFileAsync(path, null, ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path, ".rollback.sql"), null, ct);
        await fixture.Pg.ApplyFileAsync(path, null, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Spray_publishes_130_accounts_and_survives_three_hours_and_restart()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddHours(-4).ToUnixTimeSeconds());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,
            await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: start, eventKinds: [4625]), ct);
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner, ct, total: 30001, spacing: 0.36, accountCount: 130);
        await PostCollectionPostgres.Sql(owner, """
            update sli_agent_module_bindings set password_detection_domain_id=1 where module_id='sli.windows.ad-dc';
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
                select '00000000-0000-4000-8000-000000004180',id,id,'telegram',true
                from auth_users where username='platform-owner';
            """, ct);

        long finding = 0;
        long attempts = 0;
        double worst = 0;
        var passes = new[] { 0, 1 }.Concat(Enumerable.Range(14, 23)).ToArray();
        foreach (int pass in passes)
        {
            // Each new runtime and physical connection reads the durable cursor.
            await using var runtime = Runtime(fixture);
            await using var worker = await runtime.OpenAsync(ct);
            var scope = await Scope(worker, ct);
            var now = pass == 0 ? start.AddSeconds(215.8) : start.AddMinutes(5 * pass);
            var timer = Stopwatch.StartNew();
            await Pass(runtime, worker, scope, PasswordAttacks.Spray, now, ct);
            timer.Stop();
            worst = Math.Max(worst, timer.Elapsed.TotalMilliseconds);
            var observed = Assert.Single(await Findings(owner, PasswordAttacks.Spray, ct));
            long count = observed.Facts.Number("attempts");
            Assert.True(count > attempts);
            attempts = count;
            if (pass == 0)
            {
                finding = observed.Id;
                Assert.Equal(600, attempts);
                Assert.Equal(130, observed.Facts.Number("account_count"));
                Assert.Equal(20, observed.Facts["accounts"]!.AsArray().Count);
                Assert.Contains("130", Title(observed.Facts, PasswordAttacks.Spray, "en"));
                Assert.Contains("600", Title(observed.Facts, PasswordAttacks.Spray, "ru"));
            }
            Assert.Equal(finding, observed.Id);
            Assert.Equal(50, observed.Evidence);
        }
        Assert.Equal(30001, attempts);
        await using (var evidence = new NpgsqlCommand("select array_agg(event_id order by event_id) from public.finding_event_copies337 where finding_id=@finding", owner))
        {
            evidence.Parameters.AddWithValue("finding", finding);
            Assert.Equal(Enumerable.Range(900001, 10).Concat(Enumerable.Range(929962, 40)).Select(id => (long)id),
                (long[])(await evidence.ExecuteScalarAsync(ct))!);
        }
        output.WriteLine($"Spray: first pass 600 / 130, 3 h total {attempts}, {passes.Length} passes, maximum {worst:F0} ms including publication, one finding after restart and an 11,000-event catch-up.");
        Assert.True(worst < 2000, $"Maximum detection + publication pass: {worst:F0} ms");
        await using var status = new NpgsqlCommand("select state from public.read_password_threshold_status418(array[1::bigint]) where rule_id=@rule", owner);
        status.Parameters.AddWithValue("rule", PasswordAttacks.Spray);
        Assert.Equal("current", await status.ExecuteScalarAsync(ct));
        await using var retired = new NpgsqlCommand("select count(*) from public.semantic_password_checkpoints", owner);
        Assert.Equal(0L, await retired.ExecuteScalarAsync(ct));
        await using var notifications = new NpgsqlCommand("select count(*) from public.notification_outbox where object_kind='semantic_finding' and channel='telegram'", owner);
        Assert.Equal(1L, await notifications.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task Brute_force_correlates_success_and_4776_without_crossing_subthreshold_counts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = DateTimeOffset.UtcNow.AddMinutes(-5);
        var rows = new List<(int Kind, string Account, string Address, int Second)>();
        for (int i = 0; i < 25; i++) rows.Add((4625, "Case-Target", $"192.0.2.{i % 4 + 1}", i));
        rows.Add((4624, "case-target", "192.0.2.4", 25));
        for (int i = 0; i < 20; i++) rows.Add((4776, "fallback", "-", i));
        for (int i = 0; i < 19; i++)
        {
            rows.Add((4625, "sub-threshold", "192.0.2.50", i));
            rows.Add((4776, "sub-threshold", "-", i));
        }
        for (int i = 0; i < 9; i++) rows.Add((4625, $"spray-target-{i}", "192.0.2.51", i));
        var events = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: start,
            eventKinds: rows.Select(r => r.Kind).ToArray(), nativeAccounts: rows.Select(r => r.Account).ToArray(),
            nativeAddresses: rows.Select(r => r.Address).ToArray(), nativeTimestamps: rows.Select(r =>
                start.AddSeconds(r.Second).ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ", CultureInfo.InvariantCulture)).ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, events, ct);
        await using var runtime = Runtime(fixture);
        await using var worker = await runtime.OpenAsync(ct);
        var detection = await new DetectionProducer(new(), new()).RunOnceAsync(worker, ct, refreshImport: false);
        Assert.Equal(0, detection.Failed);
        Assert.Equal(2, detection.Jobs);
        await Publish(runtime, worker, detection.Jobs, ct);

        var findings = await Findings(owner, PasswordAttacks.Brute, ct);
        Assert.Equal(2, findings.Count);
        var brute = Assert.Single(findings, f => f.Severity == "critical");
        Assert.Equal(25, brute.Facts.Number("attempts"));
        Assert.Equal(4, brute.Facts.Number("address_count"));
        Assert.True(brute.Facts.Flag("password_success"));
        Assert.Contains("25", Title(brute.Facts, PasswordAttacks.Brute, "en"));
        var fallback = Assert.Single(findings, f => f.Severity == "high");
        Assert.Equal(20, fallback.Facts.Number("attempts"));
        Assert.Empty(await Findings(owner, PasswordAttacks.Spray, ct));
        output.WriteLine("Brute force: 25 failures across 4 addresses plus success => critical. NTLM-only 20 => high. 19 with same-second NTLM duplicates and 9 spray accounts => no findings.");
    }

    private static string Title(JsonObject facts, string rule, string locale) => ProblemJson.Text(ProblemPresentation.RuleMessage(
        new() { ["rule_code"] = "semantic." + rule, ["presentation_facts"] = facts.DeepClone() }, "title", locale)["text"]);

    private static PasswordProducerRuntime Runtime(SqlPostgresFixture fixture) => PasswordProducerRuntime.Create(
        name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
        _ => throw new InvalidOperationException());

    private static async Task<PasswordScope> Scope(NpgsqlConnection db, CancellationToken ct)
    {
        await using var source = new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", db);
        return PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
    }

    private static async Task Pass(PasswordProducerRuntime runtime, NpgsqlConnection worker, PasswordScope scope, string rule, DateTimeOffset now, CancellationToken ct)
    {
        int jobs = await DetectionProducer.RunPasswordThreshold(worker, scope, rule, now, ct);
        await Publish(runtime, worker, jobs, ct);
    }

    private static async Task Publish(PasswordProducerRuntime runtime, NpgsqlConnection worker, int jobs, CancellationToken ct)
    {
        var production = new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticRuntimeSettings.FindingsMode, 16);
        var result = await production.ProcessRisk(worker, ct);
        if (result.Number("failed") != 0)
        {
            await using var error = new NpgsqlCommand("select last_error_detail from semantic_risk_evaluation_jobs where evaluation_status='failed' order by updated_at desc limit 1", worker);
            Assert.Fail($"Threshold risk publication failed: {await error.ExecuteScalarAsync(ct)}");
        }
        Assert.Equal(jobs, result.Number("completed"));
    }

    private static async Task<List<(long Id, string Severity, int Evidence, JsonObject Facts)>> Findings(NpgsqlConnection db, string rule, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select id,severity,evidence_count,public.password_problem_facts395(id,rule_code)::text from findings where rule_code=@rule", db);
        command.Parameters.AddWithValue("rule", "semantic." + rule);
        await using var rows = await command.ExecuteReaderAsync(ct);
        var result = new List<(long, string, int, JsonObject)>();
        while (await rows.ReadAsync(ct)) result.Add((rows.GetInt64(0), rows.GetString(1), rows.GetInt32(2), JsonNode.Parse(rows.GetString(3))!.AsObject()));
        return result;
    }
}
