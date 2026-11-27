using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class JournalPagePerformanceTests(ITestOutputHelper output)
{
    private sealed class Connections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }

    private sealed record Measurement(string Statement, long Blocks, double Milliseconds);

    private sealed class MeasuredSession(IReportSession inner, List<Measurement> measurements) : IReportSession
    {
        public async Task<IReadOnlyList<JsonObject>> QueryAsync(string sql, IReadOnlyList<object?> values, CancellationToken ct)
        {
            if (sql.StartsWith("with short_events", StringComparison.Ordinal) ||
                sql.StartsWith("select greatest(", StringComparison.Ordinal))
            {
                var explanation = await inner.QueryAsync(Explain + sql, values, ct);
                string name = sql.StartsWith("select greatest(", StringComparison.Ordinal) ? "Seek window" : "Read rows";
                measurements.Add(Measure(name, explanation.Single()["QUERY PLAN"]![0]!));
            }
            return await inner.QueryAsync(sql, values, ct);
        }

        public Task CommitAsync(CancellationToken ct) => inner.CommitAsync(ct);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private const string Explain = "explain (analyze, buffers, timing off, serialize text, format json) ";
    private static readonly (string Label, int Hours)[] Periods = [("2 h", 2), ("24 h", 24), ("7 d", 168)];
    private static readonly JournalOptions Options = new(true, null, null, "all", "", "", 1);

    [Fact]
    public async Task Cold_postgres_page_preserves_rows_within_the_read_and_time_budgets()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        // Exercise the index migration against the actual preceding schema.
        await fixture.InstallAsync(ct, throughVersion: 424);
        await SeedAsync(fixture, ct);
        var connections = new Connections(fixture);
        var reportDatabase = new ReportDatabase(connections);
        var semanticDatabase = new SemanticDatabase(connections);
        var end = new DateTimeOffset(DateTime.UtcNow.Date, TimeSpan.Zero);
        var boundary = end.AddDays(-14);
        var baseline = new List<(JsonObject Page, JsonArray Links)>();
        for (int i = 0; i < Periods.Length; i++)
            baseline.Add(await RunAsync(i, pageOnly: false));

        string migration = MigrationDirectory.Read(425).Single(item => item.Version == 425).Path;
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        var facts = EventsJournalSemanticsTests.WithQueue(EventsJournalSemanticsTests.Facts());
        var reader = new EventsJournalReader(new ReportRunner(reportDatabase), new ReportFixture.FactsRepo(facts), semanticDatabase, null!);
        await using var host = await ReportFixture.Start(facts, new ReportDefinitionRegistry().Get("events.journal")!, nativeReader: reader);
        for (int i = 0; i < Periods.Length; i++)
        {
            var optimized = await RunAsync(i, pageOnly: true);
            foreach (string key in new[] { "items", "has_more", "next_cursor" })
                Assert.True(JsonNode.DeepEquals(baseline[i].Page[key], optimized.Page[key]), $"{Periods[i].Label}: {key} changed");
            Assert.True(JsonNode.DeepEquals(baseline[i].Links, optimized.Links), $"{Periods[i].Label}: problem links changed");
            Assert.NotEmpty(optimized.Links);

            await fixture.Pg.RestartExistingAsync(ct);
            var (label, hours) = Periods[i];
            string from = Uri.EscapeDataString(end.AddHours(-hours).ToString("O", CultureInfo.InvariantCulture));
            string to = Uri.EscapeDataString(end.ToString("O", CultureInfo.InvariantCulture));
            var clock = Stopwatch.StartNew();
            using var response = await host.Client.GetAsync($"/api/v2/reports/events.journal/data?period=custom&from={from}&to={to}&collapse=on&limit=50", ct);
            var body = await ReportFixture.Body(response);
            clock.Stop();
            Assert.True(response.IsSuccessStatusCode, body.ToJsonString());
            var items = body["items"]!.AsArray();
            Assert.Equal(baseline[i].Page["items"]!.AsArray().Select(row => row!["id"]!.GetValue<long>()),
                items.Select(row => row!["id"]!.GetValue<long>()));
            Assert.Equal(900001L, items[0]!["journal_finding_id"]!.GetValue<long>());
            output.WriteLine(FormattableString.Invariant($"{label} cold HTTP response: {clock.Elapsed.TotalMilliseconds:F1} ms"));
            Assert.True(clock.Elapsed <= TimeSpan.FromSeconds(2), $"{label} HTTP response took {clock.Elapsed.TotalMilliseconds:F1} ms");
        }

        await using (var db = await reportDatabase.OpenAsync(false, ct))
        {
            var first = baseline[0].Page;
            string cursor = first["next_cursor"]!.GetValue<string>();
            var previous = await ReadAsync(db, Options, end.AddHours(-2), end, boundary, ct, cursor: cursor);
            var next = await ReadAsync(db, Options with { PageOnly = true }, end.AddHours(-2), end, boundary, ct, cursor: cursor);
            Assert.True(JsonNode.DeepEquals(previous["items"], next["items"]));
            Assert.True(JsonNode.DeepEquals(previous["next_cursor"], next["next_cursor"]));
            var expanded = await ReadAsync(db, Options with { PageOnly = true, Expand = 600003 }, end.AddHours(-2), end, boundary, ct);
            Assert.Equal(new long[] { 600003, 600002, 600001 },
                expanded["items"]!.AsArray().Select(row => row!["id"]!.GetValue<long>()));
        }

        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await using (var db = await reportDatabase.OpenAsync(false, ct))
            Assert.Null((await db.QueryAsync("select to_regclass('public.finding_event_journal425')::text as index_name", [], ct)).Single()["index_name"]);

        async Task<(JsonObject Page, JsonArray Links)> RunAsync(int period, bool pageOnly)
        {
            // A new postmaster starts with empty shared buffers. The host file cache is outside this fixture.
            await fixture.Pg.RestartExistingAsync(ct);
            var measurements = new List<Measurement>();
            var (label, hours) = Periods[period];
            await using var db = await reportDatabase.OpenAsync(false, ct);
            var page = await ReadAsync(new MeasuredSession(db, measurements), Options with { PageOnly = pageOnly },
                end.AddHours(-hours), end, boundary, ct);
            var items = page["items"]!.AsArray();
            Assert.Equal(50, items.Count);
            var ids = items.Select(row => row!["id"]!.GetValue<long>())
                .Concat(items.SelectMany(row => (row!["_journal_members"] as JsonArray ?? [])
                    .Select(member => member![0]!.GetValue<long>())))
                .Distinct().ToArray();
            await using var semantic = await semanticDatabase.OpenAsync(false, ct);
            object?[] args = [ids, new long[] { 1 }];
            var explain = await semantic.QueryAsync(Explain + EventsJournalReader.ProblemLinksSql, ct, args);
            measurements.Add(Measure("Link problems", explain.Single()!["QUERY PLAN"]![0]!));
            var links = await semantic.QueryAsync(EventsJournalReader.ProblemLinksSql, ct, args);
            double total = measurements.Sum(entry => entry.Milliseconds);
            string phase = pageOnly ? "After" : "Before";
            foreach (var entry in measurements)
                output.WriteLine(FormattableString.Invariant($"| {label} | {phase} | {entry.Statement} | {entry.Blocks} | {entry.Milliseconds:F1} |"));
            output.WriteLine(FormattableString.Invariant($"{label} {phase}: {total:F1} ms across the measured statements"));
            if (pageOnly)
            {
                Assert.All(measurements, entry => Assert.True(entry.Blocks <= 2000,
                    $"{label} {entry.Statement} read {entry.Blocks} blocks"));
                Assert.True(total <= 2000, $"{label} took {total:F1} ms");
            }
            return (page, links);
        }
    }

    private static Measurement Measure(string statement, JsonNode explanation)
    {
        static long ReadBlocks(JsonNode? node) => new[] { "Shared Read Blocks", "Local Read Blocks", "Temp Read Blocks" }
            .Sum(key => node?[key]?.GetValue<long>() ?? 0);
        return new(statement, ReadBlocks(explanation["Plan"]) + ReadBlocks(explanation["Planning"]),
            explanation["Planning Time"]!.GetValue<double>() + explanation["Execution Time"]!.GetValue<double>());
    }

    private static Task<JsonObject> ReadAsync(IReportSession db, JournalOptions options, DateTimeOffset start,
        DateTimeOffset end, DateTimeOffset boundary, CancellationToken ct, string? cursor = null)
    {
        var query = new Dictionary<string, string>
        {
            ["time_from"] = start.ToString("O", CultureInfo.InvariantCulture),
            ["time_to"] = end.ToString("O", CultureInfo.InvariantCulture),
        };
        if (cursor is not null) query["cursor"] = cursor;
        return JournalPage.ReadAsync(db, new ReportQuery(), "", new JsonObject(),
            ["id", "event_id", "time_created_utc", "channel", "subject_user_name", "target_user_name"], query, options, 50, boundary, ct);
    }

    private static async Task SeedAsync(SqlPostgresFixture fixture, CancellationToken ct)
    {
        await using var db = await fixture.Pg.OpenAsync(ct);
        await using var seed = new NpgsqlCommand("""
            insert into servers(id,domain_id,hostname,fqdn,role) values (900001,1,'dc01','dc01.example.test','domain_controller');
            select create_event_storage_partitions(current_date-1,current_date);
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
            select n,(current_date-1)::timestamptz+n*interval '171 milliseconds',
                case pair_position when 1 then 4776 when 2 then 4625 when 3 then 4672
                    else case when n%10=5 then 4728 else 4624 end end,
                1,'test-'||(n/10%97),'dc01.example.test','192.0.2.10','dc01.example.test',
                jsonb_build_object('$server_id',900001,'$channel','Security','$provider','Microsoft-Windows-Security-Auditing',
                    '$principals',jsonb_build_object('TargetUserName','test-'||(n/10%97),'IpAddress','192.0.2.10')),
                jsonb_build_object('Status',case when pair_position in (1,2) then '0xc000006a' else '0x0' end),
                jsonb_build_object('LogonType','3','TargetLogonId',case when pair_position=4 then '0x'||to_hex(session_key) end,
                    'SubjectLogonId',case when pair_position=3 then '0x'||to_hex(session_key) end,
                    'synthetic_payload',repeat(md5(n::text),22))
            from generate_series(1,500000) n
            -- Keep pairing dense near the 50-row page and spread independent
            -- events over the whole partition to exercise the legacy scan.
            cross join lateral (select n % stride as pair_position,n / stride + 1 as session_key
                from (select case when n>495000 then 10 else 1000 end as stride) mix) pairs;
            -- The validation witness crosses the repeat bucket boundary. The
            -- two failures inside the later bucket must still collapse together.
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
            select id,current_date::timestamptz-interval '10 minutes'+offset_seconds*interval '1 second',
                kind,1,'boundary-test','dc01.example.test','192.0.2.20','dc01.example.test',
                '{"$server_id":900001,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","$principals":{"TargetUserName":"boundary-test","IpAddress":"192.0.2.20"}}',
                '{"Status":"0xc000006a"}','{"LogonType":"3"}'
            from (values(600001,-0.5,4776),(600002,0.5,4625),(600003,3.0,4625)) e(id,offset_seconds,kind);
            insert into findings(id,fingerprint,rule_code,title,status,severity,source,evidence_count,first_seen_utc,last_seen_utc)
                values(900001,'semantic:'||encode(sha256('journal-finding'::bytea),'hex'),'synthetic-journal-rule','Synthetic journal finding','new','high',
                       'synthetic-journal',50001,now()::text,now()::text);
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields,source_sha256,evidence_role)
            select 900001,event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields,
                sha256(event_id::text::bytea),'synthetic_witness'
            from event_hot where event_id%10=0 or event_id=600003;
            insert into semantic_security_scenarios(scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,strict_keys_json,merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
            values(md5('journal-scenario')::uuid,'synthetic','control_gap',sha256('journal-identity'::bytea),sha256('journal-scenario'::bytea),
                'synthetic','{}',300,'Synthetic journal scenario','Synthetic journal scenario',now(),now(),'low');
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
            values('synthetic-journal',1,'control_health','disabled','{}',sha256('{}'::bytea));
            insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,coverage_status,reason,observed_at_utc,source_reference)
            values(md5('journal-observation')::uuid,sha256('journal-observation'::bytea),'synthetic','synthetic','unknown','Synthetic journal',now(),'synthetic-journal');
            insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,control_health_id,source_reference,evaluation_mode,idempotency_key,evaluation_status,completed_at)
            values(md5('journal-job')::uuid,'synthetic-journal',1,'control_health',md5('journal-observation')::uuid,
                (md5('journal-observation')::uuid)::text,'enabled',sha256('journal-job'::bytea),'completed',now());
            insert into semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,hard_critical,confidence,confidence_score,coverage_status,evaluation_ms)
            values(md5('journal-job')::uuid,md5('journal-scenario')::uuid,'enabled','low',1,1,false,'low',1,'unknown',1);
            insert into semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
            values(md5('journal-scenario')::uuid,900001,md5('journal-job')::uuid,'semantic:'||encode(sha256('journal-finding'::bytea),'hex'),50001);
            """, db) { CommandTimeout = 0 };
        await seed.ExecuteNonQueryAsync(ct);
        foreach (string statement in new[]
        {
            "vacuum (analyze) event_hot",
            "vacuum (analyze) finding_event_copies337",
            "analyze findings",
        })
        {
            seed.CommandText = statement;
            await seed.ExecuteNonQueryAsync(ct);
        }
    }
}
