using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class JournalPagePostgresTests(ITestOutputHelper output)
{
    private sealed class Connections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<Npgsql.NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }
    private sealed class MeasuredSession(IReportSession db, ITestOutputHelper output, int budgetMs) : IReportSession
    {
        private bool measured;
        public async Task<IReadOnlyList<JsonObject>> QueryAsync(string sql, IReadOnlyList<object?> values, CancellationToken ct)
        {
            if (!measured && sql.StartsWith("with short_events", StringComparison.Ordinal))
            {
                measured = true;
                var result = await db.QueryAsync("explain (analyze, timing off, serialize text, format json) " + sql, values, ct);
                var plan = result.Single()["QUERY PLAN"]![0]!;
                double planning = plan["Planning Time"]!.GetValue<double>();
                double execution = plan["Execution Time"]!.GetValue<double>();
                double statement = planning + execution;
                output.WriteLine($"PostgreSQL journal query with output serialization: {statement:F1} ms (budget {budgetMs} ms)");
                Assert.True(statement < budgetMs, $"Journal PostgreSQL query exceeded {budgetMs} ms: {statement:F1} ms");
            }
            return await db.QueryAsync(sql, values, ct);
        }

        public Task CommitAsync(CancellationToken ct) => db.CommitAsync(ct);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    }

    [Fact]
    public async Task Counts_groups_pages_and_finds_earlier_events_in_the_granted_slice()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using (var seed = await fixture.Pg.OpenAsync(ct))
            await PostCollectionPostgres.Sql(seed, """
                insert into servers(id,domain_id,hostname,fqdn,role)
                    select 900001,id,'dc01','dc01.example.test','domain_controller' from domains where fqdn='example.test';
                insert into servers(id,domain_id,hostname,fqdn,role)
                    select 900002,id,'dc02','dc02.example.test','domain_controller' from domains where fqdn='example.test';
                update domains set netbios_name='EXAMPLE' where fqdn='example.test';
                select create_event_storage_partitions(current_date-1,current_date);
                select create_event_storage_partitions(current_date-20,current_date-20);
                insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
                select n,((current_date-1)::timestamp at time zone 'UTC')+interval '10 hours'+n*interval '20 milliseconds',
                    4624,1,'EXAMPLE\test-bulk-'||(n%45),'dc01.example.test','192.0.2.1','dc01.example.test',
                    '{"$server_id":900001,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","LogonType":"3"}',
                    '{}','{}'
                from generate_series(1,23000) n;
                insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
                select id,((current_date-1)::timestamp at time zone 'UTC')+interval '11 hours'+seconds*interval '1 second',
                    code,1,actor,'dc01.example.test',address,case when id=24002 then 'dc02.example.test' else 'dc01.example.test' end,
                    jsonb_build_object('$server_id',case when id=24002 then 900002 else 900001 end,'$channel','Security',
                        '$provider',case when code=1102 then 'Microsoft-Windows-Eventlog' else 'Microsoft-Windows-Security-Auditing' end,
                        '$principals',jsonb_build_object('TargetUserName',account,'TargetDomainName',
                            case id when 24001 then 'dc01.example.test' when 24002 then 'REPORTED' when 24020 then null else 'EXAMPLE' end,
                            'SubjectUserName',initiator,'SubjectDomainName','EXAMPLE',
                            'IpAddress',case when id between 24014 and 24016 or id=24026 then address end)),
                    jsonb_strip_nulls(jsonb_build_object('Status',status)),
                    jsonb_strip_nulls(jsonb_build_object('LogonType',logon_type,
                        'TargetLogonId',case id when 24021 then '0x42' when 24027 then '0x43' end,
                        'SubjectLogonId',case when id in (24022,24023) then '0x42' when id=24028 then '0x43' end))
                from (values
                    (24001,181,4625,'dc01.example.test','пример','operator','192.0.2.10','3','0xc000006a'),
                    (24002,182,4625,'dc01.example.test','ПРИМЕР','operator','192.0.2.10','3','0xc000006d'),
                    (24003,183,4625,'dc01.example.test','other-user','operator','192.0.2.10','3','0xc000006d'),
                    (24004,184,4625,'dc01.example.test','пример','operator','192.0.2.11','3','0xc000006d'),
                    (24005,185,4625,'dc01.example.test','пример','operator','192.0.2.10','9','0xc000006d'),
                    (24006,186,4625,'dc01.example.test','пример','operator','192.0.2.15','3','0xc000006a'),
                    (24007,187,4625,'dc01.example.test',null,'operator','192.0.2.10','3','0xc000006d'),
                    (24008,188,4625,'dc01.example.test',null,'operator','192.0.2.10','3','0xc000006d'),
                    (24009,600,4625,'dc01.example.test','пример','operator','192.0.2.10','3','0xc000006d'),
                    (24010,190,4624,'EXAMPLE\target-user','target-user','target-user','192.0.2.10','3',null),
                    (24011,191,4624,'EXAMPLE\target-user','target-user','target-user','192.0.2.10','3',null),
                    (24012,192,4672,'EXAMPLE\privileged-user',null,'privileged-user',null,null,null),
                    (24013,193,4672,'EXAMPLE\privileged-user',null,'privileged-user',null,null,null),
                    (24014,194,4776,'EXAMPLE\credential-user','different-name',null,'192.0.2.12',null,'0xc000006a'),
                    (24015,195,4776,'EXAMPLE\credential-user','different-name',null,'192.0.2.12',null,'0xc000006a'),
                    (24016,196,4776,'EXAMPLE\credential-user','different-name',null,'192.0.2.12',null,'0x0'),
                    (24017,197,4624,'EXAMPLE\device$','device$',null,'192.0.2.13','3',null),
                    (24018,198,4728,'EXAMPLE\operator','test-group','operator',null,null,null),
                    (24019,200,1102,'EXAMPLE\operator',null,'operator',null,null,null),
                    (24020,180,4776,'пример','пример',null,'reported-station',null,'0xc000006a'),
                    (24021,211,4624,'EXAMPLE\privileged-user','privileged-user',null,'192.0.2.13','10',null),
                    (24022,211,4672,'EXAMPLE\privileged-user',null,'privileged-user',null,null,null),
                    (24023,301,4672,'EXAMPLE\privileged-user',null,'privileged-user',null,null,null),
                    (24024,212,4740,'EXAMPLE\operator','target-user','operator',null,null,null),
                    (24025,213,4776,'EXAMPLE\credential-user','credential-user',null,'192.0.2.253',null,'0xc000006a'),
                    (24026,181,4776,'пример','пример',null,'192.0.2.99',null,'0xc000006a'),
                    (24027,217,4624,'EXAMPLE\service-user','service-user',null,null,'5',null),
                    (24028,217,4672,'EXAMPLE\service-user',null,'service-user',null,null,null)
                ) v(id,seconds,code,actor,account,initiator,address,logon_type,status);
                insert into event_cold_daily(day,grouping_key,event_kind,domain_id,actor,target,source,computer,method,outcome,event_count,first_seen_utc,last_seen_utc)
                select current_date-20,sha256(('journal-totals-'||kind)::bytea),kind,1,'synthetic-daily',null,'192.0.2.10','dc01.example.test',
                    '{"$server_id":900001,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}','{}',
                    9223372036854775807::bigint,((current_date-20)::timestamp at time zone 'UTC')+interval '1 hour',
                    ((current_date-20)::timestamp at time zone 'UTC')+interval '2 hours'
                from (values (4624),(4720)) v(kind);
                """, ct);

        DateTimeOffset to = new(DateTime.UtcNow.Date.AddDays(-1).AddHours(12), TimeSpan.Zero);
        DateTimeOffset from = to.AddHours(-2);
        DateTimeOffset boundary = new(DateTime.UtcNow.Date.AddDays(-14), TimeSpan.Zero);
        await using var db = await new ReportDatabase(new Connections(fixture)).OpenAsync(false, ct);
        async Task<JsonObject> Read(JournalOptions options, int limit = 25, string? cursor = null, string? search = null,
            long domain = 1, string[]? fields = null, DateTimeOffset? start = null, DateTimeOffset? end = null, int? budgetMs = null,
            bool includePeriodMetadata = false)
        {
            var sql = new ReportQuery();
            string scope = " where event.domain_id=" + sql.Parameter(domain);
            var query = new Dictionary<string, string>
            {
                ["time_from"] = (start ?? from).ToString("O", CultureInfo.InvariantCulture),
                ["time_to"] = (end ?? to).ToString("O", CultureInfo.InvariantCulture)
            };
            if (cursor is not null) query["cursor"] = cursor;
            if (search is not null) query["q"] = search;
            if (options.View is "attention" or "tasks") query["view"] = options.View;
            var result = await JournalPage.ReadAsync(budgetMs is { } budget ? new MeasuredSession(db, output, budget) : db, sql, scope, new JsonObject(),
                fields ?? ["id", "event_id", "time_created_utc", "channel", "subject_user_name", "target_user_name"],
                query, options with { PageOnly = !includePeriodMetadata }, limit, boundary, ct);
            return result;
        }

        var options = new JournalOptions(true, null, null, "all", "", "", null);
        var first = await Read(options, budgetMs: 2000);
        var firstCounts = (await Read(options, includePeriodMetadata: true))["journal_counts"];
        await Read(options, end: from.AddSeconds(100), budgetMs: 1000);
        var rows = first["items"]!.AsArray().OfType<JsonObject>().ToArray();
        JsonObject Row(long id) => Assert.Single(rows, row => row["id"]!.GetValue<long>() == id);
        var group = Row(24002);
        Assert.Equal(@"EXAMPLE\ПРИМЕР", group["journal_account"]!.GetValue<string>());
        Assert.Equal(@"EXAMPLE\operator", group["journal_initiator"]!.GetValue<string>());
        Assert.Equal("192.0.2.10", group["journal_address"]!.GetValue<string>());
        Assert.Null(group["journal_computer"]);
        Assert.Equal("3", group["logon_type"]!.GetValue<string>());
        Assert.Equal("failed_logon", group["journal_action"]!.GetValue<string>());
        Assert.Equal(2, group["event_count"]!.GetValue<long>());
        Assert.Equal(3, group["journal_source_count"]!.GetValue<long>());
        Assert.DoesNotContain(rows, row => row["id"]!.GetValue<long>() is 24020 or 24022);
        Assert.Equal("192.0.2.99", Row(24026)["journal_address"]!.GetValue<string>());
        Assert.Equal("privileged_logon", Row(24021)["journal_action"]!.GetValue<string>());
        Assert.Equal(1, Row(24021)["event_count"]!.GetValue<long>());
        Assert.Equal("192.0.2.13", Row(24021)["journal_address"]!.GetValue<string>());
        Assert.Equal("10", Row(24021)["logon_type"]!.GetValue<string>());
        Assert.Null(Row(24023)["journal_action"]);
        Assert.Null(Row(24025)["journal_address"]);
        Assert.Equal("192.0.2.253", Row(24025)["journal_workstation"]!.GetValue<string>());
        Assert.NotEqual(group["first_seen_utc"]!.ToString(), group["last_seen_utc"]!.ToString());
        Assert.Null(Row(24011)["journal_initiator"]);
        Assert.Equal(@"EXAMPLE\credential-user", Row(24015)["journal_account"]!.GetValue<string>());
        Assert.Equal("success", Row(24016)["journal_result"]!.GetValue<string>());
        Assert.Null(Row(24008)["journal_account"]);
        foreach (long id in new long[] { 24003, 24004, 24005, 24006, 24007, 24008, 24009, 24012, 24013, 24016, 24023 })
            Assert.False(Row(id)["journal_expandable"]!.GetValue<bool>());

        var paired = await Read(options with { Expand = 24002 }, budgetMs: 2000);
        var evidence = paired["items"]!.AsArray().OfType<JsonObject>().ToArray();
        Assert.Equal(new long[] { 24002, 24001, 24020 }, evidence.Select(row => row["id"]!.GetValue<long>()));
        Assert.Equal(new[] { @"REPORTED\ПРИМЕР", @"dc01.example.test\пример", "пример" },
            evidence.Select(row => row["journal_reported_account"]!.GetValue<string>()));
        Assert.Equal(new[] { "dc02.example.test", "dc01.example.test", "dc01.example.test" },
            evidence.Select(row => row["journal_computer"]!.GetValue<string>()));
        Assert.Equal(new long[] { 24001, 24002, 24020 },
            group["_journal_members"]!.AsArray().Select(member => member![0]!.GetValue<long>()).Order());
        var privilegedEvidence = await Read(options with { Expand = 24021 }, budgetMs: 2000);
        Assert.Equal(new long[] { 24022, 24021 }, privilegedEvidence["items"]!.AsArray().Select(row => row!["id"]!.GetValue<long>()));

        foreach (long id in new long[] { 24011, 24015 })
        {
            var parent = Row(id);
            Assert.True(parent["journal_expandable"]!.GetValue<bool>());
            var expanded = options with { Expand = id };
            var page = await Read(expanded, limit: 1);
            Assert.True(page["has_more"]!.GetValue<bool>());
            Assert.Null(page["journal_counts"]);
            var next = await Read(expanded, limit: 1, cursor: page["next_cursor"]!.GetValue<string>());
            var members = page["items"]!.AsArray().Concat(next["items"]!.AsArray()).ToArray();
            Assert.Equal(new[] { id, id - 1 }, members.Select(row => row!["id"]!.GetValue<long>()));
            Assert.Equal(members.LongLength, parent["event_count"]!.GetValue<long>());
            Assert.All(members, row => Assert.False(row!["journal_expandable"]!.GetValue<bool>()));
            Assert.Empty((await Read(expanded, domain: 2))["items"]!.AsArray());
        }

        var withinWindow = await Read(options, start: from.AddHours(1).AddSeconds(182), end: from.AddHours(1).AddSeconds(183));
        Assert.False(Assert.Single(withinWindow["items"]!.AsArray())!["journal_expandable"]!.GetValue<bool>());
        var accountPivot = await Read(options with { Pivot = "account" }, search: @"EXAMPLE\Пример");
        Assert.Contains(accountPivot["items"]!.AsArray(), row => row!["id"]!.GetValue<long>() == 24002);
        var withoutCollapse = await Read(options with { Collapse = false }, limit: 25);
        Assert.Contains(withoutCollapse["items"]!.AsArray(), row => row!["id"]!.GetValue<long>() == 24001);
        var services = await CheckView("service");
        Assert.Equal(new long[] { 24027, 24017 }, services["items"]!.AsArray().Select(row => row!["id"]!.GetValue<long>()));
        Assert.Equal(2, services["items"]![0]!["journal_source_count"]!.GetValue<long>());
        Assert.DoesNotContain(rows, row => row["id"]!.GetValue<long>() is 24017 or 24027 or 24028);
        var failures = await CheckView("failures");
        Assert.All(failures["items"]!.AsArray(), row => Assert.Equal("failure", row!["journal_result"]!.GetValue<string>()));
        Assert.Contains(failures["items"]!.AsArray(), row => row!["id"]!.GetValue<long>() == 24015);
        Assert.Contains(failures["items"]!.AsArray(), row => row!["id"]!.GetValue<long>() == 24024);
        var logons = await CheckView("authentication");
        Assert.Contains(logons["items"]!.AsArray(), row => row!["id"]!.GetValue<long>() == 24013);
        Assert.DoesNotContain(logons["items"]!.AsArray(), row => row!["id"]!.GetValue<long>() == 24017);
        var smallPage = await Read(options, limit: 3);
        var second = await Read(options, limit: 3, cursor: smallPage["next_cursor"]!.GetValue<string>());
        Assert.Equal(rows.Skip(3).Take(3).Select(row => row["id"]!.GetValue<long>()),
            second["items"]!.AsArray().Select(row => row!["id"]!.GetValue<long>()));
        var lightweight = await Read(options, fields: ["id", "channel"]);
        Assert.Null(lightweight["journal_counts"]);
        Assert.All(lightweight["items"]!.AsArray(), row => {
            Assert.Null(row!["journal_account"]);
            Assert.False(row["journal_expandable"]!.GetValue<bool>());
        });
        var dailyStart = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-20), TimeSpan.Zero);
        var daily = await Read(options, start: dailyStart, end: dailyStart.AddHours(3));
        Assert.Equal(2m * long.MaxValue, daily["journal_event_count"]!.GetValue<decimal>());
        Assert.Equal(2m * long.MaxValue, daily["journal_counts"]!["all"]!.GetValue<decimal>());
        Assert.Equal((decimal)long.MaxValue, daily["journal_counts"]!["accounts"]!.GetValue<decimal>());

        var before = await Read(options with { Before = 24011 }, 5);
        Assert.Null(before["journal_counts"]);
        Assert.Contains(before["items"]!.AsArray(), row => row!["id"]!.GetValue<long>() == 24010);
        Assert.Empty((await Read(options with { Before = 24011 }, domain: 2))["items"]!.AsArray());

        async Task<JsonObject> CheckView(string view)
        {
            var page = await Read(options with { View = view }, budgetMs: 2000);
            var report = await Read(options with { View = view }, includePeriodMetadata: true);
            Assert.True(JsonNode.DeepEquals(firstCounts, report["journal_counts"]));
            Assert.True(JsonNode.DeepEquals(firstCounts![view], report["journal_event_count"]));
            return page;
        }
    }
}
