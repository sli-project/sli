using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Reporting.V2;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class DomainEventRowsTests(ITestOutputHelper output)
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly DateTimeOffset Day = new(DateTime.UtcNow.Date.AddDays(-2), TimeSpan.Zero);
    static readonly DateTimeOffset Attempt = Day.AddHours(1);
    static readonly AdPeriod Period = new(Day.AddDays(-6), Day.AddDays(1));
    static AdReportRequest Request(int limit = 50, string? cursor = null, JsonObject? filters = null) => new("security", false, false, 7, Period, limit, filters ?? new(), cursor);
    static JsonObject Event(int code) => new() { ["event_db_id"] = 1, ["event_id"] = code, ["time_created_utc"] = AdJson.Iso(Attempt) };

    [Fact]
    public async Task Windows_failure_pair_is_one_row_before_paging_without_hiding_other_attempts()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct);
        await using var owner = await fixture.Pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(owner, """
            insert into domains(id,forest_id,fqdn)
            select d.id,f.forest_id,d.fqdn from domains f
            cross join (values(7,'selected.example.test'),(8,'other.example.test')) d(id,fqdn) where f.id=1;
            insert into servers(id,domain_id,hostname,role) values
                (1,7,'dc01.example.test','domain_controller'),(2,7,'dc02.example.test','domain_controller'),
                (3,8,'dc03.example.test','domain_controller');
            """, Ct);
        ShortEventRow Observation(long id, int kind, string? address = "192.0.2.10", long server = 1,
            long domain = 7, string account = "fixture-user", DateTimeOffset? at = null, string keywords = "AuditFailure",
            string? subject = null)
        {
            string computer = $"dc0{server}.example.test";
            var method = new JsonObject { ["$server_id"] = server, ["$channel"] = "Security",
                ["$provider"] = "Microsoft-Windows-Security-Auditing" };
            if (subject is not null) method["$principals"] = new JsonObject { ["SubjectUserName"] = subject };
            return new ShortEventRow(id, (at ?? Attempt).UtcDateTime, kind, "summary", account, null, address, computer,
                domain, method.ToJsonString(), new JsonObject { ["keywords"] = keywords }.ToJsonString(), new Dictionary<string, string?>());
        }
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, [Observation(10, 4625), Observation(11, 4771)], Ct);
        await using var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await db.OpenAsync(Ct);
        async Task<List<JsonObject>> Read(AdReportRequest request)
        {
            var query = AdSecurityQuery.Create(request);
            return await AdJson.ReadAsync(db, query.SelectSql, Ct, query.Args.ToArray());
        }
        var pair = Assert.Single(await Read(Request()));
        var row = Assert.Single(AdSecurity.Compose(Request(), [pair], true, false, new())["items"]!.AsArray())!.AsObject();
        SecurityEventsReader.Derived(row);
        Assert.Equal("Неудачный вход", row["change_text"]!.ToString());
        Assert.Null(row["actor"]!["name"]);
        Assert.Equal("fixture-user", row["affected_account"]!["name"]!.ToString());
        Assert.Equal(new long[] { 10, 11 }, row["evidence"]!["related_event_db_ids"]!.AsArray().Select(n => n!.GetValue<long>()).Order());

        // A repeated event of the same kind is another attempt, even at the same instant.
        var repeated = Observation(12, 4625);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, [repeated, Observation(20, 4625, "192.0.2.20"),
            Observation(21, 4771, server: 2), Observation(22, 4625, account: "another-user", subject: "observed-subject"),
            Observation(23, 4771, at: Attempt.AddTicks(10)), Observation(24, 4625, null), Observation(25, 4771, null),
            Observation(26, 4625, server: 3, domain: 8)], Ct);
        var expected = await Read(Request());
        Assert.Equal(8, expected.Count);
        var seen = new List<long>(); string? cursor = null;
        do
        {
            var request = Request(1, cursor);
            var batch = await Read(request);
            var result = AdSecurity.Compose(request, batch.Take(1).ToArray(), true, batch.Count > 1, new());
            seen.Add(AdJson.Int(Assert.Single(result["items"]!.AsArray()), "event_db_id"));
            cursor = result["next_cursor"]?.ToString();
        } while (cursor is not null);
        Assert.Equal(expected.Select(r => AdJson.Int(r, "event_db_id")), seen);
        var exact = await Read(Request(filters: new JsonObject { ["event_id"] = 4625 }));
        Assert.Contains(exact, r => AdJson.Int(r, "event_db_id") == 10);
        Assert.All(exact, r => Assert.Equal(4625, AdJson.Int(r, "event_id")));

        // Reimport of the same Windows record is also a single displayed event.
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, [repeated], Ct);
        Assert.Equal(expected.Count, (await Read(Request())).Count);
        // Credential validation failure joins the pair; successful validation remains separate.
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, [Observation(40, 4776, "192.0.2.20"),
            Observation(41, 4776, "192.0.2.20", keywords: "AuditSuccess")], Ct);
        Assert.Equal(expected.Count + 1, (await Read(Request())).Count);

        // A first page must not sort the retained week through the pairing windows.
        await using (var population = new NpgsqlCommand("""
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,source,computer,method,outcome,fields)
            select n,@start+n*interval '1 second',4625,7,'fixture-user','192.0.2.10','dc01.example.test',
                '{"$server_id":1,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}',
                '{"keywords":"AuditFailure"}','{}' from generate_series(1000,31000) n;
            analyze event_hot;
            """, owner) { CommandTimeout = 0 }) {
            population.Parameters.AddWithValue("start", Day.AddHours(2).UtcDateTime);
            await population.ExecuteNonQueryAsync(Ct);
        }
        var bounded = AdSecurityQuery.Create(Request());
        var plan = await AdJson.ReadAsync(db, "explain(analyze,format json) " + bounded.SelectSql, Ct, bounded.Args.ToArray());
        var explanation = JsonNode.Parse(plan[0].First().Value!.ToString())![0]!;
        var root = explanation["Plan"]!;
        output.WriteLine("Seven-day page query, 30001 synthetic events plus pairing fixtures: {0} ms", explanation["Execution Time"]!);
        void CheckWindows(JsonNode node)
        {
            if (node["Node Type"]?.ToString() == "WindowAgg")
                Assert.True(node["Actual Rows"]!.GetValue<double>() <= 102, "Pairing window processed " + node["Actual Rows"] + " rows");
            foreach (var child in node["Plans"] as JsonArray ?? []) CheckWindows(child!);
        }
        CheckWindows(root);
        var firstPage = await Read(Request());
        Assert.Equal(51, firstPage.Count);
        Assert.Equal(31000, AdJson.Int(firstPage[0], "event_db_id"));
        string next = AdSecurity.EncodeCursor(7, Period, new(), AdJson.Time(firstPage[49], "time_created_utc"), AdJson.Int(firstPage[49], "event_db_id"));
        var nextPage = await Read(Request(cursor: next));
        Assert.Equal(51, nextPage.Count);
        Assert.Equal(30950, AdJson.Int(nextPage[0], "event_db_id"));
        var filtered = Request(filters: new JsonObject { ["target_account"] = "another-user" });
        var unique = Assert.Single(await Read(filtered));
        Assert.Equal(22, AdJson.Int(unique, "event_db_id"));
        var stated = Assert.Single(AdSecurity.Compose(filtered, [unique], true, false, new())["items"]!.AsArray())!;
        Assert.Equal("observed-subject", stated["actor"]!["name"]!.ToString());
        Assert.Equal("another-user", stated["affected_account"]!["name"]!.ToString());
    }

    [Theory]
    [InlineData("-")]
    [InlineData(" - ")]
    [InlineData("—")]
    [InlineData("%%1793")]
    [InlineData("")]
    public void Windows_missing_values_are_absent_for_all_principals(string value)
    {
        var source = Event(4728);
        foreach (string field in new[] { "subject_user_sid", "subject_user_name", "target_user_sid", "target_user_name", "membership_member_sid", "membership_member_name", "source_host" }) source[field] = value;
        var row = Assert.Single(AdSecurity.Compose(Request(), [source], true, false, new())["items"]!.AsArray())!;
        foreach (string field in new[] { "actor", "group", "member", "affected_account", "source_host" })
        {
            Assert.Equal("unknown", row[field]!["state"]!.ToString());
            Assert.Null(row[field]!["name"]);
            Assert.Null(row[field]!["sid"]);
        }
        source["subject_user_name"] = "fixture-user";
        Assert.Equal("fixture-user", AdJson.Principal(source, "subject_user_sid", "subject_user_name")["name"]!.ToString());
    }

    public static IEnumerable<object[]> EventKinds() => AdHistory.Ids("SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS").Select(id => new object[] { id });

    [Theory]
    [MemberData(nameof(EventKinds))]
    public void Each_supported_event_has_an_action_in_both_languages(int id)
    {
        var row = Assert.Single(AdSecurity.Compose(Request(), [Event(id)], true, false, new())["items"]!.AsArray())!.AsObject();
        SecurityEventsReader.Derived(row);
        foreach (bool english in new[] { false, true })
        {
            var result = ReportPresentation.Apply(new JsonObject { ["report_key"] = "security.events.chains", ["items"] = new JsonArray(row.DeepClone()) }, english);
            string text = result["items"]![0]!["change_text"]!.ToString();
            Assert.False(string.IsNullOrWhiteSpace(text));
            Assert.DoesNotContain("_", text);
            Assert.DoesNotContain("не подтверждено", text);
            if (id is 4625 or 4771) Assert.Equal(english ? "Failed sign-in" : "Неудачный вход", text);
        }
    }
}
