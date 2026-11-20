using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class SecurityLockoutRecurringTests
{
    static IConfiguration Legacy => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"]="false" }).Build();
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    static readonly DateTimeOffset Start = new(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject Event(int id, int code, double minute, string? sid = Sid, string? result = null,
        string? ip = null, JsonObject? facts = null, bool normalized = true) => new()
    {
        ["event_db_id"] = id, ["event_id"] = code,
        ["time_created_utc"] = Start.AddMinutes(minute).ToString("O", CultureInfo.InvariantCulture),
        ["target_user_sid"] = sid, ["target_user_name"] = "account-a", ["result_code"] = result,
        ["ip_address"] = ip, ["normalized_event_id"] = normalized ? id.ToString(CultureInfo.InvariantCulture) : null,
        ["facts_json"] = facts ?? new JsonObject()
    };
    static JsonObject[] Aggregate(IEnumerable<JsonObject> events, string? account = null, string? caller = null,
        string? code = null, int minimum = 1, bool truncated = false) =>
        SecurityObservationReader.Lockouts(events, 15, minimum, account, caller, code, truncated);
    static long Number(JsonNode row, string key) => long.Parse(row[key]!.ToString(), CultureInfo.InvariantCulture);
    static string[] Strings(JsonNode row, string key) => row[key]!.AsArray().Select(n => n!.ToString()).ToArray();

    [Fact]
    public void Episodes_match_exact_sid_once_and_link_all_observations()
    {
        var events = new[] { Event(1, 4625, -2, result: "0xC000006A", ip: "192.0.2.1"),
            Event(2, 4740, 0, facts: new() { ["caller_computer"] = "workstation-a" }), Event(3, 4767, 4),
            Event(4, 4771, 6, facts: new() { ["result_code"] = "0x18" }), Event(5, 4740, 10),
            Event(6, 4776, 15, result: "0xC000006A", facts: new() { ["workstation"] = "workstation-b" }),
            Event(7, 4740, 20), Event(8, 4767, 21) };
        var row = Assert.Single(Aggregate(events.Reverse().Append(events[0])));
        Assert.Equal(3, Number(row, "lockouts")); Assert.Equal(1, Number(row, "relocks")); Assert.Equal(2, Number(row, "unlocks"));
        Assert.Equal(3, Number(row, "failures")); Assert.Equal(3, Number(row, "matched_lockouts"));
        Assert.Equal(new double[] { 600, 600 }, row["intervals_seconds"]!.AsArray().Select(n => n!.GetValue<double>()));
        Assert.Equal(600, row["last_interval_seconds"]!.GetValue<double>());
        Assert.Equal("2026-10-01T00:00:00Z", row["first_lockout"]!.ToString());
        Assert.Equal("2026-10-01T00:20:00Z", row["last_lockout"]!.ToString());
        Assert.Equal("all_with_failures", row["matching"]!.ToString());
        Assert.Equal(["workstation-a"], Strings(row, "callers")); Assert.Equal(["192.0.2.1"], Strings(row, "ips"));
        Assert.Equal(["workstation-b"], Strings(row, "workstations")); Assert.Equal(["0x18", "0xc000006a"], Strings(row, "failure_codes"));
        Assert.Equal(new long[] { 2, 7, 8, 6 }, new[] { "first_event", "last_event", "unlock_event", "failure_event" }.Select(k => Number(row, k)));
        Assert.Equal(Enumerable.Range(1, 8).Select(n => n.ToString(CultureInfo.InvariantCulture)), Strings(row, "event_ids").OrderBy(int.Parse));
    }

    [Theory]
    [InlineData(null)] [InlineData("-")] [InlineData("S-1-0-0")] [InlineData("invalid")]
    public void Unknown_identities_never_merge_by_name_or_match_failures(string? sid)
    {
        var rows = Aggregate([Event(1, 4740, 0, sid), Event(2, 4740, 10, sid), Event(3, 4625, -1, sid), Event(4, 4767, 5, sid)]);
        Assert.Equal(["unknown:1", "unknown:2"], rows.Select(r => r["account_key"]!.ToString()));
        Assert.All(rows, r => { Assert.Equal(1, Number(r, "lockouts")); Assert.Equal(0, Number(r, "failures"));
            Assert.Equal(0, Number(r, "relocks")); Assert.Equal(0, Number(r, "unlocks")); Assert.Null(r["sid"]); Assert.Equal("unknown_sid", r["matching"]!.ToString()); });
    }

    [Fact]
    public void Same_name_with_different_sid_does_not_match()
    {
        var row = Assert.Single(Aggregate([Event(1, 4740, 0), Event(2, 4740, 10), Event(3, 4625, -1, Sid + "9"), Event(4, 4767, 5, Sid + "9")]));
        Assert.Equal(0, Number(row, "failures")); Assert.Equal(0, Number(row, "relocks")); Assert.Equal("no_failures", row["matching"]!.ToString());
    }

    [Fact]
    public void Equal_timestamps_and_successful_or_unknown_4776_are_not_evidence()
    {
        var row = Assert.Single(Aggregate([Event(1, 4740, 0), Event(2, 4740, 10), Event(3, 4625, -16), Event(4, 4625, 0),
            Event(5, 4625, 10), Event(6, 4767, 0), Event(7, 4767, 10), Event(8, 4776, 5, result: "0x00000000"),
            Event(9, 4776, 6), Event(10, 4776, 7, result: "invalid")]));
        Assert.Equal(0, Number(row, "failures")); Assert.Equal(0, Number(row, "relocks"));
        Assert.Equal(1, Number(Assert.Single(Aggregate([Event(1, 4740, 0), Event(2, 4625, -15)])), "failures"));
    }

    [Theory]
    [InlineData("account", "s-1-5-21-100000001-200000002-300000003-1001", 1)]
    [InlineData("account", "ACCOUNT-A", 1)] [InlineData("account", "other", 0)]
    [InlineData("caller", "WORKSTATION-A", 1)] [InlineData("caller", "192.0.2.1", 1)] [InlineData("caller", "other", 0)]
    [InlineData("code", "0xC000006A", 1)] [InlineData("code", "0x18", 0)]
    public void Filters_preserve_complete_account_episode_counts(string key, string value, int expected)
    {
        var rows = Aggregate([Event(1, 4740, 0), Event(2, 4740, 10, facts: new() { ["caller_computer"] = "workstation-a" }),
            Event(3, 4625, 9, result: "0xc000006a", ip: "192.0.2.1")], account: key == "account" ? value : null,
            caller: key == "caller" ? value : null, code: key == "code" ? value : null);
        Assert.Equal(expected, rows.Length); Assert.All(rows, r => { Assert.Equal(2, Number(r, "lockouts")); Assert.Equal("some_with_failures", r["matching"]!.ToString()); });
    }

    [Fact]
    public void Missing_semantics_and_truncated_input_are_partial_and_minimum_is_enforced()
    {
        Assert.Equal("partial", Assert.Single(Aggregate([Event(1, 4740, 0, normalized: false)]))["matching"]!.ToString());
        Assert.Equal("partial", Assert.Single(Aggregate([Event(1, 4740, 0)], truncated: true))["matching"]!.ToString());
        Assert.Empty(Aggregate([Event(1, 4740, 0)], minimum: 2));
    }

    static AccessDecision Access(int domain = 7, bool capability = true, bool fullFields = true, bool report = true) => new("viewer",
        new(false, capability ? new HashSet<string> { "events.view" } : new HashSet<string>(), new HashSet<string>(), [], new Dictionary<string, JsonElement>()),
        report ? [new("security.events.chains", true, [new(JsonSerializer.SerializeToElement(new { kind = "domain", ids = new[] { domain } }),
            fullFields ? new HashSet<string> { "security", "technical", "raw_evidence" } : new HashSet<string> { "security" }, new HashSet<string> { "view" }, 1, 1)])] : []);
    static ReportQueryContext Context() => new(new ReportDefinitionRegistry().Get("security.events.chains")!, Access(), new Principal("user", 1, "viewer"),
        new JsonObject { ["domain"] = 7, ["period"] = new JsonObject { ["from_utc"] = Start.ToString("O"), ["to_utc"] = Start.AddHours(1).ToString("O") },
            ["min_repeats"] = 1, ["failure_window"] = "15" }, new(null, 100, "UTC", null, "asc", "lockout-recurring"), ReportScope.All, [7], "view", _ => true, []);

    sealed class Database(params JsonArray[] batches) : ISemanticDatabase, ISemanticSession
    {
        public int Opens;
        public readonly List<(string Sql, object?[] Args)> Calls = [];
        readonly Queue<JsonArray> pending = new(batches);
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Assert.False(write); Opens++; return Task.FromResult<ISemanticSession>(this); }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Calls.Add((sql, values));
            return Task.FromResult(sql.StartsWith("set ", StringComparison.Ordinal) ? new JsonArray() : new JsonArray(pending.Dequeue().Select(e=>(JsonNode?)ReportingShortEventFixture.Stored(e!)).ToArray()));
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("read only report");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    [Theory]
    [InlineData("missing")] [InlineData("domain")] [InlineData("capability")] [InlineData("fields")]
    public async Task Denies_before_database_read(string reason)
    {
        var db = new Database(); var c = Context() with { Access = reason switch {
            "missing" => Access(report: false), "domain" => Access(domain: 8), "capability" => Access(capability: false), _ => Access(fullFields: false) } };
        var raw = await new SecurityObservationReader(db, Legacy).Read(c, Ct);
        Assert.Equal("denied", raw["state"]!.ToString()); Assert.Empty(raw["items"]!.AsArray()); Assert.Equal(0, db.Opens);
    }

    [Theory]
    [InlineData("period", "2026-11-02T00:00:00Z", "security_events_period_too_wide")]
    [InlineData("period", "2026-10-01T00:00:00Z", "security_events_period_too_wide")]
    [InlineData("failure_window", "1441", "security_events_filter_invalid")]
    [InlineData("failure_window", "0", "security_events_filter_invalid")]
    [InlineData("min_repeats", "0", "security_events_filter_invalid")]
    [InlineData("limit", "501", "security_events_filter_invalid")]
    [InlineData("domain", "0", "security_events_filter_invalid")]
    [InlineData("action", "delete", "security_events_filter_invalid")]
    public async Task Invalid_bounds_are_rejected_before_opening_database(string key, string value, string expected)
    {
        var db = new Database(); var c = Context();
        if (key == "period") c.Params["period"]!["to_utc"] = value;
        else if (key == "limit") c = c with { Paging = c.Paging with { Limit = int.Parse(value, CultureInfo.InvariantCulture) } };
        else if (key == "action") c = c with { Action = value };
        else c.Params[key] = value;
        var error = await Assert.ThrowsAsync<ReportRequestException>(() => new SecurityObservationReader(db, Legacy).Read(c, Ct));
        Assert.Equal(expected, error.Message); Assert.Equal(0, db.Opens);
    }

    [Fact]
    public async Task Reader_preserves_independent_source_windows_without_timeout()
    {
        var db = new Database(new(Event(1, 4740, 0), Event(2, 4740, 10)), new(Event(3, 4767, 5)), new(Event(4, 4625, 9, result: "0x18")));
        var raw = await new SecurityObservationReader(db, Legacy).Read(Context(), Ct);
        // Both v2 result envelopes turn unverified service ok/empty states into partial.
        Assert.Equal("partial", raw["state"]!.ToString()); Assert.Equal("security.lockout-recurring", raw["window"]!["idea_key"]!.ToString());
        Assert.DoesNotContain(db.Calls, c => c.Sql.Contains("statement_timeout", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(3, db.Calls.Count);
        int[][] expectedCodes = [[4740], [4767], [4625, 4771, 4776]];
        for (int i = 0; i < 3; i++)
        {
            var (sql, args) = db.Calls[i];
            Assert.Equal(7L, args[0]); Assert.Equal(expectedCodes[i], Assert.IsType<int[]>(args[1]));
            Assert.Equal(i == 2 ? Start.AddMinutes(-15) : Start, args[2]); Assert.Equal(Start.AddHours(1), args[3]);
            Assert.Null(args[5]); // No source-row cap for recurring lockouts.

        }
        Assert.Equal(new double?[] { 1, 2, 1, 0, 0 }, raw["metrics"]!.AsArray().Select(m => m!["value"]?.GetValue<double>()));
    }

    [Fact]
    public async Task Source_rows_are_not_silently_discarded_at_legacy_cap()
    {
        var locks = new JsonArray(Enumerable.Range(1, 10001).Select(id => (JsonNode)Event(id, 4740, id / 1000.0)).ToArray());
        var db = new Database(locks, new(), new());
        var raw = await new SecurityObservationReader(db, Legacy).Read(Context(), Ct);
        Assert.Equal(10001, Number(raw["collections"]!["lockout_recurring"]![0]!, "lockouts"));
        Assert.False(raw["coverage"]!["source_truncated"]!.GetValue<bool>()); Assert.Equal("partial", raw["state"]!.ToString());
    }

    [Fact]
    public async Task Empty_is_unverified_and_account_paging_keeps_metrics_for_the_whole_filtered_slice()
    {
        var empty = await new SecurityObservationReader(new Database(new(), new(), new()), Legacy).Read(Context(), Ct);
        Assert.Equal("partial", empty["state"]!.ToString()); Assert.Empty(empty["collections"]!["lockout_recurring"]!.AsArray());
        Assert.Equal("not_proven", empty["coverage"]!["completeness"]!.ToString());
        Assert.Null(empty["metrics"]![3]!["value"]);
        var db = new Database(new(Event(1, 4740, 0), Event(2, 4740, 1, Sid + "9")), new(), new());
        var c = Context(); c = c with { Paging = c.Paging with { Limit = 1 } };
        var raw = await new SecurityObservationReader(db, Legacy).Read(c, Ct);
        Assert.Equal("partial", raw["state"]!.ToString()); Assert.True(raw["coverage"]!["accounts_truncated"]!.GetValue<bool>());
        Assert.Equal(2, Number(raw, "filtered_count")); Assert.Single(raw["collections"]!["lockout_recurring"]!.AsArray());
        Assert.Equal(2, raw["metrics"]![1]!["value"]!.GetValue<double>());
    }

    sealed class NoMainQuery : IAdReportStore
    {
        public Task<IReadOnlyList<long>> DomainsAsync(long after, CancellationToken ct) => Task.FromResult<IReadOnlyList<long>>([]);
        public Task<bool> HasSourceAsync(string kind, long domain, CancellationToken ct) => throw new InvalidOperationException("main event query");
        public Task<JsonObject> ReadAsync(AdReportRequest request, bool sensitive, CancellationToken ct) => throw new InvalidOperationException("main event query");
    }

    [Fact]
    public async Task Internal_recurring_query_preserves_defaults_and_observations()
    {
        var c = Context(); var (parameters, paging) = ReportParameters.Parse(c.Definition,
            new QueryCollection(new Dictionary<string, StringValues> { ["domain"] = "7" }), Start);
        Assert.Equal(2, Number(parameters, "min_repeats")); Assert.Equal("15", parameters["failure_window"]!.ToString());
        var db = new Database(new(Event(1, 4740, 0), Event(2, 4740, 10)), new(), new());
        var raw = await new SecurityEventsReader(new NoMainQuery(), db, null!,Legacy).QueryAsync(c with { Paging = paging with { Tab = "lockout-recurring" }, Params = parameters }, Ct);
        Assert.Equal("security.events.chains", raw["report_key"]!.ToString()); Assert.Empty(raw["items"]!.AsArray());
        Assert.Equal(2, Number(raw["collections"]!["lockout_recurring"]![0]!, "lockouts"));
        Assert.Equal(5, raw["metrics"]!.AsArray().Count); Assert.NotEmpty(raw["limitations"]!.AsArray());
        Assert.Equal("delegated", c.Definition.ScopeKind);
    }
}
