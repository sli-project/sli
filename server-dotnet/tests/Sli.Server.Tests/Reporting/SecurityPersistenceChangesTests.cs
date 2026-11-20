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

// Vectors from tests/reporting/test_security_persistence_changes.py.
public sealed class SecurityPersistenceChangesTests
{
    static IConfiguration Legacy => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"]="false" }).Build();
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    const string TaskXml = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Principals><Principal><UserId>synthetic-run-as</UserId></Principal></Principals><Actions><Exec><Command>C:\\synthetic\\task.exe</Command><Arguments>--check</Arguments></Exec></Actions></Task>";
    static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-10-01T00:00:00Z", CultureInfo.InvariantCulture);
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject Event(int id, int code = 4697, int minute = 0) => new()
    {
        ["event_db_id"] = id, ["event_id"] = code, ["domain_id"] = 7, ["server_id"] = 11,
        ["dc"] = "synthetic-dc", ["time_created_utc"] = Start.AddMinutes(minute).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
        ["normalized_event_id"] = id.ToString(CultureInfo.InvariantCulture), ["service_name"] = "synthetic-service",
        ["service_file"] = @"C:\synthetic\agent.exe", ["service_account"] = "synthetic-account", ["service_start_type"] = "2",
        ["process_user_sid"] = Sid, ["process_user_name"] = "synthetic-actor"
    };
    static JsonObject TaskEvent(int id, int code, int minute, string? content = TaskXml)
    {
        var ev = Event(id, code, minute); ev["task_name"] = @"\synthetic-task"; ev["task_content"] = content;
        ev["task_change"] = code switch { 4698 => "created", 4699 => "deleted", 4700 => "enabled", 4701 => "disabled", _ => "updated" };
        return ev;
    }
    static JsonObject[] Rows(params JsonObject[] events) => BuiltinReportExports.PersistenceRows(events, false);
    static JsonObject[] ResultRows(JsonObject data) => data["collections"]!.AsObject().Objects("persistence_changes");
    static long Metric(JsonObject data, string key) => long.Parse(data.Objects("metrics").Single(m => m.Text("key") == key)["value"]!.ToString(), CultureInfo.InvariantCulture);
    static AccessDecision Access(int domain = 7, bool fields = true, bool export = true, bool assigned = true)
    {
        var caps = new CapabilityDecisionSet(false, new HashSet<string> { "events.view" }, new HashSet<string>(), [], new Dictionary<string, JsonElement>());
        var grant = new AtomicReportGrant(JsonSerializer.SerializeToElement(new { kind = "domain", ids = new[] { domain } }),
            new HashSet<string>(fields ? ["security", "technical", "raw_evidence"] : ["security"]), new HashSet<string>(export ? ["view", "export"] : ["view"]), 1, 1);
        return new("operator", caps, assigned ? [new("security.events.chains", true, [grant])] : []);
    }
    static ReportQueryContext Context(AccessDecision? access = null, string action = "view", params (string Key, string Value)[] filters)
    {
        var definition = new ReportDefinitionRegistry().Get("security.events.chains")!;
        var query = new Dictionary<string, StringValues> { ["domain"] = "7", ["period"] = "custom", ["from"] = "2026-10-01T00:00:00Z", ["to"] = "2026-10-01T01:00:00Z", ["limit"] = "100" };
        foreach (var (key, value) in filters) query[key] = value;
        var (parameters, paging) = ReportParameters.Parse(definition, new QueryCollection(query), Start);
        return new(definition, access ?? Access(), new Principal("session", 1, "operator"), parameters, paging with { Tab = "persistence-changes" }, ReportScope.None, null, action, _ => true, []);
    }
    sealed class Database(params JsonObject[] events) : ISemanticDatabase, ISemanticSession
    {
        internal int Opens;
        internal string? Sql;
        internal object?[]? Args;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Assert.False(write); Opens++; return Task.FromResult<ISemanticSession>(this); }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            if (sql.StartsWith("select id, fqdn from domains", StringComparison.Ordinal))
                return Task.FromResult(new JsonArray(new JsonObject { ["id"] = 7L, ["fqdn"] = "example.test" }));
            Assert.Null(Sql); Sql = sql; Args = values;
            return Task.FromResult(new JsonArray(events.Select(e => (JsonNode?)ReportingShortEventFixture.Stored(e)).ToArray()));
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    static BuiltinReportExports Exports(Database db) => new(null!, null!, null!, db, Legacy);
    sealed class Sources : IAdReportStore
    {
        public Task<IReadOnlyList<long>> DomainsAsync(long after, CancellationToken ct) => Task.FromResult<IReadOnlyList<long>>([7]);
        public Task<bool> HasSourceAsync(string kind, long domain, CancellationToken ct) => throw new InvalidOperationException("unexpected source read");
        public Task<JsonObject> ReadAsync(AdReportRequest request, bool sensitive, CancellationToken ct) => throw new InvalidOperationException("unexpected main report query");
    }
    sealed class Domains : IReportDomains
    {
        public Task<IReadOnlyList<Sli.Server.Domains.DomainItem>> ReadAsync(long[]? ids, CancellationToken ct) => Task.FromResult<IReadOnlyList<Sli.Server.Domains.DomainItem>>([]);
    }

    [Fact]
    public void Source_discovery_includes_service_task_and_System_SCM_without_expanding_main_vocabulary()
    {
        int[] persistence = [4697, 4698, 4699, 4700, 4701, 4702, 7045];
        Assert.All(persistence, code => Assert.Contains(code, AdReportStore.DiscoveryEventIds("security")));
        Assert.All(persistence, code => Assert.DoesNotContain(code, AdReportStore.EventIds("security")));
        string sql = AdReportStore.SecurityPresenceSql;
        Assert.Contains("event.domain_id=$1", sql); Assert.Contains("event.event_id=any($2)", sql);
        Assert.Contains("server.role='domain_controller'", sql);
        Assert.Contains("event.event_id=7045 and channel.value='System' and provider.value='Service Control Manager'", sql);
        Assert.Contains("event.event_id<>7045 and channel.value=$3", sql);
        Assert.Contains("event.event_id=1102 and provider.value='Microsoft-Windows-Eventlog'", sql);
        Assert.Contains("event.event_id<>1102 and provider.value=$4", sql);
    }
    [Fact]
    public void Exact_pair_is_deduplicated_and_history_keeps_observations_and_previous_value()
    {
        var first = Event(1); var secondary = Event(2, 7045); secondary["process_user_sid"] = null; secondary["process_user_name"] = null;
        var last = Event(3, minute: 10); last["service_file"] = @"C:\synthetic\new.exe";
        var rows = Rows(last, secondary, first, first);
        Assert.Equal(2, rows.Length); var linked = rows[1];
        Assert.Equal(new[] { 1, 2 }, linked["event_ids"]!.AsArray().Select(n => n!.GetValue<int>()));
        Assert.Equal(2, linked["linked_event"]!.GetValue<int>()); Assert.Equal("exact_link", linked.Text("quality")); Assert.Null(linked["previous"]);
        Assert.Equal(first["service_file"]!.ToString(), rows[0]["previous"]!["action"]!.ToString());
        Assert.All(rows, r => { Assert.Equal(2, r["frequency"]!.GetValue<int>()); Assert.Equal("2026-10-01T00:00:00Z", r.Text("first_seen")); Assert.Equal("2026-10-01T00:10:00Z", r.Text("last_seen")); });
        Assert.Equal(2, linked["observations"]!.AsArray().Count); Assert.Null(linked["observations"]![1]!["initiator_sid"]);
        Assert.Equal("partially_known", linked.Text("initiator_quality"));
    }
    [Theory]
    [InlineData("time_created_utc", "2026-10-01T00:01:00Z")]
    [InlineData("server_id", "12")][InlineData("domain_id", "8")]
    [InlineData("service_name", "other")][InlineData("service_file", "other")]
    [InlineData("service_account", "other")][InlineData("service_start_type", "3")]
    [InlineData("service_account", null)][InlineData("normalized_event_id", null)]
    public void Incomplete_nearby_or_different_installs_never_link(string key, string? value)
    {
        var other = Event(2, 7045); other[key] = value;
        var rows = Rows(Event(1), other); Assert.Equal(2, rows.Length); Assert.All(rows, r => Assert.Null(r["linked_event"]));
    }
    [Fact]
    public void Ambiguous_pairs_same_codes_truncation_and_conflicting_order_do_not_invent_history()
    {
        Assert.Equal(3, Rows(Event(1), Event(2), Event(3, 7045)).Length);
        Assert.Equal(2, Rows(Event(1), Event(2)).Length);
        var truncated = BuiltinReportExports.PersistenceRows([Event(1), Event(2, 7045)], true);
        Assert.Equal(2, truncated.Length); Assert.All(truncated, r => { Assert.Null(r["linked_event"]); Assert.Equal("partial", r.Text("quality")); });
        var conflict = Event(2); conflict["service_file"] = "other";
        var rows = Rows(Event(1), conflict, Event(3, minute: 1));
        Assert.Null(rows[0]["previous"]); Assert.Equal("ambiguous_order", rows[1].Text("quality"));
    }
    [Fact]
    public void Unknown_objects_and_missing_semantics_are_isolated()
    {
        var a = Event(1); a["service_name"] = null; var b = Event(2); b["service_name"] = null; var c = Event(3); c["normalized_event_id"] = null;
        var rows = Rows(a, b, c, Event(4, minute: 1));
        Assert.All(rows, r => { Assert.Equal(1, r["frequency"]!.GetValue<int>()); Assert.Null(r["previous"]); });
        Assert.Equal(new[] { "exact_object", "missing_semantics", "unknown_object" }, rows.Select(r => r.Text("quality")).Distinct().Order());
    }
    [Fact]
    public void Task_history_extracts_actions_run_as_and_keeps_missing_values_unknown()
    {
        var rows = Rows(TaskEvent(1, 4698, 0), TaskEvent(2, 4702, 5, TaskXml.Replace("--check", "--new")), TaskEvent(3, 4701, 10, null), TaskEvent(4, 4699, 15, null));
        Assert.Equal(4, rows.Length); Assert.All(rows, r => { Assert.Equal(4, r["frequency"]!.GetValue<int>()); Assert.Null(r["task_content"]); });
        Assert.Equal(@"C:\synthetic\task.exe --check", rows[2]["previous"]!["action"]!.ToString()); Assert.Equal("synthetic-run-as", rows[2].Text("run_as"));
        Assert.Null(rows[1]["action"]); Assert.Null(rows[0]["previous"]!["action"]);
        Assert.Equal(new[] { "created", "deleted", "disabled", "updated" }, rows.Select(r => r.Text("change")).Order());
        Assert.Equal("enabled", Assert.Single(Rows(TaskEvent(5, 4700, 20))).Text("change"));
    }
    public static IEnumerable<object[]> InvalidXml => new[] { "<Task>", "<!DOCTYPE Task [<!ENTITY x \"unsafe\">]><Task>&x;</Task>", new string('x', 8193) }.Select(s => new object[] { s });
    [Theory][MemberData(nameof(InvalidXml))]
    public void Invalid_task_XML_does_not_dump_content_or_invent_action(string content)
    {
        var row = Assert.Single(Rows(TaskEvent(1, 4698, 0, content)));
        Assert.Null(row["action"]); Assert.Null(row["run_as"]); Assert.Null(row["task_content"]);
    }
    [Fact]
    public void Task_actions_reject_truncated_XML_fallback_and_preserve_multiple_actions()
    {
        var ev = TaskEvent(1, 4698, 0, null); ev["task_action"] = "<Task>truncated";
        Assert.Null(Assert.Single(Rows(ev))["action"]);
        var row = Assert.Single(Rows(TaskEvent(2, 4698, 0, TaskXml.Replace("</Actions>", "<Exec><Command>synthetic-second</Command></Exec></Actions>"))));
        Assert.Equal(@"C:\synthetic\task.exe --check; synthetic-second", row.Text("action"));
    }
    [Fact]
    public async Task Filters_apply_after_history_so_previous_values_and_frequency_survive()
    {
        Database Db() => new(TaskEvent(1, 4698, 0), TaskEvent(2, 4702, 5, TaskXml.Replace("--check", "--new")));
        var result = await Exports(Db()).PersistenceData(Context(null, "view", ("persistence_type", "task"), ("persistence_path", "--NEW"), ("actor", Sid), ("persistence_change", "updated"), ("persistence_rarity", "2")), Ct);
        var row = Assert.Single(ResultRows(result)); Assert.Equal(2, row["frequency"]!.GetValue<int>()); Assert.EndsWith("--check", row["previous"]!["action"]!.ToString());
        foreach (var filter in new[] { ("persistence_rarity", "1"), ("source", "other"), ("persistence_type", "service"), ("actor", "other") })
            Assert.Empty(ResultRows(await Exports(Db()).PersistenceData(Context(null, "view", filter), Ct)));
    }
    [Fact]
    public async Task Reader_pins_domain_half_open_window_and_source_lookahead()
    {
        var db = new Database(Event(1)); await Exports(db).PersistenceData(Context(), Ct);
        var args = db.Args!; Assert.Equal(7L, args[0]);
        Assert.Equal(new[] { 4697, 4698, 4699, 4700, 4701, 4702, 7045 }, Assert.IsType<int[]>(args[1]));
        Assert.Equal(Start, args[2]); Assert.Equal(Start.AddHours(1), args[3]);
        Assert.Equal(10001,args[5]);

        Assert.Equal(1, db.Opens);
    }
    [Theory][InlineData("unassigned")][InlineData("wrong-domain")][InlineData("missing-fields")]
    public async Task Denied_view_returns_no_rows_and_never_opens_database(string reason)
    {
        var db = new Database(); var access = reason switch { "unassigned" => Access(assigned: false), "wrong-domain" => Access(domain: 8), _ => Access(fields: false) };
        var result = await Exports(db).PersistenceData(Context(access), Ct);
        Assert.Equal("denied", result.Text("state")); Assert.Empty(result["items"]!.AsArray()); Assert.Empty(result["collections"]!.AsObject()); Assert.Equal(0, db.Opens);
    }
    [Theory]
    [InlineData("to", "2026-10-01T00:00:00Z")][InlineData("to", "2026-11-02T00:00:00Z")]
    [InlineData("limit", "501")][InlineData("domain", "0")][InlineData("persistence_rarity", "0")]
    [InlineData("persistence_type", "invalid")][InlineData("persistence_change", "invalid")]
    public async Task Invalid_filters_are_rejected_before_read(string key, string value)
    {
        var db = new Database(); await Assert.ThrowsAsync<ReportRequestException>(async () => await Exports(db).PersistenceData(Context(null, "view", (key, value)), Ct)); Assert.Equal(0, db.Opens);
    }
    [Fact]
    public async Task Invalid_action_is_rejected_before_read()
    {
        var db = new Database(); await Assert.ThrowsAsync<ReportRequestException>(() => Exports(db).PersistenceData(Context(action: "delete"), Ct)); Assert.Equal(0, db.Opens);
    }
    [Fact]
    public async Task Service_metrics_are_computed_before_paging_and_unknown_initiators_include_linked_evidence()
    {
        var changed = Event(3, minute: 10); changed["service_file"] = "other"; var task = TaskEvent(4, 4698, 20); task["process_user_sid"] = null; task["process_user_name"] = null;
        var result = await Exports(new(Event(1), Event(2, 7045), changed, task)).PersistenceData(Context(null, "view", ("limit", "1")), Ct);
        Assert.Equal("partial", result.Text("state")); Assert.True(result["coverage"]!["rows_truncated"]!.GetValue<bool>());
        Assert.Equal(new long[] { 1, 1, 1, 3, 1, 1 }, new[] { "services", "tasks", "actions", "paths", "repeated", "unknown" }.Select(k => Metric(result, "persistence_" + k)));
        Assert.Equal(3, result["filtered_count"]!.GetValue<int>()); Assert.Single(ResultRows(result)); Assert.Equal("security.persistence-changes", result["window"]!["idea_key"]!.ToString());
        var secondary = Event(2, 7045); secondary["process_user_sid"] = null; secondary["process_user_name"] = null;
        result = await Exports(new(Event(1), secondary)).PersistenceData(Context(), Ct);
        Assert.Equal(1, Metric(result, "persistence_unknown")); Assert.Equal(1, Assert.Single(ResultRows(result))["frequency"]!.GetValue<int>());
    }
    [Fact]
    public async Task Unknown_action_is_not_counted_as_a_changed_action()
    {
        var result = await Exports(new(TaskEvent(1, 4698, 0), TaskEvent(2, 4701, 10, null))).PersistenceData(Context(), Ct);
        Assert.Equal(0, Metric(result, "persistence_actions")); Assert.Null(ResultRows(result)[0]["action"]);
    }
    [Fact]
    public async Task Stored_facts_do_not_require_legacy_semantics_and_empty_window_stays_unverified()
    {
        var ev = Event(3); ev["normalized_event_id"] = null;
        var result = await Exports(new(ev)).PersistenceData(Context(), Ct);
        Assert.Equal("partial", result.Text("state")); Assert.Equal(0, result["coverage"]!["missing_current_semantics"]!.GetValue<int>()); Assert.Equal(1, Metric(result, "persistence_services"));
        var empty = await Exports(new()).PersistenceData(Context(), Ct);
        // Both V2 wrappers expose partial when completeness is not proven, including an empty slice.
        Assert.Equal("partial", empty.Text("state")); Assert.Empty(ResultRows(empty)); Assert.Equal("not_proven", empty["coverage"]!["completeness"]!.ToString());
        Assert.All(empty.Objects("metrics"), m => Assert.Equal("0", m["value"]!.ToString()));
    }
    [Fact]
    public async Task Source_truncation_disables_linking_and_ignores_the_lookahead_event()
    {
        var events = new[] { Event(1), Event(2, 7045) }.Concat(Enumerable.Range(3, 9999).Select(id => { var ev = Event(id); ev["service_name"] = null; return ev; })).ToArray();
        events[^1]["normalized_event_id"] = null;
        var result = await Exports(new(events)).PersistenceData(Context(), Ct);
        Assert.Equal("partial", result.Text("state")); Assert.True(result["coverage"]!["source_truncated"]!.GetValue<bool>());
        Assert.Equal("bounded_slice", result["coverage"]!["state"]!.ToString()); Assert.Equal(10000, result["filtered_count"]!.GetValue<int>());
        Assert.Equal(0, result["coverage"]!["missing_current_semantics"]!.GetValue<int>()); Assert.All(ResultRows(result), r => { Assert.Null(r["linked_event"]); Assert.Equal("partial", r.Text("quality")); });
        var missing = Event(1); missing["normalized_event_id"] = null;
        var unknowns = Enumerable.Range(2, 10000).Select(id => { var ev = Event(id); ev["service_name"] = null; return ev; });
        result = await Exports(new(new[] { missing }.Concat(unknowns).ToArray())).PersistenceData(Context(), Ct);
        Assert.Equal(1, Metric(result, "persistence_services")); Assert.Equal(0, result["coverage"]!["missing_current_semantics"]!.GetValue<int>());
    }
    [Fact]
    public async Task Internal_persistence_query_and_export_require_permission()
    {
        var db = new Database(Event(1)); var exports = Exports(db); var context = Context();
        // A denied query must not reach the main event store or domain option discovery.
        var denied = await exports.PersistenceData(context with { Access = Access(assigned: false) }, Ct);
        Assert.Equal("denied", denied.Text("state")); Assert.Equal(0, db.Opens);
        var result = await exports.PersistenceData(context, Ct);
        Assert.Equal("security.events.chains", result.Text("report_key")); Assert.Empty(result["items"]!.AsArray()); Assert.Single(ResultRows(result)); Assert.Equal(6, result.Objects("metrics").Length);
        var noExportDb = new Database(); var error = await Assert.ThrowsAsync<ReportRequestException>(() => Exports(noExportDb).ExportAsync(Context(Access(export: false)), Ct));
        Assert.Equal(403, error.Status); Assert.Equal("report_export_not_authorized", error.Message); Assert.Equal(0, noExportDb.Opens);
    }
}
