using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Reporting;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class EventsJournalV2Tests
{
    private const string From = "2026-09-29T09:00:00Z", To = "2026-09-29T11:00:00Z", At = "2026-09-29T10:00:00Z";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly string[] Fields = ["id", "event_id", "subject_user_name", "target_user_name", "channel", "time_created_utc"];
    private static readonly object[] FieldDefinitions = Fields.Select(key => (object)new { key, label = key, category = key is "event_id" or "subject_user_name" or "target_user_name" ? "security" : "technical" }).ToArray();
    private static JsonObject Row(int id) => new() { ["id"] = id, ["event_id"] = 4728, ["summary_key"] = "", ["actor"] = "admin", ["target"] = "ivanov", ["provider_name"] = "Microsoft-Windows-Security-Auditing", ["channel"] = "Security", ["time_created_utc"] = At };
    private static string Cursor(int id) => Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { time = At, id, group = "", @short = true }))).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // Only persistence is replaced: the published runner applies scopes, filters,
    // field policy, keyset paging and CSV projection just as it does in production.
    private sealed class Database : IReportDatabase, IReportSession
    {
        internal JsonObject[] Rows = [];
        internal readonly List<(string Sql, object?[] Values)> Commands = [];
        public Task<IReportSession> OpenAsync(bool write, CancellationToken ct) { Assert.False(write); return Task.FromResult<IReportSession>(this); }
        public Task<IReadOnlyList<JsonObject>> QueryAsync(string sql, IReadOnlyList<object?> values, CancellationToken ct)
        {
            Commands.Add((sql, values.ToArray()));
            if (sql.Contains("r.definition_json,d.dataset_key,d.fields_json"))
            {
                Assert.Equal("events.explorer", values[0]);
                return Task.FromResult<IReadOnlyList<JsonObject>>([new JsonObject
                {
                    ["dataset_key"] = "events.v2", ["fields_json"] = JsonSerializer.SerializeToNode(FieldDefinitions),
                    ["definition_json"] = JsonSerializer.SerializeToNode(new { columns = Fields, actions = new[] { "view", "export" }, export_policy = "controlled" })
                }]);
            }
            if (sql == "set local jit=off") return Task.FromResult<IReadOnlyList<JsonObject>>([]);
            Assert.Contains("from event_hot h", sql);
            Assert.Contains("limit @", sql);
            if (sql.Contains("as items from meta")) return Task.FromResult<IReadOnlyList<JsonObject>>([new JsonObject
            {
                ["items"] = new JsonArray(Rows.Select(row => (JsonNode)row.DeepClone()).ToArray()),
                ["filtered_count"] = Rows.Length, ["journal_event_count"] = Rows.Length
            }]);
            return Task.FromResult<IReadOnlyList<JsonObject>>(Rows);
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("read_only");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        internal (string Sql, object?[] Values) Page => Commands.Last();
    }

    private sealed class Sources : ISemanticDatabase, ISemanticSession
    {
        internal int Reads;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Assert.False(write); return Task.FromResult<ISemanticSession>(this); }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Reads++; Assert.Contains("e.id=any($1)", sql);
            return Task.FromResult(new JsonArray());
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("read_only");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class Fixture
    {
        internal readonly Database Db = new();
        internal readonly Sources Source = new();
        internal readonly EventsJournalReader Reader;
        private readonly AccessDecision access;
        private readonly ReportDefinition definition = new ReportDefinitionRegistry().Get("events.journal")!;
        internal Fixture()
        {
            JsonElement J(object value) => JsonSerializer.SerializeToElement(value);
            var facts = new AccessFacts(false, "viewer", [], [],
                new[] { "field.technical", "field.security", "reports.export" }.Select(capability_key => J(new { capability_key, effect = "allow", scope_json = new { kind = "all" } })).ToArray(), [], [],
                [J(new { report_key = "events.explorer", effect = "allow", scope_json = new { kind = "domain", ids = new[] { 7, 8 } }, field_categories = new[] { "technical", "security" }, allowed_actions = new[] { "view", "export" } })],
                [J(new { report_key = "events.explorer", version = 1, dataset_version = 1, fields_json = FieldDefinitions, actions_json = new[] { "view", "export" }, definition_json = new { actions = new[] { "view", "export" } } })]);
            access = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
            var repository = new ReportFixture.FactsRepo(facts);
            var runner = new ReportRunner(Db, new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"]="false" }).Build());
            Reader = new(runner, repository, Source, new BuiltinReportExports(runner, repository, null!, Source));
        }
        internal ReportQueryContext Context(Dictionary<string, StringValues>? query = null, string? cursor = null, int limit = 50, string action = "view")
        {
            var (parameters, paging) = ReportParameters.Parse(definition, new QueryCollection(query ?? []), DateTimeOffset.Parse(To));
            return new(definition, access, new Principal("session", 1, "viewer"), parameters, paging with { Cursor = cursor, Limit = limit }, ReportScope.None, null, action, _ => true, access.Reports.Single().Grants);
        }
    }

    [Fact]
    public async Task Query_passes_window_view_search_server_and_cursor_to_published_report()
    {
        var f = new Fixture(); f.Db.Rows = [Row(5), Row(4)];
        var c = f.Context(new() { ["period"] = "custom", ["from"] = From, ["to"] = To, ["view"] = "accounts", ["q"] = "4728", ["server"] = "DC1" }, Cursor(9), 1);
        var body = await f.Reader.QueryAsync(c, Ct);
        var (sql, values) = f.Db.Page;
        Assert.Contains("event.event_id=any(", sql); Assert.Contains(values, v => v is long[] ids && ids.Contains(4728));
        Assert.Contains("event.event_id=", sql); Assert.Contains(4728L, values);
        Assert.Contains("lower(server.hostname)=lower(", sql); Assert.Contains("DC1", values);
        Assert.Contains("event.time_created_utc>=", sql); Assert.Contains(DateTimeOffset.Parse(From), values);
        Assert.Contains("event.time_created_utc<", sql); Assert.Contains(DateTimeOffset.Parse(To), values);
        Assert.Contains("coalesce(event.id,0)", sql); Assert.Contains(9L, values);
        Assert.Equal(2, values[^1]); // published reader fetches one lookahead row
        var row = Assert.Single(body["items"]!.AsArray())!;
        Assert.Equal("неизвестный тип события", row["title_text"]!.ToString());
        Assert.Equal("ivanov", row["participant"]!.ToString()); Assert.Equal("admin", row["on_behalf"]!.ToString());
        Assert.True(body["has_more"]!.GetValue<bool>()); Assert.Equal(Cursor(5), body["next_cursor"]!.ToString());
        Assert.Equal(From, body["window"]!["from_utc"]!.ToString()); Assert.Equal(To, body["window"]!["to_utc_exclusive"]!.ToString());
        Assert.Equal(1, f.Source.Reads);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Default_or_all_view_is_omitted_and_empty_slice_keeps_complete_server_access_scope(bool explicitAll)
    {
        var f = new Fixture(); var c = f.Context(explicitAll ? new() { ["view"] = "all" } : null);
        var body = await f.Reader.QueryAsync(c, Ct);
        // A hidden domain parameter keeps URL domain= accepted; it must not narrow the server access scope.
        Assert.All(c.Definition.Params.Where(p => p["kind"]?.ToString() == "domain"), p => Assert.True(p["hidden"]?.GetValue<bool>() == true));
        Assert.Null(c.DomainIds);
        var (sql, values) = f.Db.Page;
        Assert.Contains("event.domain_id=any(", sql); Assert.Equal(new long[] { 7, 8 }, Assert.IsType<long[]>(values[0]));
        Assert.Equal(5, values.Length); // domain scope, both window boundaries, page size
        Assert.Equal(DateTimeOffset.Parse(To).AddHours(-2), values[1]); Assert.Equal(DateTimeOffset.Parse(To), values[2]);
        Assert.DoesNotContain("event.event_id=any(", sql); Assert.DoesNotContain("event.id<", sql);
        Assert.Equal("empty", body["state"]!.ToString()); Assert.Empty(body["items"]!.AsArray()); Assert.Equal(0, f.Source.Reads);
    }

    [Theory]
    [InlineData(3, false)] [InlineData(201, true)]
    public async Task Export_uses_published_columns_and_metadata_without_page_cursor(int rows, bool truncated)
    {
        var f = new Fixture(); f.Db.Rows = Enumerable.Range(1, rows).Select(Row).ToArray();
        var document = await f.Reader.ExportAsync(f.Context(cursor: "ignored", limit: 1, action: "export"), Ct);
        Assert.Equal(Math.Min(rows, 200), document.Rows); Assert.Equal(truncated, document.Truncated);
        Assert.StartsWith(string.Join(',', Fields) + "\r\n1,4728,admin,ivanov,Security," + At + "\r\n", document.Body);
        Assert.DoesNotContain("title_text", document.Body); Assert.DoesNotContain("participant", document.Body);
        Assert.Equal(Math.Min(rows, 200) + 1, document.Body.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length);
        var (sql, values) = f.Db.Page;
        Assert.DoesNotContain("event.id<", sql); Assert.Equal(201, values[^1]); Assert.Equal(5, values.Length);
        Assert.Equal(new long[] { 7, 8 }, Assert.IsType<long[]>(values[0])); Assert.Equal(0, f.Source.Reads);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Literal_all_search_and_server_are_preserved_for_query_and_export(bool export)
    {
        var f = new Fixture(); var c = f.Context(new() { ["view"] = "all", ["q"] = "all", ["server"] = "all" }, action: export ? "export" : "view");
        if (export) await f.Reader.ExportAsync(c, Ct); else await f.Reader.QueryAsync(c, Ct);
        var (sql, values) = f.Db.Page;
        Assert.Contains("lower(server.hostname)=lower(", sql); Assert.Contains("event.target_user_name", sql);
        Assert.Equal(8, values.Count(v => Equals(v, "all")));
        Assert.DoesNotContain("event.event_id=any(", sql);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Workstation_source_filter_precedes_groups_counts_and_export(bool export)
    {
        const string source = "41800000-0000-4000-8000-000000000001";
        var f = new Fixture();
        var c = f.Context(new()
        {
            ["source_instance_id"] = source, ["source_plugin"] = "sli.workstations",
            ["domain"] = "7", ["server"] = "WS-01", ["collapse"] = "on"
        }, action: export ? "export" : "view") with { WorkstationServerId = export ? null : 12 };
        if (export) await f.Reader.ExportAsync(c, Ct); else await f.Reader.QueryAsync(c, Ct);
        var (sql, values) = f.Db.Page;
        Assert.Contains("event.method#>>'{$origin,source_instance_id}'=", sql);
        Assert.Contains("event.method#>>'{$origin,plugin_id}'=", sql);
        Assert.Contains(source, values); Assert.Contains("sli.workstations", values);
        Assert.Contains("lower(server.hostname)=lower(", sql); Assert.Contains("WS-01", values);
        Assert.True(sql.IndexOf("event.method#>>'{$origin,source_instance_id}'=", StringComparison.Ordinal)
            < sql.IndexOf("candidates as materialized", StringComparison.Ordinal));
        if (!export) { Assert.Contains("event.server_id=", sql); Assert.Contains(12L, values); }
    }

    [Theory]
    [InlineData("not-a-source", "sli.workstations")]
    [InlineData(null, "sli.workstations")]
    [InlineData("41800000-0000-4000-8000-000000000001", "another-plugin")]
    public void Invalid_source_selection_cannot_silently_become_unfiltered(string? source, string plugin)
    {
        var c = new Fixture().Context();
        c.Params["source_instance_id"] = source; c.Params["source_plugin"] = plugin;
        Assert.Throws<ReportRequestException>(() => EventsJournalReader.Options(c));
    }
}
