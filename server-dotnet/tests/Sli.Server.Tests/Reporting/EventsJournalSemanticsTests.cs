using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Reporting;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class EventsJournalSemanticsTests
{
    const string Unknown = "неизвестный тип события";
    const string Title = "Изменение состояния службы";
    static readonly string[] Fields = ["security", "technical", "raw_evidence", "identity_basic"];
    static readonly string[] ExactCaps = ["field.security", "field.technical", "field.raw_evidence", "evidence.exact"];
    static JsonObject O(string json) => JsonNode.Parse(json)!.AsObject();
    static JsonObject Visible() => O("""{"id":5,"event_id":7036,"channel":"System","time_created_utc":"2026-10-01T12:00:00Z"}""");
    static JsonObject Source() => O("""{"id":5,"event_id":7036,"channel":"System","provider_name":"Service Control Manager","server_id":1,"domain_id":2}""");
    static JsonElement Grant(string scope = "{\"kind\":\"all\"}", string[]? fields = null) => JsonSerializer.SerializeToElement(new
    {
        report_key = "events.explorer", effect = "allow", allowed_actions = new[] { "view" },
        field_categories = fields ?? Fields, scope_json = JsonNode.Parse(scope)
    });
    internal static AccessFacts Facts(bool owner = true, JsonElement[]? grants = null, string? denied = null, bool scoped = false, bool exact = true)
    {
        string[] caps = ExactCaps.Concat(["field.identity_basic"]).Where(c => exact || c != "evidence.exact").ToArray();
        var policies = caps.Select(c => JsonSerializer.SerializeToElement(new
        {
            capability_key = c, effect = "allow", scope_json = JsonNode.Parse(scoped ? "{\"kind\":\"domain\",\"ids\":[2]}" : "{\"kind\":\"all\"}")
        })).ToList();
        if (denied is not null) policies.Add(ReportFixture.J(JsonSerializer.Serialize(new
        {
            capability_key = denied, effect = "deny", scope_json = new { kind = "domain", ids = new[] { 2 } }
        })));
        return new(owner, "admin", [], [], policies, caps.Select(c => JsonSerializer.SerializeToElement(new { capability_key = c })).ToArray(), [], grants ?? [Grant()],
            [ReportFixture.J("""{"report_key":"events.explorer","version":1,"dataset_version":1,"definition_json":{"actions":["view"]},"actions_json":["view"],"fields_json":[{"category":"security"},{"category":"technical"},{"category":"raw_evidence"},{"category":"identity_basic"}]}""")]);
    }
    internal static AccessFacts WithQueue(AccessFacts facts) => facts with
    {
        Definitions = [.. facts.Definitions, ReportFixture.J("""
            {"report_key":"security.queue","version":1,"dataset_version":1,"definition_json":{"actions":["view"]},"actions_json":["view"],"fields_json":[{"category":"security"}]}
            """)],
        ReportAssignments = [.. facts.ReportAssignments, ReportFixture.J("""
            {"report_key":"security.queue","effect":"allow","allowed_actions":["view"],"field_categories":["security"],"scope_json":{"kind":"all"}}
            """)],
    };
    sealed class Fixture
    {
        internal readonly PageDatabase Page = new();
        internal readonly EvidenceDatabase Evidence = new();
        internal readonly AccessFacts Facts;
        internal readonly EventsJournalReader Reader;
        internal readonly ReportDefinition Definition = new ReportDefinitionRegistry().Get("events.journal")!;
        internal Fixture(AccessFacts? facts = null)
        {
            Facts = facts ?? EventsJournalSemanticsTests.Facts();
            var runner = new ReportRunner(Page, new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"]="false" }).Build()); var repository = new ReportFixture.FactsRepo(Facts);
            Reader = new(runner, repository, Evidence, new BuiltinReportExports(runner, repository, null!, Evidence));
        }
        internal Task<JsonObject> Query(int limit = 50, bool collapse = false)
        {
            var access = new ReportEligibility().Compose(Facts, new CapabilityComposer().Compose(Facts));
            var parameters = O("""{"period":{"from_utc":"2026-10-01T00:00:00Z","to_utc":"2026-10-02T00:00:00Z"}}""");
            if (collapse) parameters["collapse"] = "on";
            var c = new ReportQueryContext(Definition, access, new Principal("session", 7, "admin"),
                parameters, new(null, limit, "UTC", null, "desc", null), ReportScope.All, null, "view", _ => true,
                access.Reports.Single(report => report.ReportKey == "events.explorer").Grants);
            return Reader.QueryAsync(c, TestContext.Current.CancellationToken);
        }
    }
    // Only the database boundaries are substituted: real runner field projections,
    // atomic grants, capability decisions and the journal adapter all execute.
    sealed class PageDatabase : IReportDatabase, IReportSession
    {
        internal JsonObject[] Rows = [Visible()];
        internal string[] Columns = ["id", "event_id", "channel", "subject_user_name", "target_user_name", "time_created_utc"];
        internal Dictionary<string, string> Categories = new() { ["event_id"] = "security", ["channel"] = "technical", ["id"] = "technical", ["subject_user_name"] = "identity_basic", ["target_user_name"] = "identity_basic" };
        internal Func<CancellationToken, Task<IReadOnlyList<JsonObject>>>? ReadPage;
        public Task<IReportSession> OpenAsync(bool write, CancellationToken ct) => Task.FromResult<IReportSession>(this);
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public Task<IReadOnlyList<JsonObject>> QueryAsync(string sql, IReadOnlyList<object?> values, CancellationToken ct)
        {
            if (sql.Contains("r.definition_json,d.dataset_key,d.fields_json")) return Task.FromResult<IReadOnlyList<JsonObject>>([new()
            {
                ["dataset_key"] = "events.v2",
                ["definition_json"] = JsonSerializer.SerializeToNode(new { columns = Columns, filters = Array.Empty<object>(), sort = Array.Empty<object>(), actions = new[] { "view" } }),
                ["fields_json"] = JsonSerializer.SerializeToNode(Columns.Select(c => new { key = c, category = Categories.GetValueOrDefault(c, "technical") }))
            }]);
            if (sql is "set local jit=off" or "set transaction isolation level repeatable read")
                return Task.FromResult<IReadOnlyList<JsonObject>>([]);
            if (sql.Contains("as window_event", StringComparison.Ordinal))
                return Task.FromResult<IReadOnlyList<JsonObject>>([new()
                {
                    ["window_event"] = Rows.FirstOrDefault()?["time_created_utc"] is { } time
                        && DateTimeOffset.Parse(time.ToString()) < (DateTimeOffset)values[1]!
                        ? time.DeepClone() : null,
                }]);
            Assert.Contains("from event_hot h", sql);
            if (sql.Contains("as items from meta"))
                return ReadPage?.Invoke(ct) ??
                    Task.FromResult<IReadOnlyList<JsonObject>>([new() { ["items"] = new JsonArray(Rows.Select(r => r.DeepClone()).ToArray()) }]);
            return Task.FromResult<IReadOnlyList<JsonObject>>(Rows.Select(r => r.DeepClone().AsObject()).ToArray());
        }
    }
    sealed class EvidenceDatabase : ISemanticDatabase, ISemanticSession
    {
        internal JsonObject[] Rows = [Source()];
        internal JsonObject[] Links = [];
        internal Exception? Error;
        internal readonly List<(string Sql, object?[] Values)> Queries = [];
        internal int Opens;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct)
        { Assert.False(write); Opens++; return Task.FromResult<ISemanticSession>(this); }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Queries.Add((sql, values));
            if (Error is not null) throw Error;
            var result = values.Length == 2 && values[0] is long[] ids
                ? Links.Where(link => ids.Contains(link["event_db_id"]!.GetValue<long>()))
                : Rows.AsEnumerable();
            return Task.FromResult(new JsonArray(result.Select(r => r.DeepClone()).ToArray()));
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("read_only");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    static JsonObject Row(JsonObject body) => Assert.Single(body["items"]!.AsArray())!.AsObject();

    [Theory]
    [InlineData(true, true, 41)]
    [InlineData(true, false, 32)]
    [InlineData(false, true, null)]
    public async Task Group_links_use_admitted_members_and_require_queue_access(bool queue, bool otherServer, int? finding)
    {
        var facts = Facts();
        if (!otherServer)
            facts = facts with
            {
                IsOwner = false,
                DirectCapabilities = [.. facts.DirectCapabilities, ReportFixture.J("""
                    {"capability_key":"evidence.exact","effect":"deny","scope_json":{"kind":"server","ids":[2]}}
                    """)]
            };
        if (queue) facts = WithQueue(facts);
        var f = new Fixture(facts);
        f.Page.Rows = [O("""
            {"id":5,"event_id":4625,"channel":"Security","time_created_utc":"2026-10-01T12:00:00Z",
             "server_id":1,"domain_id":2,"provider_name":"Microsoft-Windows-Security-Auditing",
             "journal_expandable":true,"_journal_members":[[5,1],[4,1],[3,2]]}
            """)];
        f.Evidence.Links = [
            O("""{"event_db_id":4,"finding_id":32,"priority":1}"""),
            O("""{"event_db_id":3,"finding_id":41,"priority":0}"""),
        ];
        var row = Row(await f.Query(collapse: true));
        Assert.Equal((long?)finding, row["journal_finding_id"]?.GetValue<long>());
        Assert.Null(row["_journal_origin"]);
        Assert.Null(row["_journal_members"]);
        if (!queue) Assert.Empty(f.Evidence.Queries);
    }

    [Fact]
    public async Task Request_abort_cancels_the_journal_database_read()
    {
        var ct = TestContext.Current.CancellationToken;
        var fixture = new Fixture();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Page.ReadPage = async token =>
        {
            using var registration = token.Register(() => canceled.TrySetResult());
            started.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return [];
        };
        await using var host = await ReportFixture.Start(fixture.Facts, fixture.Definition, nativeReader: fixture.Reader);
        using var clientAbort = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var request = host.Client.GetAsync("/api/v2/reports/events.journal/data?collapse=on&from=2026-10-01T00:00:00Z&to=2026-10-02T00:00:00Z",
            clientAbort.Token);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
        clientAbort.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
        await canceled.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
    }

    [Fact]
    public void Domain_change_link_requires_a_supported_source_and_destination_access()
    {
        var facts = Facts();
        var owner = facts with { Definitions = [.. facts.Definitions,
            ReportFixture.J("""{"report_key":"security.events.chains","version":1,"dataset_version":1,"definition_json":{"actions":["view"]},"actions_json":["view"],"fields_json":[{"category":"security"},{"category":"technical"},{"category":"raw_evidence"}]}""")] };
        var viewer = owner with { IsOwner = false };
        static AccessDecision Access(AccessFacts facts) => new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        var source = O("""{"event_id":4728,"channel":"Security","provider_name":"Microsoft-Windows-Security-Auditing","server_role":"domain_controller","domain_id":2}""");
        Assert.Equal(2L, EventsJournalReader.DomainChangeDomain(Access(owner), source));
        Assert.Null(EventsJournalReader.DomainChangeDomain(Access(viewer), source));
        source["server_role"] = "workstation";
        Assert.Null(EventsJournalReader.DomainChangeDomain(Access(owner), source));
        source["server_role"] = "domain_controller";
        source["event_id"] = 4624;
        Assert.Null(EventsJournalReader.DomainChangeDomain(Access(owner), source));
        source["event_id"] = 1102;
        Assert.Null(EventsJournalReader.DomainChangeDomain(Access(owner), source));
        source["provider_name"] = "Microsoft-Windows-Eventlog";
        Assert.Null(EventsJournalReader.DomainChangeDomain(Access(owner), source));
    }

    [Fact]
    public async Task ActualJournalShows7036CatalogueTitleWithoutDisclosingEnrichmentFields()
    {
        var body = await new Fixture().Query(); var row = Row(body);
        Assert.Equal("ok", body["state"]!.ToString());
        Assert.Equal(Title, row["title_text"]!.ToString());
        Assert.Equal("Не определён по доступным данным", row["participant"]!.ToString());
        Assert.Equal(5, row["id"]!.GetValue<int>()); Assert.Equal(7036, row["event_id"]!.GetValue<int>());
        foreach (string field in new[] { "provider_name", "server_id", "domain_id", "risk" }) Assert.False(row.ContainsKey(field));
        Assert.DoesNotContain("Service Control Manager", body.ToJsonString());
    }
    [Theory]
    [InlineData("en", null, "Service state changed", "Not identified in available data")]
    [InlineData("ru", null, Title, "Не определён по доступным данным")]
    [InlineData("en", "Администратор", "Service state changed", "Администратор")]
    public async Task HttpLocalizesDerivedLabelsButPreservesObservedNames(string language, string? target, string title, string participant)
    {
        var f = new Fixture(Facts(owner: false)); f.Page.Rows[0]["target"] = target;
        await using var host = await ReportFixture.Start(f.Facts, f.Definition, nativeReader: f.Reader);
        host.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd(language);
        using var response = await host.Client.GetAsync("/api/v2/reports/events.journal/data?from=2026-10-01T00:00:00Z&to=2026-10-02T00:00:00Z", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var row = Row(await ReportFixture.Body(response));
        Assert.Equal(title, row["title_text"]!.ToString()); Assert.Equal(participant, row["participant"]!.ToString());
        Assert.Equal(title, row["presentation_messages"]!["title_text"]!["text"]!.ToString());
        if (target is not null) Assert.Null(row["presentation_messages"]!["participant"]);
    }
    [Theory]
    [InlineData("provider_name", "\"Other provider\"")]
    [InlineData("provider_name", "null")]
    [InlineData("provider_name", "\" \"")]
    [InlineData("id", "99")]
    [InlineData("event_id", "4624")]
    [InlineData("channel", "\"Security\"")]
    [InlineData("domain_id", "null")]
    [InlineData("server_id", "0")]
    public async Task WrongOrMissingSourceTupleStaysUnknown(string field, string value)
    {
        var f = new Fixture(); f.Evidence.Rows[0][field] = JsonNode.Parse(value);
        Assert.Equal(Unknown, Row(await f.Query())["title_text"]!.ToString());
    }
    [Theory]
    [InlineData("id,event_id")]
    [InlineData("id,channel")]
    [InlineData("event_id,channel")]
    [InlineData("id,event_id,channel")]
    [InlineData("")]
    public async Task HiddenDependenciesAreNeverRecoveredOrCombinedAcrossGrantRows(string columns)
    {
        var f = new Fixture(Facts(owner: false, grants: [Grant(fields: ["security"]), Grant(fields: ["technical"]) ]));
        if (columns.Length == 0) f.Page.Rows = [];
        else f.Page.Columns = columns.Split(',');
        var body = await f.Query();
        Assert.All(body["items"]!.AsArray(), row => Assert.Equal(Unknown, row!["title_text"]!.ToString()));
        Assert.Equal(0, f.Evidence.Opens);
    }
    [Theory]
    [InlineData("id,event_id")][InlineData("id,channel")][InlineData("event_id,channel")]
    public async Task OwnerCannotRecoverDependenciesHiddenFromThePage(string columns)
    {
        var f = new Fixture(); f.Page.Columns = columns.Split(',');
        Assert.Equal(Unknown, Row(await f.Query())["title_text"]!.ToString());
        Assert.Equal(0, f.Evidence.Opens);
    }
    [Theory]
    [InlineData("id", "0")][InlineData("id", "-5")][InlineData("id", "\"5\"")]
    [InlineData("event_id", "\"7036\"")][InlineData("channel", "\" \"")]
    public async Task InvalidVisibleIdentityNeverTriggersEnrichment(string field, string value)
    {
        var f = new Fixture(); f.Page.Rows[0][field] = JsonNode.Parse(value);
        Assert.Equal(Unknown, Row(await f.Query())["title_text"]!.ToString());
        Assert.Equal(0, f.Evidence.Opens);
    }
    [Theory]
    [InlineData("field.security")][InlineData("field.technical")]
    [InlineData("field.raw_evidence")][InlineData("evidence.exact")]
    public async Task ExactResourceDeniesPreventSemanticDisclosure(string denied)
    {
        var f = new Fixture(Facts(owner: false, denied: denied));
        Assert.Equal(Unknown, Row(await f.Query())["title_text"]!.ToString());
    }
    [Fact]
    public async Task SourceOutsideGrantedDomainCannotSupplyTitle()
    {
        var f = new Fixture(Facts(owner: false, grants: [Grant("{\"kind\":\"domain\",\"ids\":[99]}")]));
        Assert.Equal(Unknown, Row(await f.Query())["title_text"]!.ToString());
    }
    [Fact]
    public async Task SeparateFieldGrantsCannotBeUnionedForExactEvidence()
    {
        var f = new Fixture(Facts(owner: false, grants: Fields.Select(field => Grant(fields: [field])).ToArray()));
        // All dependencies are visible within the technical branch, but no single
        // grant authorizes all three exact-evidence field categories.
        f.Page.Categories["event_id"] = "technical";
        var body = await f.Query();
        Assert.All(body["items"]!.AsArray(), row => Assert.Equal(Unknown, row!["title_text"]!.ToString()));
        Assert.Single(f.Evidence.Queries);
    }
    [Theory]
    [InlineData(true, Title)][InlineData(false, Unknown)]
    public async Task NonOwnerNeedsEveryScopedExactEvidenceRight(bool exact, string expected)
    {
        var f = new Fixture(Facts(owner: false, grants: [Grant("{\"kind\":\"domain\",\"ids\":[2]}")], scoped: true, exact: exact));
        Assert.Equal(expected, Row(await f.Query())["title_text"]!.ToString());
    }
    [Fact]
    public async Task EnrichmentReadsOnlyUniqueCurrentPageIds()
    {
        var f = new Fixture(); f.Page.Rows = [Visible(), Visible(), O("""{"id":99,"event_id":7036,"channel":"System"}""")];
        f.Evidence.Rows = [];
        var body = await f.Query(limit: 2);
        Assert.Equal(2, body["items"]!.AsArray().Count);
        var query = Assert.Single(f.Evidence.Queries);
        Assert.Contains("e.id=any($1)", query.Sql);
        Assert.Equal(new long[] { 5 }, Assert.IsType<long[]>(query.Values[0])); Assert.Equal(1, query.Values[1]);
    }
    [Theory]
    [InlineData(" - ", "—", "Не определён по доступным данным", null)]
    [InlineData(" actor ", null, "actor", null)]
    [InlineData(" actor ", " target ", "target", "actor")]
    [InlineData(" actor ", "actor", "actor", null)]
    public async Task ParticipantUsesOnlyObservedNames(string? actor, string? target, string participant, string? behalf)
    {
        var f = new Fixture(); f.Page.Rows[0]["actor"] = actor; f.Page.Rows[0]["target"] = target;
        var row = Row(await f.Query());
        Assert.Equal(participant, row["participant"]!.ToString()); Assert.Equal(behalf, row["on_behalf"]?.ToString());
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task FailedTitleLookupPreservesAuthorizedPageAndCursor(bool postgres)
    {
        var f = new Fixture(); f.Page.Rows = [Visible(), O("""{"id":4,"event_id":7036,"channel":"System"}""")];
        f.Evidence.Error = postgres ? new Npgsql.PostgresException("synthetic query cancelled", "ERROR", "ERROR", "57014") : new TimeoutException("synthetic lookup failure");
        var body = await f.Query(limit: 1);
        Assert.Equal("ok", body["state"]!.ToString()); Assert.Equal(5, Row(body)["id"]!.GetValue<int>());
        Assert.Equal(Unknown, Row(body)["title_text"]!.ToString()); Assert.True(body["has_more"]!.GetValue<bool>());
        var cursor = ReportQuery.DecodeCursor(body["next_cursor"]!.ToString());
        Assert.Equal(5, cursor["id"]!.GetValue<int>()); Assert.Equal("2026-10-01T12:00:00Z", cursor["time"]!.ToString());
    }
    [Fact]
    public async Task CatalogueTitleCannotBleedIntoAnotherTupleWithTheSameId()
    {
        var f = new Fixture(); var other = Visible(); other["channel"] = "Security";
        f.Page.Rows = [Visible(), other];
        var rows = (await f.Query())["items"]!.AsArray();
        Assert.Equal(Title, rows[0]!["title_text"]!.ToString()); Assert.Equal(Unknown, rows[1]!["title_text"]!.ToString());
    }
}
