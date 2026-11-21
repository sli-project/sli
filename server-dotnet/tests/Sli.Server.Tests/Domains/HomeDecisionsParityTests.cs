using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Sli.Server.Reporting.V2;
using Xunit;

namespace Sli.Server.Tests.Domains;

// Behavioral vectors from tests/reporting/test_home_decisions.py.
public sealed class HomeDecisionsParityTests
{
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-1101";
    private const string GroupSid = "S-1-5-21-100000001-200000002-300000003-512";
    private const string PreviousLogin = "2026-10-16T18:05:00Z";
    private const string Observed = "2026-10-17T08:52:00Z";
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-17T09:00:00Z");
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static JsonObject Row(object value) => JsonSerializer.SerializeToNode(value)!.AsObject();

    private static HomeReport Queue(bool identity = true, bool exact = false, long[]? ids = null)
    {
        var fields = new HashSet<string> { "security" };
        if (identity) fields.Add("identity_basic");
        if (exact) fields.Add("raw_evidence");
        var grant = new AtomicReportGrant(JsonSerializer.SerializeToElement(new { kind = "domain", ids = ids ?? [7, 8] }),
            fields, new HashSet<string> { "view" }, 1, 1);
        return new(new("security.problems", "security.queue", "domain", new HashSet<string> { "security" }, new HashSet<string>(), null, false),
            new("security.queue", true, [grant]), JsonSerializer.SerializeToElement(new { }), JsonSerializer.SerializeToElement(new { }));
    }

    private sealed class Access(params HomeReport[] reports) : IHomeSummaryAccess
    {
        public Task<IReadOnlyList<HomeReport>> LoadAsync(Principal principal, CancellationToken ct) => Task.FromResult<IReadOnlyList<HomeReport>>(reports);
    }

    private sealed class Domains : IDomainRepository
    {
        public string SnapshotState { get; set; } = "complete";
        public string? ObservedAt { get; set; } = Observed;
        public Task<IReadOnlyList<DomainItem>> ReadAsync(DomainGrant grant, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<DomainItem>>(new long[] { 7, 8 }
                .Where(id => grant.Kind == DomainGrantKind.All || grant.Kind == DomainGrantKind.Scoped && grant.DomainIds.Contains(id))
                .Select(id => new DomainItem(id, $"domain-{id}.example.test", false,
                    new DomainFreshness(ObservedAt, ObservedAt, SnapshotState, ObservedAt, ObservedAt, ObservedAt, ObservedAt))).ToArray());
    }

    private sealed class Rows : IHomeSummaryRepository
    {
        public List<(string Sql, IReadOnlyDictionary<string, object?> Parameters)> Calls { get; } = [];
        public string? Since { get; set; } = PreviousLogin;
        public string Runtime { get; set; } = "active";
        public Exception? Error { get; set; }
        public IReadOnlyList<JsonObject>? Groups { get; set; } = Enumerable.Range(0, 8).Select(i => Row(new
        {
            rule_code = $"synthetic-{i}", title = "Synthetic problem", importance = i % 4, total = i + 1,
            new_count = i < 2 ? 1 : 0, last_seen_utc = "2026-10-17T08:41:00Z", assigned_to = "synthetic-assignee",
            objects = new[] { new { name = "synthetic-object", domain = "example.test" } }, object_count = 1,
            total_problems = 10, total_new = 2, total_groups = 10
        })).ToArray();
        public IReadOnlyList<JsonObject> Labels { get; set; } = [];

        public Task<IReadOnlyList<JsonObject>> ReadAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
        {
            Calls.Add((sql, parameters));
            if (sql.Contains("to_regprocedure('public.detections_use_short337()')")) return Task.FromResult<IReadOnlyList<JsonObject>>([Row(new { installed = false })]);
            if (sql.Contains("previous_login_at")) return Task.FromResult<IReadOnlyList<JsonObject>>([Row(new { previous_login_at = Since })]);
            if (sql.Contains("population as materialized"))
            {
                if (Error is not null) throw Error;
                return Task.FromResult(Groups!);
            }
            if (sql.Contains("runtime_worker_heartbeats")) return Task.FromResult<IReadOnlyList<JsonObject>>(Runtime == "partial" ? [] : [Row(new
            {
                status = "running", heartbeat_at = Runtime == "stale" ? "2026-10-16T08:00:00Z" : Observed,
                expected_interval_seconds = 300, details_json = new { runtime_mode = "findings-v1", manual_runtime = false }
            })]);
            if (sql.Contains("as label")) return Task.FromResult(Labels);
            throw new InvalidOperationException("Unexpected home read");
        }
    }

    private static async Task<JsonObject> Summary(Rows rows, HomeReport? queue = null, string query = "", Domains? domains = null,
        HomeReport[]? reports = null)
    {
        var context = new DefaultHttpContext();
        context.Request.QueryString = new QueryString("?contract=v3" + query);
        var payload = await new HomeSummaryService(new Access(reports ?? [queue ?? Queue()]), domains ?? new Domains(), new HomeSummaryReaders(rows))
            .BuildAsync(new Principal("session", 11, "viewer"), HomeSummaryQuery.Parse(context.Request.Query, Now), Ct);
        return JsonNode.Parse(payload.ToJsonString())!.AsObject();
    }

    private static Dictionary<string, Microsoft.Extensions.Primitives.StringValues> Link(JsonNode group) =>
        QueryHelpers.ParseQuery(new Uri("https://example.test" + (string)group["href"]!).Query);

    [Fact]
    public async Task EightGroupsUseOnePopulationWithExactRemaindersAndScopedLinks()
    {
        var rows = new Rows();
        var payload = await Summary(rows, query: "&domain_id=7");
        Assert.Equal("sli.home-summary.v3", (string?)payload["contract_id"]);
        Assert.Equal("ok", (string?)payload["state"]);
        Assert.Equal(10, (int?)payload["total"]);
        Assert.Equal(2, (int?)payload["new_count"]);
        Assert.Equal(2, (int?)payload["remaining_groups"]);
        Assert.Equal(2, (int?)payload["remaining_problems"]);
        Assert.Equal(8, payload["groups"]!.AsArray().Count);
        Assert.All(payload["groups"]!.AsArray(), group =>
        {
            var link = Link(group!);
            Assert.Equal("7", link["domain"].ToString());
            Assert.StartsWith(link["rule_code"].ToString() + ":", group!["key"]!.ToString());
            Assert.Equal("open", link["population"].ToString());
        });
        Assert.Empty(payload["warnings"]!.AsArray());
        Assert.False(payload.ContainsKey("kpis")); Assert.False(payload.ContainsKey("readers"));
        var read = Assert.Single(rows.Calls, c => c.Sql.Contains("population as materialized"));
        Assert.Equal(new long[] { 7 }, (long[])read.Parameters["ids"]!);
        Assert.Equal(DateTimeOffset.Parse(PreviousLogin), read.Parameters["since"]);
        Assert.Equal(DateTimeOffset.Parse(PreviousLogin), DateTimeOffset.Parse((string)payload["previous_login_at"]!));
        Assert.Single(rows.Calls, call => call.Sql.Contains("population as materialized"));
    }

    [Fact]
    public async Task AccessibleSelectionUsesQueueGrantsRatherThanWorkspaceUnion()
    {
        var queue = Queue(ids: [7]);
        var other = queue with { Rule = queue.Rule with { RegistryKey = "ad.infrastructure", ReportKey = "ad.state" },
            Decision = Queue(ids: [8]).Decision with { ReportKey = "ad.state" } };
        var rows = new Rows();
        Assert.NotEmpty((await Summary(rows, reports: [queue, other]))["groups"]!.AsArray());
        Assert.Equal(new long[] { 7 }, (long[])rows.Calls.Single(c => c.Sql.Contains("population as materialized")).Parameters["ids"]!);
        rows.Calls.Clear();
        var error = await Assert.ThrowsAsync<HomeQueryException>(() => Summary(rows, query: "&domain_id=8", reports: [queue, other]));
        Assert.Equal(403, error.Status); Assert.Equal("domain_scope_denied", error.Message); Assert.Empty(rows.Calls);
    }

    [Fact]
    public async Task MissingLoginBaselineAndIdentityStayUnknown()
    {
        var rows = new Rows { Since = null };
        foreach (var row in rows.Groups!) { row["new_count"] = null; row["total_new"] = null; }
        var payload = await Summary(rows, Queue(identity: false));
        Assert.Null(payload["previous_login_at"]); Assert.Null(payload["new_count"]);
        Assert.All(payload["groups"]!.AsArray(), group =>
        {
            Assert.Null(group!["new_count"]); Assert.Null(group["assigned_to"]); Assert.Null(group["object_count"]);
            Assert.Empty(group["objects"]!.AsArray());
        });
        Assert.DoesNotContain("synthetic-object", payload.ToJsonString()); Assert.DoesNotContain("synthetic-assignee", payload.ToJsonString());
    }

    [Fact]
    public async Task MixedFieldGrantsRedactGlobalIdentityAndKeepSelectedDomainNamesWithoutCohort()
    {
        var queue = Queue(ids: [7]);
        queue = queue with { Decision = queue.Decision with { Grants = queue.Decision.Grants.Concat(Queue(identity: false, ids: [8]).Decision.Grants).ToArray() } };
        var rows = new Rows(); rows.Groups![0]["cohort"] = new JsonArray("finding", 7);
        Assert.Empty((await Summary(rows, queue))["groups"]![0]!["objects"]!.AsArray());
        rows.Calls.Clear();
        var selected = await Summary(rows, queue, "&domain_id=7");
        var group = selected["groups"]![0]!;
        Assert.Equal("synthetic-object", (string?)group["objects"]![0]!["name"]);
        Assert.Equal(10, (int?)selected["total"]); Assert.Equal(2, (int?)selected["remaining_groups"]);
        Assert.False(Link(group).ContainsKey("cohort"));

        // The declaration and validation used by both report data and detail keep the full issued scope.
        var definition = new ReportDefinitionRegistry().Get("security.problems")!;
        var access = new AccessDecision("viewer", new(false, new HashSet<string>(), new HashSet<string>(), [], new Dictionary<string, JsonElement>()), [queue.Decision]);
        var projection = new ReportAccess(definition, access);
        Assert.DoesNotContain(projection.Declaration()["params"]!.AsArray(), p => (string?)p!["key"] == "cohort");
        var link = new QueryCollection(Link(group));
        projection.Validate(link, null, null, false);
        Assert.Equal(new long[] { 7 }, projection.Restrict(new JsonObject { ["domain"] = 7 }).DomainIds());
        foreach (int domain in new[] { 7, 8, 9 })
        foreach (bool detail in new[] { false, true })
        {
            var context = new DefaultHttpContext();
            context.Request.QueryString = new QueryString($"?domain={domain}&cohort=%5B%22finding%22%2C7%5D");
            Assert.Equal(403, Assert.Throws<ReportRequestException>(() => projection.Validate(context.Request.Query, null, null, detail)).Status);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedGroupedReadsAreUnknownAndNeverDiscloseSourceErrors(bool timeout)
    {
        var rows = new Rows { Error = timeout ? new TimeoutException("private-source-error") : new InvalidOperationException("private-source-error") };
        var payload = await Summary(rows);
        Assert.Equal("error", (string?)payload["state"]); Assert.Null(payload["total"]); Assert.Empty(payload["groups"]!.AsArray());
        Assert.DoesNotContain("private-source-error", payload.ToJsonString());
    }

    [Theory]
    [InlineData("active", "empty", 0)]
    [InlineData("partial", "partial", null)]
    [InlineData("stale", "partial", null)]
    public async Task OnlyConfirmedEmptyCanBeZero(string runtime, string state, int? total)
    {
        var payload = await Summary(new Rows { Groups = [], Runtime = runtime });
        Assert.Equal(state, (string?)payload["state"]); Assert.Equal(total, (int?)payload["total"]);
        Assert.Equal(total, (int?)payload["new_count"]);
        Assert.Equal(Observed, (string?)payload["updated_at_utc"]);
    }

    [Fact]
    public async Task MissingAggregateResponseIsUnknown()
    {
        var payload = await Summary(new Rows { Groups = null });
        Assert.Equal("error", (string?)payload["state"]); Assert.Null(payload["total"]);
    }

    [Fact]
    public async Task DomainWarningRetainsCountsButIncompleteEmptyRemainsUnknown()
    {
        var rows = new Rows(); var domains = new Domains { SnapshotState = "partial", ObservedAt = null };
        var payload = await Summary(rows, query: "&domain_id=7", domains: domains);
        Assert.Equal(10, (int?)payload["total"]); Assert.Null(payload["updated_at_utc"]);
        var warning = Assert.Single(payload["warnings"]!.AsArray());
        Assert.Equal("domain-7.example.test", (string?)warning!["domain"]);
        Assert.Equal("home.queue.warning.source_incomplete", (string?)warning["reason_code"]);
        Assert.Equal("/app/operations?domain=7", (string?)warning["href"]);
        rows.Groups = [];
        payload = await Summary(rows, query: "&domain_id=7", domains: domains);
        Assert.Equal("partial", (string?)payload["state"]); Assert.Null(payload["total"]);
    }

    [Fact]
    public async Task ObservationWindowIsPreservedInPopulationAndDrilldown()
    {
        var rows = new Rows();
        var payload = await Summary(rows, query: "&period=custom&from=2026-10-16&to=2026-10-17&tz=UTC");
        var parameters = rows.Calls.Single(c => c.Sql.Contains("population as materialized")).Parameters;
        Assert.Equal(DateTimeOffset.Parse("2026-10-16T00:00:00Z"), parameters["from"]);
        Assert.Equal(DateTimeOffset.Parse("2026-10-18T00:00:00Z"), parameters["to"]);
        var link = Link(payload["groups"]![0]!);
        Assert.Equal("2026-10-16T00:00:00Z", link["time_from"].ToString());
        Assert.Equal("2026-10-18T00:00:00Z", link["time_to"].ToString()); Assert.Equal("UTC", link["tz"].ToString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DailyCohortRetainsProjectedNamesAndGatesExactSource(bool exact)
    {
        var rows = new Rows(); var row = rows.Groups![0];
        var cohort = new JsonArray("membership", "synthetic-0", 7, 11, Sid, GroupSid, "2026-10-17");
        row["cohort"] = cohort; row["day"] = "2026-10-17"; row["assigned_to"] = null; row["unassigned_count"] = 1;
        row["objects"] = new JsonArray(Row(new { name = "Synthetic retained name", name_state = "named", identifier = Sid, domain = "example.test",
            source = new { source_run_id = "synthetic-private-run", event_db_id = 91, observed_at_utc = "2026-08-01T00:00:00Z" } }));
        var group = (await Summary(rows, Queue(exact: exact), "&domain_id=7"))["groups"]![0]!;
        Assert.True(JsonNode.DeepEquals(cohort, JsonNode.Parse(Link(group)["cohort"].ToString())));
        Assert.Equal("unassigned", (string?)group["assignee_state"]); Assert.Equal("2026-10-17", (string?)group["day"]);
        var obj = group["objects"]![0]!;
        Assert.Equal("Synthetic retained name", (string?)obj["name"]); Assert.Equal(Sid, (string?)obj["identifier"]);
        Assert.Equal("named", (string?)obj["name_state"]); Assert.True((bool?)obj["snapshot_name"]);
        if (exact) Assert.Equal(91, (int?)obj["source"]!["event_db_id"]);
        else { Assert.DoesNotContain("synthetic-private-run", group.ToJsonString()); Assert.DoesNotContain("event_db_id", group.ToJsonString()); }
        var hidden = (await Summary(rows, Queue(identity: false)))["groups"]![0]!;
        Assert.False(Link(hidden).ContainsKey("cohort")); Assert.Equal("unknown", (string?)hidden["assignee_state"]); Assert.Null(hidden["day"]);
        Assert.DoesNotContain(Sid, hidden.ToJsonString());
    }

    [Theory]
    [InlineData("synthetic-assignee", 2, "mixed")]
    [InlineData("synthetic-assignee", 0, "assigned")]
    [InlineData(null, 1, "unassigned")]
    public async Task AssigneeStateDistinguishesPartialAndCompleteAssignment(string? assignee, int unassigned, string state)
    {
        var rows = new Rows(); rows.Groups![0]["assigned_to"] = assignee; rows.Groups[0]["unassigned_count"] = unassigned;
        var group = (await Summary(rows))["groups"]![0]!;
        Assert.Equal(state, (string?)group["assignee_state"]); Assert.Equal(unassigned, (int?)group["unassigned_count"]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RetainedIdentityLookupPreservesNamesNoMatchCohortsAndExactFieldGates(bool exact)
    {
        var rows = new Rows(); var row = rows.Groups![0];
        var cohort = new JsonArray("membership", "synthetic-0", 7, 11, Sid, GroupSid, "2026-10-17");
        row["cohort"] = cohort; row["object_names"] = new JsonArray(Sid, GroupSid);
        row["domain_name"] = "example.test"; row["representative"] = Row(new { id = 7, evidence_count = 1, target = Sid });
        rows.Labels = [Row(new { request_index = 0, witness_verified = true, label = "Retained synthetic name", source_run_id = "synthetic-private-run",
            event_db_id = 91, entity_id = 14, observed_at_utc = "2026-08-01T00:00:00Z" }),
            Row(new { request_index = 1, witness_verified = true })];
        var payload = await Summary(rows, Queue(exact: exact), "&domain_id=7");
        var group = payload["groups"]![0]!; var objects = group["objects"]!.AsArray();
        Assert.Equal(2, objects.Count);
        Assert.Equal("Retained synthetic name", (string?)objects[0]!["name"]); Assert.Equal("named", (string?)objects[0]!["name_state"]);
        Assert.True((bool?)objects[0]!["snapshot_name"]);
        Assert.Equal("", (string?)objects[1]!["name"]); Assert.Equal("no_match", (string?)objects[1]!["name_state"]);
        Assert.Equal(new[] { Sid, GroupSid }, objects.Select(o => (string)o!["identifier"]!));
        Assert.True(JsonNode.DeepEquals(cohort, JsonNode.Parse(Link(group)["cohort"].ToString())));
        Assert.Equal(1, (int?)group["total"]);
        if (exact) Assert.Equal(91, (int?)objects[0]!["source"]!["event_db_id"]);
        else Assert.DoesNotContain("synthetic-private-run", payload.ToJsonString());
        var read = Assert.Single(rows.Calls, c => c.Sql.Contains("as label"));
        Assert.Equal(2, JsonNode.Parse((string)read.Parameters["requests"]!)!.AsArray().Count);
        rows.Calls.Clear();
        var hidden = await Summary(rows, Queue(identity: false), "&domain_id=7");
        Assert.Empty(hidden["groups"]![0]!["objects"]!.AsArray());
        Assert.DoesNotContain(Sid, hidden.ToJsonString()); Assert.DoesNotContain("Retained synthetic name", hidden.ToJsonString());
        Assert.DoesNotContain(rows.Calls, c => c.Sql.Contains("as label"));
    }
}
