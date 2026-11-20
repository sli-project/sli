using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Reporting;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class ReportRunnerTests
{
    private static readonly string[] Capabilities = ["reports.design", "reports.publish", "reports.catalog", "field.identity_basic", "field.security", "field.privilege", "field.technical", "reports.export"];
    private static JsonObject O(string text) => JsonNode.Parse(text)!.AsObject();
    private static ReportCaller Caller(string dataset, JsonArray grants, bool allowed = true)
    {
        var caps = new CapabilityDecisionSet(false, Capabilities.ToHashSet(), new HashSet<string>(), [], new Dictionary<string, JsonElement>());
        var report = new JsonObject { ["report_key"] = "studio.test", ["dataset_key"] = dataset, ["version"] = 1, ["allowed"] = allowed, ["grants"] = grants };
        return new(new Principal("session", 1, "viewer", "reader"), new AccessFacts(false, "viewer", [], [], [], [], [], [], []), caps,
            new JsonObject { ["reports"] = new JsonArray(report) });
    }
    private static JsonObject Grant(string scope = "{\"kind\":\"all\"}", string fields = "[\"identity_basic\",\"security\",\"privilege\"]", string source = "user:1") =>
        O("{\"scope\":" + scope + ",\"field_categories\":" + fields + ",\"allowed_actions\":[\"view\",\"export\"],\"source_type\":\"direct\",\"source\":\"" + source + "\"}");
    private static Task<JsonObject> Execute(Recording db, ReportCaller caller, string[]? fields = null, Dictionary<string, string>? query = null, string action = "view", int limit = 1) =>
        new ReportRunner(db, new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"]="false" }).Build()).ExecuteAsync(caller, "studio.test", limit, fields, action, query ?? [], TestContext.Current.CancellationToken);

    [Theory]
    [InlineData("entities.v2", "from entities_v2_active entity")]
    [InlineData("events.v2", "from event_hot h")]
    [InlineData("security.problems", "from findings_active findings")]
    [InlineData("ad.audit.snapshot", "version.source_section='directory_accounts'")]
    [InlineData("ad.accounts.privileged", "relation.source_section='privileged_membership'")]
    [InlineData("ad.accounts.vpn", "relation.source_section='vpn_membership'")]
    [InlineData("ad.gpo.governance", "version.source_section='gpo_governance'")]
    public async Task EveryExecutableDatasetReadsItsReferenceProjection(string dataset, string expected)
    {
        var db = new Recording(dataset); var result = await Execute(db, Caller(dataset, new JsonArray(Grant())));
        Assert.Equal("available", result["state"]!.ToString()); Assert.Equal(dataset, result["dataset_key"]!.ToString()); Assert.Single(result["items"]!.AsArray());
        Assert.Contains(db.Commands, c => c.Sql.Contains(expected));
        Assert.All(db.Commands, command => { Assert.DoesNotMatch(@"\{[a-zA-Z_]", command.Sql); Assert.DoesNotContain('?', command.Sql); });
        Assert.False(result["items"]![0]!.AsObject().ContainsKey("unpublished"));
        Assert.Equal("per_grant", result["field_visibility"]!.ToString());
        if (dataset.StartsWith("ad.")) Assert.Equal("not_collected", result["summary"]!["collection"]!.AsObject().First().Value!["state"]!.ToString());
        if (dataset == "events.v2") Assert.NotNull(result["next_cursor"]);
    }
    [Theory]
    [InlineData("entities.v2", "entity.domain_id")]
    [InlineData("events.v2", "event.domain_id")]
    [InlineData("ad.audit.snapshot", "entity.domain_id")]
    [InlineData("ad.accounts.privileged", "source_entity.domain_id")]
    [InlineData("ad.accounts.vpn", "source_entity.domain_id")]
    [InlineData("ad.gpo.governance", "entity.domain_id")]
    public async Task ScopeBindsIdsAndRemapsCoverageWithoutWidening(string dataset, string expected)
    {
        var db = new Recording(dataset); await Execute(db, Caller(dataset, new JsonArray(Grant("{\"kind\":\"domain\",\"ids\":[7]}"))));
        Assert.Contains(db.Commands, c => c.Sql.Contains(expected + "=any(@p0)") && c.Values[0] is long[] ids && ids.SequenceEqual([7L]));
        if (dataset.StartsWith("ad.")) Assert.Contains(db.Commands, c => c.Sql.Contains("run.domain_id=any(@p1)") && c.Values[0] is string[] && c.Values[1] is long[]);
    }
    [Fact]
    public async Task IndependentAssignmentsDoNotCrossScopesAndFields()
    {
        var db = new Recording("entities.v2");
        var grants = new JsonArray(Grant("{\"kind\":\"domain\",\"ids\":[7]}", "[\"identity_basic\"]"), Grant("{\"kind\":\"domain\",\"ids\":[8]}", "[\"security\"]", "user:2"));
        var result = await Execute(db, Caller("entities.v2", grants), limit: 20);
        Assert.Equal("per_grant", result["field_visibility"]!.ToString()); Assert.Equal(2, result["limits"]!["grant_branches"]!.GetValue<int>());
        var rows = result["items"]!.AsArray();
        Assert.Contains(rows, r => r!.AsObject().ContainsKey("display_name") && !r.AsObject().ContainsKey("enabled"));
        Assert.Contains(rows, r => r!.AsObject().ContainsKey("enabled") && !r.AsObject().ContainsKey("display_name"));
        var branches = result["branch_continuations"]!.AsArray(); Assert.Equal(2, branches.Count);
        Assert.All(branches, b => Assert.Matches("^[a-f0-9]{64}$", b!["grant_branch"]!.ToString()));
        var other = Caller("entities.v2", new JsonArray(Grant("{\"kind\":\"domain\",\"ids\":[7]}", "[\"identity_basic\"]"), Grant("{\"kind\":\"domain\",\"ids\":[8]}", "[\"security\"]", "user:2")));
        var denied = await Assert.ThrowsAsync<ReportException>(() => Execute(db, other, ["display_name", "enabled"])); Assert.Equal("report_field_access_denied", denied.Message);
    }
    [Fact]
    public async Task Round2DisjointGrantContinuationAndExportStayInTheirOwnBranch()
    {
        var identity = Grant("""{"kind":"server","ids":[1]}""", """["identity_basic"]""", "A");
        identity["allowed_actions"] = new JsonArray("view");
        var technical = Grant("""{"kind":"server","ids":[2]}""", """["technical"]""", "B");
        var caller = Caller("entities.v2", new JsonArray(identity, technical));
        var db = new Recording("entities.v2", round2: true);
        var result = await Execute(db, caller, limit: 20);
        Assert.Equal("per_grant", result["field_visibility"]!.ToString());
        Assert.All(result["items"]!.AsArray(), row => Assert.Single(row!.AsObject()));
        var branches = result["branch_continuations"]!.AsArray();
        Assert.Equal(2, branches.Count);
        Assert.All(branches, branch => Assert.Matches("^[a-f0-9]{64}$", branch!["grant_branch"]!.ToString()));
        Assert.Contains(result["items"]!.AsArray(), row => JsonNode.DeepEquals(row, O("""{"name":"basic-row"}""")));
        Assert.Contains(result["items"]!.AsArray(), row => JsonNode.DeepEquals(row, O("""{"natural_key":"technical-row"}""")));
        string branchKey = branches.Single(b => b!["fields"]![0]!.ToString() == "name")!["grant_branch"]!.ToString();
        db.Commands.Clear();
        var page = await Execute(db, caller, query: new() { ["grant_branch"] = " " + branchKey.ToUpperInvariant() + " " }, limit: 20);
        Assert.Equal(branchKey, page["grant_branch"]!.ToString());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""[{"name":"basic-row"}]"""), page["items"]));
        Assert.Single(db.Commands, c => c.Sql.Contains("limit @"));
        Assert.Contains(db.Commands, c => c.Sql.Contains("entity.server_id=any(@p0)") && c.Values[0] is long[] ids && ids.SequenceEqual([1L]));
        foreach (var (fields, action) in new[] { (new[] { "name", "natural_key" }, "view"), (new[] { "name" }, "export") })
        {
            var error = await Assert.ThrowsAsync<ReportException>(() => Execute(db, caller, fields, action: action));
            Assert.Equal("report_field_access_denied", error.Message); Assert.Equal(403, error.Status);
        }
        var exported = await Execute(db, caller, ["natural_key"], action: "export", limit: 20);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""[{"natural_key":"technical-row"}]"""), exported["items"]));
    }

    [Theory]
    [InlineData("bad", "invalid_report_grant_branch", 400)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "report_grant_branch_access_denied", 403)]
    public async Task Round2InvalidOrUnassignedBranchFailsBeforeRowRead(string branch, string code, int status)
    {
        var db = new Recording("entities.v2");
        var error = await Assert.ThrowsAsync<ReportException>(() => Execute(db, Caller("entities.v2", new JsonArray(Grant())), query: new() { ["grant_branch"] = branch }));
        Assert.Equal(code, error.Message); Assert.Equal(status, error.Status);
        Assert.DoesNotContain(db.Commands, c => c.Sql.Contains("limit @"));
    }

    [Theory]
    [InlineData("{\"kind\":\"channel\",\"values\":[\"Security\"]}", "entities.v2")]
    [InlineData("{\"mode\":\"none\",\"clauses\":[]}", "events.v2")]
    [InlineData("{\"kind\":\"domain\",\"ids\":[7]}", "security.problems")]
    public async Task UnsupportedScopesFailClosed(string scope, string dataset)
    {
        var db = new Recording(dataset); var error = await Assert.ThrowsAsync<ReportException>(() => Execute(db, Caller(dataset, new JsonArray(Grant(scope)))));
        Assert.Equal(403, error.Status); Assert.Equal("report_scope_not_executable", error.Message);
        Assert.DoesNotContain(db.Commands, c => c.Sql.Contains("limit @"));
    }
    [Fact]
    public async Task FiltersAreBoundParametersAndEventCursorRoundTrips()
    {
        var db = new Recording("events.v2"); const string injection = "x';select pg_sleep(999)--";
        var result = await Execute(db, Caller("events.v2", new JsonArray(Grant())), query: new() { ["q"] = injection, ["time_from"] = "2026-01-01T00:00:00Z", ["view"] = "authentication" });
        Assert.DoesNotContain(db.Commands, c => c.Sql.Contains(injection)); Assert.Contains(db.Commands, c => c.Values.Contains(injection));
        string cursor = result["next_cursor"]!.ToString();
        var next = new Recording("events.v2"); await Execute(next, Caller("events.v2", new JsonArray(Grant())), query: new() { ["cursor"] = cursor });
        Assert.Contains(next.Commands, c => c.Sql.Contains("coalesce(event.id,0)") && c.Values.Any(v => v is DateTimeOffset));
    }
    [Fact]
    public async Task VpnCountExcludesCursorAndCustomSortRejectsCursor()
    {
        var db = new Recording("ad.accounts.vpn"); var first = await Execute(db, Caller("ad.accounts.vpn", new JsonArray(Grant())), query: new() { ["sort"] = "object_id", ["direction"] = "asc" });
        string cursor = first["next_cursor"]!.ToString();
        var next = new Recording("ad.accounts.vpn"); await Execute(next, Caller("ad.accounts.vpn", new JsonArray(Grant())), query: new() { ["sort"] = "object_id", ["direction"] = "asc", ["cursor"] = cursor });
        Assert.Contains(next.Commands, c => c.Sql.Contains("filtered_count") && !c.Sql.Contains("source_entity.id>"));
        Assert.Contains(next.Commands, c => c.Sql.Contains("source_entity.id>@") && c.Sql.Contains("limit @"));
        var error = await Assert.ThrowsAsync<ReportException>(() => Execute(next, Caller("ad.accounts.vpn", new JsonArray(Grant())), query: new() { ["cursor"] = cursor })); Assert.Equal("report_cursor_requires_default_sort", error.Message);
    }
    [Theory]
    [InlineData("events.v2", "cursor", "!", "invalid_report_cursor")]
    [InlineData("events.v2", "time_from", "2026-01-01", "invalid_report_time_filter")]
    [InlineData("events.v2", "view", "unknown", "invalid_report_query_filter")]
    [InlineData("ad.audit.snapshot", "entity_type", "all", "invalid_report_query_filter")]
    [InlineData("ad.accounts.vpn", "activity_state", "unsafe", "invalid_report_query_filter")]
    [InlineData("ad.gpo.governance", "has_executable_components", "yes", "invalid_report_query_filter")]
    public async Task InvalidInteractiveFiltersHaveReferenceCodes(string dataset, string field, string value, string code)
    {
        var db = new Recording(dataset); var error = await Assert.ThrowsAsync<ReportException>(() => Execute(db, Caller(dataset, new JsonArray(Grant())), query: new() { [field] = value })); Assert.Equal(code, error.Message);
    }
    [Fact]
    public async Task ExportRequiresBothActionAndCapability()
    {
        var db = new Recording("entities.v2"); var grant = Grant(); grant["allowed_actions"] = new JsonArray("view");
        var error = await Assert.ThrowsAsync<ReportException>(() => Execute(db, Caller("entities.v2", new JsonArray(grant)), action: "export")); Assert.Equal(403, error.Status);
        var caller = Caller("entities.v2", new JsonArray(Grant())); caller = caller with { Capabilities = caller.Capabilities with { Capabilities = new HashSet<string>() } };
        var denied = await Assert.ThrowsAsync<ReportException>(() => Execute(db, caller, action: "export")); Assert.Equal("report_export_denied", denied.Message);
    }
    [Fact]
    public void DefinitionSecurityRejectsStructuralChangesAndAcceptsSubset()
    {
        var before = O("""{"columns":["id","display_name"],"field_categories":["identity_basic"],"required_capabilities":["field.identity_basic"],"actions":["view","export"],"filters":[],"sort":[],"target_path":"/reports/x","export_policy":"controlled","dashboard_metrics":[]}""");
        var subset = (JsonObject)before.DeepClone(); subset["columns"] = new JsonArray("id"); subset["actions"] = new JsonArray("view"); Assert.False(ReportBuilder.SecurityExpands(before, subset));
        foreach (string field in new[] { "filters", "sort", "target_path", "export_policy", "dashboard_metrics" }) { var changed = (JsonObject)before.DeepClone(); changed[field] = "changed"; Assert.True(ReportBuilder.SecurityExpands(before, changed)); }
    }

    [Fact]
    public async Task LegacyMixedColumnsNormalizeAndUnknownColumnsFailBeforeDataRead()
    {
        var db = new Recording("entities.v2") { Columns = new JsonArray("display_name", new JsonObject { ["key"] = "enabled" }) };
        var result = await Execute(db, Caller("entities.v2", new JsonArray(Grant())));
        Assert.Equal(new[] { "display_name", "enabled" }, result["fields"]!.AsArray().Select(f => f!["key"]!.ToString()));
        db = new Recording("entities.v2") { Columns = new JsonArray("display_name", "unknown") };
        var error = await Assert.ThrowsAsync<ReportException>(() => Execute(db, Caller("entities.v2", new JsonArray(Grant()))));
        Assert.Equal("invalid_report_definition_columns", error.Message);
        Assert.DoesNotContain(db.Commands, c => c.Sql.Contains("from entities_v2_active"));
    }

    [Fact]
    public async Task ExplicitFieldsSelectOnlyTheirAtomicServerGrant()
    {
        JsonArray Grants() => new(Grant("""{"kind":"server","ids":[1]}""", """["identity_basic"]""", "A"),
            Grant("""{"kind":"server","ids":[2]}""", """["technical"]""", "B"));
        Recording Database() => new("entities.v2")
        {
            Columns = new JsonArray("display_name", "natural_key"),
            FieldDefinitions = JsonNode.Parse("""[{"key":"display_name","category":"identity_basic"},{"key":"natural_key","category":"technical"}]""")!.AsArray()
        };
        foreach (var (field, other, server) in new[] { ("display_name", "natural_key", 1L), ("natural_key", "display_name", 2L) })
        {
            var db = Database();
            var result = await Execute(db, Caller("entities.v2", Grants()), [field]);
            Assert.All(result["items"]!.AsArray(), row => { Assert.True(row!.AsObject().ContainsKey(field)); Assert.False(row.AsObject().ContainsKey(other)); });
            var command = Assert.Single(db.Commands, c => c.Sql.Contains("from entities_v2_active"));
            Assert.Equal(new[] { server }, Assert.IsType<long[]>(command.Values[0]));
        }
        var denied = await Assert.ThrowsAsync<ReportException>(() => Execute(Database(), Caller("entities.v2", Grants()), ["display_name", "natural_key"]));
        Assert.Equal("report_field_access_denied", denied.Message);
    }

    [Theory]
    [InlineData("ad.audit.snapshot")]
    [InlineData("ad.accounts.privileged")]
    [InlineData("ad.accounts.vpn")]
    public async Task AdUserAggregatesRecomputeInactivityFromCurrentStoredPolicy(string dataset)
    {
        var db = new Recording(dataset, inactivityDays: 45);
        var result = await Execute(db, Caller(dataset, new JsonArray(Grant())), query: dataset == "ad.accounts.vpn" ? new() { ["activity_state"] = "inactive" } : null);
        Assert.Contains(db.Commands, c => c.Sql.Contains("from platform_settings"));
        var policyQueries = db.Commands.Where(c => c.Sql.Contains("interval '45 days'")).ToArray();
        Assert.NotEmpty(policyQueries);
        Assert.All(policyQueries, c =>
        {
            Assert.Contains("pg_input_is_valid", c.Sql);
            Assert.Contains("::timestamptz <=", c.Sql);
            Assert.DoesNotContain("interval '90 days'", c.Sql);
            Assert.DoesNotContain("{inactivity_days}", c.Sql);
        });
        if (dataset == "ad.accounts.vpn")
        {
            Assert.Equal(45, result["summary"]!["inactive_threshold_days"]!.GetValue<long>());
            Assert.Equal(2, result["summary"]!["unknown_activity_users"]!.GetValue<int>());
            Assert.All(policyQueries, c => Assert.DoesNotContain("is_inactive", c.Sql));
            Assert.Contains(db.Commands, c => c.Sql.Contains("as filtered_count") && c.Sql.Contains("then 'unknown'") && c.Values.Contains("inactive"));
        }
        else if (dataset == "ad.accounts.privileged")
            Assert.All(policyQueries, c => Assert.DoesNotContain("->>'is_inactive'", c.Sql));
        // Snapshot aggregates retain the collector flag only for computers, never for AD users.
        else Assert.Contains(policyQueries, c => c.Sql.Contains("entity_type='ad_user'\n") && c.Sql.Contains("as inactive_users"));
    }

    [Fact]
    public void VpnInteractivePredicateUsesPolicyAndBindsOnlyTheRequestedState()
    {
        var query = new ReportQuery();
        query.Interactive("ad.accounts.vpn", new Dictionary<string, string> { ["activity_state"] = "inactive" }, 45);
        Assert.Equal("inactive", Assert.Single(query.Values));
        string predicate = Assert.Single(query.Predicates);
        Assert.Contains("interval '45 days'", predicate); Assert.Contains("pg_input_is_valid", predicate);
        Assert.Contains("then 'unknown'", predicate); Assert.DoesNotContain("is_inactive", predicate);
    }

    private sealed class Recording(string dataset, bool round2 = false, int inactivityDays = 90) : IReportDatabase, IReportSession
    {
        public JsonArray? Columns;
        public JsonArray? FieldDefinitions;
        public List<(string Sql, object?[] Values)> Commands = [];
        public Task<IReportSession> OpenAsync(bool write, CancellationToken ct) { Assert.False(write); return Task.FromResult<IReportSession>(this); }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException();
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public Task<IReadOnlyList<JsonObject>> QueryAsync(string sql, IReadOnlyList<object?> values, CancellationToken ct)
        {
            Commands.Add((sql, values.ToArray()));
            foreach (Match match in Regex.Matches(sql, "@p([0-9]+)")) Assert.InRange(int.Parse(match.Groups[1].Value), 0, values.Count - 1);
            IReadOnlyList<JsonObject> rows;
            if (sql.Contains("r.definition_json,d.dataset_key,d.fields_json")) rows = [new JsonObject { ["dataset_key"] = dataset,
                ["definition_json"] = O("""{"columns":["display_name","enabled"],"filters":[],"sort":[],"actions":["view","export"],"export_policy":"controlled"}"""),
                ["fields_json"] = JsonNode.Parse("""[{"key":"display_name","category":"identity_basic"},{"key":"enabled","category":"security"}]""") }];
            else if (sql.Contains("from platform_settings")) rows = [new JsonObject { ["value"] = inactivityDays.ToString(System.Globalization.CultureInfo.InvariantCulture) }];
            else if (sql.Contains(" as filtered_count")) rows = [O("{\"filtered_count\":2}")];
            else if (sql.Contains("as unknown_activity_users")) rows = [new JsonObject { ["unknown_activity_users"] = 2 }];
            else if (sql.Contains("limit @")) rows = Enumerable.Range(1, 2).Select(i => new JsonObject { ["event_id"] = 4740, ["id"] = i, ["object_id"] = i.ToString(), ["time_created_utc"] = "2026-01-01T00:00:00Z", ["display_name"] = "Entity " + i, ["natural_key"] = "secret", ["enabled"] = true, ["unpublished"] = "private" }).ToArray();
            else rows = [];
            if (sql.Contains("r.definition_json,d.dataset_key,d.fields_json") && Columns is not null)
                rows[0]["definition_json"]!["columns"] = Columns.DeepClone();
            if (sql.Contains("r.definition_json,d.dataset_key,d.fields_json") && FieldDefinitions is not null)
                rows[0]["fields_json"] = FieldDefinitions.DeepClone();
            if (round2 && sql.Contains("r.definition_json,d.dataset_key,d.fields_json")) rows = [new JsonObject { ["dataset_key"] = dataset,
                ["definition_json"] = O("""{"columns":["name","natural_key"],"actions":["view","export"],"export_policy":"controlled"}"""),
                ["fields_json"] = JsonNode.Parse("""[{"key":"name","category":"identity_basic"},{"key":"natural_key","category":"technical"}]""") }];
            else if (round2 && sql.Contains("limit @")) rows = [O("""{"id":77,"name":"basic-row","natural_key":"technical-row"}""")];
            return Task.FromResult(rows);
        }
    }
}
