using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Reporting;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Parity with tests/reporting/test_report_retired_security_contract.py.
// Like the reference, this uses a synthetic transactional store, not PostgreSQL.
public sealed class ReportRetiredSecurityContractTests
{
    private const string Key = "studio.test";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static JsonObject O(string json) => JsonNode.Parse(json)!.AsObject();
    private static JsonObject Payload() => O("""
        {"report_key":"studio.test","name":"Name","owner":"Owner","purpose":"Test",
         "dataset_key":"entities.v2","fields":["display_name"],
         "filters":[{"field":"entity_type","op":"eq","value":"1"}],"sort":[],
         "actions":["view"],"status":"published"}
        """);
    private static JsonObject Definition() => O("""
        {"columns":["display_name"],"filters":[{"field":"entity_type","op":"eq","value":"1"}],
         "sort":[],"actions":["view"],"required_capabilities":["field.identity_basic"],
         "field_categories":["identity_basic"],"target_path":"/reports/studio.test",
         "export_policy":"disabled","dashboard_metrics":[]}
        """);
    private static JsonObject Row(long version, JsonObject? definition = null, string status = "retired", string? published = "2026-01-01T00:00:00Z") => new()
    {
        ["id"] = version, ["report_key"] = Key, ["version"] = version, ["status"] = status,
        ["definition_json"] = (definition ?? Definition()).DeepClone(), ["dataset_key"] = "entities.v2", ["dataset_version"] = 1,
        ["published_at"] = published, ["discoverable"] = true, ["requestable"] = true,
        ["request_profile_json"] = new JsonObject { ["max_duration_days"] = 7 }
    };
    private static ReportCaller Caller()
    {
        var caps = new CapabilityDecisionSet(false,
            new HashSet<string> { "reports.design", "reports.publish", "field.identity_basic", "field.security", "reports.export" },
            new HashSet<string>(), [], new Dictionary<string, JsonElement>());
        return new(new Principal("session", 1, "admin", "designer"), new AccessFacts(false, "admin", [], [], [], [], [], [], []), caps, new());
    }
    private sealed class Catalog : IReportRuleCatalog { public IReadOnlyList<ReportRule> Rules => []; }
    private sealed class Case
    {
        public readonly ReportStudioTests.Store Store = new();
        public readonly JsonObject Input = Payload();
        public ReportStudioService Service => new(Store, new Catalog());
        public Case()
        {
            Store.Reports.Clear();
            Store.Dataset["filters_json"] = O("""{"filters":[{"key":"entity_type","ops":["eq"]}]}""")["filters"]!.DeepClone();
        }
        public void Grant(string source)
        {
            Store.HasGrants = source == "direct";
            Store.HasPackageGrants = source == "package";
        }
        public Task<JsonObject> Publish(string status = "published")
        {
            Input["status"] = status;
            return Service.PublishAsync(Caller(), Input, null, Ct);
        }
        public Task<JsonObject> Promote(long version) => Service.LifecycleAsync(Caller(), Key, "publish", version.ToString(System.Globalization.CultureInfo.InvariantCulture), new(), null, Ct);
        public Task<JsonObject> Retire() => Service.LifecycleAsync(Caller(), Key, "retire", null, new(), null, Ct);
        public async Task<Func<Task<JsonObject>>> Operation(string path)
        {
            if (path == "publish") return () => Publish();
            var draft = await Publish("draft");
            long version = long.Parse(draft["version"]!.ToString());
            return () => Promote(version);
        }
        public async Task Rejected(Func<Task<JsonObject>> operation)
        {
            string before = JsonSerializer.Serialize(Store.Reports), audit = JsonSerializer.Serialize(Store.Audit);
            Store.Statements.Clear();
            var error = await Assert.ThrowsAsync<ReportException>(operation);
            Assert.Equal("report_security_reapproval_required", error.Message);
            Assert.Equal(400, error.Status);
            Assert.Equal(before, JsonSerializer.Serialize(Store.Reports));
            Assert.Equal(audit, JsonSerializer.Serialize(Store.Audit));
            Assert.DoesNotContain(Store.Statements, sql => sql.TrimStart().StartsWith("insert ", StringComparison.OrdinalIgnoreCase)
                || sql.TrimStart().StartsWith("update ", StringComparison.OrdinalIgnoreCase) || sql.TrimStart().StartsWith("delete ", StringComparison.OrdinalIgnoreCase));
            int locked = Store.Statements.FindIndex(sql => sql.Contains("pg_advisory_xact_lock(hashtext(@p0))"));
            Assert.True(locked >= 0);
            Assert.All(Store.Statements.Select((sql, index) => (sql, index)).Where(x => x.sql.Contains("from report_registry_v4") || x.sql.Contains("as assignment_count")),
                x => Assert.True(x.index > locked));
        }
        public void AssertRetiredLookup()
        {
            string sql = Assert.Single(Store.Statements, sql => sql.Contains("r.status='retired'"));
            Assert.Contains("r.report_key=@p0", sql);
            Assert.Contains("r.published_at is not null", sql);
            Assert.Contains("order by r.published_at desc,r.version desc,r.id desc limit 1 for update of r", sql);
            string grants = Assert.Single(Store.Statements, sql => sql.Contains("as assignment_count"));
            Assert.Contains("from access_report_assignments where report_key=@p0", grants);
            Assert.Contains("from access_package_reports where report_key=@p0", grants);
        }
    }

    public static TheoryData<string, string, string> Expansions
    {
        get
        {
            var data = new TheoryData<string, string, string>();
            foreach (string source in new[] { "direct", "package" })
                foreach (string path in new[] { "publish", "promote" })
                    foreach (string change in new[] { "dataset", "filters", "field_categories", "actions", "columns", "required_capabilities" })
                        data.Add(source, path, change);
            return data;
        }
    }
    [Theory, MemberData(nameof(Expansions))]
    public async Task RetirementPreservesSecurityForBothGrantSourcesAndPublicationPaths(string source, string path, string change)
    {
        var test = new Case();
        await test.Publish(); test.Grant(source); await test.Retire();
        switch (change)
        {
            case "dataset":
                test.Input["dataset_key"] = "ad.audit.snapshot";
                test.Store.Dataset["dataset_key"] = "ad.audit.snapshot";
                break;
            case "filters": test.Input["filters"] = new JsonArray(); break;
            case "columns": test.Input["fields"]!.AsArray().Add("natural_key"); break;
            case "actions": test.Input["actions"]!.AsArray().Add("export"); break;
            // Keep columns/actions fixed and make each security allowlist the only expansion.
            case "field_categories":
                test.Store.Reports[0]["definition_json"]!["field_categories"] = new JsonArray(); break;
            case "required_capabilities":
                test.Store.Reports[0]["definition_json"]!["required_capabilities"] = new JsonArray(); break;
        }
        var operation = await test.Operation(path);
        await test.Rejected(operation);
        test.AssertRetiredLookup();
        Assert.Equal(source == "direct", test.Store.HasGrants);
        Assert.Equal(source == "package", test.Store.HasPackageGrants);
    }

    [Theory]
    [InlineData("publish")]
    [InlineData("promote")]
    public async Task GrantsWithoutPublishedHistoryFailClosed(string path)
    {
        var test = new Case(); test.Grant("direct");
        test.Store.Reports.AddRange([Row(3, status: "draft", published: null), Row(4, published: null)]);
        await test.Rejected(await test.Operation(path));
        test.AssertRetiredLookup();
    }

    [Theory]
    [InlineData("publish", false)]
    [InlineData("promote", false)]
    [InlineData("publish", true)]
    [InlineData("promote", true)]
    public async Task LatestPublicationWinsOverHigherVersionAndDraft(string path, bool tiedTime)
    {
        var test = new Case(); test.Grant("package"); test.Input["filters"] = new JsonArray();
        var expanded = Definition(); expanded["filters"] = new JsonArray();
        test.Store.Reports.AddRange(tiedTime
            ? [Row(2, expanded), Row(8), Row(9, expanded, "draft", null)]
            : [Row(2, published: "2026-01-20T00:00:00Z"), Row(8, expanded, published: "2026-01-10T00:00:00Z"), Row(9, expanded, "draft", null)]);
        await test.Rejected(await test.Operation(path));
        test.AssertRetiredLookup();
    }

    [Theory]
    [InlineData("publish", true)]
    [InlineData("promote", true)]
    [InlineData("publish", false)]
    [InlineData("promote", false)]
    public async Task SameContractOrNoGrantsAllowsPublication(string path, bool grants)
    {
        var test = new Case(); if (grants) test.Grant("direct");
        test.Store.Reports.Add(Row(1));
        if (!grants) test.Input["filters"] = new JsonArray();
        var result = await (await test.Operation(path))();
        Assert.Equal("published", result["status"]!.ToString());
        if (path == "publish")
        {
            Assert.False(result["discoverable"]!.GetValue<bool>());
            Assert.False(result["requestable"]!.GetValue<bool>());
            Assert.Equal("90", result["request_profile_json"]!["max_duration_days"]!.ToString());
        }
        else Assert.Null(test.Store.Audit[^1]["details_json"]!["retired_version"]);
        if (!grants) Assert.DoesNotContain(test.Store.Statements, sql => sql.Contains("r.status='retired'"));
    }

    [Fact]
    public async Task ExpandedDraftCanBeCreatedButCannotBePromoted()
    {
        var test = new Case(); test.Grant("direct"); test.Store.Reports.Add(Row(1));
        test.Input["filters"] = new JsonArray();
        var draft = await test.Publish("draft");
        Assert.Equal("draft", draft["status"]!.ToString());
        Assert.Equal("report_draft_created", Assert.Single(test.Store.Audit)["action"]!.ToString());
        await test.Rejected(() => test.Promote(long.Parse(draft["version"]!.ToString())));
    }

    [Theory]
    [InlineData("publish")]
    [InlineData("promote")]
    public async Task CurrentPublicationWinsAndVisibilityIsInherited(string path)
    {
        var test = new Case(); test.Grant("direct");
        var expanded = Definition(); expanded["filters"] = new JsonArray();
        test.Store.Reports.AddRange([Row(1, expanded, published: "2026-02-01T00:00:00Z"), Row(2, status: "published")]);
        var result = await (await test.Operation(path))();
        Assert.Equal("published", result["status"]!.ToString());
        Assert.True(result["discoverable"]!.GetValue<bool>());
        Assert.True(result["requestable"]!.GetValue<bool>());
        var stored = test.Store.Reports.Single(row => row["status"]!.ToString() == "published");
        Assert.Equal("7", stored["request_profile_json"]!["max_duration_days"]!.ToString());
        Assert.DoesNotContain(test.Store.Statements, sql => sql.Contains("r.status='retired'"));
        if (path == "promote") Assert.Equal("2", test.Store.Audit[^1]["details_json"]!["retired_version"]!.ToString());
    }
}
