using System.Net;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Reporting;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Behavioral vectors from tests/reporting/test_report_studio_lifecycle.py.
public sealed partial class ReportStudioTests
{
    [Fact]
    public async Task SecondPublishedVersionRetiresPreviousInsteadOfArchiving()
    {
        await using var host = await Host.Create();
        using var response = await host.Send("POST", "/api/v1/reports/definitions", Payload.Replace("studio.created", "studio.test"));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(new[] { "retired", "draft", "published" }, host.Store.Reports.Select(r => r["status"]!.ToString()));
        Assert.Equal(3, host.Store.Reports[^1]["version"]!.GetValue<long>());
        Assert.Single(host.Store.Statements, s => s.StartsWith("update report_registry_v4 set status='retired'"));
        Assert.DoesNotContain(host.Store.Statements, s => s.Contains("archived"));
        var audit = Assert.Single(host.Store.Audit);
        Assert.Equal("report_published", audit["action"]!.ToString());
        Assert.Equal("studio.test", audit["target_key"]!.ToString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PublicationIsPrivateByDefaultAndAcceptsExplicitVisibility(bool explicitVisibility)
    {
        await using var host = await Host.Create();
        var payload = JsonNode.Parse(Payload)!.AsObject();
        if (explicitVisibility) { payload["discoverable"] = true; payload["requestable"] = true; }
        using var response = await host.Send("POST", "/api/v1/reports/definitions", payload.ToJsonString());
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var item = (await LifecycleBody(response))["item"]!;
        Assert.Equal(explicitVisibility, item["discoverable"]!.GetValue<bool>());
        Assert.Equal(explicitVisibility, item["requestable"]!.GetValue<bool>());
        Assert.Equal(explicitVisibility, host.Store.Reports[^1]["discoverable"]!.GetValue<bool>());
        Assert.Equal(explicitVisibility, host.Store.Reports[^1]["requestable"]!.GetValue<bool>());
    }

    [Theory]
    [InlineData("create", "reports.publish", "report_design_capability_required")]
    [InlineData("create", "reports.design", "reports_publish_required")]
    [InlineData("publish", "reports.publish", "report_design_capability_required")]
    [InlineData("publish", "reports.design", "reports_publish_required")]
    [InlineData("retire", "", "reports_publish_required")]
    [InlineData("visibility", "", "reports_publish_required")]
    public async Task PublisherCapabilityErrorsPrecedeStorage(string action, string capability, string code)
    {
        var store = new Store();
        var caller = await LifecycleCaller(store, capability.Length == 0 ? [] : [capability]);
        var service = new ReportStudioService(store, new Catalog());
        var error = await Assert.ThrowsAsync<ReportException>(() => action == "create"
            ? service.PublishAsync(caller, JsonNode.Parse(Payload)!.AsObject(), null, TestContext.Current.CancellationToken)
            : service.LifecycleAsync(caller, "studio.test", action, "2", new(), null, TestContext.Current.CancellationToken));
        Assert.Equal(403, error.Status);
        Assert.Equal(code, error.Message);
        Assert.Empty(store.Statements);
        Assert.Empty(store.Audit);
    }

    [Fact]
    public async Task PromotionRetiresCurrentAndAuditsBothVersions()
    {
        var store = new Store();
        var caller = await LifecycleCaller(store);
        var result = await new ReportStudioService(store, new Catalog()).LifecycleAsync(caller, "studio.test", "publish", "2", new(), "192.0.2.1", TestContext.Current.CancellationToken);
        Assert.Equal("published", result["status"]!.ToString());
        Assert.Equal(new[] { "retired", "published" }, store.Reports.Select(r => r["status"]!.ToString()));
        Assert.Contains(store.Statements, s => s.Contains("pg_advisory_xact_lock"));
        Assert.True(store.Statements.FindIndex(s => s.Contains("pg_advisory_xact_lock")) < store.Statements.FindIndex(s => s.StartsWith("update report_registry_v4")));
        var audit = Assert.Single(store.Audit);
        Assert.Equal("report_version_promoted", audit["action"]!.ToString());
        Assert.Equal("report", audit["target_type"]!.ToString());
        Assert.Equal("studio.test", audit["target_key"]!.ToString());
        Assert.Equal("192.0.2.1", audit["remote_address"]!.ToString());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"version":2,"retired_version":1}"""), audit["details_json"]));
    }

    [Theory]
    [InlineData("fields", "unknown_or_empty_field_selection")]
    [InlineData("dataset", "unknown_dataset")]
    public async Task PromotionRevalidatesStoredDefinitionWithCurrentDataset(string changed, string code)
    {
        await using var host = await Host.Create();
        if (changed == "fields") host.Store.Reports[1]["definition_json"]!["columns"] = new JsonArray("removed_field");
        else host.Store.Reports[1]["dataset_key"] = "missing.dataset";
        string before = new JsonArray(host.Store.Reports.Select(r => r.DeepClone()).ToArray()).ToJsonString();
        using var response = await host.Send("POST", "/api/v1/reports/definitions/studio.test/versions/2/publish");
        await AssertLifecycleError(response, 400, code);
        Assert.Equal(before, new JsonArray(host.Store.Reports.Select(r => r.DeepClone()).ToArray()).ToJsonString());
        Assert.DoesNotContain(host.Store.Statements, s => s.StartsWith("update report_registry_v4"));
        Assert.Empty(host.Store.Audit);
    }

    [Theory]
    [InlineData("retired", "2", 400, "report_version_not_draft")]
    [InlineData("published", "2", 400, "report_version_not_draft")]
    [InlineData("draft", "99", 404, "report_version_not_found")]
    public async Task PromotionRejectsNonDraftAndUnknownVersion(string status, string version, int expectedStatus, string code)
    {
        await using var host = await Host.Create();
        host.Store.Reports[1]["status"] = status;
        if (status == "published") host.Store.Reports[0]["status"] = "retired";
        using var response = await host.Send("POST", $"/api/v1/reports/definitions/studio.test/versions/{version}/publish");
        await AssertLifecycleError(response, expectedStatus, code);
        Assert.DoesNotContain(host.Store.Statements, s => s.StartsWith("update report_registry_v4"));
        Assert.Empty(host.Store.Audit);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PromotionDatasetChangeWithDirectOrPackageGrantsRequiresReapproval(bool packageGrant)
    {
        await using var host = await Host.Create();
        host.Store.Reports[0]["dataset_key"] = "other.dataset";
        host.Store.AssignmentCount = packageGrant ? 0 : 1;
        host.Store.PackageCount = packageGrant ? 1 : 0;
        using var response = await host.Send("POST", "/api/v1/reports/definitions/studio.test/versions/2/publish");
        await AssertLifecycleError(response, 400, "report_security_reapproval_required");
        Assert.Equal(new[] { "published", "draft" }, host.Store.Reports.Select(r => r["status"]!.ToString()));
        Assert.DoesNotContain(host.Store.Statements, s => s.StartsWith("update report_registry_v4"));
        Assert.Empty(host.Store.Audit);
    }

    [Theory]
    [InlineData("versions/1/publish")]
    [InlineData("retire")]
    [InlineData("visibility")]
    public async Task CodeDefinedReportsCannotBeMutated(string suffix)
    {
        await using var host = await Host.Create();
        using var response = await host.Send("POST", "/api/v1/reports/definitions/ad.state/" + suffix, """{"discoverable":true,"requestable":true}""");
        await AssertLifecycleError(response, 400, "report_is_code_defined");
        Assert.Empty(host.Store.Statements);
        Assert.Empty(host.Store.Audit);
    }

    [Fact]
    public async Task RetirementAuditsPublishedVersionAndCannotBeRepeated()
    {
        await using var host = await Host.Create();
        using var response = await host.Send("POST", "/api/v1/reports/definitions/studio.test/retire");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("retired", (await LifecycleBody(response))["item"]!["status"]!.ToString());
        Assert.Equal("draft", host.Store.Reports[1]["status"]!.ToString());
        Assert.Contains(host.Store.Statements, s => s.Contains("pg_advisory_xact_lock"));
        var audit = Assert.Single(host.Store.Audit);
        Assert.Equal("report_retired", audit["action"]!.ToString());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"version":1}"""), audit["details_json"]));
        using var repeated = await host.Send("POST", "/api/v1/reports/definitions/studio.test/retire");
        await AssertLifecycleError(repeated, 404, "report_not_published");
        Assert.Single(host.Store.Audit);
    }

    [Fact]
    public async Task VisibilityUpdatesOnlyPublishedVersionAndAuditsBooleans()
    {
        await using var host = await Host.Create();
        host.Store.Reports[0]["discoverable"] = false;
        host.Store.Reports[1]["discoverable"] = false;
        using var response = await host.Send("POST", "/api/v1/reports/definitions/studio.test/visibility", """{"discoverable":true,"requestable":false}""");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var item = (await LifecycleBody(response))["item"]!;
        Assert.True(item["discoverable"]!.GetValue<bool>());
        Assert.False(item["requestable"]!.GetValue<bool>());
        Assert.True(host.Store.Reports[0]["discoverable"]!.GetValue<bool>());
        Assert.False(host.Store.Reports[0]["requestable"]!.GetValue<bool>());
        Assert.Equal("draft", host.Store.Reports[1]["status"]!.ToString());
        Assert.False(host.Store.Reports[1]["discoverable"]!.GetValue<bool>());
        var audit = Assert.Single(host.Store.Audit);
        Assert.Equal("report_visibility_changed", audit["action"]!.ToString());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"version":1,"discoverable":true,"requestable":false}"""), audit["details_json"]));
    }

    [Theory]
    [InlineData("""{"discoverable":"yes","requestable":false}""", "invalid_report_discovery_policy")]
    [InlineData("""{"discoverable":false,"requestable":true}""", "requestable_report_must_be_discoverable")]
    public async Task VisibilityRejectsInvalidPolicyWithoutStorage(string payload, string code)
    {
        await using var host = await Host.Create();
        using var response = await host.Send("POST", "/api/v1/reports/definitions/studio.test/visibility", payload);
        await AssertLifecycleError(response, 400, code);
        Assert.Empty(host.Store.Statements);
        Assert.Empty(host.Store.Audit);
    }

    [Theory]
    [InlineData("reports.publish")]
    [InlineData("reports.design")]
    public async Task DefinitionDetailAllowsEitherCapabilityAndPreservesVersionsAndCounts(string capability)
    {
        var store = new Store { AssignmentCount = 4, PackageCount = 2 };
        store.Reports[1]["created_by"] = 1;
        var service = new ReportStudioService(store, new Catalog());
        var caller = await LifecycleCaller(store, [capability]);
        var result = await service.DetailAsync(caller, "studio.test", TestContext.Current.CancellationToken);
        Assert.Equal(4, result["assignment_count"]!.GetValue<long>());
        Assert.Equal(2, result["package_count"]!.GetValue<long>());
        Assert.False(result["code_defined"]!.GetValue<bool>());
        var versions = result["versions"]!.AsArray();
        Assert.Equal(new[] { "2", "1" }, versions.Select(r => r!["version"]!.ToString()));
        foreach (var expected in store.Reports)
        {
            var actual = versions.Single(r => r!["version"]!.ToString() == expected["version"]!.ToString())!;
            foreach (var field in expected) Assert.True(JsonNode.DeepEquals(field.Value, actual[field.Key]), field.Key);
        }
        var error = await Assert.ThrowsAsync<ReportException>(() => service.DetailAsync(caller, "nope.report", TestContext.Current.CancellationToken));
        Assert.Equal("report_not_found", error.Message);
        Assert.Equal(404, error.Status);
    }

    [Fact]
    public async Task DefinitionListIncludesLifecycleFieldsAndCodeDefinedFlag()
    {
        await using var host = await Host.Create();
        var builtIn = (JsonObject)host.Store.Reports[0].DeepClone(); builtIn["report_key"] = "ad.state";
        host.Store.Reports.Add(builtIn); host.Store.AssignmentCount = 4; host.Store.PackageCount = 2;
        using var response = await host.Send("GET", "/api/v1/reports/definitions");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var items = (await LifecycleBody(response))["items"]!.AsArray();
        Assert.Equal(3, items.Count);
        Assert.All(items, item =>
        {
            Assert.Equal(item!["report_key"]!.ToString() == "ad.state", item["code_defined"]!.GetValue<bool>());
            Assert.True(item["discoverable"]!.GetValue<bool>());
            Assert.False(item["requestable"]!.GetValue<bool>());
            Assert.Equal(4, item["assignment_count"]!.GetValue<int>());
            Assert.Equal(2, item["package_count"]!.GetValue<int>());
        });
        var sql = Assert.Single(host.Store.Statements);
        foreach (string field in new[] { "r.discoverable", "r.requestable", "assignment_count", "package_count" }) Assert.Contains(field, sql);
    }

    [Fact]
    public async Task DatasetRegistryDistinguishesExecutableAndUnsupportedDatasets()
    {
        await using var host = await Host.Create();
        var other = (JsonObject)host.Store.Dataset.DeepClone(); other["dataset_key"] = "ad.access.vpn";
        host.Store.OtherDatasets.Add(other);
        using var response = await host.Send("GET", "/api/v1/reports/datasets");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var items = (await LifecycleBody(response))["items"]!.AsArray();
        Assert.Equal(2, items.Count);
        Assert.True(items[0]!["executable"]!.GetValue<bool>());
        Assert.Contains(items[0]!["executable_filter_keys"]!.AsArray(), k => k!.ToString() == "display_name");
        Assert.Contains(items[0]!["executable_sort_keys"]!.AsArray(), k => k!.ToString() == "id");
        Assert.False(items[1]!["executable"]!.GetValue<bool>());
        Assert.Empty(items[1]!["executable_filter_keys"]!.AsArray());
        Assert.Empty(items[1]!["executable_sort_keys"]!.AsArray());
    }

    [Fact]
    public async Task UnknownDefinitionSubpathIsNotHandledByLifecycleRoutes()
    {
        await using var host = await Host.Create();
        using var response = await host.Send("POST", "/api/v1/reports/definitions/studio.test/unknown");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(host.Store.Statements);
    }

    [Fact]
    public async Task LifecycleHttpMapsDesignPermissionErrorToForbidden()
    {
        await using var host = await Host.Create(owner: false, caps: ["reports.publish"]);
        using var response = await host.Send("POST", "/api/v1/reports/definitions/studio.test/versions/2/publish");
        await AssertLifecycleError(response, 403, "report_design_capability_required");
        Assert.Empty(host.Store.Statements);
        Assert.Empty(host.Store.Audit);
    }

    private static async Task<ReportCaller> LifecycleCaller(Store store, string[]? capabilities = null)
    {
        capabilities ??= ["reports.design", "reports.publish", "field.identity_basic", "reports.export"];
        var principal = new Principal("session", 42, "admin", "designer");
        var facts = await new Facts(store, false, "admin", capabilities).LoadAsync(principal, TestContext.Current.CancellationToken);
        return new(principal, facts, new CapabilityComposer().Compose(facts), new());
    }

    private static async Task<JsonObject> LifecycleBody(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    private static async Task AssertLifecycleError(HttpResponseMessage response, int status, string code)
    {
        Assert.Equal(status, (int)response.StatusCode);
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["error"] = code }, await LifecycleBody(response)));
    }
}
