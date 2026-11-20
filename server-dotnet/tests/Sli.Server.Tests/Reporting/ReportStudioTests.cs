using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Reporting;
using Xunit;

namespace Sli.Server.Tests.Reporting;

[CollectionDefinition("Report domain environment", DisableParallelization = true)]
public sealed class ReportDomainEnvironmentCollection;

[Collection("Report domain environment")]
public sealed partial class ReportStudioTests
{
    [Theory]
    [InlineData("timeout")]
    [InlineData("postgres")]
    [InlineData("driver")]
    public async Task Read_timeout_is_structured_and_disposes_the_failed_read(string failure)
    {
        await using var host = await Host.Create();
        host.Store.ReadError = failure switch
        {
            "postgres" => new Npgsql.PostgresException("private-database-value", "ERROR", "ERROR", "57014"),
            "driver" => new Npgsql.NpgsqlException("private-database-value", new TimeoutException("private-read")),
            _ => new TimeoutException("private-database-value")
        };
        using var response = await host.Send("GET", "/api/v1/reports/studio.test/data");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(2, body.Count);
        Assert.Equal("report_read_timeout", body["error"]!.GetValue<string>());
        Assert.Equal("unavailable", body["state"]!.GetValue<string>());
        Assert.Equal(1, host.Store.DisposedReads);

        host.Store.ReadError = null;
        using var next = await host.Send("GET", "/api/v1/reports/studio.test/data");
        Assert.Equal(HttpStatusCode.OK, next.StatusCode);
        Assert.Equal(2, host.Store.DisposedReads);
    }

    private const string Payload = """{"report_key":"studio.created","name":"Report","owner":"Owner","purpose":"Purpose","dataset_key":"entities.v2","fields":["id","display_name"],"actions":["view","export"],"status":"published"}""";
    [Theory]
    [InlineData("GET", "/api/v1/reports/studio.test/data?q=secret", null)]
    [InlineData("POST", "/api/v1/reports/definitions", Payload)]
    public async Task ReportDomainFailureIsStructured503ForReadsAndWrites(string method, string route, string? body)
    {
        await using var host = await Host.Create(); host.Store.ThrowReportDomain = true;
        using var response = await host.Send(method, route, body);
        await AssertMissingDomain(response);
    }

    [Fact]
    public async Task UsersWithoutStoredOrObservedDomainNeverQueryReportDataOrUseEnvironmentSeeds()
    {
        string[] names = ["ADLOG_REPORT_DOMAIN_FQDN", "SLI_INSTALL_DOMAIN"];
        var previous = names.Select(Environment.GetEnvironmentVariable).ToArray();
        try
        {
            Environment.SetEnvironmentVariable(names[0], "env.example.test");
            Environment.SetEnvironmentVariable(names[1], "install.example.test");
            await using var host = await Host.Create();
            host.Store.Reports[0]["report_key"] = "ad.users.v2";
            using var response = await host.Send("GET", "/api/v1/reports/ad.users.v2/data?q=secret");
            await AssertMissingDomain(response);
            Assert.Equal(2, host.Store.Statements.Count);
            Assert.Contains("platform_settings", host.Store.Statements[0]);
            Assert.Contains("from domains d", host.Store.Statements[1]);
        }
        finally { for (int i = 0; i < names.Length; i++) Environment.SetEnvironmentVariable(names[i], previous[i]); }
    }

    [Fact]
    public async Task DomainIdLookupNormalizesOnlyTheStoredSetting()
    {
        var store = new Store { StoredReportDomain = " EXAMPLE.test " };
        await using var db = await store.OpenAsync(false, TestContext.Current.CancellationToken);
        Assert.Equal(42, await ReportDomain.ResolveIdAsync(db, TestContext.Current.CancellationToken));
        var lookup = Assert.Single(store.DomainLookups);
        Assert.Equal("example.test", Assert.Single(lookup));
        Assert.Equal(2, store.Statements.Count);
    }

    private static async Task AssertMissingDomain(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var payload = await response.Content.ReadFromJsonAsync<JsonObject>(TestContext.Current.CancellationToken);
        Assert.Equal("report_domain_not_configured", payload!["error"]!.ToString());
        Assert.Contains("Домен отчётов не задан", payload["message"]!.ToString());
        Assert.Contains("Настройки платформы", payload["message"]!.ToString());
        Assert.Equal(2, payload.Count);
    }
    public static TheoryData<string, string, string?, int> Routes => new()
    {
        {"GET", "/api/reports", null, 200},
        {"GET", "/api/v1/reports/catalog", null, 200},
        {"GET", "/api/v1/reports/datasets", null, 200},
        {"GET", "/api/v1/reports/definitions?limit=200", null, 200},
        {"GET", "/api/v1/reports/definitions/studio.test", null, 200},
        {"GET", "/api/v1/reports/studio.test/data?limit=1", null, 200},
        {"GET", "/api/v1/reports/studio.test/export.csv", null, 200},
        {"GET", "/api/v1/reports/studio.test/access-summary", null, 200},
        {"GET", "/api/v1/reports/studio.test/access-trace", null, 200},
        {"POST", "/api/v1/reports/builder/preview", Payload, 200},
        {"POST", "/api/v1/reports/definitions", Payload, 201},
        {"POST", "/api/v1/reports/definitions/studio.test/versions/2/publish", null, 200},
        {"POST", "/api/v1/reports/definitions/studio.test/retire", null, 200},
        {"POST", "/api/v1/reports/definitions/studio.test/visibility", """{"discoverable":true,"requestable":true}""", 200}
    };
    [Theory, MemberData(nameof(Routes))]
    public async Task EveryRouteSucceeds(string method, string route, string? body, int status)
    {
        await using var host = await Host.Create();
        using var response = await host.Send(method, route, body);
        string text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True((int)response.StatusCode == status, text);
        Assert.DoesNotContain("not_implemented", text);
    }
    [Fact]
    public async Task Round2GrantBranchCanBeResumedThroughHttp()
    {
        await using var host = await Host.Create();
        const string route = "/api/v1/reports/studio.test/data";
        using var first = await host.Send("GET", route);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var body = JsonNode.Parse(await first.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        string branch = body["grant_branch"]!.ToString();
        using var next = await host.Send("GET", route + "?grant_branch=" + branch);
        Assert.Equal(HttpStatusCode.OK, next.StatusCode);
        var page = JsonNode.Parse(await next.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(branch, page["grant_branch"]!.ToString());
        Assert.True(JsonNode.DeepEquals(body["items"], page["items"]));
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task EveryRouteRejectsMissingRightsBeforeStorage(string method, string route, string? body, int _)
    {
        await using var host = await Host.Create(owner: false, caps: []);
        using var response = await host.Send(method, route, body);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(host.Store.Statements);
    }
    public static TheoryData<string, string, string?, int, string> Invalid => new()
    {
        {"GET", "/api/v1/reports/definitions?limit=bad", null, 400, "invalid literal for int()"},
        {"GET", "/api/v1/reports/definitions/missing", null, 404, "report_not_found"},
        {"GET", "/api/v1/reports/studio.test/data?limit=bad", null, 400, "invalid literal for int()"},
        {"GET", "/api/v1/reports/studio.test/export.csv?unexpected=yes", null, 400, "unknown_report_query_filter"},
        {"GET", "/api/v1/reports/!/access-summary", null, 400, "invalid_report_key"},
        {"GET", "/api/v1/reports/!/access-trace", null, 400, "invalid_report_key"},
        {"POST", "/api/v1/reports/builder/preview", "{}", 400, "unknown_dataset"},
        {"POST", "/api/v1/reports/definitions", "{}", 400, "unknown_dataset"},
        {"POST", "/api/v1/reports/definitions/studio.test/versions/x/publish", null, 400, "invalid_report_version"},
        {"POST", "/api/v1/reports/definitions/!/retire", null, 400, "invalid_report_key"},
        {"POST", "/api/v1/reports/definitions/studio.test/visibility", "{}", 400, "invalid_report_discovery_policy"},
        {"GET", "/api/v1/reports/studio.test/data?q=a&q=b", null, 400, "duplicate_report_query_filter"},
        {"GET", "/api/v1/reports/studio.test/data?sort=id", null, 400, "incomplete_report_sort"},
        {"GET", "/api/v1/reports/studio.test/data?sort=id&direction=desc;drop", null, 400, "report_sort_not_executable"},
        {"GET", "/api/v1/reports/studio.test/data?field=secret", null, 403, "report_field_access_denied"},
        {"GET", "/api/v1/reports/studio.test/data?grant_branch=bad", null, 400, "invalid_report_grant_branch"},
        {"GET", "/api/v1/reports/studio.test/data?grant_branch=" + new string('a', 64), null, 403, "report_grant_branch_access_denied"},
        {"GET", "/api/v1/reports/studio.test/data?grant_branch=a&grant_branch=b", null, 400, "duplicate_report_query_filter"},
        {"POST", "/api/v1/reports/builder/preview", "[]", 400, "json_object_required"},
        {"POST", "/api/v1/reports/definitions", "{", 400, "invalid_json"}
    };
    [Theory, MemberData(nameof(Invalid))]
    public async Task InputErrorsHaveReferenceStatusAndCode(string method, string route, string? body, int status, string code)
    {
        await using var host = await Host.Create();
        using var response = await host.Send(method, route, body);
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Contains(code, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
    [Theory]
    [InlineData("/api/reports")]
    [InlineData("/api/v1/reports/catalog")]
    [InlineData("/api/v1/reports/datasets")]
    public async Task InputFreeReadsIgnoreUnusedParametersLikeReference(string route)
    {
        await using var host = await Host.Create();
        using var response = await host.Send("GET", route + "?unused=bad");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
    [Fact]
    public async Task PublishReadBackPromoteVisibilityRetireAndAuditAreAtomic()
    {
        await using var host = await Host.Create();
        using var created = await host.Send("POST", "/api/v1/reports/definitions", Payload.Replace("published", "draft"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        using var detail = await host.Send("GET", "/api/v1/reports/definitions/studio.created");
        var card = JsonNode.Parse(await detail.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("draft", card["versions"]![0]!["status"]!.ToString());
        using var registry = await host.Send("GET", "/api/v1/reports/definitions");
        Assert.Contains("studio.created", await registry.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        using var promoted = await host.Send("POST", "/api/v1/reports/definitions/studio.created/versions/1/publish"); Assert.Equal(HttpStatusCode.OK, promoted.StatusCode);
        using var visible = await host.Send("POST", "/api/v1/reports/definitions/studio.created/visibility", """{"discoverable":true,"requestable":true}"""); Assert.Equal(HttpStatusCode.OK, visible.StatusCode);
        using var data = await host.Send("GET", "/api/v1/reports/studio.created/data"); Assert.Equal(HttpStatusCode.OK, data.StatusCode);
        using var retired = await host.Send("POST", "/api/v1/reports/definitions/studio.created/retire"); Assert.Equal(HttpStatusCode.OK, retired.StatusCode);
        Assert.Equal(new[] { "report_draft_created", "report_version_promoted", "report_visibility_changed", "report_retired" }, host.Store.Audit.Select(a => a["action"]!.ToString()));
        Assert.All(host.Store.Audit, a => { Assert.Equal("studio.created", a["target_key"]!.ToString()); Assert.Equal("ok", a["outcome"]!.ToString()); });
    }
    [Fact]
    public async Task AuditFailureRollsBackPublishedVersionAndRetirement()
    {
        await using var host = await Host.Create(); host.Store.FailAudit = true;
        using var response = await host.Send("POST", "/api/v1/reports/definitions", Payload.Replace("studio.created", "studio.test"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(2, host.Store.Reports.Count);
        Assert.Equal("published", host.Store.Reports[0]["status"]!.ToString()); Assert.Empty(host.Store.Audit);
    }
    [Fact]
    public async Task ExistingGrantsRequireReapprovalEvenAfterRetirement()
    {
        await using var host = await Host.Create(); host.Store.HasGrants = true;
        using var retired = await host.Send("POST", "/api/v1/reports/definitions/studio.test/retire"); Assert.Equal(HttpStatusCode.OK, retired.StatusCode);
        var body = JsonNode.Parse(Payload)!.AsObject(); body["report_key"] = "studio.test";
        body["fields"]!.AsArray().Add("natural_key");
        using var response = await host.Send("POST", "/api/v1/reports/definitions", body.ToJsonString());
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("report_security_reapproval_required", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(2, host.Store.Reports.Count); Assert.Single(host.Store.Audit);
    }
    [Theory]
    [InlineData("viewer", "/api/v1/reports/builder/preview", 200)]
    [InlineData("viewer", "/api/v1/reports/definitions", 403)]
    [InlineData("operator", "/api/v1/reports/definitions", 201)]
    [InlineData("operator", "/api/v1/reports/definitions/studio.test/retire", 403)]
    [InlineData("admin", "/api/v1/reports/definitions/studio.test/retire", 200)]
    public async Task MutationRolesMatchReference(string role, string route, int status)
    {
        await using var host = await Host.Create(role: role, owner: false, caps: ["reports.design", "reports.publish", "reports.catalog", "field.identity_basic", "reports.export"]);
        using var response = await host.Send("POST", route, Payload); Assert.Equal(status, (int)response.StatusCode);
    }
    [Fact]
    public async Task OriginAndAuthenticationAreCheckedBeforeReads()
    {
        await using var host = await Host.Create();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/reports/definitions") { Content = new StringContent(Payload, Encoding.UTF8, "application/json") };
        request.Headers.Add("Origin", "https://attacker.invalid"); using var response = await host.Client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(host.Store.Statements);
        host.Authentication.Denied = true;
        using var denied = await host.Send("GET", "/api/v1/reports/datasets"); Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
    }
    [Fact]
    public async Task PreviewIsMetadataOnlyUnlessAuthorizedRowsRequested()
    {
        await using var host = await Host.Create();
        using var response = await host.Send("POST", "/api/v1/reports/builder/preview", Payload);
        var preview = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("not_requested_no_data_disclosure", preview["sample_state"]!.ToString()); Assert.Empty(preview["sample_rows"]!.AsArray());
        Assert.DoesNotContain(host.Store.Statements, s => s.Contains("from entities_v2_active"));
        var payload = JsonNode.Parse(Payload)!; payload["with_rows"] = true;
        using var sample = await host.Send("POST", "/api/v1/reports/builder/preview", payload.ToJsonString());
        var rows = JsonNode.Parse(await sample.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!; Assert.Equal("rows", rows["sample_state"]!.ToString());
        Assert.False(rows["sample_rows"]![0]!.AsObject().ContainsKey("secret"));
    }
    [Theory]
    [InlineData(null)]
    [InlineData(false)]
    public async Task PreviewWithoutRowsPreservesMetadataContract(bool? withRows)
    {
        var store = PreviewStore(); var payload = PreviewPayload();
        if (withRows.HasValue) payload["with_rows"] = withRows.Value; else payload.Remove("with_rows");
        var result = await new ReportStudioService(store, new Catalog()).PreviewAsync(PreviewCaller(), payload, TestContext.Current.CancellationToken);
        Assert.Equal("not_requested_no_data_disclosure", result["sample_state"]!.ToString());
        Assert.Empty(result["sample_rows"]!.AsArray());
        Assert.False(result.ContainsKey("sample_columns")); Assert.False(result.ContainsKey("sample_limit"));
        Assert.DoesNotContain(store.Statements, sql => sql.Contains("from entities_v2_active"));
    }
    [Theory]
    [InlineData(false, 30, 20, "rows")]
    [InlineData(true, 2, 2, "rows")]
    [InlineData(false, 0, 0, "empty")]
    public async Task PreviewRowsAreBoundedAndProjectedByDatasetGrant(bool owner, int available, int expected, string state)
    {
        var store = PreviewStore(); store.RowCount = available;
        // An owner needs no report assignment; an ordinary designer has only identity_basic.
        var caller = PreviewCaller(owner: owner, grant: !owner);
        var result = await new ReportStudioService(store, new Catalog()).PreviewAsync(caller, PreviewPayload(true), TestContext.Current.CancellationToken);
        Assert.Equal("accepted", result["status"]!.ToString()); Assert.Equal(state, result["sample_state"]!.ToString());
        Assert.Equal(20, result["sample_limit"]!.GetValue<int>()); Assert.Equal(expected, result["sample_rows"]!.AsArray().Count);
        string[] keys = owner ? ["display_name", "natural_key"] : ["display_name"];
        Assert.Equal(keys, result["sample_columns"]!.AsArray().Select(c => c!["key"]!.ToString()));
        Assert.All(result["sample_rows"]!.AsArray(), row =>
        {
            Assert.Equal(keys, row!.AsObject().Select(p => p.Key));
            Assert.Equal("=SUM(1)", row["display_name"]!.ToString());
        });
        if (owner) Assert.Equal("entity:1", result["sample_rows"]![0]!["natural_key"]!.ToString());
        var read = Assert.Single(store.Commands, c => c.Sql.Contains("from entities_v2_active"));
        Assert.Equal(21, read.Values[^1]);
    }
    [Fact]
    public async Task PreviewMissingFieldCapabilityGatesBeforeReadingRows()
    {
        var store = PreviewStore();
        var caller = PreviewCaller(caps: ["reports.design", "field.identity_basic"]);
        var result = await new ReportStudioService(store, new Catalog()).PreviewAsync(caller, PreviewPayload(true), TestContext.Current.CancellationToken);
        Assert.Equal("gated", result["status"]!.ToString()); Assert.Equal("gated", result["sample_state"]!.ToString());
        Assert.Equal(new[] { "field.technical" }, result["sample_missing_capabilities"]!.AsArray().Select(v => v!.ToString()));
        Assert.Empty(result["sample_rows"]!.AsArray());
        Assert.DoesNotContain(store.Statements, sql => sql.Contains("from entities_v2_active"));
    }
    [Fact]
    public async Task PreviewWithoutDatasetGrantGatesBeforeReadingRows()
    {
        var store = PreviewStore();
        var result = await new ReportStudioService(store, new Catalog()).PreviewAsync(PreviewCaller(grant: false), PreviewPayload(true), TestContext.Current.CancellationToken);
        Assert.Equal("gated", result["sample_state"]!.ToString()); Assert.Equal("no_dataset_access", result["sample_gate_reason"]!.ToString());
        Assert.Empty(result["sample_rows"]!.AsArray()); Assert.Empty(result["sample_missing_capabilities"]!.AsArray());
        Assert.DoesNotContain(store.Statements, sql => sql.Contains("from entities_v2_active"));
    }
    [Theory]
    [InlineData("reports.assign")]
    [InlineData("access.manage")]
    public async Task AccessSummaryReturnsAssignmentsPackagesAndPendingRequestsWithoutCatalog(string capability)
    {
        await using var host = await Host.Create(owner: false, caps: [capability]);
        host.Store.Reports[0]["version"] = 3;
        host.Store.SummaryAssignments.Add(JsonNode.Parse("""{"subject_type":"user","subject_id":7,"subject_name":"alice","effect":"allow","source_type":"direct","valid_until":null,"actions":["view"],"field_categories":["identity_basic"]}""")!.AsObject());
        host.Store.SummaryPackages.Add(new JsonObject { ["package_key"] = "pkg", ["name"] = "Пакет" }); host.Store.PendingRequests = 2;
        using var response = await host.Send("GET", "/api/v1/reports/studio.test/access-summary");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        var expected = JsonNode.Parse("""{"api_version":"v4","report_key":"studio.test","published_version":3,"discoverable":true,"requestable":false,"assignments":[{"subject_type":"user","subject_id":7,"subject_name":"alice","effect":"allow","source_type":"direct","valid_until":null,"actions":["view"],"field_categories":["identity_basic"]}],"packages":[{"package_key":"pkg","name":"Пакет"}],"pending_requests":2}""");
        Assert.True(JsonNode.DeepEquals(expected, result), result.ToJsonString());
        using var data = await host.Send("GET", "/api/v1/reports/studio.test/data");
        Assert.Equal(HttpStatusCode.Forbidden, data.StatusCode);
        var denied = JsonNode.Parse(await data.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("reports.catalog", denied["required_capability"]!.ToString());
    }
    [Theory]
    [InlineData("reports.design")]
    [InlineData("reports.catalog")]
    public async Task AccessSummaryRejectsUnrelatedCapabilitiesBeforeStorage(string capability)
    {
        await using var host = await Host.Create(owner: false, caps: [capability]);
        using var response = await host.Send("GET", "/api/v1/reports/studio.test/access-summary");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("reports_assign_required", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Empty(host.Store.Statements);
    }
    [Fact]
    public async Task AccessSummaryRequiresKnownReport()
    {
        await using var host = await Host.Create(owner: false, caps: ["reports.assign"]);
        using var response = await host.Send("GET", "/api/v1/reports/missing.report/access-summary");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Contains("report_not_found", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
    [Fact]
    public async Task PublisherAssignmentEnablesReportDataWithoutChangingCapabilities()
    {
        var store = PreviewStore();
        store.Reports[0]["definition_json"] = JsonNode.Parse("""{"columns":["display_name"],"actions":["view"],"field_categories":["identity_basic"]}""");
        var caller = PreviewCaller(caps: ["field.identity_basic"]);
        var denied = caller with { Access = (JsonObject)caller.Access.DeepClone() };
        denied.Access["reports"]![0]!["allowed"] = false; denied.Access["reports"]![0]!["grants"] = new JsonArray();
        var runner = new ReportRunner(store);
        var error = await Assert.ThrowsAsync<ReportException>(() => runner.ExecuteAsync(denied, "studio.test", 50, null, "view", new Dictionary<string, string>(), TestContext.Current.CancellationToken));
        Assert.Equal(403, error.Status); Assert.Equal("report_access_denied", error.Message); Assert.Empty(store.Statements);
        var result = await runner.ExecuteAsync(caller, "studio.test", 50, null, "view", new Dictionary<string, string>(), TestContext.Current.CancellationToken);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""[{"display_name":"=SUM(1)"},{"display_name":"=SUM(1)"}]"""), result["items"]));
    }

    private static JsonObject PreviewPayload(bool withRows = false) => new()
    {
        ["dataset_key"] = "entities.v2", ["fields"] = new JsonArray("display_name", "natural_key"), ["with_rows"] = withRows
    };
    private static Store PreviewStore()
    {
        var store = new Store(); store.Dataset["fields_json"]![2]!["category"] = "technical"; return store;
    }
    private static ReportCaller PreviewCaller(bool owner = false, bool grant = true, string[]? caps = null)
    {
        caps ??= ["reports.design", "field.identity_basic", "field.technical"];
        var capabilities = new CapabilityDecisionSet(owner, caps.ToHashSet(), new HashSet<string>(), [], new Dictionary<string, JsonElement>());
        var assignment = JsonNode.Parse("""{"source_type":"direct","source":"user:7","scope":{"kind":"all"},"field_categories":["identity_basic"],"allowed_actions":["view"]}""");
        var report = new JsonObject { ["report_key"] = "studio.test", ["version"] = 1, ["dataset_key"] = "entities.v2", ["allowed"] = true, ["grants"] = new JsonArray(assignment) };
        return new(new Principal("session", 7, "viewer", "alice"), new AccessFacts(owner, "viewer", [], [], [], [], [], [], []), capabilities,
            new JsonObject { ["reports"] = grant ? new JsonArray(report) : new JsonArray() });
    }
    [Fact]
    public async Task CsvHasBomFormulaEscapingAndBoundedExportHeaders()
    {
        await using var host = await Host.Create(); host.Store.RowCount = 201;
        using var response = await host.Send("GET", "/api/v1/reports/studio.test/export.csv");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        byte[] bytes = await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken); Assert.Equal(new byte[] { 239, 187, 191 }, bytes[..3]);
        string csv = Encoding.UTF8.GetString(bytes); Assert.Contains("'=SUM(1)", csv); Assert.DoesNotContain("secret-value", csv);
        Assert.Equal("true", response.Headers.GetValues("X-Sli-Export-Truncated").Single()); Assert.Equal("200", response.Headers.GetValues("X-Sli-Export-Rows").Single());
        Assert.Contains("INCOMPLETE-first-200-rows.csv", response.Content.Headers.ContentDisposition!.FileName);
    }
    [Fact]
    public async Task SummaryAllowsAssignerWithoutCatalogAndTraceHidesInternalSubjectIds()
    {
        await using var host = await Host.Create(owner: false, caps: ["reports.assign"]);
        using var summary = await host.Send("GET", "/api/v1/reports/studio.test/access-summary"); Assert.Equal(HttpStatusCode.OK, summary.StatusCode);
        using var denied = await host.Send("GET", "/api/v1/reports/studio.test/access-trace"); Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        await using var reader = await Host.Create(owner: false, caps: ["reports.catalog", "field.identity_basic", "reports.export"]);
        using var trace = await reader.Send("GET", "/api/v1/reports/studio.test/access-trace");
        string text = await trace.Content.ReadAsStringAsync(TestContext.Current.CancellationToken); Assert.Contains("current_subject", text); Assert.DoesNotContain("user:42", text);
    }
    [Theory]
    [InlineData("sql")][InlineData(" RAW_SQL ")][InlineData("query")][InlineData("expression")][InlineData("where")][InlineData("having")][InlineData("join")]
    public async Task NestedSqlDefinitionsAreRejected(string key)
    {
        await using var host = await Host.Create(); var body = JsonNode.Parse(Payload)!; body["nested"] = new JsonArray(new JsonObject { [key] = "select private" });
        using var response = await host.Send("POST", "/api/v1/reports/builder/preview", body.ToJsonString()); Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("arbitrary_sql_or_unsafe_definition_rejected", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task OrdinaryFilterTextContainingSqlWordsIsAccepted()
    {
        await using var host = await Host.Create();
        var body = JsonNode.Parse(Payload)!;
        body["filters"] = new JsonArray(new JsonObject { ["field"] = "display_name", ["op"] = "eq", ["value"] = "SQL Server select account" });
        using var response = await host.Send("POST", "/api/v1/reports/builder/preview", body.ToJsonString());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("SQL Server select account", result["filters"]![0]!["value"]!.ToString());
    }

    private sealed class Authentication(string role) : IPrincipalAuthenticator
    {
        public bool Denied;
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) => ValueTask.FromResult(Denied ? AuthenticationResult.Denied(401, "authentication_required") : AuthenticationResult.Success(new("session", 42, role, "designer")));
    }
    private sealed class Facts(Store store, bool owner, string role, string[] capabilities) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            static JsonElement J(JsonNode node) => JsonSerializer.SerializeToElement(node);
            var reports = store.Reports.Where(r => r["status"]!.ToString() == "published").Select(r =>
            {
                var row = (JsonObject)r.DeepClone(); row["fields_json"] = store.Dataset["fields_json"]!.DeepClone(); row["actions_json"] = store.Dataset["actions_json"]!.DeepClone(); row["dataset_version"] = 1; return J(row);
            }).ToArray();
            var direct = capabilities.Select(c => J(new JsonObject { ["capability_key"] = c, ["effect"] = "allow", ["scope_json"] = new JsonObject { ["kind"] = "all" } })).ToArray();
            var assignment = JsonNode.Parse("""{"report_key":"studio.test","effect":"allow","subject_type":"user","subject_id":42,"source_type":"direct","scope_json":{"kind":"all"},"field_categories":["identity_basic"],"allowed_actions":["view","export"]}""")!;
            return Task.FromResult(new AccessFacts(owner, role, [], [], direct, capabilities.Select(c => J(new JsonObject { ["capability_key"] = c })).ToArray(), [], [J(assignment)], reports));
        }
    }
    private sealed class Host(IHost app, Store store, Authentication authentication) : IAsyncDisposable
    {
        public Store Store => store; public Authentication Authentication => authentication; public HttpClient Client { get; } = app.GetTestClient();
        public static async Task<Host> Create(bool owner = true, string role = "admin", string[]? caps = null)
        {
            caps ??= ["reports.design", "reports.publish", "reports.catalog", "reports.assign", "access.manage", "field.identity_basic", "field.security", "field.privilege", "reports.export"];
            var store = new Store(); var authentication = new Authentication(role);
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "1", ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:Root"] = Path.Combine(Path.GetTempPath(), "sli-empty-reports-" + Guid.NewGuid().ToString("N")) }).Build();
            var app = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
            {
                services.AddRouting(); services.AddSingleton<IConfiguration>(config); services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
                services.AddSingleton<IPrincipalAuthenticator>(authentication); services.AddSingleton<IAccessFactsRepository>(new Facts(store, owner, role, caps));
                services.AddSingleton<IReportRuleCatalog>(new Catalog()); services.AddSingleton<IReportDatabase>(store); services.AddReportStudio();
            }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapReportStudio()); })).StartAsync(TestContext.Current.CancellationToken);
            return new(app, store, authentication);
        }
        public Task<HttpResponseMessage> Send(string method, string route, string? body = null)
        {
            var request = new HttpRequestMessage(new HttpMethod(method), route);
            if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            return Client.SendAsync(request, TestContext.Current.CancellationToken);
        }
        public async ValueTask DisposeAsync() { Client.Dispose(); await app.StopAsync(TestContext.Current.CancellationToken); app.Dispose(); }
    }
    private sealed class Catalog : IReportRuleCatalog
    {
        public IReadOnlyList<ReportRule> Rules => [new("ad.state", "ad.state", "global", new HashSet<string>(), new HashSet<string>(), null, false)];
    }

    internal sealed class Store : IReportDatabase
    {
        public Exception? ReadError;
        public int DisposedReads;
        public readonly JsonObject Dataset = JsonNode.Parse("""{"id":1,"dataset_key":"entities.v2","version":1,"name":"Entities","object_type":"entity","fields_json":[{"key":"id","label":"ID","category":"identity_basic"},{"key":"display_name","label":"Name","category":"identity_basic"},{"key":"natural_key","label":"Key","category":"identity_basic"}],"filters_json":[{"key":"display_name","ops":["eq","contains","in"]}],"actions_json":["view","export"]}""")!.AsObject();
        public List<JsonObject> Reports = [];
        public bool ThrowReportDomain;
        public string? StoredReportDomain;
        public List<object?[]> DomainLookups = [];
        public List<JsonObject> OtherDatasets = [];
        public int AssignmentCount, PackageCount;
        public List<JsonObject> Audit = []; public List<string> Statements = []; public bool HasGrants, HasPackageGrants, FailAudit; public int RowCount = 2;
        public List<(string Sql, object?[] Values)> Commands = [];
        public List<JsonObject> SummaryAssignments = [], SummaryPackages = []; public int PendingRequests;
        public Store()
        {
            for (int version = 1; version <= 2; version++) Reports.Add(JsonNode.Parse("""{"report_key":"studio.test","name":"Test","owner_name":"Owner","purpose":"Purpose","dataset_key":"entities.v2","sensitivity":"restricted","discoverable":true,"requestable":false,"definition_json":{"columns":["id","display_name"],"filters":[],"sort":[],"actions":["view","export"],"required_capabilities":["field.identity_basic","reports.export"],"field_categories":["identity_basic"],"target_path":"/reports/studio.test","export_policy":"controlled","dashboard_metrics":[]}}""")!.AsObject());
            Reports[0]["version"] = 1; Reports[0]["status"] = "published"; Reports[0]["published_at"] = "2026-01-01T00:00:00Z";
            Reports[1]["version"] = 2; Reports[1]["status"] = "draft";
        }
        public Task<IReportSession> OpenAsync(bool write, CancellationToken ct) => ThrowReportDomain
            ? throw new ReportDomainNotConfiguredException() : Task.FromResult<IReportSession>(new Session(this, write));
        private sealed class Session(Store store, bool write) : IReportSession
        {
            private List<JsonObject> reports = store.Reports.Select(r => (JsonObject)r.DeepClone()).ToList();
            private List<JsonObject> audit = store.Audit.Select(r => (JsonObject)r.DeepClone()).ToList();
            public Task CommitAsync(CancellationToken ct) { if (write) { store.Reports = reports; store.Audit = audit; } return Task.CompletedTask; }
            public ValueTask DisposeAsync() { store.DisposedReads++; return ValueTask.CompletedTask; }
            public Task<IReadOnlyList<JsonObject>> QueryAsync(string sql, IReadOnlyList<object?> args, CancellationToken ct)
            {
                if (store.ReadError is { } error) throw error;
                store.Statements.Add(sql); store.Commands.Add((sql, args.ToArray())); string key = args.Count > 0 ? args[0]?.ToString() ?? "" : "";
                List<JsonObject> result;
                if (sql.Contains("from platform_settings")) result = store.StoredReportDomain is null ? [] : [new JsonObject { ["value"] = store.StoredReportDomain }];
                else if (sql.Contains("select id from domains"))
                {
                    store.DomainLookups.Add(args.ToArray());
                    Assert.Equal("example.test", Assert.Single(args));
                    result = [new JsonObject { ["id"] = 42L }];
                }
                else if (sql.Contains("from domains d")) result = [];
                else if (sql.Contains("pg_advisory_xact_lock")) result = [];
                else if (sql.Contains("insert into access_audit_v4"))
                {
                    if (store.FailAudit) return Task.FromResult<IReadOnlyList<JsonObject>>([]);
                    var row = new JsonObject { ["id"] = audit.Count + 1, ["created_at"] = "2026-08-03T00:00:00Z", ["action"] = args[2]?.ToString(), ["target_type"] = "report", ["target_key"] = args[3]?.ToString(), ["outcome"] = "ok", ["details_json"] = JsonNode.Parse(args[5]!.ToString()!), ["remote_address"] = args[6]?.ToString() };
                    audit.Add(row); result = [row];
                }
                else if (sql.StartsWith("insert into report_registry_v4"))
                {
                    var row = new JsonObject { ["report_key"] = key, ["version"] = Convert.ToInt64(args[1]), ["name"] = args[2]?.ToString(), ["owner_name"] = args[3]?.ToString(), ["purpose"] = args[4]?.ToString(),
                        ["dataset_key"] = store.Dataset["dataset_key"]!.DeepClone(), ["definition_json"] = JsonNode.Parse(args[6]!.ToString()!), ["sensitivity"] = args[7]?.ToString(), ["status"] = args[8]?.ToString(), ["discoverable"] = (bool)args[10]!, ["requestable"] = (bool)args[11]!, ["request_profile_json"] = JsonNode.Parse(args[12]!.ToString()!) };
                    if (row["status"]!.ToString() == "published") row["published_at"] = "2026-01-02T00:00:00Z";
                    reports.Add(row); result = [row];
                }
                else if (sql.StartsWith("update report_registry_v4"))
                {
                    var matches = reports.Where(r => r["report_key"]!.ToString() == key && (sql.Contains("and version=@p1") ? r["version"]!.ToString() == args[1]?.ToString() : r["status"]!.ToString() == "published")).ToArray();
                    foreach (var row in matches)
                    {
                        if (sql.Contains("set status='retired'")) row["status"] = "retired";
                        else if (sql.Contains("set status='published'")) { row["status"] = "published"; row["published_at"] = "2026-01-02T00:00:00Z"; }
                        else { row["discoverable"] = (bool)args[1]!; row["requestable"] = (bool)args[2]!; }
                    }
                    result = sql.Contains("returning") ? matches.ToList() : [];
                }
                else if (sql.Contains("as assignment_count"))
                {
                    if (sql.Contains("from report_registry_v4 r")) result = reports.Select(r =>
                    {
                        var row = (JsonObject)r.DeepClone(); row["assignment_count"] = store.AssignmentCount; row["package_count"] = store.PackageCount; return row;
                    }).ToList();
                    else result = [new JsonObject { ["assignment_count"] = store.HasGrants ? 1 : store.AssignmentCount, ["package_count"] = store.HasPackageGrants ? 1 : store.PackageCount }];
                }
                else if (sql.Contains("coalesce(max(version),0)+1")) result = [new JsonObject { ["version"] = reports.Where(r => r["report_key"]!.ToString() == key).Select(r => long.Parse(r["version"]!.ToString())).DefaultIfEmpty().Max() + 1 }];
                else if (sql.Contains("from report_datasets_v4")) result = new[] { store.Dataset }.Concat(store.OtherDatasets)
                    .Where(d => args.Count == 0 || d["dataset_key"]!.ToString() == key && d["version"]!.ToString() == args[1]?.ToString()).ToList();
                else if (sql.Contains("from report_registry_v4"))
                {
                    var matches = reports.Where(r => r["report_key"]!.ToString() == key);
                    if (sql.Contains("r.version=@p1")) matches = matches.Where(r => r["version"]!.ToString() == args[1]?.ToString());
                    if (sql.Contains("status='published'")) matches = matches.Where(r => r["status"]!.ToString() == "published");
                    if (sql.Contains("status='retired'")) matches = matches.Where(r => r["status"]!.ToString() == "retired" && r["published_at"] is not null);
                    var ordered = sql.Contains("order by r.published_at desc,r.version desc,r.id desc")
                        ? matches.OrderByDescending(r => r["published_at"]?.ToString(), StringComparer.Ordinal)
                            .ThenByDescending(r => long.Parse(r["version"]!.ToString()))
                            .ThenByDescending(r => r["id"]?.GetValue<long>() ?? 0)
                        : matches.OrderByDescending(r => long.Parse(r["version"]!.ToString()));
                    if (sql.Contains("limit 1")) matches = ordered.Take(1); else matches = ordered;
                    result = matches.Select(r => { var row = (JsonObject)r.DeepClone(); row["fields_json"] = store.Dataset["fields_json"]!.DeepClone(); row["dataset_version"] = 1; return row; }).ToList();
                }
                else if (sql.Contains("from entities_v2_active")) result = Enumerable.Range(1, Math.Min(store.RowCount, Convert.ToInt32(args[^1]))).Select(i => new JsonObject { ["id"] = i, ["display_name"] = "=SUM(1)", ["natural_key"] = "entity:" + i, ["secret"] = "secret-value" }).ToList();
                else if (sql.Contains("from access_report_assignments a")) result = store.SummaryAssignments;
                else if (sql.Contains("from access_package_reports pr")) result = store.SummaryPackages;
                else if (sql.Contains("from report_access_requests_v4")) result = [new JsonObject { ["n"] = store.PendingRequests }];
                else throw new InvalidOperationException("Unscripted report query: " + sql);
                return Task.FromResult<IReadOnlyList<JsonObject>>(result.Select(r => (JsonObject)r.DeepClone()).ToArray());
            }
        }
    }
}
