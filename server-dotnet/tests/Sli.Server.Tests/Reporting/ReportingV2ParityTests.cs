using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Logging;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Ad;
using Sli.Server.Domains;
using Sli.Server.Gpo;
using Sli.Server.Workspace;
using Sli.Server.Reporting.V2;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Behavioral vectors from tests/reporting/test_reporting_v2.py; no runtime Python dependency.
public sealed class ReportingV2ParityTests
{
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-29T12:00:00Z");
    static IQueryCollection Query(params (string Key, string Value)[] values) =>
        new QueryCollection(values.ToDictionary(v => v.Key, v => new StringValues(v.Value)));
    static ReportDefinition Demo()
    {
        var d = ReportFixture.Definition();
        d.Rule["scope"] = "domain";
        d.Declaration["params"] = JsonNode.Parse("""
            [{"key":"period","kind":"period","default":"7d","max_days":31},
             {"key":"q","label":"Поиск","kind":"text"},
             {"key":"os","kind":"choice","options":[{"value":"win","label":"Windows"}]},
             {"key":"event_id","kind":"int"}]
            """);
        d.Declaration["columns"] = JsonNode.Parse("""[{"key":"name","sortable":true},{"key":"seen"}]""");
        d.Declaration["views"] = JsonNode.Parse("""[{"key":"table"},{"key":"related"}]""");
        d.Declaration["limits"] = new JsonObject { ["default"] = 100, ["max"] = 500 };
        return d;
    }

    [Fact]
    public void DefaultPeriodAndPagingMatchReference()
    {
        var (p, paging) = ReportParameters.Parse(Demo(), Query(), Now);
        Assert.True(JsonNode.DeepEquals(p["period"], JsonNode.Parse("""{"preset":"7d","from_utc":"2026-09-22T12:00:00Z","to_utc":"2026-09-29T12:00:00Z"}""")));
        Assert.Equal(new ReportPaging(null, 100, "UTC", null, "asc", null), paging);
    }

    [Theory]
    [InlineData(256)] [InlineData(4096)]
    public void TextAcceptsItsDeclaredBoundaryAndRejectsTheNextCharacter(int length)
    {
        var d = Demo();
        d.Declaration["params"] = new JsonArray(new JsonObject { ["key"] = "q", ["kind"] = "text", ["max_length"] = length });
        string value = new('x', length);
        Assert.Equal(value, ReportParameters.Parse(d, Query(("q", value)), Now).Params["q"]!.GetValue<string>());
        Assert.Equal("report_parameter_invalid:q", Assert.Throws<ReportRequestException>(() => ReportParameters.Parse(d, Query(("q", value + "x")), Now)).Message);
    }

    [Theory] [InlineData(256)] [InlineData(4096)]
    public void TextDeclarationOmitsTheLegacyLimitButKeepsCustomLimits(int length)
    {
        var d = Demo();
        d.Declaration["params"] = new JsonArray(new JsonObject { ["key"] = "q", ["label"] = "Поиск", ["kind"] = "text", ["max_length"] = length, ["field_categories"] = new JsonArray() });
        var expected = ReportFixture.O("""{"key":"q","label":"Поиск","kind":"text"}""");
        if (length != 256) expected["max_length"] = length;
        Assert.True(JsonNode.DeepEquals(expected, new ReportAccess(d, ReportFixture.Access()).Declaration()["params"]![0]));
    }

    [Theory]
    [InlineData("2026-09-10", "2026-09-11", "Asia/Novosibirsk", "2026-09-09T17:00:00Z", "2026-09-11T17:00:00Z")]
    [InlineData("2026-09-10T06:15:00Z", "2026-09-10T12:00:00+03:00", "UTC", "2026-09-10T06:15:00Z", "2026-09-10T09:00:00Z")]
    public void CustomPeriodsPreserveCalendarDaysOrExactInstants(string from, string to, string zone, string start, string end)
    {
        var (p, _) = ReportParameters.Parse(Demo(), Query(("period", "custom"), ("from", from), ("to", to), ("tz", zone)), Now);
        Assert.Equal(start, p["period"]!["from_utc"]!.GetValue<string>());
        Assert.Equal(end, p["period"]!["to_utc"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("2026-09-10T06:00:00", "2026-09-10T07:00:00Z", "report_period_invalid")]
    [InlineData("2026-09-10T07:00:00Z", "2026-09-10T06:00:00Z", "report_period_invalid")]
    [InlineData("2026-09-12", "2026-09-10", "report_period_invalid")]
    [InlineData("2026-01-01", "2026-09-10", "report_period_too_wide")]
    public void InvalidCustomPeriodsKeepTheirErrorCodes(string from, string to, string code) =>
        Assert.Equal(code, Assert.Throws<ReportRequestException>(() => ReportParameters.Parse(Demo(), Query(("period", "custom"), ("from", from), ("to", to)), Now)).Message);

    [Theory]
    [InlineData("typo", "x", "report_parameter_unknown:typo")]
    [InlineData("period", "1y", "report_period_invalid")]
    [InlineData("os", "mac", "report_parameter_invalid:os")]
    [InlineData("event_id", "abc", "report_parameter_invalid:event_id")]
    [InlineData("event_id", "-1", "report_parameter_invalid:event_id")]
    [InlineData("limit", "0", "report_limit_invalid")]
    [InlineData("limit", "501", "report_limit_invalid")]
    [InlineData("sort", "seen", "report_sort_invalid")]
    [InlineData("direction", "up", "report_sort_invalid")]
    [InlineData("tz", "Mars/Base", "report_timezone_invalid")]
    public void InvalidParametersNeverReachTheReader(string key, string value, string code) =>
        Assert.Equal(code, Assert.Throws<ReportRequestException>(() => ReportParameters.Parse(Demo(), Query((key, value)), Now)).Message);

    [Fact]
    public void RequiredDomainParsesToAnInteger()
    {
        var d = Demo(); d.Declaration["params"] = JsonNode.Parse("""[{"key":"domain","kind":"domain","required":true}]""");
        Assert.Equal("report_parameter_required:domain", Assert.Throws<ReportRequestException>(() => ReportParameters.Parse(d, Query(), Now)).Message);
        Assert.Equal(2, ReportParameters.Parse(d, Query(("domain", "2")), Now).Params["domain"]!.GetValue<int>());
        Assert.Equal(new long[] { 1, 3 }, new ReportAccess(d, ReportFixture.Access("{\"kind\":\"domain\",\"ids\":[3,1]}")).Scope.DomainIds());
        Assert.Null(new ReportAccess(d, ReportFixture.Access()).Scope.DomainIds());
    }

    [Theory]
    [InlineData("denied", "report_access_denied")]
    [InlineData("export", "report_access_denied")]
    [InlineData("fields", "report_field_categories_not_allowed")]
    [InlineData("scope", "report_scope_not_executable")]
    public void DomainScopeDenialsKeepV1ErrorCodes(string vector, string code)
    {
        var d = Demo(); var access = ReportFixture.Access(); var report = access.Reports.Single(); var grant = report.Grants.Single();
        report = vector switch
        {
            "denied" => report with { Allowed = false },
            "fields" => report with { Grants = [grant with { FieldCategories = new HashSet<string>(["identity_basic"]) }] },
            "scope" => report with { Grants = [grant with { Scope = ReportFixture.J("""{"kind":"domain","ids":[]}""") }] },
            _ => report with { Grants = [grant with { AllowedActions = new HashSet<string>(["view"]) }] }
        };
        access = access with { Reports = [report] };
        var error = Assert.Throws<ReportRequestException>(() => new ReportAccess(d, access, vector == "export" ? "export" : "view"));
        Assert.Equal(403, error.Status); Assert.Equal(code, error.Message);
    }

    [Theory]
    [InlineData("?typo=x", "report_parameter_unknown:typo")]
    [InlineData("?period=custom&from=invalid-date&to=2026-10-04", "report_period_invalid")]
    public async Task InvalidRequestsReturn400BeforeQuery(string query, string code)
    {
        await using var h = await ReportFixture.Start(definition: Demo());
        using var response = await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/data{query}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Equal(0, h.Reader.Calls);
        Assert.Equal(code, (await ReportFixture.Body(response))["error"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("", false)] [InlineData("data", false)] [InlineData("export.csv", false)] [InlineData("rows/7/detail", false)]
    [InlineData("", true)] [InlineData("data", true)] [InlineData("export.csv", true)] [InlineData("rows/7/detail", true)]
    public async Task MissingOrExplicitlyDeniedGrantsKeepTheExactErrorBody(string action, bool denied)
    {
        var facts = ReportFixture.Facts(assigned: denied);
        if (denied)
        {
            var assignment = ReportFixture.O(facts.ReportAssignments.Single().GetRawText()); assignment["effect"] = "deny";
            facts = facts with { ReportAssignments = [ReportFixture.J(assignment.ToJsonString())] };
        }
        await using var h = await ReportFixture.Start(facts);
        using var response = await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}" + (action.Length == 0 ? "" : "/" + action), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(0, h.Reader.Calls);
        Assert.True(JsonNode.DeepEquals(ReportFixture.O("""{"error":"report_access_denied"}"""), await ReportFixture.Body(response)));
    }

    [Fact]
    public async Task UnknownReportReturns404()
    {
        await using var h = await ReportFixture.Start(ReportFixture.Facts(assigned: false));
        using var response = await h.Client.GetAsync("/api/v2/reports/nope.report", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode); Assert.Equal(0, h.Reader.Calls);
        Assert.Equal("report_not_found", (await ReportFixture.Body(response))["error"]!.GetValue<string>());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task DetailRetainsTheMainContextAndAcceptsExplicitViewOverrides(bool overrides)
    {
        var d = Demo(); d.Declaration["columns"]![1]!["sortable"] = true;
        d.Declaration["detail"]!["default_limit"] = 25;
        await using var h = await ReportFixture.Start(ReportFixture.Facts("{\"kind\":\"domain\",\"ids\":[3,1]}"), d);
        const string query = "?period=custom&from=2026-09-22T12:00:00Z&to=2026-09-29T12:00:00Z&q=fixture&cursor=fixture-cursor&limit=40&tz=Asia/Bangkok";
        using var mainResponse = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data{query}&tab=related&sort=name&direction=desc", TestContext.Current.CancellationToken);
        var main = h.Reader.Last!;
        using var detailResponse = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/rows/7/detail{query}&tab={(overrides ? "table" : "related")}&sort={(overrides ? "seen" : "name")}&direction={(overrides ? "asc" : "desc")}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, mainResponse.StatusCode); Assert.Equal(HttpStatusCode.OK, detailResponse.StatusCode);
        var detail = h.Reader.Last!;
        Assert.Equal("7", h.Reader.Row);
        Assert.True(JsonNode.DeepEquals(main.Params, detail.Params));
        Assert.Equal(JsonSerializer.Serialize(main.Access), JsonSerializer.Serialize(detail.Access));
        Assert.Equal(main.Principal, detail.Principal); Assert.Equal(main.Scope.Fingerprint, detail.Scope.Fingerprint);
        Assert.Equal(new long[] { 1, 3 }, detail.DomainIds); Assert.Equal(main.DomainIds, detail.DomainIds);
        Assert.Equal("view", detail.Action); Assert.Equal(main.Action, detail.Action);
        Assert.Equal(main.Paging with { Limit = 25, Tab = overrides ? "table" : "related", Sort = overrides ? "seen" : "name", Direction = overrides ? "asc" : "desc" }, detail.Paging);
        Assert.Equal(40, main.Paging.Limit);
    }

    public static IEnumerable<object?[]> DomainDefaults()
    {
        foreach (bool inline in new[] { false, true })
        {
            yield return [inline, 7, "3,7", null, 7];
            yield return [inline, 99, "3", null, 3];
            yield return [inline, 99, "3,7", null, null];
            yield return [inline, 99, "3,7", "  ", null];
            yield return [inline, 99, "", null, null];
            yield return [inline, 7, "3,7", "3", 3];
        }
    }
    [Theory] [MemberData(nameof(DomainDefaults))]
    public async Task DomainDefaultsUseOnlyAvailableOptions(bool inline, int declared, string available, string? explicitValue, int? expected)
    {
        var d = Demo();
        var options = new JsonArray(available.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(v => (JsonNode)new JsonObject { ["value"] = v, ["label"] = "Domain " + v }).ToArray());
        var p = new JsonObject { ["key"] = "domain", ["kind"] = "domain", ["required"] = true, ["default"] = declared };
        if (inline) p["options"] = options.DeepClone(); else p["options_from"] = "registered_domains";
        d.Declaration["params"] = new JsonArray(p);
        await using var h = await ReportFixture.Start(definition: d);
        h.Reader.Options["registered_domains"] = options;
        using var response = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data" + (explicitValue is null ? "" : "?domain=" + Uri.EscapeDataString(explicitValue)), TestContext.Current.CancellationToken);
        Assert.Equal(expected is null ? HttpStatusCode.BadRequest : HttpStatusCode.OK, response.StatusCode);
        if (expected is null) { Assert.Equal(0, h.Reader.Calls); Assert.Equal("report_parameter_required:domain", (await ReportFixture.Body(response))["error"]!.GetValue<string>()); }
        else { Assert.Equal(1, h.Reader.Calls); Assert.Equal(expected.Value, h.Reader.Last!.Params["domain"]!.GetValue<int>()); }
    }

    sealed class SourceLog : ILoggerProvider, ILogger
    {
        public System.Collections.Concurrent.ConcurrentQueue<(string Text, Exception? Exception)> Entries = new();
        public ILogger CreateLogger(string categoryName) => this;
        public void Dispose() { }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => Entries.Enqueue((formatter(state, exception), exception));
    }

    [Theory] [InlineData("data")] [InlineData("export.csv")]
    public async Task GpoContractErrorsReturnSanitized503AndLogWithoutExceptionDetails(string action)
    {
        var logger = new SourceLog();
        await using var h = await ReportFixture.Start(logger: logger);
        var error = new GpoReportSourceException(); error.Data["private"] = "synthetic-private-marker";
        h.Reader.DuringRead = () => throw error;
        using var response = await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/{action}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var payload = await ReportFixture.Body(response);
        Assert.Equal("gpo_snapshot_unavailable", payload["error"]!.GetValue<string>());
        Assert.Equal("error", payload["state"]!.GetValue<string>()); Assert.Equal("source_contract_error", payload["reason"]!.GetValue<string>());
        Assert.Equal("reports.renderer.error_gpo_snapshot", payload["message"]!["code"]!.GetValue<string>());
        Assert.Contains("недоступен или повреждён", payload["message"]!["text"]!.GetValue<string>());
        Assert.DoesNotContain("synthetic-private-marker", payload.ToJsonString());
        Assert.Contains(logger.Entries, e => e.Text.Contains("source contract violation", StringComparison.Ordinal));
        Assert.All(logger.Entries, e => { Assert.Null(e.Exception); Assert.DoesNotContain("synthetic-private-marker", e.Text); });
    }

    static AccessDecision AccessFor(ReportDefinition d, string scope = "{\"kind\":\"all\"}", params string[] actions)
    {
        var access = ReportFixture.Access();
        var fields = new HashSet<string>(["technical", "security", "raw_evidence"]);
        return access with { Capabilities = access.Capabilities with { Capabilities = new HashSet<string>(access.Capabilities.Capabilities.Append("events.view")) },
            Reports = [new(d.AccessKey, true, [new(ReportFixture.J(scope), fields, new HashSet<string>(actions), 1, 1)])] };
    }

    [Theory]
    [InlineData("view", true)] [InlineData("export", false)] [InlineData("", false)]
    public void DelegatedCatalogRequiresViewAction(string action, bool expected)
    {
        var d = new ReportDefinitionRegistry().Get("security.events.chains")!;
        var access = AccessFor(d, actions: [action]);
        var facts = ReportFixture.Facts();
        var catalog = JsonSerializer.SerializeToNode(WorkspaceReportCatalog.Compose(new(facts, access.Capabilities, access), new ReportRuleCatalog(new PluginGenerationReader(null)).Rules, []))!;
        var item = Assert.Single(catalog["items"]!.AsArray());
        Assert.Equal(d.Key, item!["key"]!.GetValue<string>());
        Assert.Equal(expected, item["executable"]!.GetValue<bool>());
    }

    [Theory]
    [InlineData("{\"kind\":\"domain\",\"ids\":[3,1]}", "technical", "view", true)]
    [InlineData("{\"kind\":\"all\"}", "technical", "view", true)]
    [InlineData("{\"kind\":\"domain\",\"ids\":[]}", "technical", "view", false)]
    [InlineData("{\"kind\":\"all\"}", "identity_basic", "view", false)]
    [InlineData("{\"kind\":\"all\"}", "technical", "export", false)]
    public void DomainCatalogMarksNonExecutableGrants(string scope, string field, string action, bool expected)
    {
        var d = Demo();
        var access = AccessFor(d, scope, action);
        var report = access.Reports.Single();
        access = access with { Reports = [report with { Grants = [report.Grants.Single() with { FieldCategories = new HashSet<string>([field]) }] }] };
        var rule = new ReportRule(d.Key, d.AccessKey, "domain", new HashSet<string>(["technical"]), new HashSet<string>(), null, false);
        JsonNode Catalog(AccessDecision decision) => JsonSerializer.SerializeToNode(WorkspaceReportCatalog.Compose(new(ReportFixture.Facts(), decision.Capabilities, decision), [rule], []))!;
        var item = Assert.Single(Catalog(access)["items"]!.AsArray());
        Assert.Equal(expected, item!["executable"]!.GetValue<bool>());
        Assert.Empty(Catalog(access with { Reports = [] })["items"]!.AsArray());
    }

    [Fact]
    public void UiDeclarationsKeepSecurityPathsHomeOrderChartsAndCustomComponents()
    {
        var registry = new ReportDefinitionRegistry();
        var definitions = new ReportRuleCatalog(new PluginGenerationReader(null)).Rules.Select(r => registry.Get(r.RegistryKey)!).ToArray();
        var securityDefinition = registry.Get("security.events.chains")!;
        var security = new ReportAccess(securityDefinition, AccessFor(securityDefinition, actions: ["view"])).Declaration();
        Assert.True(security["params"]![0]!["hidden"]!.GetValue<bool>());
        Assert.Equal("domain", security["params"]![0]!["options_from"]!.GetValue<string>());
        foreach (string path in new[] { "actor.name", "affected_account.name", "outcome_code" }) Assert.Contains(security["columns"]!.AsArray(), c => c!["path"]!.GetValue<string>() == path);
        Assert.True(security["export"]!.GetValue<bool>());
        Assert.Equal("table", security["views"]!.AsArray().Single(v => v!["key"]!.GetValue<string>() == "events")!["kind"]!.GetValue<string>());
        Assert.DoesNotContain(security["views"]!.AsArray(), v => v!["key"]!.GetValue<string>() == "chains");
        var catalog = WorkspaceJson.Declarations.GetProperty("reports").EnumerateArray().Select(r => ReportFixture.O(r.GetRawText())).ToArray();
        var sections = new HashSet<string>(["investigation", "reports/identity", "reports/computers", "reports/policies", "reports/remote-access", "reports/workstations", "reports/file-audit", "operations", "admin"]);
        foreach (var item in catalog) Assert.Contains(item["section"]!.GetValue<string>(), sections);
        Assert.Equal(10, catalog.Single(d => d["key"]!.ToString() == "security.problems")["home_order"]!.GetValue<int>());
        Assert.Equal(30, catalog.Single(d => d["key"]!.ToString() == "ad.users.v2")["home_order"]!.GetValue<int>());
        Assert.Null(catalog.Single(d => d["key"]!.ToString() == "ad.computer-logons")["home_order"]);
        Assert.Equal(new[] { "security.problems", "security.events.chains", "ad.infrastructure" }, catalog.Where(d => d["home_order"] is not null).OrderBy(d => d["home_order"]!.GetValue<int>()).Take(3).Select(d => d["key"]!.ToString()));
        var charts = catalog.Where(d => d["home_view"] is not null).ToArray();
        Assert.DoesNotContain(charts, d => d["key"]!.ToString() == "security.events.chains"); Assert.Contains(charts, d => d["key"]!.ToString() == "vpn.connections");
        foreach (var item in charts)
        {
            var d = definitions.Single(d => d.Key == item["key"]!.ToString());
            Assert.NotNull(item["home_order"]);
            Assert.Equal("chart", item["home_view"]!["kind"]!.GetValue<string>());
            Assert.Equal("chart", d.Views.Single(v => v["key"]!.ToString() == item["home_view"]!["key"]!.ToString())["kind"]!.GetValue<string>());
        }
    }

    sealed class SecurityStore : IAdReportStore
    {
        public long[] Available = [1]; public List<AdReportRequest> Requests = [];
        public JsonObject Payload = ReportFixture.O("""{"state":"available","items":[]}""");
        public Task<IReadOnlyList<long>> DomainsAsync(long after, CancellationToken ct) => Task.FromResult<IReadOnlyList<long>>(Available.Where(id => id > after).ToArray());
        public Task<bool> HasSourceAsync(string kind, long domain, CancellationToken ct) => throw new InvalidOperationException("unexpected source lookup");
        public Task<JsonObject> ReadAsync(AdReportRequest request, bool sensitive, CancellationToken ct) { Requests.Add(request); return Task.FromResult((JsonObject)Payload.DeepClone()); }
    }
    sealed class SecurityDomains : IReportDomains
    {
        public Task<IReadOnlyList<DomainItem>> ReadAsync(long[]? ids, CancellationToken ct) => Task.FromResult<IReadOnlyList<DomainItem>>(
            (ids ?? [1]).Select(id => new DomainItem(id, "example.test", false, new(null, null, null, null, null, null, null))).ToArray());
    }
    static ReportQueryContext SecurityContext(IQueryCollection query)
    {
        var d = new ReportDefinitionRegistry().Get("security.events.chains")!;
        var access = AccessFor(d, actions: ["view", "export"]);
        var (p, paging) = ReportParameters.Parse(d, query, Now);
        return new(d, access, new("session", 7, "viewer"), p, paging, ReportScope.None, null, "view", _ => true, access.Reports.Single().Grants);
    }

    [Theory] [InlineData("empty_unverified", "partial")] [InlineData("not_authorized", "denied")] [InlineData("available", "ok")]
    public async Task SecurityAdapterMapsEngineStatesAndForwardsFilters(string state, string expected)
    {
        var store = new SecurityStore { Payload = ReportFixture.O("""
            {"state":"empty_unverified","items":[],"has_more":false,"next_cursor":null,
             "collection_coverage":{"state":"empty_unverified","source_completeness":"not_proven"},
             "limitations":["An empty window does not prove complete source coverage."],
             "time_bounds":{"from_utc":"a","to_utc_exclusive":"b"}}
            """) };
        store.Payload["state"] = state;
        if (state == "available") store.Payload["items"]!.AsArray().Add(new JsonObject { ["event_db_id"] = 7, ["time_created_utc"] = "2026-09-29T11:00:00Z" });
        var reader = new SecurityEventsReader(store, new SecurityEventDomainOptionsTests.Names(), null!);
        var result = await reader.QueryAsync(SecurityContext(Query(("domain", "1"), ("period", "24h"), ("outcome", "failure"), ("limit", "50"))), TestContext.Current.CancellationToken);
        Assert.Equal(expected, result["state"]!.GetValue<string>());
        var request = Assert.Single(store.Requests); Assert.Equal(1, request.Domain); Assert.Equal(50, request.Limit); Assert.Equal("failure", request.Filters["outcome"]!.GetValue<string>());
        if (state == "empty_unverified")
        {
            Assert.Equal("not_proven", result["coverage"]!["completeness"]!.GetValue<string>());
            Assert.True(JsonNode.DeepEquals(result["limitations"], JsonNode.Parse("""[{"code":"empty_not_proof","text":"Пустой результат не доказывает, что источник собран полностью."}]""")));
            Assert.Equal("domain1.example.test", result["filter_options"]!["domain"]![0]!["label"]!.GetValue<string>());
        }
    }

    [Theory]
    [InlineData("available", "empty")] [InlineData("not_collected", "not_collected")]
    [InlineData("processing", "processing")] [InlineData("stale", "stale")]
    [InlineData("unavailable", "error")] [InlineData("unexpected", "error")]
    public async Task SecurityAdapterDoesNotInventAStateFromAnEmptyPage(string state, string expected)
    {
        var store = new SecurityStore { Payload = new JsonObject { ["state"] = state, ["items"] = new JsonArray() } };
        var reader = new SecurityEventsReader(store, new SecurityEventDomainOptionsTests.Names(), null!);
        var result = await reader.QueryAsync(SecurityContext(Query(("domain", "1"))), TestContext.Current.CancellationToken);
        Assert.Equal(expected, result["state"]!.GetValue<string>());
    }

    [Theory] [InlineData("7")] [InlineData("7,8")]
    public async Task MissingSecurityDomainReadsEveryAccessibleDomain(string domains)
    {
        var store = new SecurityStore { Available = domains.Split(',').Select(long.Parse).ToArray() };
        var reader = new SecurityEventsReader(store, new SecurityEventDomainOptionsTests.Names(), null!);
        var context = SecurityContext(Query());
        Assert.Null(context.Params["domain"]);
        await reader.QueryAsync(context, TestContext.Current.CancellationToken);
        Assert.Equal(store.Available, store.Requests.Select(r => r.Domain));
    }

    [Theory]
    [InlineData("""{"event_id":4740,"account_change":{"observed_transition":{"before":{"state":"unknown","reason":"prior_account_state_not_observed"},"after":{"state":"observed","value":"locked"}}}}""", "Блокировка учётной записи")]
    [InlineData("""{"event_id":4724,"change":{"state":"observed","kind":"password_reset"}}""", "Попытка сброса пароля")]
    [InlineData("""{"change":{"state":"unknown"}}""", null)]
    public void ChangeTextNamesTheEventWithoutUnprovenTransitions(string json, string? expected)
    { var row = ReportFixture.O(json); SecurityEventsReader.Derived(row); Assert.Equal(expected, row["change_text"]?.GetValue<string>()); }

    [Theory]
    [InlineData("""{"state":"observed","name":"synthetic-user"}""", "synthetic-user")]
    [InlineData("""{"state":"unknown"}""", null)]
    public void MemberTextRequiresAnObservedMember(string member, string? expected)
    { var row = new JsonObject { ["member"] = JsonNode.Parse(member) }; SecurityEventsReader.Derived(row); Assert.Equal(expected, row["member_text"]?.GetValue<string>()); }

    [Fact]
    public void CsvUsesLabelsNestedListsNullsAndNeutralizesFormulas()
    {
        var columns = JsonNode.Parse("""[{"key":"name","label":"Имя"},{"key":"state","label":"Состояние","labels":{"on":"Включена"}},{"key":"tags","label":"Метки","path":"meta.tags"}]""")!.AsArray().OfType<JsonObject>();
        var rows = JsonNode.Parse("""[{"name":"=SUM(A1)","state":"on","meta":{"tags":["x","y"]}},{"name":null,"state":"off"}]""")!.AsArray().OfType<JsonObject>();
        Assert.Equal("Имя,Состояние,Метки\r\n'=SUM(A1),Включена,\"x, y\"\r\n,off,\r\n", ReportCsv.FromColumns(columns, rows));
    }

    [Theory] [InlineData(null, "asc")] [InlineData("settings", "asc")] [InlineData(null, "desc")]
    public async Task GpoUsesMetricFiltersServerSortingAndOnlyTheOpenCollection(string? tab, string direction)
    {
        var store = new Sli.Server.Tests.Gpo.GpoReportTests.Store { Pair = ReportFixture.O("""
            {"state":"available","previous":null,"current":{
              "collection_status":"completed","observed_at":"2026-09-10T00:00:00Z","completed_at":"2026-09-10T01:00:00Z",
              "source_states":{"links":{"status":"observed"}},"gpos":[
                {"id":"gpo-a","display_name":"Beta","link_ids":["l1"],"setting_ids":[],"permission_ids":[],"source_states":{"links":{"status":"observed"}}},
                {"id":"gpo-b","display_name":"Alpha","link_ids":[],"setting_ids":["s1","s2"],"permission_ids":[],"source_states":{"links":{"status":"observed"}}}],
              "settings":[{"id":"s1","gpo_name":"Alpha","setting_name":"=cmd"}],"scopes":[],"permissions":[],"wmi_filters":[]}}
            """) };
        var request = new GpoRequest("all", "", tab, "name", direction, 500, null, "UTC", Now.AddDays(-7), Now);
        var result = await GpoReport.QueryAsync(store, [1], request, TestContext.Current.CancellationToken);
        Assert.Equal(direction == "asc" ? new[] { "Alpha", "Beta" } : new[] { "Beta", "Alpha" }, result["items"]!.AsArray().Select(r => r!["display_name"]!.GetValue<string>()));
        Assert.Equal("unlinked", result["metrics"]!.AsArray().Single(m => m!["key"]!.ToString() == "unlinked")!["filter"]!["view"]!.GetValue<string>());
        if (tab is null) Assert.Empty(result["collections"]!.AsObject());
        else { Assert.Equal(new[] { "settings" }, result["collections"]!.AsObject().Select(p => p.Key)); Assert.Equal("=cmd", result["collections"]!["settings"]![0]!["setting_name"]!.GetValue<string>()); }
        var texts = result["limitations"]!.AsArray().Select(l => l!["text"]!.GetValue<string>()).ToArray();
        Assert.Contains(texts, t => t.Contains("RSoP", StringComparison.Ordinal)); Assert.Contains(texts, t => t.Contains("удаление", StringComparison.Ordinal));
    }

    [Theory] [InlineData("asc")] [InlineData("desc")]
    public async Task GpoSortingKeepsEmptyNamesLastInBothDirections(string direction)
    {
        var store = new Sli.Server.Tests.Gpo.GpoReportTests.Store { Pair = ReportFixture.O("""
            {"state":"available","current":{"collection_status":"completed","gpos":[
              {"id":"b","display_name":"b"},{"id":"missing","display_name":null},{"id":"a","display_name":"A"}]}}
            """) };
        var result = await GpoReport.QueryAsync(store, [1], new("all", "", null, "name", direction, 500, null, "UTC", Now.AddDays(-7), Now), TestContext.Current.CancellationToken);
        Assert.Equal(direction == "asc" ? new string?[] { "A", "b", null } : new string?[] { "b", "A", null }, result["items"]!.AsArray().Select(r => r!["display_name"]?.GetValue<string>()));
    }
}
