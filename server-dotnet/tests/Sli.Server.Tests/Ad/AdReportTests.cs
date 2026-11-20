using System.Net;
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
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Reporting.V2;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class AdReportTests
{
    [Theory]
    [InlineData("=fixture()")][InlineData("  +fixture")][InlineData("-fixture")][InlineData("@fixture")][InlineData("\tfixture")][InlineData("\rfixture")][InlineData("\nfixture")]
    public void Both_CSV_builders_escape_untrusted_formula_cells(string value)
    {
        var payload = JsonNode.Parse("""{"state":"available","has_more":false,"items":[{"event_db_id":7,"event_id":4625,"actor":{},"evidence":{"state":"complete"}}]}""")!.AsObject();
        payload["items"]![0]!["actor"]!["name"] = value;
        Assert.Contains("'" + value, AdSecurity.Csv(payload));
        string journal = ReportCsv.FromColumns([new JsonObject { ["key"] = "name", ["label"] = "Name" }], [new JsonObject { ["name"] = value }]);
        Assert.Contains("'" + value, journal);
        Assert.StartsWith("'=label", ReportCsv.FromColumns([new JsonObject { ["key"] = "name", ["label"] = "=label" }], []));
    }
    [Fact]
    public async Task V2_security_export_delegates_to_the_scoped_store_and_denial_never_reads()
    {
        var principal = new Principal("session", 1, "operator"); var facts = await new Facts(true).LoadAsync(principal, Ct);
        var access = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        var definition = new ReportDefinitionRegistry().Get("security.events.chains")!;
        var (parameters, paging) = ReportParameters.Parse(definition, new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues> { ["domain"] = "1" }));
        var context = new ReportQueryContext(definition, access, principal, parameters, paging, ReportScope.None, null, "export", _ => true, []);
        var store = new Store { Payload = JsonNode.Parse("""{"state":"available","has_more":true,"category_coverage":{},"items":[{"event_db_id":7,"event_id":4625,"time_created_utc":"2026-11-06T00:00:00Z","actor":{"name":"=fixture()"},"evidence":{"state":"complete"}}]}""")!.AsObject() };
        var export = await new BuiltinReportExports(null!, null!, store, null!).ExportAsync(context, Ct);
        Assert.Equal(1, export.Rows); Assert.True(export.Truncated); Assert.Contains("'=fixture()", export.Body);
        int calls = store.Reads;
        var deniedFacts = await new Facts(false).LoadAsync(principal, Ct); var denied = new ReportEligibility().Compose(deniedFacts, new CapabilityComposer().Compose(deniedFacts));
        var error = await Assert.ThrowsAsync<ReportRequestException>(() => new BuiltinReportExports(null!, null!, store, null!).ExportAsync(context with { Access = denied }, Ct));
        Assert.Equal(403, error.Status); Assert.Equal(calls, store.Reads);
    }
    [Fact]
    public void Persistence_export_links_only_exact_pairs_and_rejects_unsafe_task_XML()
    {
        JsonObject Event(long id, int code) {
            var ev = JsonNode.Parse("""{"event_db_id":1,"event_id":4697,"domain_id":1,"server_id":1,"time_created_utc":"2026-11-06T00:00:00Z","normalized_event_id":1,"service_name":"fixture","service_file":"fixture.exe","service_account":"fixture","service_start_type":"auto"}""")!.AsObject();
            ev["event_db_id"] = id; ev["event_id"] = code; return ev;
        }
        var events = new[] { Event(7, 4697), Event(8, 7045) };
        var row = Assert.Single(BuiltinReportExports.PersistenceRows(events, false));
        Assert.Equal("exact_link", row["quality"]!.ToString()); Assert.Equal(2, row["evidence"]!.AsArray().Count);
        Assert.Equal(2, BuiltinReportExports.PersistenceRows(events, true).Length);
        var changed = Event(10, 4697); changed["time_created_utc"] = "2026-11-06T00:01:00Z"; changed["service_file"] = "updated.exe";
        var latest = BuiltinReportExports.PersistenceRows([events[0], changed], false)[0];
        Assert.Equal("fixture.exe", latest["previous_value"]!.ToString()); Assert.Equal("fixture", latest["previous"]!["run_as"]!.ToString());
        Assert.Equal("unknown_sid", latest["initiator_quality"]!.ToString());
        events[1]["normalized_event_id"] = null; Assert.Equal(2, BuiltinReportExports.PersistenceRows(events, false).Length);
        var task = Event(9, 4698); task["task_name"] = "fixture"; task["task_content"] = "<!DOCTYPE Task [<!ENTITY x SYSTEM 'file:///fixture'>]><Task><Actions><Exec><Command>&x;</Command></Exec></Actions></Task>";
        Assert.Null(Assert.Single(BuiltinReportExports.PersistenceRows([task], false))["action"]);
    }
    static readonly CancellationToken Ct = TestContext.Current.CancellationToken;
    static readonly AdPeriod Period = new(DateTimeOffset.Parse("2026-11-01T00:00:00Z"), DateTimeOffset.Parse("2026-11-02T00:00:00Z"));
    [Fact] public void Pure_history_matches_frozen_python_including_empty_and_missing_coverage()
    {
        using var stream = typeof(AdReportTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.reference.json")!;
        foreach (var vector in JsonNode.Parse(stream)!.AsArray())
        {
            var actual = AdHistory.Compose(vector!["kind"]!.GetValue<string>(), 1, Period, vector["events"]!.AsArray().Select(e => e!.AsObject()).ToArray(), vector["history"]!.GetValue<bool>());
            Assert.True(JsonNode.DeepEquals(vector["expected"], actual), $"{vector["kind"]}: {actual}");
        }
    }
    [Fact] public void Cursor_is_bound_to_domain_period_and_filters()
    {
        var filters = JsonNode.Parse("{\"actor\":\"example\"}")!.AsObject();
        string cursor = AdSecurity.EncodeCursor(1, Period, filters, Period.Start.AddHours(1), 17);
        Assert.Equal(17, AdSecurity.DecodeCursor(cursor, 1, Period, filters).Id);
        Assert.Throws<AdInputException>(() => AdSecurity.DecodeCursor(cursor, 2, Period, filters));
        Assert.Throws<AdInputException>(() => AdSecurity.DecodeCursor(cursor, 1, Period, new()));
        Assert.Throws<AdInputException>(() => AdSecurity.DecodeCursor(cursor[..^3] + "zzz", 1, Period, filters));
    }
    [Theory]
    [InlineData("2026-11-01", "2026-11-01", "Asia/Bangkok", "2026-10-31T17:00:00+00:00", "2026-11-01T17:00:00+00:00")]
    [InlineData("2026-11-01T00:00:00+03:00", "2026-11-01T01:00:00+03:00", "UTC", "2026-10-31T21:00:00+00:00", "2026-10-31T22:00:00+00:00")]
    public void Time_bounds_follow_exclusive_date_contract(string from, string to, string zone, string start, string end)
    {
        var period = AdPeriod.Parse(from, to, zone, "security_events");
        Assert.Equal(DateTimeOffset.Parse(start), period.Start); Assert.Equal(DateTimeOffset.Parse(end), period.End);
    }
    public static IEnumerable<object[]> Routes => AdReportEndpoints.Routes.Select(r => new object[] { r });
    sealed class Auth(bool authenticated) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(authenticated ? AuthenticationResult.Success(new("session", 1, "operator")) : AuthenticationResult.Denied(401, "authentication_required"));
    }
    sealed class Facts(bool allowed) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct)
        {
            var definitions = new[] { "ad.state", "security.events.chains" }.Select(key => JsonSerializer.SerializeToElement(new
            {
                report_key = key, version = 1, dataset_version = 1,
                definition_json = new { actions = new[] { "view", "export" }, field_categories = new[] { "security", "technical", "raw_evidence" } },
                actions_json = new[] { "view", "export" }, fields_json = new[] { new { category = "security" }, new { category = "technical" }, new { category = "raw_evidence" } }
            })).ToArray();
            return Task.FromResult(new AccessFacts(allowed, "operator", [], [], [], [], [], [], definitions));
        }
    }
    sealed class Store : IAdReportStore
    {
        public int Reads;
        public JsonObject? Payload;
        public Task<IReadOnlyList<long>> DomainsAsync(long after, CancellationToken ct) => Task.FromResult<IReadOnlyList<long>>(after == 0 ? [1, 2] : []);
        public Task<bool> HasSourceAsync(string kind, long domain, CancellationToken ct) { Reads++; return Task.FromResult(true); }
        public Task<JsonObject> ReadAsync(AdReportRequest request, bool sensitive, CancellationToken ct)
        {
            Reads++;
            if (Payload is not null) return Task.FromResult(Payload.DeepClone().AsObject());
            return Task.FromResult(request.Kind == "security" ? AdSecurity.Compose(request, [], true, false, new()) : AdHistory.Compose(request.Kind, request.Domain, request.Period!, [], true));
        }
    }
    static async Task<IHost> Host(Store store, bool allowed = true, bool authenticated = true)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s =>
        {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Auth(authenticated)); s.AddSingleton<IAccessFactsRepository>(new Facts(allowed)); s.AddSingleton<IAdReportStore>(store);
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(routes => routes.MapAdReports()); })).StartAsync(Ct);
    }
    static string Query(string route, bool invalid = false) => route.EndsWith("sources") ? "?unknown=ignored" : $"?domain_id={(invalid ? "bad" : "1")}&time_from=2026-11-01&time_to=2026-11-01";
    [Theory] [MemberData(nameof(Routes))] public async Task Every_route_dispatches_without_501(string route)
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync(route + Query(route), Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.True(store.Reads > 0);
        if (route.EndsWith(".csv")) { Assert.Equal("text/csv", response.Content.Headers.ContentType!.MediaType); Assert.Equal("false", response.Headers.GetValues("X-Sli-Export-Truncated").Single()); }
    }
    [Theory] [MemberData(nameof(Routes))] public async Task Denied_routes_do_not_read_protected_data(string route)
    {
        var store = new Store(); using var host = await Host(store, allowed: false); using var client = host.GetTestClient();
        using var response = await client.GetAsync(route + Query(route), Ct);
        Assert.Equal(route.EndsWith(".csv") ? HttpStatusCode.Forbidden : HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(route.EndsWith(".csv") ? "security_events_export_not_authorized" : "not_authorized", await response.Content.ReadAsStringAsync(Ct)); Assert.Equal(0, store.Reads);
    }
    [Theory] [MemberData(nameof(Routes))] public async Task Authentication_precedes_input_and_reads(string route)
    {
        var store = new Store(); using var host = await Host(store, authenticated: false); using var client = host.GetTestClient();
        using var response = await client.GetAsync(route + Query(route, true), Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode); Assert.Equal(0, store.Reads);
    }
    [Theory] [MemberData(nameof(Routes))] public async Task Invalid_input_or_ignored_source_query_matches_reference(string route)
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync(route + Query(route, true), Ct);
        Assert.Equal(route.EndsWith("sources") ? HttpStatusCode.OK : HttpStatusCode.BadRequest, response.StatusCode);
        if (!route.EndsWith("sources")) Assert.Equal(0, store.Reads);
    }
    [Fact] public void All_five_heavy_handlers_are_compiled_and_pin_exact_manifest()
    {
        var catalog = Sli.Server.Jobs.CoreJobPluginCatalog.Compiled();
        foreach (string handler in AdJobPlugin.Handlers) Assert.True(catalog.Contains(new JsonObject { ["plugin_id"] = "sli.ad", ["handler_id"] = handler }));
        var source = JsonNode.Parse("{\"manifest_id\":\"00000000-0000-0000-0000-000000000001\",\"snapshot_sha256\":\"abc\",\"domain_id\":1,\"revision\":\"1\"}")!.AsObject();
        var pinned = AdJobPlugin.Pin(new(), source, "generation"); Assert.Equal("ad-snapshot", pinned.Partition); Assert.Equal(source["manifest_id"]!.ToString(), pinned.Pinned["input_range"]![0]!.ToString());
    }
}
