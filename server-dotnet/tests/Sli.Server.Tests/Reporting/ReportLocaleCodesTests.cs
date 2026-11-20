using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
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

namespace Sli.Server.Tests.Reporting;

public sealed class ReportLocaleCodesTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    // Frozen inputs and outputs of tests/reporting/test_report_locale_codes.py, with synthetic data only.
    static JsonArray Vectors()
    {
        using var stream = typeof(ReportLocaleCodesTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Reporting.report-locale-vectors.json")!;
        return JsonNode.Parse(stream)!.AsArray();
    }
    static JsonObject Vector(string name) => Vectors().OfType<JsonObject>().Single(v => v["name"]!.ToString() == name);
    public static IEnumerable<object[]> LocaleVectors() => Vectors().OfType<JsonObject>().SelectMany(v => new[] { new object[] { v["name"]!.ToString(), "ru" }, new object[] { v["name"]!.ToString(), "en" } });
    static bool Envelope(string key) => key is "presentation_messages" or "labels_messages" or "entity_messages" || key.EndsWith("_message", StringComparison.Ordinal);
    static IEnumerable<string> TextLeaves(JsonNode? node) => node switch
    {
        JsonObject obj => obj.SelectMany(p => TextLeaves(p.Value)),
        JsonArray array => array.SelectMany(TextLeaves),
        JsonValue value when value.TryGetValue<string>(out var text) => [text],
        _ => []
    };
    static IEnumerable<string> Codes(JsonNode? node, bool declared = false)
    {
        if (node is JsonObject obj)
        {
            if (declared && obj["code"] is JsonValue code && obj.ContainsKey("params")) yield return code.ToString();
            foreach (var (key, value) in obj) foreach (string item in Codes(value, declared || Envelope(key))) yield return item;
        }
        if (node is JsonArray array) foreach (var value in array) foreach (string item in Codes(value, declared)) yield return item;
    }
    static void Equal(JsonNode? expected, JsonNode? actual, string path = "")
    {
        if (JsonNode.DeepEquals(expected, actual)) return;
        if (expected is JsonObject a && actual is JsonObject b)
            foreach (string key in a.Select(p => p.Key).Union(b.Select(p => p.Key))) Equal(a[key], b[key], path + "." + key);
        if (expected is JsonArray x && actual is JsonArray y && x.Count == y.Count)
            for (int i = 0; i < x.Count; i++) Equal(x[i], y[i], path + "[" + i + "]");
        Assert.Fail(path + " expected " + expected + " actual " + actual);
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Both_catalogs_have_every_key_and_matching_placeholders(bool english)
    {
        var catalog = english ? ReportPresentation.English : ReportPresentation.Russian;
        Assert.Equal(ReportPresentation.Russian.Keys.Order(), catalog.Keys.Order());
        foreach (var (code, text) in catalog)
        {
            Assert.False(string.IsNullOrWhiteSpace(text), code);
            string[] Placeholders(string value) => Regex.Matches(value, @"\{\w+\}").Select(m => m.Value).Order().ToArray();
            Assert.Equal(Placeholders(ReportPresentation.Russian[code]), Placeholders(text));
            if (english) Assert.DoesNotMatch("[А-Яа-яЁё]", text);
        }
    }
    [Theory] [MemberData(nameof(LocaleVectors))]
    public void DeclaredVocabularyLocalizesMessagesWithoutMutatingObservations(string name, string locale)
    {
        var vector = Vector(name); var source = vector["input"]!.AsObject(); var original = source.DeepClone();
        var actual = ReportPresentation.Apply(source, locale == "en");
        // Locale changes presentation, while retained identifiers, counts and
        // authorization-relevant observations remain the same.
        var before = source["items"] as JsonArray ?? [];
        var after = actual["items"] as JsonArray ?? [];
        Assert.Equal(before.Count, after.Count);
        for (int i = 0; i < before.Count; i++)
            foreach (string field in new[] { "id", "key", "rule_code", "severity", "status", "total",
                "new_count", "previous_total", "delta", "evidence", "entity_identifiers" })
                Equal(before[i]?[field], after[i]?[field], field);
        Assert.Equal(source["report_key"]?.ToString(), actual["report_key"]?.ToString());
        Assert.Equal(source["state"]?.ToString(), actual["state"]?.ToString());
        Equal(original, source);
        Equal(actual, JsonNode.Parse(actual.ToJsonString()));
        foreach (string code in Codes(actual))
        {
            Assert.True(ReportPresentation.Russian.ContainsKey(code), code);
            Assert.True(ReportPresentation.English.ContainsKey(code), code);
        }
        if (locale == "en" && !name.StartsWith("inventory", StringComparison.Ordinal) && name != "unknown-limitation")
            Assert.All(TextLeaves(actual), text => Assert.DoesNotMatch("[А-Яа-яЁё]", text));
    }
    [Theory]
    [InlineData("ad.users.v2")] [InlineData("ad.computers.v6")] [InlineData("ad.infrastructure")]
    public void Native_definitions_localize_vocabulary_and_preserve_column_fields(string key)
    {
        // Exercise both the general registry and the AD route's projected declaration source.
        foreach (var declaration in new[] { new ReportDefinitionRegistry().Get(key)!.Declaration, AdV2Endpoints.Definitions[key]!["declaration"]!.AsObject() })
        {
            var source = declaration.DeepClone().AsObject();
            // The Python vector grants ALL_FIELDS without contact; mail/phones are projected out.
            if (source["columns"] is JsonArray columns)
                foreach (var column in columns.OfType<JsonObject>().Where(c =>
                    (c["field_categories"] as JsonArray ?? AdV2Endpoints.Definitions[key]?["column_fields"]?[c["key"]!.ToString()] as JsonArray ?? [])
                        .Any(f => f?.ToString() == "contact")).ToArray()) columns.Remove(column);
            if (key == "ad.infrastructure")
            {
                Assert.DoesNotContain(source["columns"]!.AsArray(), c => c?["key"]?.ToString() == "basis");
                Assert.DoesNotContain(source["detail"]?["columns"] as JsonArray ?? [], c => c?["key"]?.ToString() == "basis");
            }
            var russian = ReportPresentation.Apply(source, false);
            foreach (var localized in new[] { russian, ReportPresentation.Apply(source, true) })
            {
                var originalColumns=source["columns"]!.AsArray();
                var localizedColumns=localized["columns"]!.AsArray();
                Assert.Equal(originalColumns.Select(c=>c?["key"]?.ToString()),localizedColumns.Select(c=>c?["key"]?.ToString()));
                for (int i=0;i<originalColumns.Count;i++)
                {
                    foreach (string field in new[] { "path", "kind", "field_categories" })
                        Equal(originalColumns[i]?[field],localizedColumns[i]?[field],field);
                    Assert.False(string.IsNullOrWhiteSpace(localizedColumns[i]?["label"]?.ToString()));
                    if (localizedColumns[i]?["presentation_messages"]?["label"] is JsonObject label)
                        Equal(label["text"],localizedColumns[i]?["label"]);
                }
            }
            var english = ReportPresentation.Apply(source, true);
            Assert.All(TextLeaves(english), text => Assert.DoesNotMatch("[А-Яа-яЁё]", text));
        }
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Native_infrastructure_rows_localize_without_changing_observations(bool english)
    {
        using var stream = typeof(ReportLocaleCodesTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.control-reference.json")!;
        var entities = JsonNode.Parse(stream)!["entities"]!.AsArray().OfType<JsonObject>().ToArray();
        var source = new JsonObject
        {
            ["report_key"] = "ad.infrastructure",
            ["items"] = new JsonArray(AdInfrastructure.Compose(entities, new()).Select(row => (JsonNode)row).ToArray())
        };
        var original = source.DeepClone();
        var localized = ReportPresentation.Apply(source, english);
        Assert.NotEmpty(localized["items"]!.AsArray());
        if (english) Assert.All(TextLeaves(localized), text => Assert.DoesNotMatch("[А-Яа-яЁё]", text));
        foreach (var row in localized["items"]!.AsArray().OfType<JsonObject>())
        {
            var before = source["items"]!.AsArray().Single(item => item!["row_id"]!.ToString() == row["row_id"]!.ToString());
            foreach (string field in new[] { "row_id", "entity_id", "control_id", "actual_value", "qualification", "object_context", "observed_at_utc" })
                Equal(before![field], row[field], field);
            foreach (var (field, envelope) in row["presentation_messages"]!.AsObject())
                Equal(envelope!["text"], row[field], field);
        }
        Equal(original, source);
    }
    [Theory] [InlineData(0)] [InlineData(1)] [InlineData(5)]
    public void Infrastructure_query_counts_every_coverage_gap(int count)
    {
        var vector = Vector("coverage-" + count); var source = vector["input"]!.DeepClone().AsObject();
        source["limitations"] = AdInfrastructure.Limitations(source["coverage"]!.AsObject());
        Equal(vector["input"]!["limitations"], source["limitations"]);
        foreach (bool english in new[] { false, true }) Equal(vector[english ? "en" : "ru"], ReportPresentation.Apply(source, english));
    }
    [Fact]
    public void Native_inventory_emits_all_eight_reason_envelopes_and_retains_their_parameters()
    {
        var expected = Vector("inventory")["input"]!["items"]![0]!["reasons"]!.AsArray().OfType<JsonObject>().ToDictionary(r => r["code"]!.ToString());
        var common = JsonNode.Parse("""{"enabled":true,"computer_type":"unknown","quality_issues":[{"code":"source_failed"}],"delegation":{"unconstrained":true},"laps":{"state":"expired","expiration_utc":"2026-10-01T00:00:00Z"}}""")!.AsObject();
        var old = common.DeepClone().AsObject(); old["operating_system"] = "Windows Server 2012 R2"; old["operating_system_version"] = "6.3"; old["last_logon_utc"] = "2026-01-01T00:00:00Z"; old["activity"] = new JsonObject { ["age_days"] = 289 };
        var missing = common.DeepClone().AsObject(); missing["activity"] = new JsonObject { ["age_days"] = null };
        var reasons = new Dictionary<string, JsonObject>();
        foreach (var row in new[] { old, missing })
        {
            AdInventoryRows.ComputerReasons(row, JsonNode.Parse("""{"sources":{"os":{"status":"observed"}}}""")!.AsObject(), 90, DateTimeOffset.Parse("2026-10-17T03:00:00Z"));
            foreach (var reason in row["reasons"]!.AsArray().OfType<JsonObject>()) reasons[reason["code"]!.ToString()] = reason;
        }
        Assert.Equal(expected.Keys.Order(), reasons.Keys.Order());
        foreach (var (code, reason) in reasons) Equal(expected[code], reason, code);
        var noDate = new JsonObject { ["enabled"] = true, ["activity"] = new JsonObject { ["age_days"] = 91 }, ["quality_issues"] = new JsonArray() };
        AdInventoryRows.ComputerReasons(noDate, new(), 90, DateTimeOffset.Parse("2026-10-17T03:00:00Z"));
        var stale = noDate["reasons"]!.AsArray().Single(r => r!["code"]!.ToString() == "stale_activity");
        Equal(Vector("inventory-missing-date")["input"]!["items"]![0]!["reasons"]![0], stale);
    }
    static AccessFacts Facts(string accessKey)
    {
        string[] fields = ["identity_basic", "technical", "security", "privilege", "hr"];
        var definition = JsonSerializer.SerializeToElement(new { report_key = accessKey, version = 1, dataset_version = 1,
            definition_json = new { field_categories = fields, actions = new[] { "view", "export" } },
            fields_json = fields.Select(category => new { category }), actions_json = new[] { "view", "export" } });
        return new(true, "operator", [], [], [], [], [], [], [definition]);
    }
    [Theory]
    [InlineData("ad.users.v2", "user-checks", "sli.ad")] [InlineData("ad.computers.v6", "computer-checks", "sli.ad")]
    [InlineData("ad.infrastructure", "ad-state", "sli.ad")] [InlineData("security.problems", "problem-queue", "sli.core")]
    public async Task General_HTTP_engine_localizes_definitions_and_rows(string key, string vector, string owner)
    {
        var definition = new ReportDefinitionRegistry().Get(key)!;
        var reader = new ReportFixture.Reader { ReportKey = key, OwnerId = owner, Query = _ => Vector(vector)["input"]!.DeepClone().AsObject() };
        await using var host = await ReportFixture.Start(Facts(definition.AccessKey), definition, suppliedReader: reader);
        host.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en");
        foreach (string suffix in new[] { "", "/data" })
        {
            using var response = await host.Client.GetAsync("/api/v2/reports/" + key + suffix, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await ReportFixture.Body(response);
            Assert.All(TextLeaves(body), text => Assert.DoesNotMatch("[А-Яа-яЁё]", text));
            if (suffix.Length > 0) Assert.NotEmpty(body["items"]!.AsArray());
        }
    }
    sealed class AdStore(string vector) : IAdV2Store
    {
        public Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant grant, CancellationToken ct) => Task.FromResult<IReadOnlyList<JsonObject>>([new() { ["id"] = 1, ["display_name"] = "example.test", ["is_preferred"] = true }]);
        public Task<JsonObject> ReadAsync(AdV2Request request, Func<IEnumerable<string>, bool> fields, CancellationToken ct) => Task.FromResult(Vector(vector)["input"]!.DeepClone().AsObject());
    }
    [Theory]
    [InlineData("ad.users.v2", "user-checks")] [InlineData("ad.computers.v6", "computer-checks")] [InlineData("ad.infrastructure", "ad-state")]
    public async Task AD_HTTP_routes_localize_after_field_projection(string key, string vector)
    {
        var definition = new ReportDefinitionRegistry().Get(key)!;
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        using var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(new ReportFixture.Auth { Role = "operator" });
            services.AddSingleton<IAccessFactsRepository>(new ReportFixture.FactsRepo(Facts(definition.AccessKey)));
            services.AddSingleton<IReportCatalogProvider>(new ReportRuleCatalog(new PluginGenerationReader(null)));
            services.AddSingleton<IAdV2Store>(new AdStore(vector));
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapAdV2()); })).StartAsync(Ct);
        using var client = host.GetTestClient(); client.BaseAddress = new Uri("https://localhost");
        client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en");
        foreach (string suffix in new[] { "", "/data" })
        {
            using var response = await client.GetAsync("/api/v2/reports/" + key + suffix, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await ReportFixture.Body(response);
            Assert.All(TextLeaves(body), text => Assert.DoesNotMatch("[А-Яа-яЁё]", text));
            if (suffix.Length > 0) Assert.NotEmpty(body["items"]!.AsArray());
        }
    }
}
