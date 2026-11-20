using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.TestHost;
using Microsoft.VisualBasic.FileIO;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Gpo;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Ad;
using Sli.Server.Tests.Gpo;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Input/output vectors from tests/reporting/test_report_v2_filtered_exports.py.
public sealed class ReportV2FilteredExportTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    const string AdUrl = "/api/v2/reports/ad.infrastructure";
    const string GpoUrl = "/api/v2/reports/ad.gpo.v2";
    static JsonObject O(string json) => JsonNode.Parse(json)!.AsObject();
    static List<string[]> Csv(string text, string delimiter = ",")
    {
        using var parser = new TextFieldParser(new StringReader(text.TrimStart('\uFEFF')));
        parser.SetDelimiters(delimiter); parser.HasFieldsEnclosedInQuotes = true; parser.TrimWhiteSpace = false;
        var rows = new List<string[]>();
        while (!parser.EndOfData) rows.Add(parser.ReadFields()!);
        return rows;
    }
    static string[] Column(List<string[]> csv, string label) => csv.Skip(1).Select(r => r[Array.IndexOf(csv[0], label)]).ToArray();
    static async Task<JsonObject> Body(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return O(await response.Content.ReadAsStringAsync(Ct));
    }
    sealed class AdStore : IAdV2Store
    {
        internal AdV2Request? Last;
        internal bool Unavailable;
        static JsonObject Entity(int id, string name, string kind, string field, string value) => new()
        {
            ["entity_id"] = id, ["domain_id"] = 1, ["domain_name"] = "example.test", ["display_name"] = name,
            ["entity_type"] = kind, ["source_section"] = "domain_health", ["observed_at_utc"] = "2026-11-08T00:00:00Z",
            ["record"] = new JsonObject { ["attributes"] = new JsonObject { [field] = value } }.ToJsonString()
        };
        internal static JsonObject[] Entities() => [
            Entity(1, "Synthetic link", "replication_link", "replication_state", "=synthetic"),
            Entity(2, "Synthetic passed", "replication_link", "replication_state", "passed"),
            Entity(3, "Synthetic controller", "domain_controller", "advertising_state", "failed"),
            Entity(4, "Other link", "replication_link", "replication_state", "failed")];
        public Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant grant, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<JsonObject>>([O("""{"id":1,"display_name":"example.test"}""")]);
        public Task<JsonObject> ReadAsync(AdV2Request request, Func<IEnumerable<string>, bool> fields, CancellationToken ct)
        {
            Last = request; Assert.Equal(new long[] { 1 }, request.Domains);
            if (Unavailable) return Task.FromResult(AdV2Store.Result(request.Key, "error"));
            var entities = Entities();
            var controls = AdInfrastructure.Compose(entities, request.Params);
            var result = AdV2Store.Result(request.Key, controls.Count == 0 ? "empty" : "ok", controls);
            if (request.Tab == "semantic")
                result["collections"]!["semantic"] = AdInfrastructure.SemanticRows(entities.Select(e => new JsonObject
                {
                    ["entity_id"] = e["entity_id"]!.DeepClone(), ["title"] = "Finding " + e["entity_id"], ["summary"] = e["display_name"]!.DeepClone()
                }), entities, request.Params);
            return Task.FromResult(result);
        }
    }
    [Theory]
    [InlineData("tab=controls&view=replication&qualification=failed&entity_type=replication_link&q=synthetic", "Synthetic link")]
    [InlineData("qualification=passed", "Synthetic passed")]
    [InlineData("entity_type=domain_controller", "Synthetic controller")]
    [InlineData("q=OTHER", "Other link")]
    [InlineData("q=no-match", null)]
    public async Task Ad_control_export_matches_screen_filters_and_preserves_empty_headers(string query, string? expected)
    {
        var store = new AdStore(); using var host = await AdV2Tests.Host(store); using var client = host.GetTestClient();
        using var screen = await client.GetAsync(AdUrl + "/data?" + query, Ct); var data = await Body(screen);
        using var export = await client.GetAsync(AdUrl + "/export.csv?" + query, Ct);
        Assert.Equal(HttpStatusCode.OK, export.StatusCode);
        var csv = Csv(await export.Content.ReadAsStringAsync(Ct), ";");
        Assert.Equal("Параметр", csv[0][0]); Assert.Equal("Объект", csv[0][1]);
        Assert.Equal(expected is null ? [] : new[] { expected }, Column(csv, "Объект"));
        Assert.Equal(data["items"]!.AsArray().Select(r => r!["entity_name"]!.ToString()), Column(csv, "Объект"));
        Assert.Equal("false", Assert.Single(export.Headers.GetValues("X-Sli-Export-Truncated")));
        Assert.Equal("export", store.Last!.Action);
        if (query.StartsWith("tab=controls", StringComparison.Ordinal))
        {
            Assert.Equal("replication", store.Last.Params["view"]!.ToString());
            Assert.Equal("'=synthetic", Assert.Single(Column(csv, "Фактическое значение")));
        }
    }
    [Fact]
    public void Empty_control_ledger_keeps_control_headers()
    {
        var csv = Csv(AdInfrastructure.CsvControls([]), ";");
        Assert.Single(csv); Assert.Equal("Параметр", csv[0][0]); Assert.Equal("Объект", csv[0][1]);
    }
    [Theory]
    [InlineData("view=replication&qualification=failed&entity_type=replication_link&q=synthetic", "Finding 1", false)]
    [InlineData("q=FINDING%201", "Finding 1", true)]
    [InlineData("entity_type=domain_controller", "Finding 3", false)]
    public async Task Ad_semantic_export_uses_filtered_findings_independently_of_control_search(string query, string expected, bool noControls)
    {
        var store = new AdStore(); using var host = await AdV2Tests.Host(store); using var client = host.GetTestClient();
        using var screen = await client.GetAsync(AdUrl + "/data?tab=semantic&" + query, Ct); var data = await Body(screen);
        if (noControls) Assert.Empty(data["items"]!.AsArray());
        using var export = await client.GetAsync(AdUrl + "/export.csv?tab=semantic&" + query, Ct);
        Assert.Equal(HttpStatusCode.OK, export.StatusCode);
        var csv = Csv(await export.Content.ReadAsStringAsync(Ct));
        Assert.Equal(new[] { expected }, Column(csv, "Находка"));
        Assert.Equal(data["collections"]!["semantic"]!.AsArray().Select(r => r!["title"]!.ToString()), Column(csv, "Находка"));
        Assert.Equal("semantic", store.Last!.Tab);
        Assert.Equal("false", Assert.Single(export.Headers.GetValues("X-Sli-Export-Truncated")));
    }
    [Fact]
    public void Ad_semantic_entity_filter_recognizes_only_controller_role_from_computer_records()
    {
        var entities = AdStore.Entities();
        foreach (int index in new[] { 1, 2 })
        {
            entities[index]["entity_type"] = "ad_computer";
            entities[index]["record"] = new JsonObject { ["attributes"] = new JsonObject
                { ["advertising_state"] = "failed", ["infrastructure_role"] = index == 2 ? "domain_controller" : "workstation" } }.ToJsonString();
        }
        Assert.Equal(new long[] { 3 }, AdInfrastructure.SemanticEntityIds(entities, O("""{"entity_type":"domain_controller"}""")));
    }
    [Fact]
    public async Task Ad_unavailable_evidence_keeps_export_error()
    {
        using var host = await AdV2Tests.Host(new AdStore { Unavailable = true }); using var client = host.GetTestClient();
        using var response = await client.GetAsync(AdUrl + "/export.csv", Ct);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("active_directory_evidence_not_exportable", O(await response.Content.ReadAsStringAsync(Ct))["error"]!.ToString());
    }
    sealed class GpoStore : IGpoReadStore
    {
        internal JsonObject Snapshot = O("""
            {"collection_status":"completed","source_states":{"links":{"status":"observed"}},
             "gpos":[{"id":"gpo-a","display_name":"Synthetic policy","link_ids":[],"source_states":{"links":{"status":"observed"},"settings":{"status":"partial"}}},
                     {"id":"gpo-b","display_name":"Other policy","link_ids":["link"]}],
             "settings":[{"id":"s1","gpo_name":"Synthetic policy","setting_name":"=synthetic"},{"id":"s2","gpo_name":"Other policy","setting_name":"other"}],
             "scopes":[{"id":"scope1","name":"Synthetic scope","direct_link_ids":["link"]},{"id":"scope2","name":"Other scope"}],
             "permissions":[{"id":"p1","gpo_name":"Synthetic policy","trustee_name":"Synthetic trustee"},{"id":"p2","gpo_name":"Other policy"}],
             "wmi_filters":[{"id":"w1","name":"Synthetic filter","used_by_gpo_ids":["gpo-a"]},{"id":"w2","name":"Other filter"}]}
            """);
        internal int HistoryReads;
        public Task<JsonObject> PairAsync(long[]? domains, CancellationToken ct)
        {
            Assert.Equal(new long[] { 1 }, domains);
            return Task.FromResult(new JsonObject { ["state"] = "available", ["current"] = Snapshot.DeepClone() });
        }
        public Task<JsonObject> GraphAsync(JsonObject snapshot, long[]? domains, CancellationToken ct) => throw new InvalidOperationException("Unexpected graph read");
        public Task<JsonObject> HistoryAsync(long[]? domains, DateTimeOffset from, DateTimeOffset to, string query, CancellationToken ct)
        {
            HistoryReads++; Assert.Equal(new long[] { 1 }, domains); Assert.Equal("synthetic", query);
            string[] names = ["Synthetic change", "Other change"];
            return Task.FromResult(new JsonObject
            {
                ["state"] = "ok", ["coverage"] = O("""{"state":"complete"}"""),
                ["items"] = new JsonArray(names.Where(n => n.Contains(query, StringComparison.OrdinalIgnoreCase))
                    .Select(n => (JsonNode)new JsonObject { ["object_id"] = n }).ToArray())
            });
        }
    }
    [Theory]
    [InlineData("gpos", "Политика", "Synthetic policy")]
    [InlineData("changes", "Объект", "Synthetic change")]
    [InlineData("scopes", "Контейнер", "Synthetic scope")]
    [InlineData("settings", "Политика", "Synthetic policy")]
    [InlineData("permissions", "Кому", "Synthetic trustee")]
    [InlineData("wmi", "Фильтр", "Synthetic filter")]
    [InlineData("quality", "Объект", "Synthetic policy")]
    public async Task Gpo_export_uses_selected_tab_columns_and_filtered_rows(string tab, string label, string expected)
    {
        var store = new GpoStore(); using var host = await GpoEndpointTests.Host(store); using var client = host.GetTestClient();
        string query = "?tab=" + tab + "&view=unlinked&q=synthetic";
        using var screen = await client.GetAsync(GpoUrl + "/data" + query, Ct); var data = await Body(screen);
        using var export = await client.GetAsync(GpoUrl + "/export.csv" + query, Ct);
        Assert.Equal(HttpStatusCode.OK, export.StatusCode);
        string text = await export.Content.ReadAsStringAsync(Ct); var csv = Csv(text);
        var declaration = GpoJson.Metadata["declaration"]!;
        var view = declaration["views"]!.AsArray().Single(v => v!["key"]!.ToString() == tab)!;
        var columns = view["columns"] as JsonArray ?? declaration["columns"]!.AsArray();
        Assert.Equal(columns.Select(c => c!["label"]!.ToString()), csv[0]);
        string source = view["source"]!.ToString();
        var displayed = source == "items" ? data["items"]!.AsArray() : data["collections"]![source]!.AsArray();
        Assert.Single(displayed); Assert.Equal(displayed.Count, csv.Count - 1);
        Assert.Equal(new[] { expected }, Column(csv, label)); Assert.DoesNotContain("Other", text);
        Assert.Equal("1", Assert.Single(export.Headers.GetValues("X-Sli-Export-Rows")));
        Assert.Equal("false", Assert.Single(export.Headers.GetValues("X-Sli-Export-Truncated")));
        if (tab == "settings") Assert.Contains("'=synthetic", text);
        if (tab == "changes") Assert.Equal(2, store.HistoryReads);
    }
    [Fact]
    public async Task Gpo_collection_export_marks_truncation()
    {
        var store = new GpoStore();
        store.Snapshot["settings"] = new JsonArray(Enumerable.Range(0, 2001).Select(i => (JsonNode)new JsonObject
            { ["id"] = "s" + i, ["gpo_name"] = "Synthetic policy", ["setting_name"] = "Synthetic setting " + i }).ToArray());
        using var host = await GpoEndpointTests.Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync(GpoUrl + "/export.csv?tab=settings&q=synthetic", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("true", Assert.Single(response.Headers.GetValues("X-Sli-Export-Truncated")));
        Assert.Equal("2000", Assert.Single(response.Headers.GetValues("X-Sli-Export-Rows")));
        Assert.Equal(2001, Csv(await response.Content.ReadAsStringAsync(Ct)).Count);
    }
    [Theory]
    [InlineData("ad.infrastructure", "sli.ad", "semantic", "qualification=failed&entity_type=replication_link&q=synthetic")]
    [InlineData("ad.gpo.v2", "sli.gpo", "settings", "view=unlinked&q=synthetic")]
    public async Task Shared_export_route_preserves_tab_conditions_and_domain_scope(string key, string owner, string tab, string query)
    {
        var definition = new ReportDefinitionRegistry().Get(key)!;
        var reader = new ReportFixture.Reader { ReportKey = key, OwnerId = owner, Csv = "header\r\n" };
        await using var host = await ReportFixture.Start(ReportV2DispatchTests.Facts(definition, "{\"kind\":\"domain\",\"ids\":[1]}"), definition, suppliedReader: reader);
        using var response = await host.Client.GetAsync($"/api/v2/reports/{key}/export.csv?tab={tab}&{query}", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(1, reader.Calls);
        Assert.Equal(tab, reader.Last!.Paging.Tab); Assert.Equal(new long[] { 1 }, reader.Last.DomainIds); Assert.Equal("export", reader.Last.Action);
        foreach (string condition in query.Split('&'))
        {
            var pair = condition.Split('='); Assert.Equal(pair[1], reader.Last.Params[pair[0]]!.ToString());
        }
    }
}
