using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Reporting.V2;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class SecurityEventOutcomePresentationTests
{
    static readonly AdPeriod Period = new(DateTimeOffset.Parse("2026-01-01T00:00:00Z"), DateTimeOffset.Parse("2026-01-02T00:00:00Z"));

    [Theory]
    [InlineData("{}", 4624, "success", """{"state":"observed","value":"success","basis":"event_id"}""")]
    [InlineData("{}", 4625, "failure", """{"state":"observed","value":"failure","basis":"event_id"}""")]
    [InlineData("""{"audit_keywords":"AuditSuccess","result_code":"0xC000006D"}""", 4724, "success", """{"state":"observed","value":"success","basis":"audit_keywords","result_code":"0xC000006D"}""")]
    [InlineData("""{"audit_keywords":"AuditFailure","result_code":"0x0"}""", 4724, "failure", """{"state":"observed","value":"failure","basis":"audit_keywords","result_code":"0x0"}""")]
    [InlineData("""{"result_code":"0x0"}""", 4724, "unknown", """{"state":"unknown","reason":"event_outcome_not_proven_by_scoped_contract","result_code":"0x0"}""")]
    [InlineData("{}", 4740, "unknown", """{"state":"unknown","reason":"event_outcome_not_proven_by_scoped_contract"}""")]
    public async Task ActualEngineOutcomesKeepSourceEvidence(string eventJson, int eventId, string expected, string evidenceJson)
    {
        var source = JsonNode.Parse(eventJson)!.AsObject();
        source["event_db_id"] = 7;
        source["event_id"] = eventId;
        source["time_created_utc"] = "2026-01-01T01:00:00Z";
        var request = new AdReportRequest("security", false, false, 1, Period, 100, new(), null);
        var payload = AdSecurity.Compose(request, [source], true, false, new());
        var item = payload["items"]![0]!.DeepClone().AsObject();
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(evidenceJson), item["outcome"]));
        await AssertDisplay(item, expected);
    }

    [Theory]
    [InlineData("""{"outcome":null}""")]
    [InlineData("""{"outcome":{}}""")]
    [InlineData("""{"outcome":"success"}""")]
    [InlineData("""{"outcome":[]}""")]
    [InlineData("""{"outcome":{"state":"unknown"}}""")]
    [InlineData("""{"outcome":{"state":"unknown","value":"success","reason":"not_proven"}}""")]
    [InlineData("""{"outcome":{"state":"unexpected","value":"failure"}}""")]
    [InlineData("""{"outcome":{"value":"success"}}""")]
    [InlineData("""{"outcome":{"state":"observed"}}""")]
    [InlineData("""{"outcome":{"state":"observed","value":"unexpected"}}""")]
    [InlineData("""{"outcome":{"state":"observed","value":["success"]}}""")]
    [InlineData("{}")]
    public async Task MissingOrUnprovenOutcomesNeverPromoteAValue(string itemJson)
    {
        var item = JsonNode.Parse(itemJson)!.AsObject();
        item["event_db_id"] = 7;
        item["time_created_utc"] = "2026-01-01T01:00:00Z";
        await AssertDisplay(item, "unknown");
    }

    [Fact]
    public void DerivationRetainsTheOutcomeObjectAndItsEvidence()
    {
        var row = JsonNode.Parse("""{"outcome":{"state":"observed","value":"success","basis":"audit_keywords","result_code":"0xC000006D"}}""")!.AsObject();
        var outcome = row["outcome"];
        var original = outcome!.DeepClone();
        SecurityEventsReader.Derived(row);
        Assert.Same(outcome, row["outcome"]);
        Assert.True(JsonNode.DeepEquals(original, row["outcome"]));
        Assert.Equal("success", row["outcome_code"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("success", "Успех")]
    [InlineData("failure", "Отказ")]
    [InlineData("unknown", "—")]
    public void ColumnDisplaysTheDerivedOutcome(string outcome, string expected)
    {
        var definition = new ReportDefinitionRegistry().Get("security.events.chains")!;
        var column = Assert.Single(definition.Columns, c => c["key"]!.GetValue<string>() == "outcome");
        var row = new JsonObject { ["outcome"] = new JsonObject { ["state"] = outcome == "unknown" ? "unknown" : "observed", ["value"] = outcome } };
        SecurityEventsReader.Derived(row);
        string value = row[column["path"]!.ToString()]!.ToString();
        Assert.Equal(expected, column["labels"]![value]!.ToString());
    }

    static async Task AssertDisplay(JsonObject item, string expected)
    {
        Assert.Null(item.Parent);
        var original = item.DeepClone();
        var outcome = item["outcome"];
        var store = new Store(item);
        var definition = new ReportDefinitionRegistry().Get("security.events.chains")!;
        var grant = new AtomicReportGrant(JsonSerializer.SerializeToElement(new { kind = "domain", ids = new[] { 1 } }),
            new HashSet<string> { "security", "technical", "raw_evidence" }, new HashSet<string> { "view" }, 1, 1);
        var access = new AccessDecision("viewer", new(false, new HashSet<string> { "events.view" }, new HashSet<string>(), [], new Dictionary<string, JsonElement>()),
            [new(definition.Key, true, [grant])]);
        var parameters = JsonNode.Parse("""{"domain":1,"period":{"from_utc":"2026-01-01T00:00:00Z","to_utc":"2026-01-02T00:00:00Z"}}""")!.AsObject();
        var context = new ReportQueryContext(definition, access, new("session", 1, "viewer"), parameters,
            new(null, 100, "UTC", null, "desc", null), ReportScope.None, [1], "view", _ => true, [grant]);
        var result = await new SecurityEventsReader(store, null!, null!, null!).QueryAsync(context, TestContext.Current.CancellationToken);
        Assert.Equal("ok", result["state"]!.GetValue<string>());
        var row = Assert.Single(result["items"]!.AsArray())!.AsObject();
        Assert.Equal(expected, row["outcome_code"]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(original, item));
        Assert.Equal(item.ContainsKey("outcome"), row.ContainsKey("outcome"));
        Assert.Same(outcome, item["outcome"]);
        Assert.True(JsonNode.DeepEquals(original["outcome"], row["outcome"]));
    }

    // Return the source payload itself so the production reader must preserve it.
    sealed class Store(JsonObject item) : IAdReportStore
    {
        readonly JsonObject payload = new() { ["state"] = "available", ["items"] = new JsonArray(item) };
        public Task<IReadOnlyList<long>> DomainsAsync(long after, CancellationToken ct) => Task.FromResult<IReadOnlyList<long>>([]);
        public Task<bool> HasSourceAsync(string kind, long domain, CancellationToken ct) => throw new InvalidOperationException("Unexpected source probe");
        public Task<JsonObject> ReadAsync(AdReportRequest request, bool sensitive, CancellationToken ct) => Task.FromResult(payload);
    }
}
