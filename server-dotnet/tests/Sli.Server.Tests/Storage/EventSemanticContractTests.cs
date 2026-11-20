using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Investigations;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Vectors from tests/semantic/test_event_semantic_contract.py.
public sealed class EventSemanticContractTests
{
    static readonly string[] MachineFields = ["category", "purpose_tier", "base_risk", "final_risk", "confidence", "noise_class"];
    static JsonObject Event(int eventId) => new()
    {
        ["id"] = eventId, ["event_db_id"] = eventId, ["event_id"] = eventId, ["event_record_id"] = 17,
        ["time_created_utc"] = "2026-07-17T01:00:00Z", ["server"] = "DC1", ["channel"] = "Security",
        ["provider_name"] = "Microsoft-Windows-Security-Auditing", ["event_data"] = new JsonObject()
    };
    static Task<JsonObject> Card(JsonObject row) => new KnownBundleNormalizer(EventCardSemanticsTests.Repository(), null, null)
        .CardAsync(row, TestContext.Current.CancellationToken);
    static JsonObject Wire(JsonObject item) => JsonNode.Parse(JsonSerializer.Serialize(item))!.AsObject();
    static void EqualField(JsonObject expected, JsonObject actual, string field) =>
        Assert.True(JsonNode.DeepEquals(expected[field], actual[field]), $"{field}: expected {expected[field]}, actual {actual[field]}");

    [Theory]
    [InlineData(4720, "account_management", "important", "medium", "signal")]
    [InlineData(4624, "authentication", "technical", "low", "context")]
    public async Task Catalog_card_exposes_one_machine_contract(int eventId, string category, string tier, string risk, string noise)
    {
        var card = await Card(Event(eventId));
        var expected = new JsonObject { ["category"] = category, ["purpose_tier"] = tier, ["base_risk"] = risk, ["final_risk"] = risk, ["noise_class"] = noise };
        foreach (var actual in new[] { card, Wire(card) })
        {
            foreach (var field in expected) EqualField(expected, actual, field.Key);
            Assert.Contains(actual["confidence"]!.ToString(), new[] { "high", "medium", "low", "unknown" });
            Assert.Equal(actual["final_risk"]!.ToString(), actual["severity"]!.ToString());
            Assert.Equal(actual["purpose_tier"]!.ToString(), actual["tier"]!.ToString());
            Assert.Equal(actual["final_risk"]!.ToString(), actual["final_security_severity"]!.ToString());
            Assert.Equal(actual["confidence"]!.ToString(), actual["assessment_confidence"]!.ToString());
            Assert.Equal(actual["risk"]!.ToString(), actual["display_labels"]!["risk"]!.ToString());
            Assert.Equal(actual["assessment_confidence_label"]!.ToString(), actual["display_labels"]!["confidence"]!.ToString());
            Assert.True(actual["catalog_match"]!.GetValue<bool>());
            Assert.Contains("catalog_rule_matched", actual["reasons"]!.AsArray().Select(n => n!.ToString()));
        }
    }

    [Fact]
    public async Task Catalog_base_is_not_a_contextual_assessment()
    {
        var row = Event(4624); row["id"] = 517548;
        var card = await Card(row);
        Assert.Equal("catalog_base", card["classification_origin"]!.ToString());
        Assert.Equal("not_applicable", card["card_completeness"]!.ToString());
        Assert.Equal("unknown", card["assessment_confidence"]!.ToString());
        Assert.Equal("low", card["base_risk"]!.ToString());
        Assert.Equal(card["base_risk"]!.ToString(), card["final_risk"]!.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("expired")]
    public async Task List_uses_canonical_semantics_without_a_catalog_card(string? payloadState)
    {
        var row = Event(4720); row.Remove("event_data"); row["event_data_json"] = "{}"; row["source_payload_state"] = payloadState;
        var canonical = await Card(row);
        Assert.True(canonical["known"]!.GetValue<bool>());
        Assert.False(canonical["has_card"]!.GetValue<bool>());
        var item = EventListProjection.Project(row);
        foreach (var actual in new[] { item, Wire(item) })
        {
            Assert.Equal(payloadState, actual["source_payload_state"]?.ToString());
            foreach (string field in MachineFields) EqualField(canonical, actual, field);
            Assert.Equal("medium", actual["severity"]!.ToString());
            Assert.Equal("important", actual["tier"]!.ToString());
            Assert.Equal("account_management", actual["category"]!.ToString());
        }
    }

    [Fact]
    public void List_preserves_legacy_fallback_for_uncatalogued_source()
    {
        var row = Event(4720); row["id"] = 72; row["event_record_id"] = 72;
        row["channel"] = "Unknown"; row["provider_name"] = "Unknown";
        row.Remove("event_data"); row["event_data_json"] = "{}";
        var item = EventListProjection.Project(row);
        foreach (var actual in new[] { item, Wire(item) })
        {
            Assert.Equal("high", actual["severity"]!.ToString());
            Assert.Equal("account_lifecycle", actual["category"]!.ToString());
            Assert.Null(actual["tier"]);
            Assert.Equal("unknown", actual["final_risk"]!.ToString());
        }
    }

    [Theory]
    [InlineData(4720, "medium")]
    [InlineData(4624, "low")]
    public async Task Investigation_timeline_uses_the_card_machine_risk(int eventId, string risk)
    {
        var row = Event(eventId); var card = await Card(row);
        var timeline = InvestigationTimeline.Build(row, "exact fixture").Item;
        Assert.Equal(risk, card["final_risk"]!.ToString());
        foreach (var actual in new[] { timeline, Wire(timeline) })
        {
            Assert.Equal(risk, actual["severity"]!.ToString());
            foreach (string field in MachineFields.Where(f => f != "final_risk")) EqualField(card, actual, field);
        }
    }
}
