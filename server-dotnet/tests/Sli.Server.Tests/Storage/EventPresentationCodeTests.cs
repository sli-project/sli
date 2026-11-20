using System.Text.Json.Nodes;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Vectors from tests/events/test_event_presentation_codes.py.
public sealed class EventPresentationCodeTests
{
    [Theory]
    [InlineData("same_logon_id_same_server", 1)]
    [InlineData("same_task_same_server_time_window", 42)]
    public void Relation_response_keeps_text_and_adds_reason_code(string rule, int delta)
    {
        var response = EventRelationContract.Build(1,
            [new RelationCandidate(2, 4624, null, "", "fixture", rule, delta)], 100);
        var relation = response["items"]![0]!;

        Assert.Equal(rule, relation["reason_code"]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["time_delta_seconds"] = delta }, relation["reason_params"]));
        Assert.EndsWith($"разница во времени {delta} с.", relation["reason"]!.GetValue<string>());
        Assert.Contains("fixture", relation["explanation"]!.GetValue<string>());
    }

    [Fact]
    public void Unknown_event_card_adds_codes_without_interpreting_message()
    {
        var card = EventCardSemantics.Build(new JsonObject
        {
            ["event_id"] = 999999,
            ["message_text"] = "Исходное сообщение"
        }, null, null);

        Assert.Equal("uncatalogued.title", card["title_code"]!.GetValue<string>());
        Assert.Equal("uncatalogued.summary", card["summary_code"]!.GetValue<string>());
        Assert.Equal("Событие пока не расшифровано каталогом", card["title"]!.GetValue<string>());
        Assert.DoesNotContain("Исходное сообщение", card["summary"]!.GetValue<string>());
    }

    [Fact]
    public void Catalog_card_codes_preserve_identity_and_contextual_assessment()
    {
        var entry = JsonNode.Parse("""
            {
              "event_id": 140, "channel": "Fixture", "provider_name": "FixtureProvider",
              "title": "Типовое событие", "why": "Типовое пояснение", "severity": "info",
              "card": {
                "action": "Типовое действие",
                "risk_rules": [{ "severity": "medium", "assessment": "Контекстное пояснение", "all": [] }]
              }
            }
            """)!.AsObject();
        var item = new JsonObject { ["event_id"] = 140 };
        var card = EventCardSemantics.Build(item, entry, null);

        Assert.Equal("Fixture:FixtureProvider:140.title", card["title_code"]!.GetValue<string>());
        Assert.Equal("Fixture:FixtureProvider:140.summary.rule.0", card["summary_code"]!.GetValue<string>());
        Assert.Equal("Типовое действие", card["title"]!.GetValue<string>());
        Assert.Equal("Контекстное пояснение", card["summary"]!.GetValue<string>());

        entry["card"] = new JsonObject();
        entry["provider_name"] = "OtherFixtureProvider";
        var other = EventCardSemantics.Build(item, entry, null);

        Assert.NotEqual(card["title_code"]!.GetValue<string>(), other["title_code"]!.GetValue<string>());
        Assert.Equal("Fixture:OtherFixtureProvider:140.summary", other["summary_code"]!.GetValue<string>());
        Assert.Equal("Типовое пояснение", other["summary"]!.GetValue<string>());
    }
}
