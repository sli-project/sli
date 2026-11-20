using System.Text.Json.Nodes;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class Stage6sStorageBenchmarkTests
{
    [Theory]
    [InlineData("4608")]
    [InlineData("4624")]
    [InlineData("4634")]
    public void Authentication_catalog_budgets_are_positive_and_representative(string eventKey)
    {
        var entry = Assert.Single(new LifecycleCatalog().Entries, e => e["event_key"]?.ToString() == eventKey);
        var budget = entry["lifecycle"]!["promotion"]!["budget"]!;
        Assert.Equal("representative", budget["calibration"]!.GetValue<string>());
        foreach (string field in new[] { "events_per_day_upper", "source_bytes_per_event_upper", "derived_bytes_per_object_upper" })
            Assert.True(budget[field]!.GetValue<long>() > 0, field);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("events_per_day_upper")]
    [InlineData("source_bytes_per_event_upper")]
    [InlineData("derived_bytes_per_object_upper")]
    public void High_volume_zero_budget_is_rejected_before_admission(string? zeroField)
    {
        var entry = Entry();
        var budget = entry["lifecycle"]!["promotion"]!["budget"]!;
        foreach (string field in new[] { "events_per_day_upper", "source_bytes_per_event_upper", "derived_bytes_per_object_upper" })
            budget[field] = zeroField is null || zeroField == field ? 0 : 1;

        var error = Assert.Throws<InvalidDataException>(() => new LifecycleCatalog([entry]));
        Assert.Equal("high-volume lifecycle budget bounds must be positive", error.Message);
    }

    [Fact]
    public void Positive_high_volume_budget_is_admitted()
    {
        var catalog = new LifecycleCatalog([Entry()]);
        Assert.Single(catalog.Entries);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("true")]
    [InlineData("\"1\"")]
    [InlineData("1.5")]
    [InlineData("null")]
    public void High_volume_budget_bounds_require_non_negative_integers(string invalidJson)
    {
        foreach (string field in new[] { "events_per_day_upper", "source_bytes_per_event_upper", "derived_bytes_per_object_upper" }) {
            var entry = Entry();
            entry["lifecycle"]!["promotion"]!["budget"]![field] = JsonNode.Parse(invalidJson);
            var error = Assert.Throws<InvalidDataException>(() => new LifecycleCatalog([entry]));
            Assert.Equal($"lifecycle promotion budget {field} must be a non-negative integer", error.Message);
        }
    }

    private static JsonObject Entry() => JsonNode.Parse("""
        {
          "lifecycle": {
            "raw_payload_days": 2,
            "record_days": 7,
            "warm_record_days": 365,
            "rollup": "authentication_session",
            "rollup_role": "open",
            "promotion": {
              "version": "descriptor-lifecycle-v2",
              "archive_requirement": "no_archive",
              "post_promotion_disposition": "delete_source",
              "read_representation": "derived_only",
              "high_volume": true,
              "semantic_role": "authentication_boundary",
              "hot_need": "raw_investigation_window",
              "warm_value": "closed_or_incomplete_authentication_history",
              "executable_lifecycle": "existing_warm_then_retention_executor",
              "budget": {
                "events_per_day_upper": 1,
                "source_bytes_per_event_upper": 1,
                "derived_bytes_per_object_upper": 1,
                "calibration": "representative"
              }
            }
          }
        }
        """)!.AsObject();
}
