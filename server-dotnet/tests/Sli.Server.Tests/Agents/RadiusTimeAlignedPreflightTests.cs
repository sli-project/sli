using System.Text.Json.Nodes;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class RadiusTimeAlignedPreflightTests
{
    private static readonly DateTimeOffset EventTime = new(2026, 7, 30, 1, 0, 0, TimeSpan.Zero);
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-1101";

    private static JsonObject ApprovedTarget() => new()
    {
        ["source_name"] = "radius01.example.test", ["connect_address"] = "radius01.example.test", ["owner_confirmed_ip"] = "192.0.2.15",
    };

    private static JsonObject ValidatePlan(JsonObject plan, JsonObject? inventory = null) => RadiusTimeAlignedPlan.ValidatePlan(
        plan, inventory ?? new JsonObject { ["targets"] = new JsonArray(ApprovedTarget()) }, ApprovedTarget());

    [Fact]
    public void PlanIsBoundedReadOnlyAndOwnerAuthorized()
    {
        var result = ValidatePlan(RadiusTimeAlignedPlan.LoadPlan());
        Assert.Equal("owner_authorized", result["status"]!.GetValue<string>());
        Assert.False(result["source_contact"]!.GetValue<bool>());
        Assert.True(result["read_only"]!.GetValue<bool>());
        Assert.Equal(1, result["target_count"]!.GetValue<int>());
        Assert.Equal(500, result["limits"]!["nps_events"]!.GetValue<int>());
        Assert.Equal(262144, result["limits"]!["accounting_bytes"]!.GetValue<int>());
        Assert.Equal(10800, result["limits"]!["maximum_alignment_span_seconds"]!.GetValue<int>());
        Assert.True(JsonNode.DeepEquals(ApprovedTarget(), result["target"]));
    }

    [Fact]
    public void PlanRejectsLimitChange()
    {
        var plan = RadiusTimeAlignedPlan.LoadPlan();
        plan["limits"]!["nps_events"] = 501;
        var error = Assert.Throws<RadiusTimeAlignedPlanError>(() => ValidatePlan(plan));
        Assert.Equal("bounded_limits_changed", error.Code);
    }

    [Theory]
    [InlineData("schema_version", "unsupported_plan_schema")]
    [InlineData("plan_id", "unexpected_plan_id")]
    [InlineData("status", "owner_authorization_required")]
    [InlineData("targets_source", "unexpected_targets_source")]
    [InlineData("expected_windows_account", "unexpected_windows_account")]
    [InlineData("prohibited_actions", "required_action_prohibition_missing")]
    [InlineData("prohibited_persistence", "required_persistence_prohibition_missing")]
    [InlineData("evaluation_contract", "evaluation_contract_changed")]
    [InlineData("next_action", "unexpected_next_action")]
    public void PlanCannotDropAuthorizationOrSafetyContract(string field, string code)
    {
        var plan = RadiusTimeAlignedPlan.LoadPlan();
        plan.Remove(field);
        Assert.Equal(code, Assert.Throws<RadiusTimeAlignedPlanError>(() => ValidatePlan(plan)).Code);
    }

    [Fact]
    public void PlanCannotAuthorizeDifferentTargetFromInventory()
    {
        var changed = ApprovedTarget();
        changed["connect_address"] = "other.example.test";
        var inventory = new JsonObject { ["targets"] = new JsonArray(changed) };
        var error = Assert.Throws<RadiusTimeAlignedPlanError>(() => ValidatePlan(RadiusTimeAlignedPlan.LoadPlan(), inventory));
        Assert.Equal("approved_target_changed", error.Code);
    }

    private static string AccountingLine(string status = "1", string time = "08:00:00", string epoch = "1785373200")
    {
        var fields = Enumerable.Repeat("", 66).ToArray();
        fields[0] = "nps"; fields[1] = "IAS"; fields[2] = "07/30/2026"; fields[3] = time;
        fields[4] = "4"; fields[11] = "vpn-a"; fields[17] = epoch; fields[31] = status; fields[35] = "opaque";
        return string.Join(',', fields);
    }

    private static RadiusPreflightEvent Event() => new(6272, EventTime, "opaque", "vpn-a", Sid);
    private static RadiusPreflightAccounting Accounting() => new("start", "opaque", "VPN-A", EventTime, EventTime);
    private static Dictionary<string, bool> NoCaps() => new()
    {
        ["accounting_candidate_cap_reached"] = false, ["accounting_record_cap_reached"] = false,
        ["accounting_byte_cap_reached"] = false, ["selected_file_was_sampled_not_fully_read"] = false,
        ["nps_event_cap_reached"] = false,
    };

    private static JsonObject Aggregate(RadiusPreflightEvent[] events, RadiusPreflightAccounting[] accounting,
        IReadOnlyDictionary<string, bool>? caps = null) => RadiusTimeAlignedPreflight.AggregateObservations(
            events, accounting, new Dictionary<string, int> { ["lifecycle_rows"] = accounting.Length }, 0, caps ?? NoCaps());

    [Fact]
    public void AccountingLocalTimeIsConvertedToUtcInMemory()
    {
        var (records, counts) = RadiusTimeAlignedPreflight.ParseAccountingSample([AccountingLine()], 420);
        var record = Assert.Single(records);
        Assert.Equal(EventTime, record.RecordTimeUtc);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1785373200), record.EventTimeUtc);
        Assert.Equal("start", record.Lifecycle);
        Assert.Equal(5, counts.Count);
        Assert.All(counts.Values, value => Assert.Equal(1, value));
    }

    [Fact]
    public void XPathUsesExactAccountingDerivedUtcInterval()
    {
        string xpath = RadiusTimeAlignedPreflight.BuildTimeAlignedXPath(EventTime.AddMinutes(-10), EventTime.AddMinutes(10));
        Assert.Equal("*[System[(EventID=6272 or EventID=6273) and TimeCreated[@SystemTime >= '2026-07-30T00:50:00.000Z' and @SystemTime <= '2026-07-30T01:10:00.000Z']]]", xpath);
        Assert.Equal(xpath, RadiusTimeAlignedPreflight.BuildTimeAlignedXPath(
            EventTime.AddMinutes(-10).ToOffset(TimeSpan.FromHours(7)), EventTime.AddMinutes(10).ToOffset(TimeSpan.FromHours(-3))));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void XPathRejectsEmptyOrReversedInterval(int endOffset)
    {
        var error = Assert.Throws<ArgumentException>(() => RadiusTimeAlignedPreflight.BuildTimeAlignedXPath(EventTime, EventTime.AddSeconds(endOffset)));
        Assert.Equal("invalid_alignment_window", error.Message);
    }

    [Fact]
    public void AggregateProvesJoinWithoutPersistingValues()
    {
        var result = Aggregate([Event()], [Accounting()]);
        var expected = JsonNode.Parse("""
            {
              "accounting_sample_counts": {"lifecycle_rows":1,"lifecycle":{"start":1,"interim_update":0,"stop":0}},
              "alignment_window_quality": {"basis":"accounting_record_date_time_plus_explicit_source_utc_offset","span_seconds":0},
              "nps_event_counts_by_id":{"6272":1},
              "cap_and_truncation_flags":{"accounting_candidate_cap_reached":false,"accounting_record_cap_reached":false,"accounting_byte_cap_reached":false,"selected_file_was_sampled_not_fully_read":false,"nps_event_cap_reached":false},
              "join_quality_counts":{"accounting_lifecycle_records":1,"one_to_one_records":1,"ambiguous_records":0,"unmatched_records":0},
              "exact_principal_bridge_counts":{"exact_subject_sid_records":1,"missing_or_invalid_subject_sid_records":0},
              "joined_time_delta_bucket_counts":{"event_timestamp":{"absolute_le_60_seconds":1},"record_local_time":{"absolute_le_60_seconds":1}},
              "classification":{"correlation":"proven_on_time_aligned_bounded_sample","timestamp":"event_timestamp_proven"}
            }
            """);
        Assert.True(JsonNode.DeepEquals(expected, result));
        string encoded = result.ToJsonString();
        Assert.DoesNotContain("opaque", encoded);
        Assert.DoesNotContain("vpn-a", encoded, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Sid, encoded);
        Assert.DoesNotContain("2026-07-30", encoded);
        Assert.Equal(nameof(RadiusPreflightEvent), Event().ToString());
        Assert.Equal(nameof(RadiusPreflightAccounting), Accounting().ToString());
    }

    [Fact]
    public void AggregateFailsClosedWhenNpsSampleIsTruncated()
    {
        var result = Aggregate([Event()], [Accounting()], new Dictionary<string, bool> { ["nps_event_cap_reached"] = true });
        Assert.Equal("correlation_not_proven", result["classification"]!["correlation"]!.GetValue<string>());
    }

    [Fact]
    public void AccountingTailLimitStillAllowsBoundedSampleConclusion()
    {
        var result = Aggregate([Event()], [Accounting()], new Dictionary<string, bool>
        {
            ["accounting_byte_cap_reached"] = true, ["selected_file_was_sampled_not_fully_read"] = true,
            ["nps_event_cap_reached"] = false,
        });
        Assert.Equal("proven_on_time_aligned_bounded_sample", result["classification"]!["correlation"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("accounting_candidate_cap_reached")]
    [InlineData("accounting_record_cap_reached")]
    public void AccountingSelectionFlagsDoNotHideNpsMatches(string flag)
    {
        var result = Aggregate([Event()], [Accounting()], new Dictionary<string, bool> { [flag] = true });
        Assert.Equal("proven_on_time_aligned_bounded_sample", result["classification"]!["correlation"]!.GetValue<string>());
        Assert.True(result["cap_and_truncation_flags"]![flag]!.GetValue<bool>());
    }

    [Theory]
    [InlineData(0, 0, 1)]
    [InlineData(2, 1, 0)]
    public void MissingAndAmbiguousNpsMatchesFailClosed(int eventCount, int ambiguous, int unmatched)
    {
        var result = Aggregate(Enumerable.Repeat(Event(), eventCount).ToArray(), [Accounting()]);
        Assert.Equal("correlation_not_proven", result["classification"]!["correlation"]!.GetValue<string>());
        Assert.Equal("timestamp_not_proven", result["classification"]!["timestamp"]!.GetValue<string>());
        Assert.Equal(ambiguous, result["join_quality_counts"]!["ambiguous_records"]!.GetValue<int>());
        Assert.Equal(unmatched, result["join_quality_counts"]!["unmatched_records"]!.GetValue<int>());
        Assert.Equal(0, result["exact_principal_bridge_counts"]!["exact_subject_sid_records"]!.GetValue<int>());
    }

    [Fact]
    public void EmptySampleAndMissingKeysCannotProveCorrelation()
    {
        var empty = Aggregate([], []);
        Assert.Equal("correlation_not_proven", empty["classification"]!["correlation"]!.GetValue<string>());
        Assert.Equal("timestamp_not_proven", empty["classification"]!["timestamp"]!.GetValue<string>());
        var missing = Aggregate([Event() with { SessionId = "" }], [Accounting() with { SessionId = "" }]);
        Assert.Equal(1, missing["join_quality_counts"]!["unmatched_records"]!.GetValue<int>());
    }

    [Fact]
    public void SessionIsCaseSensitiveAndNasUsesPythonCaseFold()
    {
        var differentSession = Aggregate([Event()], [Accounting() with { SessionId = "OPAQUE" }]);
        Assert.Equal("correlation_not_proven", differentSession["classification"]!["correlation"]!.GetValue<string>());
        var folded = Aggregate([Event() with { NasIdentity = "Straße" }], [Accounting() with { NasIdentity = "STRASSE" }]);
        Assert.Equal("proven_on_time_aligned_bounded_sample", folded["classification"]!["correlation"]!.GetValue<string>());
    }

    [Theory]
    [InlineData(-901, "absolute_gt_15_minutes", "record_local_time_plus_timezone_proven")]
    [InlineData(-900, "absolute_le_15_minutes", "event_timestamp_proven")]
    [InlineData(60, "absolute_le_60_seconds", "event_timestamp_proven")]
    [InlineData(61, "absolute_le_5_minutes", "event_timestamp_proven")]
    [InlineData(300, "absolute_le_5_minutes", "event_timestamp_proven")]
    [InlineData(301, "absolute_le_15_minutes", "event_timestamp_proven")]
    [InlineData(900, "absolute_le_15_minutes", "event_timestamp_proven")]
    [InlineData(901, "absolute_gt_15_minutes", "record_local_time_plus_timezone_proven")]
    public void TimestampPreferenceAndDeltaBoundariesMatchReference(int seconds, string bucket, string classification)
    {
        var result = Aggregate([Event()], [Accounting() with { EventTimeUtc = EventTime.AddSeconds(seconds) }]);
        Assert.Equal(classification, result["classification"]!["timestamp"]!.GetValue<string>());
        Assert.Equal(1, result["joined_time_delta_bucket_counts"]!["event_timestamp"]![bucket]!.GetValue<int>());
    }

    [Fact]
    public void InvalidSidAndMissingTimestampsAreReportedWithoutInventingIdentity()
    {
        var result = Aggregate([Event() with { SubjectSid = "invalid" }], [Accounting() with { EventTimeUtc = null, RecordTimeUtc = null }]);
        Assert.Equal("proven_on_time_aligned_bounded_sample", result["classification"]!["correlation"]!.GetValue<string>());
        Assert.Equal("timestamp_not_proven", result["classification"]!["timestamp"]!.GetValue<string>());
        Assert.Equal(1, result["exact_principal_bridge_counts"]!["missing_or_invalid_subject_sid_records"]!.GetValue<int>());
        Assert.Equal(0, result["exact_principal_bridge_counts"]!["exact_subject_sid_records"]!.GetValue<int>());
    }

    [Fact]
    public void ParserCountsSkippedRowsAndKeepsInvalidTimesUnknown()
    {
        var (records, counts) = RadiusTimeAlignedPreflight.ParseAccountingSample(
            [" ", "not,csv", "\"unclosed", AccountingLine("7"), AccountingLine("9"), AccountingLine("2", "invalid", "9999999999999999999")], 420);
        Assert.Equal(5, counts["sampled_rows"]);
        Assert.Equal(3, counts["database_compatible_rows"]);
        Assert.Equal(1, counts["lifecycle_rows"]);
        Assert.Equal(0, counts["local_time_parsed_rows"]);
        Assert.Equal(0, counts["event_timestamp_parsed_rows"]);
        var record = Assert.Single(records);
        Assert.Equal("stop", record.Lifecycle);
        Assert.Null(record.RecordTimeUtc);
        Assert.Null(record.EventTimeUtc);
    }
}
