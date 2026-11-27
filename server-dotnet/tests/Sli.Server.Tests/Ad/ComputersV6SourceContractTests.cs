using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Ad;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Domains;
using Xunit;

namespace Sli.Server.Tests.Ad;

// Input/output vectors from tests/sources/test_computers_v6_source_contract.py.
public sealed class ComputersV6SourceContractTests
{
    private static JsonObject Snapshot()
    {
        using var stream = typeof(ComputersV6SourceContractTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.computers-source-contract.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    private static JsonObject Item(JsonObject snapshot) => snapshot["objects"]![0]!.AsObject();
    private static JsonObject State(JsonObject snapshot, string source = "site") => Item(snapshot)["sources"]![source]!.AsObject();
    private static JsonObject Stage(JsonObject snapshot, string source = "site") => snapshot["metadata"]!["sources"]!.AsArray().Single(s => s!["name"]!.ToString() == source)!.AsObject();
    private static JsonArray Error(string status) => new(new JsonObject { ["source"] = "site", ["status"] = status, ["code"] = "site_" + status, ["message"] = "site " + status, ["target"] = "example.test" });
    private static void SetStatus(JsonObject snapshot, string status, string source = "site", bool requested = true)
    {
        var state = State(snapshot, source);
        state["status"] = status;
        state["value"] = status is "observed" or "partial" ? JsonValue.Create("HQ") : null;
        state["observed_at"] = status is "not_collected" or "not_applicable" ? null : JsonValue.Create("2026-08-30T01:05:00Z");
        state["error"] = status is "failed" or "access_denied" or "parse_error" or "partial" ? Error(status) : null;
        state["details"] = status switch {
            "not_evaluated" => new JsonObject { ["reason"] = "no_ipv4_for_site_mapping", ["dependency"] = "dns", ["dependency_status"] = "no_record" },
            "partial" => new JsonObject { ["queried"] = 1, ["failed"] = 1 },
            "missing_in_source" => new JsonObject { ["missing_field"] = "site" },
            "no_record" => new JsonObject { ["reason"] = "no_matching_ad_subnet" },
            "not_applicable" => new JsonObject { ["reason"] = "source_not_applicable" },
            _ => null
        };
        var stage = Stage(snapshot, source);
        stage["status"] = status; stage["requested"] = requested;
        stage["counts"] = new JsonObject { [status] = 1 };
        if (status is not ("observed" or "not_collected" or "not_applicable")) snapshot["metadata"]!["collection_status"] = "partial";
    }
    private static void Accept(JsonObject snapshot)
    {
        var validated = ComputersSnapshotValidation.Validate(snapshot);
        Assert.True(JsonNode.DeepEquals(snapshot, validated));
        Assert.NotSame(snapshot, validated);
        AdSnapshotPreparation.ValidateComputers(snapshot);
        Assert.True(HomeComputerSource.Valid(snapshot));
    }
    private static void Reject(JsonObject snapshot)
    {
        Assert.Throws<ProtocolException>(() => ComputersSnapshotValidation.Validate(snapshot));
        Assert.Throws<ProtocolException>(() => AdSnapshotPreparation.ValidateComputers(snapshot));
        Assert.False(HomeComputerSource.Valid(snapshot));
    }
    private static JsonObject Report(JsonObject snapshot) => AdInventoryRows.Computer(Item(snapshot), new JsonObject {
        ["snapshot"] = snapshot.DeepClone(), ["domain_id"] = 7, ["fqdn"] = "example.test"
    }, snapshot["metadata"]!["completed_at"]!.ToString(), new JsonObject());

    [Theory]
    [InlineData(4096, "Windows 11 Pro", "workstation", "enabled")]
    [InlineData(4098, "Windows Server 2022", "server", "disabled")]
    [InlineData(8192, null, "domain_controller", "enabled")]
    [InlineData(4098, null, "unknown", "disabled")]
    [InlineData(null, null, "unknown", "unknown")]
    public void Report_preserves_directory_facts_for_precreated_and_joined_accounts(int? uac, string? os, string role, string state)
    {
        var snapshot = Snapshot();
        var item = Item(snapshot);
        item["classification"] = null;
        item["deviceType"] = "unknown";
        item["enabled"] = null;
        item["userAccountControl"] = uac;
        item["osName"] = os;
        State(snapshot, "os")["status"] = os is null ? "missing_in_source" : "observed";
        State(snapshot, "os")["value"] = os;
        var row = Report(snapshot);
        Assert.Equal(os, row["operating_system"]?.GetValue<string>());
        Assert.Equal(role, row["computer_type"]!.GetValue<string>());
        Assert.Equal(state, row["account_state"]!.GetValue<string>());
        Assert.Equal(uac is null ? (bool?)null : (uac & 2) == 0, AdInventoryRows.Bool(row["enabled"]));
    }

    [Fact]
    public void Observed_OS_and_legacy_agent_classification_are_preserved()
    {
        var snapshot = Snapshot();
        var item = Item(snapshot);
        item["classification"] = null;
        item["deviceType"] = "server";
        item["userAccountControl"] = 4096;
        item["osName"] = null;
        State(snapshot, "os")["status"] = "observed";
        State(snapshot, "os")["value"] = "Windows Server 2022";
        var row = Report(snapshot);
        Assert.Equal("Windows Server 2022", row["operating_system"]!.GetValue<string>());
        Assert.Equal("server", row["computer_type"]!.GetValue<string>());
    }

    [Fact]
    public void Report_reads_non_dc_facts_from_observed_source_values()
    {
        var snapshot = Snapshot();
        var item = Item(snapshot);
        item["osName"] = "";
        item["osVersion"] = null;
        item["deviceType"] = "unknown";
        item["classification"] = new JsonObject { ["value"] = "workstation" };
        item["lastLogonTimestamp"] = null;
        item["exactLastLogon"] = null;
        item["eventLastSeen"] = null;
        var stamp = DateTimeOffset.Parse("2026-08-29T12:00:00Z");
        State(snapshot, "os")["value"] = new JsonObject { ["name"] = "Windows 11 Pro", ["version"] = "10.0 (26100)" };
        State(snapshot, "last_logon_timestamp")["value"] = stamp.ToFileTime();

        var row = Report(snapshot);

        Assert.Equal("Windows 11 Pro", row["operating_system"]!.GetValue<string>());
        Assert.Equal("10.0 (26100)", row["operating_system_version"]!.GetValue<string>());
        Assert.Equal("workstation", row["computer_type"]!.GetValue<string>());
        Assert.Equal(stamp, AdInventoryRows.Date(row["ad_last_logon_utc"]));
        Assert.Equal(stamp, AdInventoryRows.Date(row["last_logon_utc"]));
    }

    [Theory]
    [InlineData("Windows 11 Pro", "workstation")]
    [InlineData("Windows Server 2022", "server")]
    public void Report_recovers_directory_facts_for_the_same_computer(string os, string role)
    {
        var snapshot = Snapshot();
        var item = Item(snapshot);
        item["classification"] = null;
        item["deviceType"] = "unknown";
        item["osName"] = item["enabled"] = item["userAccountControl"] = null;
        item["lastLogonTimestamp"] = item["exactLastLogon"] = item["eventLastSeen"] = null;
        SetStatus(snapshot, "missing_in_source", "os");
        SetStatus(snapshot, "missing_in_source", "last_logon_timestamp");
        var attrs = new JsonObject { ["operating_system"] = os, ["user_account_control"] = 4096,
            ["last_logon_timestamp_utc"] = "2026-08-29T12:00:00Z" };
        var source = new JsonObject { ["domain_id"] = 7, ["fqdn"] = "example.test", ["snapshot"] = snapshot,
            ["computer_directory_attributes"] = new JsonObject { [item["objectGuid"]!.ToString()] = attrs } };

        var row = AdInventoryRows.Computer(item, source, snapshot["metadata"]!["completed_at"]!.ToString(), new JsonObject());

        Assert.Equal(os, row["operating_system"]!.GetValue<string>());
        Assert.Equal(role, row["computer_type"]!.GetValue<string>());
        Assert.True(row["enabled"]!.GetValue<bool>());
        Assert.Equal(DateTimeOffset.Parse("2026-08-29T12:00:00Z"), AdInventoryRows.Date(row["last_logon_utc"]));
        Assert.Equal("active_directory", row["last_logon_source"]!.GetValue<string>());
        Assert.Null(item["osName"]);
    }

    [Theory]
    [InlineData(0, "within_30_days")]
    [InlineData(30, "within_30_days")]
    [InlineData(31, "days_31_to_90")]
    [InlineData(61, "days_31_to_90")]
    [InlineData(90, "days_31_to_90")]
    [InlineData(91, "over_90_days")]
    public void Available_logon_belongs_to_one_activity_bucket(int days, string expected)
    {
        var snapshot = Snapshot();
        var item = Item(snapshot);
        item["lastLogonTimestamp"] = null;
        item["eventLastSeen"] = null;
        SetStatus(snapshot, "missing_in_source", "last_logon_timestamp");
        var observed = DateTimeOffset.Parse(snapshot["metadata"]!["completed_at"]!.ToString());
        item["exactLastLogon"] = observed.AddDays(-days).ToString("O");
        var row = Report(snapshot);
        string[] buckets = ["within_30_days", "days_31_to_90", "over_90_days", "never"];
        Assert.Equal(new[] { expected }, buckets.Where(bucket => AdInventoryRows.MatchesComputerActivity(row, bucket, 60)));
    }

    [Fact]
    public void Most_recent_valid_logon_is_used_for_the_display_and_bucket()
    {
        var snapshot = Snapshot();
        var item = Item(snapshot);
        var observed = DateTimeOffset.Parse(snapshot["metadata"]!["completed_at"]!.ToString());
        item["eventLastSeen"] = observed.AddDays(-91).ToString("O");
        item["exactLastLogon"] = observed.AddDays(-2).ToString("O");
        item["lastLogonTimestamp"] = observed.AddDays(-40).ToString("O");
        var row = Report(snapshot);
        Assert.Equal(observed.AddDays(-2), AdInventoryRows.Date(row["last_logon_utc"]));
        Assert.Equal("domain_controllers", row["last_logon_source"]!.GetValue<string>());
        Assert.True(AdInventoryRows.MatchesComputerActivity(row, "within_30_days", 90));
    }

    [Fact]
    public void Never_requires_a_collected_no_logon_result()
    {
        var snapshot = Snapshot();
        var item = Item(snapshot);
        foreach (string field in new[] { "lastLogonTimestamp", "exactLastLogon", "eventLastSeen" }) item[field] = null;
        SetStatus(snapshot, "missing_in_source", "last_logon_timestamp");
        SetStatus(snapshot, "not_collected", "exact_last_logon", false);
        Assert.False(AdInventoryRows.MatchesComputerActivity(Report(snapshot), "never", 90));
        SetStatus(snapshot, "missing_in_source", "exact_last_logon");
        State(snapshot, "exact_last_logon")["details"] = new JsonObject
        {
            ["discovered_dc_count"] = 2, ["successful_dc_count"] = 2
        };
        Assert.True(AdInventoryRows.MatchesComputerActivity(Report(snapshot), "never", 90));
    }

    [Fact]
    public void Production_source_is_accepted_without_mutating_the_document()
    {
        var snapshot = Snapshot(); var before = snapshot.DeepClone(); Accept(snapshot);
        Assert.True(JsonNode.DeepEquals(before, snapshot));
        var validated = ComputersSnapshotValidation.Validate(snapshot);
        Item(validated)["name"] = "changed";
        Assert.Equal("APP-01", Item(snapshot)["name"]!.ToString());
        Assert.Equal(1, snapshot["metadata"]!["object_count"]!.GetValue<int>());
    }

    [Theory]
    [InlineData("demo")]
    [InlineData("object_count")]
    [InlineData("metadata_fields")]
    [InlineData("stable_identity")]
    [InlineData("duplicate")]
    [InlineData("required_sources")]
    [InlineData("source_state_fields")]
    [InlineData("base_ad")]
    [InlineData("time_window")]
    [InlineData("dc_events")]
    public void Invalid_source_never_becomes_inventory_authority(string mutation)
    {
        var snapshot = Snapshot();
        switch (mutation) {
            case "demo": snapshot["metadata"]!["snapshot_id"] = "demo-current-20260830"; snapshot["metadata"]!["collector_version"] = "evidence-collector-demo-1.0"; break;
            case "object_count": snapshot["metadata"]!["object_count"] = 2; break;
            case "metadata_fields": snapshot["metadata"]!.AsObject().Remove("query_dc"); break;
            case "stable_identity": Item(snapshot)["objectGuid"] = "00000000-0000-4000-8000-000000000002"; break;
            case "duplicate": snapshot["objects"]!.AsArray().Add(Item(snapshot).DeepClone()); snapshot["metadata"]!["object_count"] = 2; break;
            case "required_sources": Item(snapshot)["sources"]!.AsObject().Remove("exact_last_logon"); break;
            case "source_state_fields": State(snapshot, "dns").Remove("details"); break;
            case "base_ad": SetStatus(snapshot, "failed", "ad"); break;
            case "time_window": snapshot["metadata"]!["completed_at"] = "2026-08-30T00:59:59Z"; break;
            case "dc_events": SetStatus(snapshot, "observed", "dc_events"); State(snapshot, "dc_events")["value"] = "4624"; break;
        }
        Reject(snapshot);
    }

    [Theory]
    [InlineData("observed", null)]
    [InlineData("not_collected", null)]
    [InlineData("not_evaluated", "not_evaluated")]
    [InlineData("missing_in_source", "no_record_or_missing_source")]
    [InlineData("no_record", "no_record_or_missing_source")]
    [InlineData("partial", "partial")]
    [InlineData("failed", "source_error")]
    [InlineData("access_denied", "source_error")]
    [InlineData("parse_error", "source_error")]
    [InlineData("not_applicable", null)]
    public void Source_statuses_preserve_their_meaning_and_quality_category(string status, string? category)
    {
        var snapshot = Snapshot(); SetStatus(snapshot, status, requested: status != "not_collected"); Accept(snapshot);
        var row = Report(snapshot);
        Assert.Equal(status, row["evidence"]!["source_states"]!["site"]!["status"]!.ToString());
        var codes = row["quality_issues"]!.AsArray().Select(q => q!["code"]!.ToString()).ToArray();
        if (category is null) Assert.Empty(codes); else Assert.Equal(new[] { category }, codes);
        // C079: only an observed source can supply affirmative address evidence.
        var dnsSnapshot = Snapshot(); SetStatus(dnsSnapshot, status, "dns", requested: status != "not_collected");
        var dns = AdComputerPosture.Dns(Item(dnsSnapshot));
        Assert.Equal(status == "observed" ? 1 : 0, dns["addresses"]!.AsArray().Count);
    }

    [Theory]
    [InlineData("observed")]
    [InlineData("missing_in_source")]
    [InlineData("no_record")]
    [InlineData("partial")]
    [InlineData("failed")]
    [InlineData("access_denied")]
    [InlineData("parse_error")]
    public void Queried_sources_require_an_observation_time(string status)
    {
        var snapshot = Snapshot(); SetStatus(snapshot, status); Accept(snapshot);
        State(snapshot)["observed_at"] = null; Reject(snapshot);
    }

    [Theory]
    [InlineData("not_evaluated")]
    [InlineData("partial")]
    public void Incomplete_sources_require_details(string status)
    {
        var snapshot = Snapshot(); SetStatus(snapshot, status); Accept(snapshot);
        State(snapshot)["details"] = null; Reject(snapshot);
    }

    [Theory]
    [InlineData("failed")]
    [InlineData("access_denied")]
    [InlineData("parse_error")]
    public void Error_sources_require_nonempty_error_evidence(string status)
    {
        var snapshot = Snapshot(); SetStatus(snapshot, status); Accept(snapshot);
        foreach (string raw in new[] { "null", "[]", "{}", "\"\"", "false", "0" }) {
            State(snapshot)["error"] = JsonNode.Parse(raw); Reject(snapshot);
        }
    }

    [Fact]
    public void Not_collected_cannot_claim_an_observation_and_is_an_issue_only_when_requested()
    {
        var snapshot = Snapshot(); SetStatus(snapshot, "not_collected", requested: false); Accept(snapshot);
        Assert.Empty(Report(snapshot)["quality_issues"]!.AsArray());
        Stage(snapshot)["requested"] = true;
        Assert.Equal("not_collected", Assert.Single(Report(snapshot)["quality_issues"]!.AsArray())!["code"]!.ToString());
        State(snapshot)["value"] = "HQ"; Reject(snapshot);
        State(snapshot)["value"] = null; State(snapshot)["observed_at"] = "2026-08-30T01:05:00Z"; Reject(snapshot);
        SetStatus(snapshot, "failed", requested: false); Accept(snapshot);
        Assert.Equal("source_error", Assert.Single(Report(snapshot)["quality_issues"]!.AsArray())!["code"]!.ToString());
    }

    [Fact]
    public void Missing_fields_use_the_ordered_last_observed_fallback()
    {
        var snapshot = Snapshot(); Assert.Empty(Report(snapshot)["quality_issues"]!.AsArray());
        var item = Item(snapshot);
        item["osName"] = null; item["dnsHostName"] = ""; item["distinguishedName"] = null;
        item["eventLastSeen"] = null; item["exactLastLogon"] = null; item["lastLogonTimestamp"] = null;
        SetStatus(snapshot, "missing_in_source", "os");
        SetStatus(snapshot, "missing_in_source", "last_logon_timestamp");
        IEnumerable<string> MissingFields() => Assert.Single(Report(snapshot)["quality_issues"]!.AsArray(),
            issue => issue!["code"]!.ToString() == "missing_field")!["fields"]!.AsArray().Select(f => f!.ToString());
        Assert.Equal(new[] { "osName", "dnsHostName", "lastObserved", "distinguishedName" },
            MissingFields());
        foreach (string field in new[] { "eventLastSeen", "exactLastLogon", "lastLogonTimestamp" }) {
            item[field] = "2026-08-29T12:00:00Z";
            Assert.DoesNotContain("lastObserved", MissingFields());
            item[field] = null;
        }
    }

    [Fact]
    public void Optional_source_failures_preserve_base_inventory_and_failed_base_can_be_empty()
    {
        var snapshot = Snapshot();
        SetStatus(snapshot, "failed", "dns"); State(snapshot, "dns")["details"] = new JsonObject { ["stage"] = "A+AAAA" };
        SetStatus(snapshot, "not_evaluated"); State(snapshot)["details"]!["dependency_status"] = "failed";
        SetStatus(snapshot, "partial", "exact_last_logon");
        State(snapshot, "exact_last_logon")["value"] = "2026-08-29T12:30:00Z";
        State(snapshot, "exact_last_logon")["details"] = new JsonObject { ["queried_dc"] = 1, ["total_dc"] = 2, ["failed_dc"] = new JsonArray("dc02") };
        Accept(snapshot); Assert.Single(snapshot["objects"]!.AsArray()); Assert.Equal("observed", Stage(snapshot, "ad")["status"]!.ToString());
        var row = Report(snapshot);
        Assert.Equal(new[] { "source_error", "not_evaluated", "partial" }, row["quality_issues"]!.AsArray().Select(q => q!["code"]!.ToString()));
        SetStatus(snapshot, "failed", "ad"); Reject(snapshot);
        snapshot = Snapshot(); snapshot["objects"] = new JsonArray(); snapshot["metadata"]!["object_count"] = 0; snapshot["metadata"]!["collection_status"] = "failed";
        snapshot["metadata"]!["sources"] = new JsonArray(new JsonObject { ["name"] = "ad", ["status"] = "failed", ["requested"] = true, ["counts"] = new JsonObject { ["failed"] = 0 } });
        Accept(snapshot);
    }

    [Fact]
    public void Naive_times_are_rejected_by_all_source_consumers()
    {
        var snapshot = Snapshot(); snapshot["metadata"]!["completed_at"] = "2026-08-30T01:10:00";
        Assert.Throws<ProtocolException>(() => ComputersSnapshotValidation.Validate(snapshot));
        Assert.Throws<FormatException>(() => AdSnapshotPreparation.ValidateComputers(snapshot));
        Assert.False(HomeComputerSource.Valid(snapshot));
    }

    [Fact]
    public void Parser_accepts_utf8_at_exact_byte_bound_and_rejects_invalid_json()
    {
        var snapshot = Snapshot(); Item(snapshot)["description"] = "Проверка";
        var raw = Encoding.UTF8.GetBytes(CanonicalJson.Serialize(snapshot, ensureAscii: false));
        Assert.True(raw.Length > Encoding.UTF8.GetString(raw).Length);
        Assert.True(JsonNode.DeepEquals(snapshot, ComputersSnapshotValidation.Parse(raw, raw.Length)));
        Assert.Equal("snapshot_size_out_of_bounds", Assert.Throws<ProtocolException>(() => ComputersSnapshotValidation.Parse(raw, raw.Length - 1)).Message);
        Assert.Equal("snapshot_json_invalid", Assert.Throws<ProtocolException>(() => ComputersSnapshotValidation.Parse(Encoding.UTF8.GetBytes("{not-json"), 100)).Message);
        Assert.Equal("snapshot_utf8_invalid", Assert.Throws<ProtocolException>(() => ComputersSnapshotValidation.Parse(new byte[] { 0xff })).Message);
        Assert.True(JsonNode.DeepEquals(snapshot, ComputersSnapshotValidation.Parse(new byte[] { 0xef, 0xbb, 0xbf }.Concat(raw).ToArray())));
    }

    [Fact]
    public void Agent_family_decoder_enforces_the_computers_source_contract()
    {
        var snapshot = Snapshot();
        SnapshotTransport Transport(JsonObject value) => new(Guid.Empty, "S-1-5-21-100000001-200000002-300000003", new JsonObject(),
            new Dictionary<string, byte[]> { ["computers_v6"] = Encoding.UTF8.GetBytes(value.ToJsonString()) },
            new[] { new SnapshotCycleRow(new JsonObject(), new JsonObject { ["family"] = "computers_v6", ["total_objects"] = 1 }, "") }, true);
        Assert.True(JsonNode.DeepEquals(snapshot, SnapshotFamilyDecoder.Decode(Transport(snapshot))["computers_v6"]));
        State(snapshot).Remove("details");
        Assert.Throws<ProtocolException>(() => SnapshotFamilyDecoder.Decode(Transport(snapshot)));
    }

    [Fact]
    public void Callers_cannot_relax_source_boundary_limits()
    {
        var snapshot = Snapshot(); var raw = Encoding.UTF8.GetBytes(snapshot.ToJsonString());
        Assert.Equal("byte_limit_out_of_bounds", Assert.Throws<ProtocolException>(() => ComputersSnapshotValidation.Parse(raw, ComputersSnapshotValidation.MaxSnapshotBytes + 1)).Message);
        Assert.Equal("object_limit_out_of_bounds", Assert.Throws<ProtocolException>(() => ComputersSnapshotValidation.Validate(snapshot, ComputersSnapshotValidation.MaxObjects + 1)).Message);
        Assert.Equal("object_limit_out_of_bounds", Assert.Throws<ProtocolException>(() => ComputersSnapshotValidation.Parse(raw, maxObjects: ComputersSnapshotValidation.MaxObjects + 1)).Message);
        Assert.Throws<ProtocolException>(() => ComputersSnapshotValidation.Validate(snapshot, 0));
        snapshot["objects"] = new JsonArray(); snapshot["metadata"]!["object_count"] = 0;
        Assert.Empty(ComputersSnapshotValidation.Validate(snapshot, 0)["objects"]!.AsArray());
    }
}
