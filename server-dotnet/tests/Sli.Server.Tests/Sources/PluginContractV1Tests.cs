using System.Text.Json.Nodes;
using Sli.Server.Sources;
using Xunit;

namespace Sli.Server.Tests.Sources;

// Vectors from tests/sources/test_plugin_contract_v1.py, using the same three fixtures.
public sealed class PluginContractV1Tests
{
    static JsonObject O(string json) => JsonNode.Parse(json)!.AsObject();
    static JsonObject Resource(string name)
    {
        using var stream = typeof(PluginContractV1Tests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Sources." + name)!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    static JsonObject Decision() => Resource("plugin_architecture_v1.json");
    static JsonObject Shared() => Resource("shared_windows_pull.json");
    static JsonObject Record(string key = "6272", long cursor = 7) => new()
    {
        ["stream_id"] = "stream-fixture-security", ["provider"] = "Microsoft-Windows-Security-Auditing",
        ["schema_version"] = 1, ["event_key"] = key, ["cursor"] = cursor
    };
    static void EqualJson(JsonNode? expected, JsonNode? actual) => Assert.True(JsonNode.DeepEquals(expected, actual), actual?.ToJsonString());

    [Fact]
    public void P0aDecisionExplicitlyAllowsOnlyFixtureValidation()
    {
        var result = PluginContractV1.ValidateDecisionRecord(Decision());
        Assert.Equal("sli.plugin-architecture.v1", result["decision_id"]!.GetValue<string>());
        var prohibited = result["prohibited_actions"]!.AsArray().Select(p => p!.GetValue<string>()).ToArray();
        Assert.Contains("source_contact", prohibited);
        Assert.Contains("worker_activation", prohibited);
        Assert.Contains("postgresql_migration", prohibited);
        // Digests pinned to Python canonical_hash, not to the .NET implementation.
        Assert.Equal("9f2ff7814ec09af714fad81e12b55c1c8fc8bc523d99f6c99446cbf7e08c20fa", result["decision_hash"]!.GetValue<string>());
        EqualJson(Decision()["state_axes"], result["state_axes"]);
    }

    [Theory]
    [InlineData("shared_windows_pull.json", "shared_bounded_pull", "22e8d8b7ca7d4f7d4bfeb3cf39a550570da81ac07d161b6c83f21b01479ef287", "consumer_neutral_source|full_channel|independent_subscriptions")]
    [InlineData("snapshot_generation.json", "snapshot_generation", "c1206d8f4243924c3bc39857e4c89a43ac69f638223ab63d00c28c0492cc84f1", "snapshot_complete|atomic_publish")]
    [InlineData("continuous_transport_declaration.json", "unique_continuous_transport_declaration", "2f0fcb2314940afb310a19c12aa89ee524891fcdcb31a29019d95a062a98b6e1", "continuous_declared_not_started|gap_semantics")]
    public void AllThreeArchetypesValidate(string file, string archetype, string hash, string checks)
    {
        var fixture = Resource(file);
        var result = PluginContractV1.ValidateFixture(fixture, Decision());
        EqualJson(fixture["fixture_id"], result["fixture_id"]);
        Assert.Equal(archetype, result["archetype"]!.GetValue<string>());
        Assert.Equal(hash, result["fixture_hash"]!.GetValue<string>());
        Assert.Equal(new[] { "runtime_disabled", "bundled_reviewed", "orthogonal_states" }.Concat(checks.Split('|')),
            result["checks"]!.AsArray().Select(p => p!.GetValue<string>()));
    }

    [Fact]
    public void SharedSourceIdentityCannotBePluginOwned()
    {
        var fixture = Shared(); fixture["source_instance"]!["plugin_id"] = "sli.remote-access";
        Assert.Equal("source_identity_must_be_consumer_neutral", Assert.Throws<PluginContractException>(() => PluginContractV1.ValidateFixture(fixture, Decision())).Message);
    }

    [Fact]
    public void WindowsStreamMustRemainFullChannelInFirstPilot()
    {
        var fixture = Shared(); fixture["streams"]![0]!["collection_policy"] = "union_subscriptions";
        Assert.Equal("collection_policy_must_equal_full_channel", Assert.Throws<PluginContractException>(() => PluginContractV1.ValidateFixture(fixture, Decision())).Message);
    }

    [Fact]
    public void ExactRouterUsesProviderEventKeyStreamAndSchemaWithIndependentFanOut()
    {
        var fixture = Shared();
        Assert.Equal(["subscription-fixture-ad"], PluginContractV1.RouteEvent(fixture, Record("4624")));
        Assert.Equal(["subscription-fixture-nps"], PluginContractV1.RouteEvent(fixture, Record()));
        var record = Record(); record["provider"] = "Unrelated-Provider";
        Assert.Empty(PluginContractV1.RouteEvent(fixture, record));
        record["provider"] = "microsoft-windows-security-auditing";
        Assert.Equal(["subscription-fixture-nps"], PluginContractV1.RouteEvent(fixture, record));
        record["schema_version"] = 2;
        Assert.Empty(PluginContractV1.RouteEvent(fixture, record));
        record["schema_version"] = 1; record["stream_id"] = "other-stream";
        Assert.Empty(PluginContractV1.RouteEvent(fixture, record));
        Assert.Empty(PluginContractV1.RouteEvent(fixture, Record("9999")));
        // Two consumers may select the same event; the router returns both in stable order.
        var second = fixture["subscriptions"]![1]!.DeepClone(); second["subscription_id"] = "subscription-fixture-shadow";
        fixture["subscriptions"]!.AsArray().Insert(0, second);
        Assert.Equal(["subscription-fixture-nps", "subscription-fixture-shadow"], PluginContractV1.RouteEvent(fixture, Record()));
    }

    [Theory]
    [InlineData("evidence_write", "injected_after_evidence_write", false)]
    [InlineData("evidence_verify", "injected_after_evidence_verify", true)]
    [InlineData("before_registry_transaction", "injected_before_registry_transaction", true)]
    public void CursorNeverAdvancesBeforeEvidenceOutboxTransaction(string phase, string error, bool verified)
    {
        var ledger = new EvidenceFirstLedger(); var fixture = Shared(); var record = Record();
        Assert.Equal(error, Assert.Throws<InvalidOperationException>(() => ledger.Ingest(fixture, record, phase)).Message);
        Assert.Equal(0, ledger.TransportCursor); Assert.Empty(ledger.Outbox); Assert.Empty(ledger.DeliveryPositions);
        Assert.Equal(verified, Assert.Single(ledger.Evidence).Value);
        // Retrying any interrupted phase reuses evidence and commits exactly one delivery.
        ledger.Ingest(fixture, record);
        Assert.Equal(7, ledger.TransportCursor); Assert.Single(ledger.Outbox); Assert.True(Assert.Single(ledger.Evidence).Value);
    }

    [Fact]
    public void ReplayIsIdempotentAndConsumerBackpressureIsolated()
    {
        var ledger = new EvidenceFirstLedger(); var fixture = Shared();
        var ad = Record("4624", 10); var nps = Record("6272", 11);
        ledger.Ingest(fixture, ad); var first = ledger.Ingest(fixture, nps); var replay = ledger.Ingest(fixture, nps);
        EqualJson(first, replay);
        Assert.Equal(11, ledger.TransportCursor); Assert.Equal(2, ledger.Outbox.Count); Assert.Equal(2, ledger.Evidence.Count);
        Assert.All(ledger.Evidence.Values, v => Assert.True(v));
        ledger.Deliver("subscription-fixture-ad", 10);
        Assert.Equal(2, ledger.DeliveryPositions.Count);
        Assert.Equal(10, ledger.DeliveryPositions["subscription-fixture-ad"]);
        Assert.Equal(0, ledger.DeliveryPositions["subscription-fixture-nps"]);
        ledger.Deliver("subscription-fixture-ad", 1); ledger.Ingest(fixture, ad);
        Assert.Equal(10, ledger.DeliveryPositions["subscription-fixture-ad"]); Assert.Equal(11, ledger.TransportCursor);
        Assert.Equal("unknown_subscription_delivery", Assert.Throws<PluginContractException>(() => ledger.Deliver("unknown", 1)).Message);
    }

    static JsonObject Authority(string mode = "authoritative", long start = 1, long end = 100) => new()
    {
        ["contract_id"] = "directory.vpn_entitlements.v1", ["organization"] = "fixture-org", ["authority_kind"] = "domain",
        ["authority_partition_id"] = "fixture-domain-a", ["valid_from"] = start, ["valid_to"] = end, ["mode"] = mode
    };

    [Fact]
    public void AuthoritativeOverlapIsBlockedButShadowAndAdjacentIntervalsAreAllowed()
    {
        EqualJson(O("{\"authority_partition_count\":1,\"authoritative_interval_count\":1,\"shadow_count\":1}"),
            PluginContractV1.ValidateAuthorityRegistrations([Authority(), Authority("shadow")]));
        Assert.Equal("authority_partition_overlap", Assert.Throws<PluginContractException>(() =>
            PluginContractV1.ValidateAuthorityRegistrations([Authority(), Authority(start: 99, end: 120)])).Message);
        var adjacent = PluginContractV1.ValidateAuthorityRegistrations([Authority(), Authority(start: 100, end: 120)]);
        Assert.Equal(2, adjacent["authoritative_interval_count"]!.GetValue<int>());
        var otherPartition = Authority(); otherPartition["authority_partition_id"] = "fixture-domain-b";
        Assert.Equal(2, PluginContractV1.ValidateAuthorityRegistrations([Authority(), otherPartition])["authority_partition_count"]!.GetValue<int>());
    }

    [Fact]
    public void InformationFlowInheritsAllGroupsAndStrongestSensitivity()
    {
        JsonObject[] inputs = [
            O("{\"resource_groups\":[[{\"kind\":\"domain\",\"id\":1}]],\"row_sensitivity\":\"restricted\",\"evidence_access_requirement\":true,\"provenance\":[\"ad\"]}"),
            O("{\"resource_groups\":[[{\"kind\":\"server\",\"id\":2}]],\"row_sensitivity\":\"confidential\",\"evidence_access_requirement\":true,\"provenance\":[\"nps\"]}")];
        var expected = O("""
            {"resource_groups":[[{"kind":"domain","id":1}],[{"kind":"server","id":2}]],
             "row_sensitivity":"confidential","evidence_access_requirement":true,"provenance":["ad","nps"],
             "field_visibility_categories":{"subject":"identity"},"producer_contract_version":"remote_access.assessment.v1","label_policy_version":1}
            """);
        EqualJson(expected, PluginContractV1.InheritAccessLabel(inputs, O("{\"subject\":\"identity\"}"), "remote_access.assessment.v1"));
        // AND resource groups are retained rather than flattened or discarded; evidence is OR.
        inputs[0]["evidence_access_requirement"] = false;
        inputs[1]["provenance"]!.AsArray().Add("ad");
        EqualJson(expected, PluginContractV1.InheritAccessLabel(inputs, O("{\"subject\":\"identity\"}"), "remote_access.assessment.v1"));
        Assert.Equal("mandatory_input_labels_required", Assert.Throws<PluginContractException>(() => PluginContractV1.InheritAccessLabel([], new(), "v1")).Message);
    }

    [Theory]
    [InlineData("[1,2]", "[1,2]", true, true, "complete")]
    [InlineData("[1,2]", "[1]", true, true, "partial")]
    [InlineData("[1,2]", "[1,2]", true, false, "partial")]
    [InlineData("[1,2]", "[1,2]", false, true, "partial")]
    [InlineData("[1,2]", "[2,1]", true, true, "complete")]
    [InlineData("[1,2]", "[1,2,2]", true, true, "invalid")]
    [InlineData("[1,1]", "[1]", true, true, "invalid")]
    [InlineData("[]", "[]", true, true, "partial")]
    public void SnapshotGenerationNeverCallsPartialComplete(string expected, string received, bool verified, bool atomic, string status)
    {
        Assert.Equal(status, PluginContractV1.SnapshotStatus(new() { ["expected_pages"] = JsonNode.Parse(expected),
            ["received_pages"] = JsonNode.Parse(received), ["manifest_verified"] = verified, ["atomic_publish"] = atomic }));
    }

    [Fact]
    public void WorkerBoundaryAndDetachReaderAreFailClosed()
    {
        var fixture = Shared(); var boundaries = fixture["worker"]!["boundaries"]!.AsArray();
        boundaries.Remove(boundaries.Single(v => v!.GetValue<string>() == "postgres_role"));
        Assert.Equal("worker_boundaries_incomplete", Assert.Throws<PluginContractException>(() => PluginContractV1.ValidateFixture(fixture, Decision())).Message);
        foreach (string key in new[] { "source_contact", "jobs_enabled", "write_rights" })
        {
            fixture = Shared(); fixture["detach_reader"]![key] = true;
            Assert.Equal(key + "_must_equal_False", Assert.Throws<PluginContractException>(() => PluginContractV1.ValidateFixture(fixture, Decision())).Message);
        }
    }

    [Fact]
    public void ProducerReplacementHashIgnoresOnlyProducerProvenance()
    {
        var first = O("{\"subject\":\"fixture\",\"entitlement\":\"vpn\",\"valid_from\":1,\"producer_id\":\"core-ad-context\",\"producer_version\":\"1\"}");
        var replacement = first.DeepClone().AsObject(); replacement["producer_id"] = "sli.ad-dc"; replacement["producer_version"] = "2";
        Assert.Equal("b83a5168a9f44983149e5e97d49b530e7f8c92fa1babc5e841479b8d9bd7d0de", PluginContractV1.SemanticProjectionHash(first));
        Assert.Equal(PluginContractV1.SemanticProjectionHash(first), PluginContractV1.SemanticProjectionHash(replacement));
        replacement["observed_at"] = "2026-01-01T00:00:00Z";
        Assert.Equal(PluginContractV1.SemanticProjectionHash(first), PluginContractV1.SemanticProjectionHash(replacement));
        replacement["entitlement"] = "admin-vpn";
        Assert.NotEqual(PluginContractV1.SemanticProjectionHash(first), PluginContractV1.SemanticProjectionHash(replacement));
        Assert.Equal("0fcc53f51072a5da523bd331d6be44586a87c0f5a8382c6f70e36d5fc6b318af", PluginContractV1.SemanticProjectionHash(
            O("{\"subject\":\"проверка 😀\",\"n\":1.0,\"nested\":{\"z\":2,\"a\":3},\"producer_id\":\"ignored\"}")));
    }
}
