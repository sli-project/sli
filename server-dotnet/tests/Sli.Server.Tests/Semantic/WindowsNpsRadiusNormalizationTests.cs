using System.Text.Json.Nodes;
using Sli.Server.Compatibility;
using Sli.Server.Operations;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Parity vectors from tests/events/test_windows_nps_radius_normalization.py.
public sealed class WindowsNpsRadiusNormalizationTests
{
    private const string Provider = "Microsoft-Windows-Security-Auditing";

    [Fact]
    public void Radius_descriptor_and_pack_metadata_are_bundled()
    {
        var pack = Assert.Single(new OperationsCatalog().Packs().OfType<JsonObject>(),
            p => p.Text("pack_id") == "sli.windows.vpn-radius");
        Assert.Equal("Security", Assert.Single(pack["channels"]!.AsArray())!.GetValue<string>());
        Assert.Equal("windows-nps-radius-v1", pack.Text("normalizer"));

        using var stream = typeof(SemanticProducer).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.radius_event_catalog.json");
        Assert.NotNull(stream);
        var catalog = JsonNode.Parse(stream)!;
        Assert.Equal(2, catalog["entries"]!.AsArray().Count);
        Assert.Equal(new[] { "6272", "6273" }, catalog["entries"]!.AsArray().Select(e => e.Text("event_key")));
    }

    [Theory]
    [InlineData(4624, "sli.windows.ad-dc", "context")]
    [InlineData(6272, "sli.windows.vpn-radius", "context")]
    [InlineData(6273, "sli.windows.vpn-radius", "signal")]
    public void Shared_security_catalog_resolves_exact_source_identity(int eventId, string source, string noise)
    {
        var entry = LegacySemantics.Entry(Event(eventId));
        Assert.NotNull(entry);
        Assert.Equal(source, entry.Text("source"));
        Assert.Equal(noise, entry.Text("noise_class"));
    }

    [Theory]
    [InlineData(6272, "Wrong-Provider")]
    [InlineData(6273, "Wrong-Provider")]
    [InlineData(6999, Provider)]
    [InlineData(999999, Provider)]
    public void Wrong_provider_and_unknown_events_never_borrow_dc_semantics(int eventId, string provider)
    {
        var source = Event(eventId, provider);
        var original = source.ToJsonString();
        Assert.Null(LegacySemantics.Entry(source));
        var normalized = SemanticNormalization.Normalize(source);
        Assert.Equal("event.unknown", normalized.Type);
        Assert.True(normalized.Quality["unknown_event_mapping"]!.GetValue<bool>());
        Assert.Equal("source_pack_or_provider_unresolved", normalized.Quality.Text("semantic_mapping_status"));
        Assert.Equal("32", normalized.Roles.Text("source_host"));
        Assert.Single(normalized.Roles);
        Assert.Equal(original, source.ToJsonString());
    }

    [Fact]
    public void Prequeue_selects_denial_and_unknown_provider_but_skips_allowed_context()
    {
        var selected = SemanticProducer.Select([
            new(1, "6272", "Security", Provider),
            new(2, "6273", "Security", Provider),
            new(3, "6273", "Security", "Wrong-Provider")
        ]);
        Assert.Equal(new[] { (2L, "signal"), (3L, "descriptor_missing") },
            selected.Jobs.Select(j => (j.Id, j.Reason)));
        Assert.All(selected.Jobs, j => Assert.Equal("normalize_event", j.Kind));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            {"scanned":3,"queued":2,"signal_queued":1,"unknown_queued":1,
             "unknown_suppressed":0,"context_skipped":1,"noise_skipped":0}
            """), selected.Counters), selected.Counters.ToJsonString());
    }

    private static JsonObject Event(int eventId, string provider = Provider) => new()
    {
        ["id"] = 3400L + eventId,
        ["event_id"] = eventId,
        ["channel"] = "Security",
        ["provider_name"] = provider,
        ["computer"] = "nps01.example.test",
        ["source_host_id"] = 32,
        ["time_created_utc"] = "2026-07-30T01:30:00Z",
        ["event_data_json"] = new JsonObject
        {
            ["SubjectUserSid"] = "S-1-5-21-100000001-200000002-300000003-1101",
            ["SubjectUserName"] = "sample.user",
            ["SubjectDomainName"] = "EXAMPLE",
            ["AccountSessionIdentifier"] = "RADIUS-SESSION-001",
            ["CallingStationID"] = "192.0.2.10",
            ["AuthenticationType"] = "MS-CHAP-v2",
            ["NetworkPolicyName"] = "VPN users",
            ["NASIdentifier"] = "VPN-GW-01",
            ["ReasonCode"] = "16"
        }
    };
}
