using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class CatalogCorrelationTests
{
    [Fact]
    public void Descriptor_lifecycle_does_not_reenable_generic_catalog_pair()
    {
        var entries = CatalogCorrelation.ReadEntries();
        Assert.NotEmpty(entries);
        Assert.Contains(entries, e => e["event_key"]?.ToString() == "4624" && e["lifecycle"] is JsonObject);
        Assert.Empty(CatalogCorrelation.Compile());
    }

    [Fact]
    public void Generic_catalog_pair_route_is_unavailable()
    {
        var error = Assert.Throws<InvalidDataException>(() => CatalogCorrelation.Get("sli.windows.ad-dc", "Security", "4624"));
        Assert.Equal("catalog_pair_rule_not_unique:sli.windows.ad-dc/Security/4624", error.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Duplicate_v2_identity_fails_closed_even_without_pair_declarations(bool normalize)
    {
        var entries = CatalogCorrelation.ReadEntries().ToList();
        var duplicate = entries[0].DeepClone().AsObject();
        if (normalize) foreach (string field in new[] { "source", "stream", "event_key" }) duplicate[field] = " " + duplicate[field]!.ToString().ToUpperInvariant() + " ";
        entries.Add(duplicate);
        var error = Assert.Throws<InvalidDataException>(() => CatalogCorrelation.Compile(entries));
        var first = entries[0];
        Assert.Equal($"catalog_pair_duplicate_identity:{first["source"]!.ToString().ToLowerInvariant()}/{first["stream"]!.ToString().ToLowerInvariant()}/{first["event_key"]}", error.Message);
    }

    [Fact]
    public void Explicit_pair_declaration_compiles_and_lookup_uses_v2_identity()
    {
        var entries = Pair();
        var rule = Assert.Single(CatalogCorrelation.Compile(entries));
        Assert.Equal("sli.windows.ad-dc", rule.Source);
        Assert.Equal("Security", rule.Stream);
        Assert.Equal("4624", rule.OpenEventKey);
        Assert.Equal("4634", rule.CloseEventKey);
        Assert.Equal(4624, rule.OpenEventId);
        Assert.Equal(4634, rule.CloseEventId);
        Assert.Equal(new[] { "logon_id" }, rule.KeyFields);
        Assert.Equal(3600, rule.CloseTimeoutSeconds);
        Assert.Equal("session", rule.Rollup);
        Assert.Equal(rule.OpenEventId, CatalogCorrelation.Get(" SLI.WINDOWS.AD-DC ", " security ", " 4624 ", entries).OpenEventId);
    }

    [Fact]
    public void Incomplete_pair_fails_closed()
    {
        var entries = Pair();
        entries[1]["correlation"] = null;
        Assert.Equal("catalog_pair_terminator_has_no_correlation", Assert.Throws<InvalidDataException>(() => CatalogCorrelation.Compile(entries)).Message);
    }

    private static JsonObject[] Pair() => JsonNode.Parse("""
        [
          {"source":"sli.windows.ad-dc","stream":"Security","event_key":"4624","event_id":4624,
           "lifecycle":{"rollup":"session"},"correlation":{"role":"open","cardinality":"pair","terminators":["4634"],"key":["logon_id"],"close_timeout_seconds":3600}},
          {"source":"sli.windows.ad-dc","stream":"Security","event_key":"4634","event_id":4634,
           "lifecycle":{"rollup":"session"},"correlation":{"role":"close","cardinality":"pair","key":["logon_id"],"close_timeout_seconds":3600}}
        ]
        """)!.AsArray().Select(e => e!.AsObject()).ToArray();
}
