using System.Text.Json.Nodes;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

// Behavioral vectors from tests/sources/test_source_pack_manifest_v2.py.
public sealed class SourcePackManifestV2Tests
{
    private const string Entry = "sli_source_packs.example_minimal:minimal";
    private static SourceNormalizerHandlers Minimal() => new()
    {
        EventFacts = _ => new JsonObject { ["fact"] = 1 },
        EntitySemantics = _ => JsonValue.Create("entities"),
        EventLabel = (id, lang) => $"label {id} {lang}"
    };
    private static SourceNormalizerRegistry Registry() => new(new Dictionary<string, SourceNormalizerHandlers>
    {
        [Entry] = Minimal(),
        ["sli_source_packs.example_minimal:broken"] = new() { EventFacts = _ => new() }
    });
    private static JsonObject Manifest() => JsonNode.Parse("""
        {"schema_version":2,"pack_id":"example.minimal","version":"0.1.0","display_name":"Example",
         "channels":["Security"],"adapters":["windows-eventlog-pywin32"],"event_catalog":"radius_event_catalog.json",
         "normalizer":"example-v1","normalizer_entry":"sli_source_packs.example_minimal:minimal",
         "entity_contract":"identity-ladder-v1","analysis_contract":"example-v1","capabilities":["authentication",""]}
        """)!.AsObject();
    private static JsonObject Catalog(string reference)
    {
        // Use the actual bundled catalog, as the Python vector does.
        Assert.Equal("radius_event_catalog.json", reference);
        using var stream = typeof(OperationsCatalog).Assembly.GetManifestResourceStream("Sli.Server.Compatibility.radius_event_catalog.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    private static JsonObject Load(JsonObject manifest, SourceNormalizerRegistry? registry = null) =>
        SourcePackManifest.Load(manifest.ToJsonString(), registry ?? Registry(), Catalog);

    [Fact]
    public void EntryNeedsOnlyCoreHandlersAndUsesSafeDefaults()
    {
        var normalizer = Registry().LoadEntry("example-v1", Entry);
        var handlers = normalizer.Handlers;
        Assert.Equal("label 4624 ru", handlers.EventLabel!(4624, "ru"));
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["fact"] = 1 }, handlers.EventFacts!(new() { ["event_id"] = 1 })));
        Assert.Equal("entities", handlers.EntitySemantics!(new())!.GetValue<string>());
        Assert.Empty(handlers.FindingRules());
        Assert.Empty(handlers.EventIdsForSearchFamily("logon"));
        Assert.Equal("other", handlers.InvestigationCategory(1));
        Assert.Null(handlers.CorrelationId(new() { ["channel"] = "x", ["event_id"] = 1, ["event_data"] = new JsonObject() }));
        Assert.Null(handlers.SemanticCoreRoleFilters("t", [], new()));
    }

    [Fact]
    public void MissingCoreHandlerAndForeignModuleAreRejected()
    {
        var registry = Registry();
        Assert.Contains("lacks required handler: entity_semantics", Assert.Throws<InvalidDataException>(() => registry.LoadEntry("broken-v1", "sli_source_packs.example_minimal:broken")).Message);
        Assert.Contains("not allowed", Assert.Throws<InvalidDataException>(() => registry.LoadEntry("os-v1", "os:path")).Message);
        // Even a registered target outside the allowed namespaces cannot run.
        var foreign = new SourceNormalizerRegistry(new Dictionary<string, SourceNormalizerHandlers> { ["os:path"] = Minimal() });
        Assert.Throws<InvalidDataException>(() => foreign.LoadEntry("os-v1", "os:path"));
    }

    [Fact]
    public void BundledIdsCannotBeReplacedAndRegisteredEntriesResolve()
    {
        var registry = Registry();
        foreach (string id in SourceNormalizerRegistry.BundledIds)
        {
            Assert.Contains("reserved", Assert.Throws<InvalidDataException>(() => registry.Register(registry.LoadEntry(id, Entry))).Message);
            Assert.True(registry.IsKnown(id));
            Assert.Null(registry.Get(id));
        }
        var entry = registry.LoadEntry("example-v1", Entry);
        registry.Register(entry);
        Assert.Same(entry, registry.Get(" example-v1 "));
        Assert.Equal("label 1 en", registry.Get("example-v1")!.Handlers.EventLabel!(1, "en"));
    }

    [Fact]
    public void ManifestRegistersNormalizerAndCleansCapabilitiesInCatalogMetadata()
    {
        var registry = Registry();
        var catalog = new OperationsCatalog([Manifest().ToJsonString()], registry, Catalog);
        var pack = Assert.Single(catalog.Packs())!;
        Assert.Equal("example-v1", pack["normalizer"]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(new JsonArray("authentication"), pack["capabilities"]));
        Assert.NotNull(registry.Get("example-v1"));
        // Metadata is owned by the catalog and cannot be changed by a caller.
        pack["capabilities"]!.AsArray().Clear();
        Assert.Single(catalog.Packs()[0]!["capabilities"]!.AsArray());
    }

    [Theory]
    [InlineData(1, Entry, "requires schema_version 2")]
    [InlineData(2, "sli_source_packs.example_minimal:missing", "normalizer entry failed")]
    [InlineData(2, "os:path", "normalizer entry failed")]
    [InlineData(2, "sli_source_packs.example_minimal:broken", "normalizer entry failed")]
    public void OldSchemaAndInvalidEntriesFailClosed(int schema, string entry, string expected)
    {
        var manifest = Manifest(); manifest["schema_version"] = schema; manifest["normalizer_entry"] = entry;
        var registry = Registry();
        Assert.Contains(expected, Assert.Throws<InvalidDataException>(() => Load(manifest, registry)).Message);
        Assert.Null(registry.Get("example-v1"));
    }

    [Fact]
    public void BundledV1ManifestsStillLoadWithKnownNativeNormalizers()
    {
        var packs = new OperationsCatalog().Packs();
        Assert.Contains(packs, p => p!["pack_id"]!.GetValue<string>() == "sli.windows.vpn-radius");
        foreach (var pack in packs.OfType<JsonObject>())
            if (pack["normalizer"] is { } id) Assert.Contains(id.GetValue<string>(), SourceNormalizerRegistry.BundledIds);
        var manifest = Manifest();
        manifest["schema_version"] = 1; manifest["normalizer_entry"] = ""; manifest["normalizer"] = "windows-nps-radius-v1"; manifest.Remove("capabilities");
        var loaded = Load(manifest);
        Assert.Equal("windows-nps-radius-v1", loaded["normalizer"]!.GetValue<string>());
        Assert.False(loaded.ContainsKey("capabilities"));
    }

    [Fact]
    public void V2MayOmitBundledAdaptersButV1MustDeclareThem()
    {
        var manifest = Manifest(); manifest["adapters"] = new JsonArray();
        Assert.Empty(Load(manifest)["adapters"]!.AsArray());
        manifest.Remove("adapters");
        Assert.Empty(Load(manifest)["adapters"]!.AsArray());
        manifest["schema_version"] = 1; manifest["normalizer_entry"] = ""; manifest["adapters"] = new JsonArray();
        Assert.Contains("requires non-empty adapters", Assert.Throws<InvalidDataException>(() => Load(manifest)).Message);
    }

    [Fact]
    public void OptionalOverridesArePreservedAndEmptyCapabilitiesAreOmitted()
    {
        var handlers = Minimal() with { InvestigationCategory = _ => "authentication", FindingRules = () => new() { ["1"] = "rule" } };
        var registry = new SourceNormalizerRegistry(new Dictionary<string, SourceNormalizerHandlers> { [Entry] = handlers });
        var manifest = Manifest(); manifest["capabilities"] = new JsonArray("", "  ");
        Assert.False(Load(manifest, registry).ContainsKey("capabilities"));
        Assert.Equal("authentication", registry.Get("example-v1")!.Handlers.InvestigationCategory(1));
        Assert.Equal("rule", registry.Get("example-v1")!.Handlers.FindingRules()["1"]!.GetValue<string>());
    }
}
