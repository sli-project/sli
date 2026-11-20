using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Sli.Server.SourcePacks;

// Collector-facing manifest v2 fields. Existing operations catalog ownership is unchanged.
public sealed class SourcePackCollectorManifest
{
    private readonly JsonObject manifest;
    private readonly string hash;
    public string PackId => manifest["pack_id"]!.GetValue<string>();
    public string NormalizerId => manifest["normalizer"]!.GetValue<string>();
    public CollectorSpec? Collector { get; }

    public SourcePackCollectorManifest(string json)
    {
        manifest = JsonNode.Parse(json) as JsonObject ?? throw new ArgumentException("source pack manifest must be an object");
        if (manifest["schema_version"]?.GetValue<int>() != 2) throw new ArgumentException("collector requires schema_version 2");
        foreach (string key in new[] { "pack_id", "version", "display_name", "normalizer", "entity_contract", "analysis_contract" })
            if (string.IsNullOrWhiteSpace(manifest[key]?.GetValue<string>())) throw new ArgumentException("source pack requires " + key);
        Collector = CollectorSpec.Parse(manifest["collector"]);
        hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json.Replace("\r\n", "\n"))));
    }

    public JsonObject EventFacts(JsonObject row, JsonObject? eventData = null)
    {
        if (NormalizerId != LinuxAuth.NormalizerId || manifest["normalizer_entry"]?.ToString() != LinuxAuth.NormalizerEntry)
            throw new NotSupportedException("source_pack_normalizer_not_implemented");
        return LinuxAuth.EventFacts(row, eventData);
    }

    public JsonObject PublicDict()
    {
        var result = new JsonObject();
        foreach (string key in new[] { "pack_id", "version", "display_name", "channels", "adapters", "entity_contract", "analysis_contract", "normalizer", "capabilities" })
            if (manifest[key] is { } value) result[key] = value.DeepClone();
        result["source_kind"] = manifest["source_kind"]?.DeepClone() ?? JsonValue.Create("event");
        result["sections"] = manifest["sections"]?.DeepClone() ?? new JsonArray();
        result["manifest_sha256"] = hash;
        if (Collector is { } spec) result["collector"] = new JsonObject { ["kind"] = spec.Kind, ["entry"] = spec.Entry };
        return result;
    }
}
