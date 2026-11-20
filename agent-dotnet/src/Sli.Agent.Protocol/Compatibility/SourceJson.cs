using System.Text.Json.Nodes;

namespace Sli.Agent.Protocol.Compatibility;

// Python json.dumps(value, ensure_ascii=False) for JSON-compatible source data.
// Object insertion order and the default comma/colon spaces are significant to search.
public static class SourceJson
{
    public static string Serialize(JsonNode? value) => CanonicalJson.Format(value, ensureAscii: false, sortKeys: false, spaced: true);
    public static string SerializeSorted(JsonNode? value) => CanonicalJson.Format(value, ensureAscii: false, sortKeys: true, spaced: true);
}
