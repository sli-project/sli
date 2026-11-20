using System.Numerics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
namespace Sli.Server.Agents.Updates;

// Source int(version_part) ValueError escapes updates.upload's PackageError
// catch. Keep it distinct so the existing executing-operation boundary sends
// safe agent_service_unavailable/503 before any package INSERT.
internal sealed class AgentPackageVersionLimitException():Exception("agent_package_version_limit");

// Signed release documents intentionally differ from ordinary API json.loads:
// duplicate decoded keys and all floating-point tokens are source-invalid.
internal static class AgentPackageJson
{
    private const string VersionPattern=@"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)";
    private static readonly HashSet<string> Reserved=new[]{"CON","PRN","AUX","NUL","CLOCK$","CONIN$","CONOUT$"}
        .Concat(Enumerable.Range(1,9).SelectMany(i=>new[]{"COM"+i.ToString(CultureInfo.InvariantCulture),"LPT"+i.ToString(CultureInfo.InvariantCulture)})).ToHashSet(StringComparer.OrdinalIgnoreCase);
    internal static void Need(bool condition){if(!condition)throw new InvalidDataException("invalid agent release");}
    internal static JsonObject Parse(byte[] raw)
    {
        using var document=JsonDocument.Parse(new UTF8Encoding(false,true).GetString(raw),new JsonDocumentOptions { MaxDepth=1000 });
        return Object(Read(document.RootElement));
    }
    private static JsonNode? Read(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Object) {
            var obj=new JsonObject();foreach(var property in value.EnumerateObject()){Need(!obj.ContainsKey(property.Name));obj.Add(property.Name,Read(property.Value));}return obj;
        }
        if(value.ValueKind==JsonValueKind.Array){var array=new JsonArray();foreach(var item in value.EnumerateArray())array.Add(Read(item));return array;}
        if(value.ValueKind==JsonValueKind.Number) {
            string token=value.GetRawText();Need(!token.Any(c=>c is '.' or 'e' or 'E'));
            // Frozen CPython3.14.6 json.loads uses its standard int digit limit.
            Need(token.Length-(token[0]=='-'?1:0)<=4300);
        }
        return value.ValueKind==JsonValueKind.Null?null:JsonValue.Create(value.Clone());
    }
    internal static JsonObject Object(JsonNode? value){Need(value is JsonObject);return (JsonObject)value!;}
    internal static JsonArray Array(JsonNode? value){Need(value is JsonArray);return (JsonArray)value!;}
    internal static void Fields(JsonObject value,params string[] names)=>Need(value.Count==names.Length && names.All(value.ContainsKey));
    internal static string Text(JsonNode? value){Need(value is JsonValue v && v.TryGetValue<string>(out _));return value!.GetValue<string>();}
    internal static bool Match(JsonNode? value,string pattern)=>value is JsonValue v && v.TryGetValue<string>(out var text) && Regex.IsMatch(text,"\\A(?:"+pattern+")\\z",RegexOptions.CultureInvariant|RegexOptions.NonBacktracking);
    internal static BigInteger Integer(JsonNode? value)
    {
        Need(value is JsonValue);using var doc=JsonDocument.Parse(value!.ToJsonString());var e=doc.RootElement;
        Need(e.ValueKind==JsonValueKind.Number && !e.GetRawText().Any(c=>c is '.' or 'e' or 'E'));
        return BigInteger.Parse(e.GetRawText(),NumberStyles.AllowLeadingSign,CultureInfo.InvariantCulture);
    }
    internal static bool Boolean(JsonNode? value){Need(value is JsonValue v && v.TryGetValue<bool>(out _));return value!.GetValue<bool>();}
    internal static string Token(JsonNode? value){Need(Match(value,"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}"));return Text(value);}
    internal static bool IsVersion(JsonNode? value)=>Match(value,VersionPattern);
    internal static BigInteger[] Version(JsonNode? value)
    {
        Need(IsVersion(value));string[] parts=Text(value).Split('.');
        if(parts.Any(p=>p.Length>4300))throw new AgentPackageVersionLimitException();
        return parts.Select(x=>BigInteger.Parse(x,CultureInfo.InvariantCulture)).ToArray();
    }
    internal static int CompareVersion(JsonNode? left,JsonNode? right){var a=Version(left);var b=Version(right);for(int i=0;i<3;i++){int c=a[i].CompareTo(b[i]);if(c!=0)return c;}return 0;}
    internal static string Path(string path)
    {
        Need(path.Length is >0 and <=220);
        foreach(string part in path.Split('/')) {
            Need(Regex.IsMatch(part,@"\A[a-zA-Z0-9_.-]+\z",RegexOptions.CultureInvariant|RegexOptions.NonBacktracking) && part is not ("." or "..") && !part.EndsWith('.') && part.Length<=120);
            Need(!Reserved.Contains(part.Split('.')[0]));
        }
        return path;
    }
}
