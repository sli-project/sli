using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text;
using System.Text.RegularExpressions;

namespace Sli.Server.Compatibility;

// JsonDocument enforces the original body limits; eager conversion reproduces
// Python json.loads last decoded member semantics recursively.
internal static class PythonJson
{
    // Tokens have already passed JsonDocument/Utf8JsonReader validation. JSON's
    // escape alphabet is a subset of Regex.Unescape's; unlike GetString this
    // preserves lone UTF-16 surrogate code units until Python repr escapes them.
    internal static string StringToken(string escaped) => Regex.Unescape(escaped);
    internal static string StringValue(JsonElement value) => StringToken(value.GetRawText()[1..^1]);

    internal static IReadOnlyDictionary<string, JsonElement> Members(JsonElement value)
    {
        var result = new OrderedDictionary<string, JsonElement>(StringComparer.Ordinal);
        var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(value.GetRawText()), new JsonReaderOptions { MaxDepth = 1000 });
        reader.Read(); // object start
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string name = StringToken(Encoding.UTF8.GetString(reader.ValueSpan));
            reader.Read();
            using var document = JsonDocument.ParseValue(ref reader);
            // Updating a member retains its original insertion position.
            result[name] = document.RootElement.Clone();
        }
        return result;
    }

    internal static JsonNode? FromElement(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Object) {
            var result=new JsonObject();
            foreach(var member in value.EnumerateObject())result[member.Name]=FromElement(member.Value);
            return result;
        }
        if(value.ValueKind==JsonValueKind.Array) {
            var result=new JsonArray();
            foreach(var item in value.EnumerateArray())result.Add(FromElement(item));
            return result;
        }
        return value.ValueKind==JsonValueKind.Null?null:JsonValue.Create(value.Clone());
    }
}
