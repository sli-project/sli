using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Gpo.SnapshotModel;

// Python str/repr only for JSON values exposed by the GPO report.
internal static class GpoPythonText
{
    public static string Str(JsonNode? node) => node is null ? "None" : Str(JsonSerializer.SerializeToElement(node));
    public static string Str(JsonElement value) => value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : Repr(value);
    private static string Repr(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Null or JsonValueKind.Undefined => "None",
        JsonValueKind.True => "True", JsonValueKind.False => "False",
        JsonValueKind.String => Quote(value.GetString() ?? ""),
        JsonValueKind.Number => CanonicalJson.Serialize(JsonNode.Parse(value.GetRawText())),
        JsonValueKind.Array => "[" + string.Join(", ", value.EnumerateArray().Select(Repr)) + "]",
        JsonValueKind.Object => "{" + string.Join(", ", value.EnumerateObject().Select(x => Quote(x.Name) + ": " + Repr(x.Value))) + "}",
        _ => throw new InvalidOperationException("unsupported_gpo_value")
    };
    private static string Quote(string value)
    {
        char quote = value.Contains('\'') && !value.Contains('"') ? '"' : '\'';
        var output = new StringBuilder().Append(quote);
        foreach (var rune in value.EnumerateRunes())
        {
            int c = rune.Value;
            if (c == quote || c == '\\') { output.Append('\\').Append((char)c); continue; }
            if (c == '\n') { output.Append("\\n"); continue; }
            if (c == '\r') { output.Append("\\r"); continue; }
            if (c == '\t') { output.Append("\\t"); continue; }
            var category = Rune.GetUnicodeCategory(rune);
            if (c != 0x20 && category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned or UnicodeCategory.SpaceSeparator or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
            {
                output.Append(c <= 0xff ? "\\x" : c <= 0xffff ? "\\u" : "\\U");
                output.Append(c.ToString(c <= 0xff ? "x2" : c <= 0xffff ? "x4" : "x8", CultureInfo.InvariantCulture));
            }
            else output.Append(rune.ToString());
        }
        return output.Append(quote).ToString();
    }
}

