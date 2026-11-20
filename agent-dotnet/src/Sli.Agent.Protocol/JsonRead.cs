using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Agent.Protocol;

/// <summary>Strict readers: Python checks <c>type(x) is int</c>, so booleans and floats are not integers.</summary>
public static partial class JsonRead
{
    public static bool TryString(JsonNode? node, out string value)
    {
        value = string.Empty;
        if (node is JsonValue json && json.GetValueKind() == JsonValueKind.String)
        {
            value = json.GetValue<string>();
            return true;
        }
        return false;
    }

    public static bool TryInteger(JsonNode? node, out BigInteger value)
    {
        value = default;
        if (node is not JsonValue json || !TryIntegerText(json, out var text)) return false;
        value = BigInteger.Parse(text, System.Globalization.CultureInfo.InvariantCulture);
        return true;
    }

    /// <summary>
    /// The decimal text of an exact integer node, or false for strings, booleans and floating point (a CLR double 1.0 would
    /// print as "1", so only integer CLR types and raw JSON integer text count). <c>-0</c> is <c>0</c>, as in Python.
    /// </summary>
    public static bool TryIntegerText(JsonValue json, out string text)
    {
        text = string.Empty;
        if (json.GetValueKind() != JsonValueKind.Number) return false;
        string raw;
        if (json.TryGetValue(out JsonElement element)) raw = element.GetRawText();
        else if (json.TryGetValue(out long l)) raw = l.ToString(System.Globalization.CultureInfo.InvariantCulture);
        else if (json.TryGetValue(out int i)) raw = i.ToString(System.Globalization.CultureInfo.InvariantCulture);
        else if (json.TryGetValue(out ulong ul)) raw = ul.ToString(System.Globalization.CultureInfo.InvariantCulture);
        else if (json.TryGetValue(out uint ui)) raw = ui.ToString(System.Globalization.CultureInfo.InvariantCulture);
        else if (json.TryGetValue(out short s)) raw = s.ToString(System.Globalization.CultureInfo.InvariantCulture);
        else if (json.TryGetValue(out ushort us)) raw = us.ToString(System.Globalization.CultureInfo.InvariantCulture);
        else if (json.TryGetValue(out byte b)) raw = b.ToString(System.Globalization.CultureInfo.InvariantCulture);
        else return false;
        if (!IntegerPattern().IsMatch(raw)) return false;
        text = raw == "-0" ? "0" : raw;
        return true;
    }

    public static bool IsNull(JsonNode? node) => node is null || node is JsonValue value && value.GetValueKind() == JsonValueKind.Null;

    public static bool HasExactly(JsonObject obj, params string[] keys) =>
        obj.Count == keys.Length && keys.All(obj.ContainsKey);

    /// <summary>Python's <c>len(str)</c> counts code points, not UTF-16 units.</summary>
    public static int CodePoints(string text) => text.EnumerateRunes().Count();

    /// <summary>An exact integer as a JSON number, including values beyond 64 bits.</summary>
    public static JsonNode Integer(BigInteger value) => JsonNode.Parse(value.ToString(System.Globalization.CultureInfo.InvariantCulture))!;

    public static JsonNode Integer(long value) => JsonValue.Create(value);

    [GeneratedRegex(@"\A-?(0|[1-9][0-9]*)\z")]
    private static partial Regex IntegerPattern();
}
