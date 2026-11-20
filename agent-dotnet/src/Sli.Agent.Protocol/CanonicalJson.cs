using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Agent.Protocol;

/// <summary>
/// The byte-exact twin of Python's
/// <c>json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)</c>
/// (<c>sli_agent/envelope.py: canonical</c>). Hashes and signatures use only this form.
/// Finite floating-point values use the Python binary64 representation; non-finite values are rejected.
/// </summary>
public static class CanonicalJson
{
    public static string Serialize(JsonNode? node) => Serialize(node, ensureAscii: true);

    public static string Serialize(JsonNode? node, bool ensureAscii) => Format(node, ensureAscii, sortKeys: true, spaced: false);

    internal static string Format(JsonNode? node, bool ensureAscii, bool sortKeys, bool spaced)
    {
        var builder = new StringBuilder();
        Write(builder, node, ensureAscii, sortKeys, spaced);
        return builder.ToString();
    }

    /// <summary>The text is pure ASCII, so characters and bytes coincide.</summary>
    public static byte[] ToBytes(JsonNode? node) => Encoding.ASCII.GetBytes(Serialize(node));

    public static int Length(JsonNode? node) => Serialize(node).Length;

    private static void Write(StringBuilder builder, JsonNode? node, bool ensureAscii, bool sortKeys, bool spaced)
    {
        switch (node)
        {
            case null:
                builder.Append("null");
                break;
            case JsonObject obj:
                WriteObject(builder, obj, ensureAscii, sortKeys, spaced);
                break;
            case JsonArray array:
                builder.Append('[');
                for (var i = 0; i < array.Count; i++)
                {
                    if (i > 0) builder.Append(spaced ? ", " : ",");
                    Write(builder, array[i], ensureAscii, sortKeys, spaced);
                }
                builder.Append(']');
                break;
            case JsonValue value:
                WriteValue(builder, value, ensureAscii);
                break;
            default:
                throw new ProtocolException(ErrorCodes.PacketInvalid);
        }
    }

    private static void WriteObject(StringBuilder builder, JsonObject obj, bool ensureAscii, bool sortKeys, bool spaced)
    {
        var keys = obj.Select(pair => pair.Key).ToList();
        if (sortKeys) keys.Sort(CodePointComparer.Instance);
        builder.Append('{');
        for (var i = 0; i < keys.Count; i++)
        {
            if (i > 0) builder.Append(spaced ? ", " : ",");
            WriteString(builder, keys[i], ensureAscii);
            builder.Append(spaced ? ": " : ":");
            Write(builder, obj[keys[i]], ensureAscii, sortKeys, spaced);
        }
        builder.Append('}');
    }

    private static void WriteValue(StringBuilder builder, JsonValue value, bool ensureAscii)
    {
        switch (value.GetValueKind())
        {
            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
                builder.Append("null");
                break;
            case JsonValueKind.True:
                builder.Append("true");
                break;
            case JsonValueKind.False:
                builder.Append("false");
                break;
            case JsonValueKind.String:
                WriteString(builder, value.GetValue<string>(), ensureAscii);
                break;
            case JsonValueKind.Number:
                builder.Append(NumberText(value));
                break;
            default:
                throw new ProtocolException(ErrorCodes.PacketInvalid);
        }
    }

    private static string NumberText(JsonValue value)
    {
        if (JsonRead.TryIntegerText(value, out var integer)) return integer;
        string raw;
        try { raw = value.TryGetValue<JsonElement>(out var element) ? element.GetRawText() : value.ToJsonString(); }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or JsonException)
        { throw new ProtocolException(ErrorCodes.PacketInvalid); }
        if (!double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var number) || !double.IsFinite(number))
            throw new ProtocolException(ErrorCodes.PacketInvalid);
        return PythonFloat(number);
    }

    private static string PythonFloat(double value)
    {
        if (value == 0) return double.IsNegative(value) ? "-0.0" : "0.0";
        var text = value.ToString("R", CultureInfo.InvariantCulture);
        bool negative = text[0] == '-';
        if (negative) text = text[1..];
        int e = text.IndexOfAny(['E', 'e']);
        var mantissa = e < 0 ? text : text[..e];
        int exponent = e < 0 ? 0 : int.Parse(text[(e + 1)..], CultureInfo.InvariantCulture);
        int point = mantissa.IndexOf('.');
        int decimalPosition = (point < 0 ? mantissa.Length : point) + exponent;
        var digits = mantissa.Replace(".", "", StringComparison.Ordinal);
        int leading = 0;
        while (leading < digits.Length - 1 && digits[leading] == '0') leading++;
        digits = digits[leading..].TrimEnd('0');
        decimalPosition -= leading;
        int power = decimalPosition - 1;
        string result;
        if (power is >= -4 and < 16)
        {
            if (decimalPosition <= 0) result = "0." + new string('0', -decimalPosition) + digits;
            else if (decimalPosition >= digits.Length) result = digits + new string('0', decimalPosition - digits.Length) + ".0";
            else result = digits[..decimalPosition] + "." + digits[decimalPosition..];
        }
        else
        {
            string coefficient = digits.Length == 1 ? digits : digits[..1] + "." + digits[1..];
            result = coefficient + "e" + (power < 0 ? "-" : "+") + Math.Abs(power).ToString("D2", CultureInfo.InvariantCulture);
        }
        return negative ? "-" + result : result;
    }

    /// <summary>Python escapes everything outside U+0020..U+007E, using UTF-16 units (surrogate pairs) in lower-case hex.</summary>
    private static void WriteString(StringBuilder builder, string text, bool ensureAscii)
    {
        builder.Append('"');
        foreach (var c in text)
        {
            switch (c)
            {
                case '"': builder.Append("\\\""); break;
                case '\\': builder.Append("\\\\"); break;
                case '\n': builder.Append("\\n"); break;
                case '\r': builder.Append("\\r"); break;
                case '\t': builder.Append("\\t"); break;
                case '\b': builder.Append("\\b"); break;
                case '\f': builder.Append("\\f"); break;
                default:
                    if (c < ' ' || ensureAscii && c > '~') builder.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else builder.Append(c);
                    break;
            }
        }
        builder.Append('"');
    }
}

/// <summary>Orders strings by Unicode code point, as Python does (UTF-16 order differs above U+FFFF).</summary>
internal sealed class CodePointComparer : IComparer<string>
{
    public static readonly CodePointComparer Instance = new();

    public int Compare(string? x, string? y)
    {
        x ??= string.Empty;
        y ??= string.Empty;
        int i = 0, j = 0;
        while (i < x.Length && j < y.Length)
        {
            var a = CodePointAt(x, ref i);
            var b = CodePointAt(y, ref j);
            if (a != b) return a < b ? -1 : 1;
        }
        if (i < x.Length) return 1;
        return j < y.Length ? -1 : 0;
    }

    private static int CodePointAt(string text, ref int index)
    {
        var c = text[index];
        if (char.IsHighSurrogate(c) && index + 1 < text.Length && char.IsLowSurrogate(text[index + 1]))
        {
            var point = char.ConvertToUtf32(c, text[index + 1]);
            index += 2;
            return point;
        }
        index++;
        return c;
    }
}
