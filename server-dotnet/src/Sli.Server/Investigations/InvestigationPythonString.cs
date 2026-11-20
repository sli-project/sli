using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using Sli.Server.Compatibility;

namespace Sli.Server.Investigations;

// The source explicitly calls str(payload.get("body") or ""). JSON display is
// observably different for booleans, nested strings and floating-point numbers.
internal static class InvestigationPythonString
{
    internal static string String(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString()!,
        JsonValueKind.Null => "None",
        JsonValueKind.True => "True",
        JsonValueKind.False => "False",
        JsonValueKind.Number => Number(value),
        JsonValueKind.Array => "[" + string.Join(", ", value.EnumerateArray().Select(Repr)) + "]",
        JsonValueKind.Object => "{" + string.Join(", ", PythonJson.Members(value).Select(p => Quote(p.Key) + ": " + Repr(p.Value))) + "}",
        _ => ""
    };
    private static string Repr(JsonElement value) => value.ValueKind == JsonValueKind.String ? Quote(PythonJson.StringValue(value)) : String(value);
    private static string Quote(string value)
    {
        char quote = value.Contains('\'') && !value.Contains('"') ? '"' : '\'';
        var result = new StringBuilder().Append(quote);
        for (int index = 0; index < value.Length;)
        {
            if (!Rune.TryGetRuneAt(value, index, out var rune))
            {
                result.Append("\\u").Append(((int)value[index++]).ToString("x4"));
                continue;
            }
            index += rune.Utf16SequenceLength;
            int c = rune.Value;
            if (c == quote || c == '\\') result.Append('\\').Append(rune.ToString());
            else if (c is '\t' or '\r' or '\n') result.Append(c == '\t' ? "\\t" : c == '\r' ? "\\r" : "\\n");
            else if (Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate
                or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
                || c != 32 && Rune.GetUnicodeCategory(rune) == UnicodeCategory.SpaceSeparator)
                result.Append(c <= 255 ? "\\x" + c.ToString("x2") : c <= 65535 ? "\\u" + c.ToString("x4") : "\\U" + c.ToString("x8"));
            else result.Append(rune.ToString());
        }
        return result.Append(quote).ToString();
    }
    private static string Number(JsonElement value)
    {
        string raw = value.GetRawText();
        if (raw.IndexOfAny(['.', 'e', 'E']) < 0) return BigInteger.Parse(raw, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);
        double number = value.GetDouble();
        if (double.IsInfinity(number)) return number < 0 ? "-inf" : "inf";
        if (double.IsNaN(number)) return "nan";
        string text = number.ToString("R", CultureInfo.InvariantCulture).ToLowerInvariant();
        // CPython repr uses scientific notation below 1e-4 or from 1e16.
        int exponent = text.IndexOf('e');
        if (exponent >= 0)
        {
            string mantissa = text[..exponent];
            int power = int.Parse(text[(exponent + 1)..], CultureInfo.InvariantCulture);
            if (power is >= -4 and < 16)
            {
                text = number.ToString("0.0##############################", CultureInfo.InvariantCulture);
                return text;
            }
            return mantissa + "e" + (power < 0 ? "-" : "+") + Math.Abs(power).ToString("D2", CultureInfo.InvariantCulture);
        }
        if (Math.Abs(number) >= 1e16)
        {
            string sign = text.StartsWith('-') ? "-" : "";
            string digits = text.TrimStart('-').Replace(".", "");
            int power = text.TrimStart('-').Split('.')[0].Length - 1;
            digits = digits.TrimEnd('0');
            return sign + digits[0] + (digits.Length > 1 ? "." + digits[1..] : "") + "e+" + power.ToString("D2", CultureInfo.InvariantCulture);
        }
        return text.Contains('.') ? text : text + ".0";
    }
}
