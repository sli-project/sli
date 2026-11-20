using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;

namespace Sli.Agent.Core;

/// <summary>
/// Python's <c>int(str)</c>, which the server applies again to every event it re-parses: surrounding whitespace,
/// one sign, decimal digits of any script, single underscores between digits.
/// </summary>
public static partial class PythonInt
{
    public static bool TryParse(string? text, out BigInteger value)
    {
        value = default;
        if (text is null) return false;
        var trimmed = text.Trim();
        var negative = false;
        if (trimmed.StartsWith('+') || trimmed.StartsWith('-'))
        {
            negative = trimmed[0] == '-';
            trimmed = trimmed[1..];
        }
        if (!DigitsPattern().IsMatch(trimmed)) return false;
        BigInteger result = 0;
        foreach (var rune in trimmed.EnumerateRunes())
        {
            if (rune.Value == '_') continue;
            var digit = CharUnicodeInfo.GetDecimalDigitValue(rune.ToString(), 0);
            if (digit < 0) return false;
            result = result * 10 + digit;
        }
        value = negative ? -result : result;
        return true;
    }

    [GeneratedRegex(@"\A\p{Nd}+(_\p{Nd}+)*\z")]
    private static partial Regex DigitsPattern();
}
