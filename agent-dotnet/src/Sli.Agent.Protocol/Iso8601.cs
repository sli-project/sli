using System.Globalization;
using System.Text.RegularExpressions;

namespace Sli.Agent.Protocol;

/// <summary>UTC timestamps as Python writes and reads them (<c>datetime.isoformat()</c> / <c>fromisoformat</c>).</summary>
public static partial class Iso8601
{
    private const long TicksPerMicrosecond = 10;

    /// <summary><c>2026-10-07T12:00:00+00:00</c>, with six fractional digits only when the microseconds are not zero.</summary>
    public static string Format(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        var microseconds = utc.Ticks % TimeSpan.TicksPerSecond / TicksPerMicrosecond;
        var text = utc.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture);
        return microseconds == 0
            ? text + "+00:00"
            : text + "." + microseconds.ToString("D6", CultureInfo.InvariantCulture) + "+00:00";
    }

    /// <summary>Python's clocks have microsecond resolution; keep the same resolution on the wire.</summary>
    public static DateTimeOffset Truncate(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(utc.Ticks - utc.Ticks % TicksPerMicrosecond, TimeSpan.Zero);
    }

    public static DateTimeOffset ParseUtc(string? text) =>
        TryParseUtc(text, out var result) ? result : throw new ProtocolException(ErrorCodes.PacketInvalid);

    /// <summary>Accepts only an instant with a zero offset (<c>Z</c>, <c>+00:00</c>); anything else is not a UTC timestamp.</summary>
    public static bool TryParseUtc(string? text, out DateTimeOffset result)
    {
        result = default;
        if (text is null) return false;
        var match = Pattern().Match(text);
        if (!match.Success) return false;
        try
        {
            var fraction = match.Groups["f"].Success ? match.Groups["f"].Value.PadRight(7, '0')[..7] : "0";
            var ticks = long.Parse(fraction, CultureInfo.InvariantCulture);
            var seconds = new DateTime(
                int.Parse(match.Groups["y"].Value, CultureInfo.InvariantCulture), int.Parse(match.Groups["mo"].Value, CultureInfo.InvariantCulture),
                int.Parse(match.Groups["d"].Value, CultureInfo.InvariantCulture), int.Parse(match.Groups["h"].Value, CultureInfo.InvariantCulture),
                int.Parse(match.Groups["mi"].Value, CultureInfo.InvariantCulture), int.Parse(match.Groups["s"].Value, CultureInfo.InvariantCulture),
                DateTimeKind.Utc);
            result = new DateTimeOffset(seconds.AddTicks(ticks), TimeSpan.Zero);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    [GeneratedRegex(@"\A(?<y>\d{4})-(?<mo>\d{2})-(?<d>\d{2})[T ](?<h>\d{2}):(?<mi>\d{2}):(?<s>\d{2})(?:\.(?<f>\d{1,9}))?(?:Z|[+-]00(?::?00)?)\z",
        RegexOptions.CultureInvariant)]
    private static partial Regex Pattern();
}
