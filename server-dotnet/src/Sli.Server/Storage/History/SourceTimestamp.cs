using System.Globalization;
using System.Text.RegularExpressions;

namespace Sli.Server.Storage.History;

internal static partial class SourceTimestamp
{
    // Python fromisoformat truncates beyond six digits. StorageV2 additionally rounds
    // long fractions half-even only when an explicit ±HH:MM offset is present.
    [GeneratedRegex(@"^(?<base>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:\.(?<fraction>\d+))?(?<zone>Z|[+-]\d\d(?::?\d\d(?::?\d\d(?:[.,]\d+)?)?)?)?$")]
    private static partial Regex Iso();
    internal static DateTimeOffset Parse(string text, bool storageV2)
    {
        var match=Iso().Match(text.Trim());
        if (!match.Success) throw new InvalidDataException("event_timestamp_invalid");
        string fraction=match.Groups["fraction"].Value;
        string zone=match.Groups["zone"].Value;
        string micros=(fraction+"000000")[..6];
        if (!DateTime.TryParseExact(match.Groups["base"].Value+"."+micros,
            ["yyyy-MM-dd'T'HH:mm:ss.ffffff","yyyy-MM-dd HH:mm:ss.ffffff"], CultureInfo.InvariantCulture,
            DateTimeStyles.None,out var date)) throw new InvalidDataException("event_timestamp_invalid");
        bool round=storageV2 && (zone == "Z" || Regex.IsMatch(zone,@"^[+-]\d\d:\d\d$")) && fraction.Length > 6 &&
            (fraction[6] > '5' || (fraction[6] == '5' && (fraction.AsSpan(7).IndexOfAnyExcept('0') >= 0 || ((micros[5]-'0') & 1) != 0)));
        try
        {
            if (round) date=date.AddTicks(10);
            if (zone.Length > 1)
            {
                string offset=zone[1..].Replace(":","").Replace(',', '.');
                var parts=offset.Split('.'); string digits=parts[0];
                int hours=int.Parse(digits.AsSpan(0,2),CultureInfo.InvariantCulture);
                int minutes=digits.Length >= 4 ? int.Parse(digits.AsSpan(2,2),CultureInfo.InvariantCulture) : 0;
                int seconds=digits.Length >= 6 ? int.Parse(digits.AsSpan(4,2),CultureInfo.InvariantCulture) : 0;
                if (hours > 23 || minutes > 59 || seconds > 59) throw new InvalidDataException("event_timestamp_invalid");
                long micro=parts.Length == 2 ? long.Parse((parts[1]+"000000")[..6],CultureInfo.InvariantCulture) : 0;
                long ticks=((hours*3600L+minutes*60L+seconds)*1_000_000L+micro)*10;
                date=date.AddTicks(zone[0]=='-' ? ticks : -ticks);
            }
            return new DateTimeOffset(DateTime.SpecifyKind(date,DateTimeKind.Utc));
        }
        catch (ArgumentOutOfRangeException ex) { throw new InvalidDataException("event_timestamp_invalid",ex); }
    }
}
