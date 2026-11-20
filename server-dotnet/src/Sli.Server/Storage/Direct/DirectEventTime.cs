using System.Globalization;
using System.Numerics;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Access.Administration;

namespace Sli.Server.Storage.Direct;

// storage_v2_models.parse_utc_timestamp: Python microsecond rounding for
// seven-or-more fractional digits only with a final +/-HH:MM offset.
internal static class DirectEventTime
{
    private static readonly Regex Rounded = new(@"\.(?<fraction>[0-9]{7,})[+-][0-9]{2}:[0-9]{2}\z",RegexOptions.CultureInvariant,TimeSpan.FromSeconds(1));
    internal static DateTime Utc(string text)
    {
        text=AssignmentValidation.Strip(text);
        if(text.EndsWith('Z')) text=text[..^1]+"+00:00";
        if(!PythonIsoDateTime.TryParse(text,out var parsed)) throw new InvalidDataException("storage_v2_event_profile_pending");
        DateTimeOffset utc;
        if(parsed.IsAware) {
            if(!parsed.TryToUtc(out utc)) throw new InvalidDataException("storage_v2_event_profile_pending");
        } else utc=new DateTimeOffset(parsed.WallTime,TimeSpan.Zero);
        var match=Rounded.Match(text);
        if(match.Success) {
            string fraction=match.Groups["fraction"].Value;
            bool round=RoundsUpFromTruncatedMicros(fraction);
            if(round) try { utc=utc.AddTicks(10); } catch(ArgumentOutOfRangeException) { throw new InvalidDataException("storage_v2_event_profile_pending"); }
        }
        return utc.UtcDateTime;
    }
    // Decimal(fraction) * 1_000_000 is rounded to 28 significant digits
    // by the source's default Decimal context before integral HALF_EVEN.
    private static bool RoundsUpFromTruncatedMicros(string fraction)
    {
        int first=0;while(first<fraction.Length && fraction[first]=='0')first++;
        if(first>=7 || first==fraction.Length)return false;
        int count=Math.Min(28,fraction.Length-first);
        BigInteger significant=BigInteger.Parse(fraction.AsSpan(first,count),NumberStyles.None,CultureInfo.InvariantCulture);
        int discarded=first+count;
        if(discarded<fraction.Length) {
            char next=fraction[discarded];
            bool later=discarded+1<fraction.Length && fraction.AsSpan(discarded+1).IndexOfAnyExcept('0')>=0;
            if(next>'5' || next=='5' && (later || !significant.IsEven))significant++;
        }
        int scale=first+count-6;
        BigInteger divisor=BigInteger.Pow(10,scale);
        BigInteger integer=BigInteger.DivRem(significant,divisor,out var remainder);
        int comparison=(remainder*2).CompareTo(divisor);
        if(comparison>0 || comparison==0 && !integer.IsEven)integer++;
        return integer>int.Parse(fraction.AsSpan(0,6),NumberStyles.None,CultureInfo.InvariantCulture);
    }
    internal static string IsoUtc(string text)
    {
        DateTime utc=Utc(text);long micros=utc.Ticks%TimeSpan.TicksPerSecond/10;
        return utc.ToString("yyyy-MM-dd'T'HH:mm:ss",CultureInfo.InvariantCulture)+(micros==0?"":"."+micros.ToString("D6",CultureInfo.InvariantCulture))+"+00:00";
    }
}
