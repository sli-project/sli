using System.Globalization;
using System.Text.RegularExpressions;

namespace Sli.Agent.Protocol.Compatibility;

/// <summary>Python 3.14 datetime.fromisoformat for JSON strings, with microsecond precision.</summary>
public readonly struct PythonIsoDateTime
{
    private static readonly Regex Pattern = new(
        @"\A(?<year>[0-9]{4})(?:(?:-(?<month>[0-9]{2})-(?<day>[0-9]{2}))|(?<month>[0-9]{2})(?<day>[0-9]{2})|(?:-W(?<week>[0-9]{2})(?:-(?<weekday>[1-7]))?)|(?:W(?<week>[0-9]{2})(?<weekday>[1-7])?))(?:(?:[\uD800-\uDBFF][\uDC00-\uDFFF]|[\s\S])(?<hour>[0-9]{2})(?:(?<tc>:?)(?<minute>[0-9]{2})(?:\k<tc>(?<second>[0-9]{2})(?:[.,](?<fraction>[0-9]+))?)?)?(?<zone>Z|(?<sign>[+-])(?<oh>[0-9]{2})(?:(?<oc>:?)(?<om>[0-9]{2})(?:\k<oc>(?<os>[0-9]{2})(?:[.,](?<of>[0-9]+))?)?)?)?)?\z",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private PythonIsoDateTime(DateTime wallTime,TimeSpan? offset) { WallTime=wallTime; Offset=offset; }
    public DateTime WallTime { get; }
    public TimeSpan? Offset { get; }
    public bool IsAware => Offset.HasValue;

    public bool TryToUtc(out DateTimeOffset utc)
    {
        utc=default;
        if(Offset is null) return false;
        long ticks=WallTime.Ticks-Offset.Value.Ticks;
        if(ticks<DateTime.MinValue.Ticks || ticks>DateTime.MaxValue.Ticks) return false;
        utc=new DateTimeOffset(ticks,TimeSpan.Zero); return true;
    }
    /// <summary>Source envelope timestamp: replace Z, then require an aware zero-offset value.</summary>
    public static bool TryParseUtc(string? text,out DateTimeOffset utc)
    {
        utc=default;
        return text is not null && TryParse(text.Replace("Z","+00:00",StringComparison.Ordinal),out var parsed)
            && parsed.Offset==TimeSpan.Zero && parsed.TryToUtc(out utc);
    }
    public static bool TryParse(string? text,out PythonIsoDateTime result)
    {
        result=default; if(text is null) return false;
        try
        {
            var m=Pattern.Match(text); if(!m.Success) return false;
            int Number(string name)=>m.Groups[name].Success?int.Parse(m.Groups[name].Value,CultureInfo.InvariantCulture):0;
            static long Fraction(string s) { s=s.Length>6?s[..6]:s.PadRight(6,'0'); return long.Parse(s,CultureInfo.InvariantCulture)*10; }
            int year=Number("year"); DateTime day;
            if(m.Groups["week"].Success)
            {
                int week=Number("week"), weekday=m.Groups["weekday"].Success?Number("weekday"):1;
                if(year<1||week<1||week>ISOWeek.GetWeeksInYear(year)) return false;
                day=ISOWeek.ToDateTime(year,week,weekday==7?DayOfWeek.Sunday:(DayOfWeek)weekday);
            }
            else day=new DateTime(year,Number("month"),Number("day"));
            int hour=Number("hour"),minute=Number("minute"),second=Number("second"); long fraction=Fraction(m.Groups["fraction"].Value);
            if(hour>24||minute>59||second>59||hour==24&&(minute!=0||second!=0||fraction!=0)) return false;
            var wall=DateTime.SpecifyKind(day.AddHours(hour).AddMinutes(minute).AddSeconds(second).AddTicks(fraction),DateTimeKind.Unspecified);
            TimeSpan? offset=null;
            if(m.Groups["zone"].Success)
            {
                long seconds=Number("oh")*3600L+Number("om")*60L+Number("os");
                // CPython chooses UTC before considering the fractional portion when whole offset seconds are zero.
                long ticks=seconds==0?0:seconds*TimeSpan.TicksPerSecond+Fraction(m.Groups["of"].Value);
                if(ticks>=TimeSpan.TicksPerDay) return false;
                if(m.Groups["sign"].Value=="-") ticks=-ticks;
                offset=TimeSpan.FromTicks(ticks);
            }
            result=new PythonIsoDateTime(wall,offset); return true;
        }
        catch(Exception error) when(error is ArgumentException or FormatException or OverflowException or RegexMatchTimeoutException) { return false; }
    }
}
