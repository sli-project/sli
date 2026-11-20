using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Domains;

internal static class HomeTrends
{
    internal static bool Numeric(JsonNode? value, out double number)
    {
        number = 0;
        return value is JsonValue scalar && scalar.GetValueKind() == JsonValueKind.Number
            && (scalar.TryGetValue(out number) || double.TryParse(scalar.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
            && double.IsFinite(number) && number >= 0;
    }

    internal static JsonObject Compare(JsonObject current, JsonObject? previous, string meaning = "neutral")
    {
        var result = new JsonObject { ["state"] = "missing", ["message_code"] = "home.comparison.missing",
            ["absolute_change"] = null, ["percent_change"] = null, ["tone"] = "neutral" };
        if (previous is null || !Numeric(previous["value"], out var baseline) || !Numeric(current["value"], out var value))
            return result;

        var same = new[] { "scope", "time_zone", "unit", "definition_version", "coverage" }
            .All(key => current[key] is not null && JsonNode.DeepEquals(current[key], previous[key]));
        same = same && current["coverage"] is JsonObject coverage && coverage["complete"]?.GetValueKind() == JsonValueKind.True;
        try
        {
            var zone = TimeZoneInfo.FindSystemTimeZoneById(current["time_zone"]!.GetValue<string>());
            DateTimeOffset Bound(JsonObject measurement, string key)
            {
                var text = measurement["window"]![key]!.GetValue<string>();
                if (!(text.EndsWith('Z') || System.Text.RegularExpressions.Regex.IsMatch(text, @"[+-]\d\d:\d\d$")))
                    throw new FormatException("home_window_timezone_required");
                return DateTimeOffset.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.None).ToUniversalTime();
            }
            var start = Bound(current, "from_utc"); var end = Bound(current, "to_utc");
            var priorStart = Bound(previous, "from_utc"); var priorEnd = Bound(previous, "to_utc");
            var local = new[] { start, end, priorStart, priorEnd }.Select(at => TimeZoneInfo.ConvertTime(at, zone).DateTime).ToArray();
            // Complete local days can contain 23 or 25 hours across DST.
            var midnights = local.All(at => at.TimeOfDay == TimeSpan.Zero);
            var durationMatches = end - start == priorEnd - priorStart
                || midnights && local[1] - local[0] == local[3] - local[2];
            same = same && end > start && priorEnd > priorStart && durationMatches && priorEnd == start;
        }
        catch (Exception e) when (e is ArgumentException or FormatException or InvalidOperationException
            or NullReferenceException or TimeZoneNotFoundException or InvalidTimeZoneException)
        { same = false; }
        if (!same)
        {
            result["state"] = "incomparable"; result["message_code"] = "home.comparison.incomparable";
            return result;
        }
        var change = value - baseline;
        var good = meaning == "lower_is_better" ? change < 0 : change > 0;
        result["state"] = "comparable";
        result["message_code"] = baseline == 0 ? "home.comparison.absolute" : "home.comparison.percent";
        result["absolute_change"] = change;
        result["percent_change"] = baseline == 0 ? null : change / baseline * 100;
        result["tone"] = change == 0 || meaning == "neutral" ? "neutral" : good ? "success" : "danger";
        return result;
    }
}
