using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.WindowsEventLog;

// server/source_packs/adapters.py and scripts/collect/collect_windows_events.py.
public sealed record WindowsEventLogSelection(IReadOnlyList<int> EventIds, string StartTimeUtc, string EndTimeUtc)
{
    public static WindowsEventLogSelection? Parse(string? eventIdsJson, string? startTimeUtc, string? endTimeUtc)
    {
        // The legacy lower bound alone must not enable bounded admission.
        if (eventIdsJson is null && endTimeUtc is null) return null;
        if (string.IsNullOrWhiteSpace(eventIdsJson) || string.IsNullOrWhiteSpace(startTimeUtc) || string.IsNullOrWhiteSpace(endTimeUtc))
            throw new ArgumentException("bounded Event Log selection requires event IDs and explicit start/end UTC");
        int[] ids;
        try
        {
            using var doc = JsonDocument.Parse(eventIdsJson);
            var value = doc.RootElement;
            if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() is < 1 or > 64)
                throw new ArgumentException("bounded Event Log event ID allowlist must contain 1..64 integers");
            ids = value.EnumerateArray().Select(id => id.ValueKind == JsonValueKind.Number && id.TryGetInt32(out int n) && n is >= 1 and <= 65535
                ? n : throw new ArgumentException("bounded Event Log event IDs must be integers in range 1..65535")).ToArray();
        }
        catch (JsonException) { throw new ArgumentException("bounded Event Log event ID allowlist must be valid JSON"); }
        if (ids.Distinct().Count() != ids.Length) throw new ArgumentException("bounded Event Log event IDs must be unique");
        var start = Utc(startTimeUtc); var end = Utc(endTimeUtc);
        if (start >= end) throw new ArgumentException("bounded Event Log start/end UTC range must be increasing");
        return new(Array.AsReadOnly(ids), Iso8601.Format(start), Iso8601.Format(end));
    }

    internal static DateTimeOffset Utc(string? value) => Iso8601.TryParseUtc(value, out var parsed)
        ? Iso8601.Truncate(parsed) : throw new ArgumentException("bounded Event Log timestamps must be explicit UTC");

    public string BuildXPath(long? afterRecordId = null)
    {
        var terms = EventIds.Select(id => "EventID=" + id.ToString(CultureInfo.InvariantCulture)).ToArray();
        string ids = terms.Length == 1 ? terms[0] : "(" + string.Join(" or ", terms) + ")";
        string Stamp(string value) => Utc(value).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
        // As in the reference, a saved canary cursor takes precedence over the lower time bound.
        string bounds = afterRecordId is { } after ? "EventRecordID > " + after.ToString(CultureInfo.InvariantCulture)
            : $"TimeCreated[@SystemTime >= '{Stamp(StartTimeUtc)}' and @SystemTime <= '{Stamp(EndTimeUtc)}']";
        return $"*[System[{ids} and {bounds}]]";
    }

    public void ValidateRow(JsonObject row)
    {
        if (row["event_id"] is not JsonValue id || !id.TryGetValue<int>(out var number) || !EventIds.Contains(number))
            throw new InvalidOperationException("bounded_selection_event_id_mismatch");
        DateTimeOffset time;
        try { time = Utc(row["time_created"]?.GetValue<string>()); }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException)
        { throw new InvalidOperationException("bounded_selection_event_time_invalid"); }
        if (time < Utc(StartTimeUtc) || time > Utc(EndTimeUtc))
            throw new InvalidOperationException("bounded_selection_event_time_out_of_range");
    }
}
