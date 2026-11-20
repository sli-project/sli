using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Server.Agents.Registry;
using Sli.Server.Compatibility;

namespace Sli.Server.Agents.Radius;

internal sealed record RadiusPreflightEvent(int EventId, DateTimeOffset? EventTimeUtc,
    string SessionId, string NasIdentity, string SubjectSid)
{
    public override string ToString() => nameof(RadiusPreflightEvent);
}

internal sealed record RadiusPreflightAccounting(string Lifecycle, string SessionId, string NasIdentity,
    DateTimeOffset? RecordTimeUtc, DateTimeOffset? EventTimeUtc)
{
    public override string ToString() => nameof(RadiusPreflightAccounting);
}

// Pure analysis from stage9_radius_time_aligned_preflight.py. No source contact,
// persistence, runtime limits, or authorization to run the retired operator plan.
internal static class RadiusTimeAlignedPreflight
{
    public static (IReadOnlyList<RadiusPreflightAccounting> Records, Dictionary<string, int> Counts)
        ParseAccountingSample(IEnumerable<string> lines, int utcOffsetMinutes)
    {
        var records = new List<RadiusPreflightAccounting>();
        var counts = new Dictionary<string, int>
        {
            ["sampled_rows"] = 0, ["database_compatible_rows"] = 0, ["lifecycle_rows"] = 0,
            ["local_time_parsed_rows"] = 0, ["event_timestamp_parsed_rows"] = 0,
        };
        foreach (string raw in lines)
        {
            string line = PythonText.Strip(raw);
            if (line.Length == 0) continue;
            counts["sampled_rows"]++;
            var fields = CsvFields(line);
            if (fields is null || fields.Count != 66) continue;
            string Value(int index) => PythonText.Strip(fields[index]);
            if (!new[] { "ias", "nps", "ras", "routing and remote access service" }.Contains(UnicodeCaseFold.Fold(Value(1)))
                || Value(4).Length == 0 || !Value(4).EnumerateRunes().All(Rune.IsDigit)
                || !PythonInt.TryParse(Value(4), out var packet) || packet < 0 || packet > 255) continue;
            counts["database_compatible_rows"]++;
            if (Value(4) != "4") continue;
            string? lifecycle = Value(31) switch { "1" => "start", "2" => "stop", "3" => "interim_update", _ => null };
            if (lifecycle is null) continue;
            counts["lifecycle_rows"]++;
            DateTimeOffset? localTime = null;
            if (DateTime.TryParseExact(Value(2) + " " + Value(3), ["M/d/yyyy H:m:s", "MM/dd/yyyy HH:mm:ss"],
                CultureInfo.InvariantCulture, DateTimeStyles.None, out var local))
                localTime = new DateTimeOffset(DateTime.SpecifyKind(local.AddMinutes(-utcOffsetMinutes), DateTimeKind.Utc));
            DateTimeOffset? eventTime = null;
            if (Regex.IsMatch(Value(17), @"\A-?\d+\z") && long.TryParse(Value(17), CultureInfo.InvariantCulture, out long epoch))
            {
                try { eventTime = DateTimeOffset.FromUnixTimeSeconds(epoch); }
                catch (ArgumentOutOfRangeException) { }
            }
            if (localTime is not null) counts["local_time_parsed_rows"]++;
            if (eventTime is not null) counts["event_timestamp_parsed_rows"]++;
            records.Add(new(lifecycle, Value(35), Value(11).Length > 0 ? Value(11) : Value(12), localTime, eventTime));
        }
        return (records, counts);
    }

    // Same strict, single-row CSV state machine as RadiusAccountingRecord, without
    // its ingress policy: preflight counts unsupported lifecycle rows then skips them.
    private static List<string>? CsvFields(string line)
    {
        var fields = new List<string>();
        var value = new StringBuilder();
        bool quoted = false, closed = false, first = true;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (quoted)
            {
                if (c != '"') value.Append(c);
                else if (i + 1 < line.Length && line[i + 1] == '"') { value.Append('"'); i++; }
                else { quoted = false; closed = true; }
            }
            else if (c == ',') { fields.Add(value.ToString()); value.Clear(); closed = false; first = true; }
            else if (closed) return null;
            else if (c == '"' && first) { quoted = true; first = false; }
            else if (c is '\r' or '\n') return null;
            else { value.Append(c); first = false; }
        }
        if (quoted) return null;
        fields.Add(value.ToString());
        return fields;
    }

    public static string BuildTimeAlignedXPath(DateTimeOffset startUtc, DateTimeOffset endUtc)
    {
        if (startUtc >= endUtc) throw new ArgumentException("invalid_alignment_window");
        static string Format(DateTimeOffset time) => time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        return "*[System[(EventID=6272 or EventID=6273) and TimeCreated[@SystemTime >= '"
            + Format(startUtc) + "' and @SystemTime <= '" + Format(endUtc) + "']]]";
    }

    private static string DeltaBucket(double seconds) => Math.Abs(seconds) switch
    {
        <= 60 => "absolute_le_60_seconds", <= 300 => "absolute_le_5_minutes",
        <= 900 => "absolute_le_15_minutes", _ => "absolute_gt_15_minutes",
    };

    public static JsonObject AggregateObservations(IEnumerable<RadiusPreflightEvent> events,
        IEnumerable<RadiusPreflightAccounting> accounting, IReadOnlyDictionary<string, int> accountingCounts,
        int alignmentSpanSeconds, IReadOnlyDictionary<string, bool> caps)
    {
        var eventRows = events.ToArray();
        var accountingRows = accounting.ToArray();
        var byJoint = eventRows.Where(e => e.SessionId.Length > 0 && e.NasIdentity.Length > 0)
            .ToLookup(e => (e.SessionId, UnicodeCaseFold.Fold(e.NasIdentity)));
        int oneToOne = 0, ambiguous = 0, unmatched = 0, exactSid = 0;
        var lifecycle = new JsonObject { ["start"] = 0, ["interim_update"] = 0, ["stop"] = 0 };
        var preferred = new JsonObject();
        var fallback = new JsonObject();
        static void Increment(JsonObject counts, string name) => counts[name] = (counts[name]?.GetValue<int>() ?? 0) + 1;
        foreach (var record in accountingRows)
        {
            if (lifecycle.ContainsKey(record.Lifecycle)) Increment(lifecycle, record.Lifecycle);
            var matches = byJoint[(record.SessionId, UnicodeCaseFold.Fold(record.NasIdentity))].ToArray();
            if (matches.Length == 1)
            {
                oneToOne++;
                var match = matches[0];
                if (Regex.IsMatch(match.SubjectSid, @"\AS-\d(?:-\d+)+\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)) exactSid++;
                if (match.EventTimeUtc is { } eventTime)
                {
                    if (record.EventTimeUtc is { } epoch) Increment(preferred, DeltaBucket((epoch - eventTime).TotalSeconds));
                    if (record.RecordTimeUtc is { } local) Increment(fallback, DeltaBucket((local - eventTime).TotalSeconds));
                }
            }
            else if (matches.Length > 1) ambiguous++;
            else unmatched++;
        }
        bool capped = caps.TryGetValue("nps_event_cap_reached", out bool reached) && reached;
        string correlation = accountingRows.Length > 0 && oneToOne == accountingRows.Length && ambiguous == 0 && unmatched == 0 && !capped
            ? "proven_on_time_aligned_bounded_sample" : "correlation_not_proven";
        static int Near(JsonObject buckets) => buckets.Where(x => x.Key != "absolute_gt_15_minutes").Sum(x => x.Value!.GetValue<int>());
        string timestamp = oneToOne > 0 && Near(preferred) == oneToOne ? "event_timestamp_proven"
            : oneToOne > 0 && Near(fallback) == oneToOne ? "record_local_time_plus_timezone_proven" : "timestamp_not_proven";
        var sampleCounts = new JsonObject();
        foreach (var (key, value) in accountingCounts) sampleCounts[key] = value;
        sampleCounts["lifecycle"] = lifecycle;
        var eventCounts = new JsonObject();
        foreach (var row in eventRows) Increment(eventCounts, row.EventId.ToString(CultureInfo.InvariantCulture));
        var flags = new JsonObject();
        foreach (var (key, value) in caps) flags[key] = value;
        return new JsonObject
        {
            ["accounting_sample_counts"] = sampleCounts,
            ["alignment_window_quality"] = new JsonObject
            {
                ["basis"] = "accounting_record_date_time_plus_explicit_source_utc_offset", ["span_seconds"] = alignmentSpanSeconds,
            },
            ["nps_event_counts_by_id"] = eventCounts,
            ["cap_and_truncation_flags"] = flags,
            ["join_quality_counts"] = new JsonObject
            {
                ["accounting_lifecycle_records"] = accountingRows.Length, ["one_to_one_records"] = oneToOne,
                ["ambiguous_records"] = ambiguous, ["unmatched_records"] = unmatched,
            },
            ["exact_principal_bridge_counts"] = new JsonObject
            {
                ["exact_subject_sid_records"] = exactSid, ["missing_or_invalid_subject_sid_records"] = oneToOne - exactSid,
            },
            ["joined_time_delta_bucket_counts"] = new JsonObject { ["event_timestamp"] = preferred, ["record_local_time"] = fallback },
            ["classification"] = new JsonObject { ["correlation"] = correlation, ["timestamp"] = timestamp },
        };
    }
}
