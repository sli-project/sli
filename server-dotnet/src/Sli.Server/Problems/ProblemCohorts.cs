using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Problems;

internal static class ProblemCohorts
{
    // Home callers retain their signature; the source is always the problem's event copies.
    internal static string PasswordFacts(string alias, bool shortEvents = true, string? eventSource = null)
    {
        string sql = Sql("password-presentation").Replace("\r\n", "\n");
        if (eventSource is not null) sql = sql.Replace("finding_event_details337", eventSource, StringComparison.Ordinal);
        return $"case when {alias}.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray') then (" +
            sql.Replace("__FINDING__", alias + ".id").Replace("__RULE__", alias + ".rule_code") + ") end";
    }
    internal static string Queue(string population, string where, string status, string accepted) => Sql("queue-groups")
        .Replace("__POPULATION__", population).Replace("__WHERE__", where).Replace("__STATUS__", status).Replace("__ACCEPTED__", accepted).Replace("__COHORT__", Sql("queue-cohort"));
    internal static string Sql(string name) {
        using var stream = typeof(ProblemCohorts).Assembly.GetManifestResourceStream($"Sli.Server.Problems.{name}.sql")!;
        using var reader = new StreamReader(stream);
        string sql = reader.ReadToEnd().Replace("__RETAINED_COHORT__", name == "legacy-queue-cohort" ? Sql("cohort") : "");
        return sql;
    }
    internal static JsonArray Parse(string raw) {
        try {
            if (raw.Length > 4096 || JsonNode.Parse(raw) is not JsonArray a) throw new FormatException();
            bool Text(JsonNode? n, int max = 2048) => n is JsonValue v && v.TryGetValue<string>(out var s) && s.Length > 0 && s.Length <= max;
            bool Id(JsonNode? n) => n is JsonValue v && v.TryGetValue<long>(out var id) && id > 0;
            bool Day(JsonNode? n) => Text(n) && DateOnly.TryParseExact(n!.ToString(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _);
            bool valid = a.Count == 2 && a[0]?.ToString() == "finding" && Id(a[1]);
            valid |= a.Count == 6 && a[0]?.ToString() == "queue" && Text(a[1], 512) && Text(a[2]) && Text(a[3]) && a[4] is JsonArray names && names.All(n => Text(n)) && Day(a[5]);
            valid |= a.Count == 3 && a[0]?.ToString() is "rule-object" or "rule-source" && Text(a[1], 512) && Text(a[2]);
            valid |= a.Count == 4 && a[0]?.ToString() == "rule-entity" && Text(a[1], 512) && Text(a[2]) && Text(a[3]);
            bool membership = a.Count == 7 && a[0]?.ToString() == "membership";
            valid |= (membership || a.Count == 6 && a[0]?.ToString() == "object") && Text(a[1], 512) && Id(a[2]) && Id(a[3]) && a.Skip(4).SkipLast(1).All(n => Text(n) && (!membership || Regex.IsMatch(n!.ToString(), @"\AS-1-(?:\d+-)*\d+\z"))) && Day(a[^1]);
            if (!valid) throw new FormatException(); return a;
        }
        catch (Exception e) when (e is FormatException or System.Text.Json.JsonException or InvalidOperationException) { throw new ProblemException("problem_cohort_invalid"); }
    }
}
