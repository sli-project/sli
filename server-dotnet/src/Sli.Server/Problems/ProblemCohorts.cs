using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Problems;

internal static class ProblemCohorts
{
    internal static string PasswordFacts(string alias) =>
        $"case when {alias}.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray') " +
        $"then public.password_problem_facts395({alias}.id,{alias}.rule_code) end";
    internal static string Queue(string population, string where, string status, string accepted, string partition = "", bool owners = false, bool usePasswordProjection = false) => Sql("queue-groups")
        .Replace("__POPULATION__", population).Replace("__WHERE__", where).Replace("__STATUS__", status).Replace("__ACCEPTED__", accepted)
        .Replace("__PARTITION__", partition).Replace("__ASSIGNEE__", owners ? "findings.assigned_to" : "null::text").Replace("__COHORT__", Sql("queue-cohort", usePasswordProjection));
    internal static string Sql(string name, bool usePasswordProjection = false) {
        using var stream = typeof(ProblemCohorts).Assembly.GetManifestResourceStream($"Sli.Server.Problems.{name}.sql")!;
        using var reader = new StreamReader(stream);
        string sql = reader.ReadToEnd().Replace("__RETAINED_COHORT__", name == "legacy-queue-cohort" ? Sql("cohort") : "");
        if (name == "queue-cohort") sql = sql.Replace("__PASSWORD_EVIDENCE__", usePasswordProjection
            ? "select facts,aliases from public.password_queue_presentation399(findings.id,findings.rule_code)"
            : "select public.password_problem_facts395(findings.id,findings.rule_code) as facts,null::jsonb as aliases");
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
            valid |= a.Count == 3 && a[0]?.ToString() == "password" && ProblemPresentation.IsPasswordFinding(a[1]?.ToString() ?? "") &&
                a[2]?.ToString() is { } hash && Regex.IsMatch(hash, @"\A[a-f0-9]{64}\z");
            valid |= a.Count == 4 && a[0]?.ToString() == "rule-entity" && Text(a[1], 512) && Text(a[2]) && Text(a[3]);
            bool membership = a.Count == 7 && a[0]?.ToString() == "membership";
            valid |= (membership || a.Count == 6 && a[0]?.ToString() == "object") && Text(a[1], 512) && Id(a[2]) && Id(a[3]) && a.Skip(4).SkipLast(1).All(n => Text(n) && (!membership || Regex.IsMatch(n!.ToString(), @"\AS-1-(?:\d+-)*\d+\z"))) && Day(a[^1]);
            if (!valid) throw new FormatException(); return a;
        }
        catch (Exception e) when (e is FormatException or System.Text.Json.JsonException or InvalidOperationException) { throw new ProblemException("problem_cohort_invalid"); }
    }
}
