using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Problems;
namespace Sli.Server.Notifications;
public sealed record NotificationJob(Guid Id,Guid Subscription,long Revision,string Kind,Guid ObjectId,long Recipient,int Attempts,Guid Lease,DateTime Created,string? Severity,string Reason,int Delay)
{
    public string? Channel {get;init;}
    public JsonElement? ReportRun {get;init;}
    public long? ReportChannelRevision {get;init;}
    internal bool Abandoned {get;init;}
}
public static class NotificationMessage
{
    public static string Format(NotificationJob job, string baseUrl, JsonObject? finding, ProblemAccess? access,
        string language = "en", TimeZoneInfo? zone = null)
    {
        if (job.Kind == "report_schedule") return ReportScheduleDelivery.Digest(job, baseUrl);
        baseUrl = baseUrl.TrimEnd('/');
        if (!baseUrl.EndsWith("/app", StringComparison.Ordinal)) baseUrl += "/app";
        string M(string key, JsonObject? args = null) => ProblemJson.Text(ProblemPresentation.Message("notifications.message." + key, language, args)["text"]);
        if (job.Kind == "test_problem") return $"{M("test")}\n{baseUrl}/report/notifications.deliveries";
        if (job.Kind != "semantic_finding" || finding is null || access is null || ProblemJson.Long(finding["id"]) is not > 0)
            throw new FormatException();

        ApplySeverity(finding, job.Severity);
        var row = ProblemPresentation.Finding(finding, access, language, queue: true, includeDescription: true);
        string rule = ProblemJson.Text(finding["rule_code"]);
        var facts = new List<string>();
        var parameters = ProblemPresentation.RuleParameters(finding, access, language);
        var lines = new List<string> { Headline(finding, row, parameters, language) };
        void Fact(string key, string value)
        {
            value = Line(value, 160);
            if (value.Length > 0) facts.Add(M(key, new() { ["value"] = value }));
        }
        if (ProblemPresentation.IsPasswordFinding(rule)) {
            if (rule == "semantic.qw.password-brute-force") Fact("account", ProblemJson.Text(row["entity_text"]));
            Fact("source", ProblemJson.Text(row["actor_text"]));
        } else {
            Fact("source", ProblemJson.Text(parameters["source"]));
            Fact("computer", ProblemJson.Text(parameters["computer"]));
        }
        long count = ProblemJson.Long(row["occurrence_count"]);
        if (count <= 0)
            count = ProblemPresentation.IsPasswordFinding(rule)
                ? Math.Max(ProblemJson.Long(finding["evidence_count"]), ProblemJson.Long(parameters["count"]))
                : 1 + Math.Max(0, ProblemJson.Long(row["repeat_count"]));
        if (count > 0) Fact("count", count.ToString(CultureInfo.InvariantCulture));
        if (ProblemJson.Stamp(row["first_seen_utc"], out var first))
            Fact("first", TimeZoneInfo.ConvertTime(first, zone ?? TimeZoneInfo.Local).ToString("dd.MM HH:mm", CultureInfo.InvariantCulture));
        if (job.Reason == "pipeline_delay" && job.Delay > 0)
            Fact("late", job.Delay.ToString(CultureInfo.InvariantCulture));
        if (facts.Count > 0) lines.Add(string.Join(" · ", facts));
        if (ProblemPresentation.HasRuleMessage(rule, "next", language) ||
            ProblemJson.Text(row["presentation_messages"]?["next_text"]?["code"]).StartsWith("security.problems.presentation.", StringComparison.Ordinal)) {
            string action = Line(ProblemJson.Text(row["next_text"]), 640);
            if (action.Length > 0) lines.Add(action);
        }
        lines.Add($"{baseUrl}/report/security.problems?id={ProblemJson.Long(row["id"]).ToString(CultureInfo.InvariantCulture)}");
        return string.Join('\n', lines);
    }

    internal static string ProblemHeadline(JsonObject finding, string? severity, ProblemAccess access, string language)
    {
        ApplySeverity(finding, severity);
        return Headline(finding, ProblemPresentation.Finding(finding, access, language, queue: true, includeDescription: true),
            ProblemPresentation.RuleParameters(finding, access, language), language);
    }

    private static void ApplySeverity(JsonObject finding, string? severity)
    {
        if (severity is not ("critical" or "high" or "medium" or "low")) return;
        finding["severity"] = severity;
        if (severity != "critical" && finding["presentation_facts"] is JsonObject facts) facts.Remove("password_success");
    }

    private static string Headline(JsonObject finding, JsonObject row, JsonObject parameters, string language)
    {
        string rule = ProblemJson.Text(finding["rule_code"]);
        string title = ProblemPresentation.HasRuleMessage(rule, "title", language) ? ProblemJson.Text(row["title_text"]) : "";
        if (title.Length == 0) title = ProblemJson.Text(ProblemPresentation.Message("notifications.message.problem", language)["text"]);
        string label = ProblemJson.Text(row["severity_message"]?["text"]);
        if (label.Length == 0) label = ProblemJson.Text(ProblemPresentation.Message("notifications.message.info", language)["text"]);

        var subjects = new[] { row["entity_text"], parameters["account"], parameters["target"], parameters["member"], parameters["source"], parameters["computer"], parameters["actor"] }
            .Select(value => Line(ProblemJson.Text(value), 120)).Where(value => value.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).Where(value => !title.Contains(value, StringComparison.OrdinalIgnoreCase)).Take(2);
        return Line(string.Join(" · ", new[] { label, title }.Concat(subjects)), 384);
    }

    internal static string Line(string value, int limit)
    {
        value = Regex.Replace(value, @"\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b", "", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        // Transport bodies are plain text. Keep host strings from introducing another URI scheme.
        value = value.Replace("://", ":∕∕", StringComparison.Ordinal);
        return string.Concat(value.EnumerateRunes().Where(r => System.Text.Rune.GetUnicodeCategory(r) is not
            (UnicodeCategory.Format or UnicodeCategory.Surrogate)).Take(limit).Select(r =>
                System.Text.Rune.IsControl(r) || System.Text.Rune.IsWhiteSpace(r) ? " " : r.ToString())).Trim();
    }
}
