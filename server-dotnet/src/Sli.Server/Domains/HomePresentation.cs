using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Problems;

namespace Sli.Server.Domains;

internal static class HomePresentation
{
    private static readonly Lazy<Dictionary<string, string>> Russian = new(() =>
    {
        using var stream = typeof(HomePresentation).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server.ru.json")!;
        return JsonSerializer.Deserialize<Dictionary<string, string>>(stream)!;
    });
    internal static string Text(string code) => Russian.Value.GetValueOrDefault(code, code);
    internal static JsonObject Message(string code) => new() { ["code"] = code, ["params"] = new JsonObject(), ["text"] = Text(code) };

    internal static string? DisplayName(string? value)
    {
        var name = value?.Trim();
        return name is null or "" or "-" or "—" || name.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("sid:", StringComparison.OrdinalIgnoreCase) ? null
            : string.Concat(name.EnumerateRunes().Take(512).Select(rune => rune.ToString()));
    }

    internal static (string? Name, string? Fact) PeriodProblem(JsonObject finding, HomeSummaryQuery query, bool identity)
    {
        string rule = finding.Text("rule_code") ?? "";
        var password = finding["password"];
        if (ProblemPresentation.IsPasswordFinding(rule))
        {
            const string prefix = "home.period.problem.";
            var locale = DomainHttp.SelectEnglish(query.Language) ? "en" : "ru";
            var culture = CultureInfo.GetCultureInfo(locale);
            string? Title() => ProblemPresentation.HasRuleMessage(rule, "title", query.Language)
                ? DisplayName(ProblemPresentation.RuleMessage(finding, "title", query.Language).Text("text")) : null;
            string NumberMessage(string key, long count) => ProblemPresentation.Message(prefix + key, query.Language,
                new() { ["count"] = count.ToString("N0", culture) }).Text("text")!;

            if (password.Boolean("password_success") == true)
            {
                finding = finding.DeepClone().AsObject();
                finding["presentation_facts"] = new JsonObject { ["password_success"] = true };
            }
            var totals = finding["password_totals"];
            var accounts = totals?["accounts"] is null ? password.Number("accounts") : totals.Number("accounts");
            var addresses = totals?["addresses"] is null ? password.Number("addresses") : totals.Number("addresses");
            var name = accounts > 1
                ? NumberMessage(query.OpenQueue && totals?["accounts"] is null ? "sample_accounts" : "accounts", accounts)
                : DisplayName(totals.Text("account") ?? password.Text("account"));
            string? title = Title();

            var attempts = totals?["attempts"] is null ? password.Number("attempts") : totals.Number("attempts");
            var attemptText = attempts > 0
                ? NumberMessage(query.OpenQueue && totals?["attempts"] is null ? "sample_attempts" : "attempts", attempts) : null;
            if (query.OpenQueue)
                return (name, title is not null && attemptText is not null ? $"{title} · {attemptText}" : title ?? attemptText);

            var detail = new List<string>();
            if (attemptText is not null) detail.Add(attemptText);
            if (addresses > 1) detail.Add(NumberMessage("addresses", addresses));
            else if (DisplayName(totals.Text("address") ?? password.Text("address")) is { } address) detail.Add(address);
            if ((totals.Stamp("first_at") ?? password.Stamp("first_at")) is { } first &&
                (totals.Stamp("last_at") ?? password.Stamp("last_at")) is { } last)
            {
                var zone = TimeZoneInfo.FindSystemTimeZoneById(query.TimeZone);
                var from = TimeZoneInfo.ConvertTime(first, zone);
                var to = TimeZoneInfo.ConvertTime(last, zone);
                var format = from.Date == to.Date ? "HH:mm" : "g";
                detail.Add(first == last ? from.ToString(format, culture) : $"{from.ToString(format, culture)}–{to.ToString(format, culture)}");
            }
            return (name, string.Join(" · ", detail.Prepend(title).Where(text => text is not null)) is { Length: > 0 } fact ? fact : null);
        }

        var subject = finding["subject"];
        var group = DisplayName(subject.Text("group_name"));
        var member = DisplayName(subject.Text("member_name"));
        var target = group is not null && member is not null ? $"{group} · {member}"
            : group ?? DisplayName(finding.Text("entity_name")) ?? DisplayName(subject.Text("account")) ?? DisplayName(finding.Text("target"));
        if (rule is "semantic.security.audit_controls_changed" or "semantic.qw.audit-disabled" or "semantic.qw.security-log-cleared")
            target = DisplayName(subject.Text("computer")) ?? target;
        target ??= DisplayName(finding.Text("actor"));
        return (identity ? target : null, ProblemPresentation.HasRuleMessage(rule, "title", query.Language)
            ? DisplayName(ProblemPresentation.RuleMessage(finding, "title", query.Language).Text("text")) : null);
    }

    internal static JsonObject Finding(JsonObject finding, string language = "", bool identity = true, bool technical = true)
    {
        finding = finding.DeepClone().AsObject();
        if (!identity) {
            foreach (string field in new[] { "actor", "target", "account", "computer", "hostname", "evidence", "entities", "identity_context" }) finding.Remove(field);
            if (finding["presentation_facts"] is JsonObject facts)
                foreach (string field in new[] { "actor", "account", "computer" }) facts.Remove(field);
        }
        if (!technical) {
            finding.Remove("source");
            (finding["presentation_facts"] as JsonObject)?.Remove("source");
        }
        var view = new JsonObject();
        foreach (var (field, suffix) in new[] { ("title", "title"), ("what", "what"), ("why", "why"), ("next_step", "next") }) {
            var message = Problems.ProblemPresentation.RuleMessage(finding, suffix, language);
            view[field] = message["text"].Copy();
            view[field + "_code"] = message["code"].Copy();
            if (field == "title") view["title_message"] = message;
        }
        view["presentation_code"] = Problems.ProblemPresentation.PresentationCode(finding);
        return view;
    }
}
