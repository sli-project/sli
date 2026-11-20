using System.Text.Json.Nodes;
using Sli.Server.Semantic;

namespace Sli.Server.Legacy;

public interface ILegacyFindings
{
    Task<JsonObject> RefreshAsync(CancellationToken ct);
}

// An Event ID alone has no admitted policy identity. The retired producer
// cannot read events, publish verdicts, or advance its watermark.
public sealed partial class LegacyFindings : ILegacyFindings
{
    public LegacyFindings(ISemanticDatabase database) { }

    private static JsonObject Disabled() => new() { ["status"] = "disabled", ["reason"] = "module_disabled" };
    internal static readonly int[] HintEvents = Compatibility.LegacySemantics.FindingRules.Select(p => int.Parse(p.Key)).ToArray();

    // Candidate formatting is not publication authority. RefreshAsync is disabled.
    internal static JsonObject? EventCandidate(JsonObject row,
        IReadOnlyDictionary<int, (string Code, string Title, string Severity, string Why)> rules,
        Func<int, string> eventLabel, Func<string?, string?, string?> principal, Func<string, string> recommendation)
    {
        if (!int.TryParse(row["event_id"]?.ToString(), out int eventId) || !rules.TryGetValue(eventId, out var rule)) return null;
        static string? Present(string? value) => string.IsNullOrEmpty(value) ? null : value;
        string target = Present(principal(row.Text("target_domain_name"), row.Text("target_user_name")))
            ?? Present(principal(row.Text("subject_domain_name"), row.Text("subject_user_name"))) ?? "unknown";
        string? actor = principal(row.Text("subject_domain_name"), row.Text("subject_user_name"));
        string? source = Present(row.Text("ip_address")) ?? Present(row.Text("workstation_name"))
            ?? Present(row.Text("computer")) ?? Present(row.Text("hostname"));
        string hostname = Present(row.Text("hostname")) ?? Present(row.Text("computer")) ?? "unknown";
        return new JsonObject {
            ["event_db_id"] = long.Parse(row["id"]!.ToString(), System.Globalization.CultureInfo.InvariantCulture),
            ["event_id"] = eventId, ["event_note"] = eventLabel(eventId), ["event_time"] = row.Text("time_created_utc") ?? "",
            ["fingerprint"] = $"{rule.Code}|{target}|{hostname}|{eventId}", ["rule_code"] = rule.Code,
            ["title"] = rule.Title, ["severity"] = rule.Severity, ["actor"] = actor, ["target"] = target, ["source"] = source,
            ["hostname"] = hostname, ["summary"] = $"{rule.Title}: {target} на {hostname} ({eventLabel(eventId)}).",
            ["why_it_matters"] = rule.Why, ["recommended_action"] = recommendation(rule.Code),
            ["entities"] = new JsonArray(
                new JsonObject { ["entity_type"] = "account", ["display_name"] = target == "unknown" ? null : target, ["entity_role"] = "target" },
                new JsonObject { ["entity_type"] = "account", ["display_name"] = actor, ["entity_role"] = "actor" },
                new JsonObject { ["entity_type"] = "ip", ["display_name"] = row.Text("ip_address"), ["entity_role"] = "source" },
                new JsonObject { ["entity_type"] = "host", ["display_name"] = Present(row.Text("workstation_name"))
                    ?? Present(row.Text("computer")) ?? Present(row.Text("hostname")), ["entity_role"] = "source" })
        };
    }

    public Task<JsonObject> RefreshAsync(CancellationToken ct)
    {
        return Task.FromResult(Disabled());
    }
}
