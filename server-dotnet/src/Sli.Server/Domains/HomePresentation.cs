using System.Text.Json;
using System.Text.Json.Nodes;

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
