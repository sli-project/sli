using System.Text.Json.Nodes;
namespace Sli.Server.Reporting.V2;

public sealed record ReportDefinition(JsonObject Declaration)
{
    public string Key => Declaration.Text("key");
    public JsonObject Rule => Declaration["access_rule"]!.AsObject();
    public string AccessKey => Rule.Text("report_key");
    public string ScopeKind => Rule.Text("scope");
    public bool Generic => ScopeKind == "generic";
    public int DefaultLimit => Declaration.Number("limits", "default", 100);
    public int MaxLimit => Declaration.Number("limits", "max", 500);
    public JsonObject[] Params => Declaration.Objects("params");
    public JsonObject[] Columns => Declaration.Objects("columns");
    public JsonObject[] Views => Declaration.Objects("views");
    public JsonObject? Detail => Declaration["detail"] as JsonObject;
    public bool HasDetail => Detail?.Flag("query_available") == true;
    public bool HasExport => Declaration.Flag("export");
    public JsonObject IntentContract() => ReportIntent.Contract(this);
}
internal static class ReportJson
{
    internal static string Text(this JsonObject obj, string key, string fallback = "") => obj[key]?.GetValue<string>() ?? fallback;
    internal static bool Flag(this JsonObject obj, string key) => obj[key]?.GetValue<bool>() == true;
    internal static JsonObject[] Objects(this JsonObject obj, string key) => (obj[key] as JsonArray)?.OfType<JsonObject>().ToArray() ?? [];
    internal static HashSet<string> Strings(this JsonObject obj, string key) => (obj[key] as JsonArray)?.Select(n => n!.GetValue<string>()).ToHashSet(StringComparer.Ordinal) ?? [];
    internal static int Number(this JsonObject obj, string key, string child, int fallback) => (obj[key] as JsonObject)?[child]?.GetValue<int>() ?? fallback;
    internal static JsonObject Copy(this JsonObject obj) => (JsonObject)obj.DeepClone();
    internal static JsonNode? Read(JsonNode? row, string path)
    {
        foreach (string part in path.Split('.')) row = (row as JsonObject)?[part];
        return row;
    }
    internal static void Remove(JsonNode? node, string path)
    {
        if (node is JsonArray array) { foreach (var item in array) Remove(item, path); return; }
        if (node is not JsonObject row) return;
        int dot = path.IndexOf('.');
        if (dot < 0) row.Remove(path); else Remove(row[path[..dot]], path[(dot + 1)..]);
    }
}
public sealed class ReportRequestException(string code, int status = 400) : Exception(code)
{
    public int Status { get; } = status;
}
public interface IReportDefinitionRegistry { ReportDefinition? Get(string key); }
public sealed class ReportDefinitionRegistry : IReportDefinitionRegistry
{
    private readonly IReadOnlyDictionary<string, ReportDefinition> reports;
    public ReportDefinitionRegistry() : this(Load()) { }
    internal ReportDefinitionRegistry(IEnumerable<ReportDefinition> definitions)
    {
        reports = definitions.Select(r => new ReportDefinition(r.Declaration.Copy())).ToDictionary(r => r.Key, StringComparer.Ordinal);
    }
    private static IEnumerable<ReportDefinition> Load()
    {
        using var stream = typeof(ReportDefinitionRegistry).Assembly.GetManifestResourceStream("Sli.Server.Reporting.V2.report-definitions.json")
            ?? throw new InvalidOperationException("Report declarations missing");
        return JsonNode.Parse(stream)!.AsArray().OfType<JsonObject>().Select(n => new ReportDefinition(n)).ToArray();
    }
    public ReportDefinition? Get(string key) => reports.TryGetValue(key, out var report) ? new(report.Declaration.Copy()) : null;
    public IReadOnlyList<ReportDefinition> RegisteredReports(bool validateIntents = false)
    {
        var definitions = reports.Values.Select(r => new ReportDefinition(r.Declaration.Copy())).ToArray();
        if (validateIntents) ReportIntent.ValidateReports(definitions);
        return definitions;
    }
    // Opt-in declaration acceptance, like the Python registry; never calls readers.
    public void ValidateIntents() => ValidateIntents(reports.Values);
    public static void ValidateIntents(IEnumerable<ReportDefinition> definitions)
    {
        foreach (var definition in definitions)
        {
            ReportIntent.ValidateDeclaration(definition);
            ReportIntent.Validate(definition.IntentContract());
        }
    }
}
