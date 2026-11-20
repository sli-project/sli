using System.Globalization;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.InstallationSetup;

namespace Sli.Server.Workspace;

// Declarative ownership only: this adapter never starts jobs or applies migrations.
internal static class NavigationRegistry
{
    internal static readonly IReadOnlyDictionary<string, string> PluginSections = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["sli.ad"] = "active-directory", ["sli.gpo"] = "group-policies", ["sli.remote-access"] = "remote-access",
        ["sli.workstations"] = "workstations", ["sli.file-audit"] = "file-audit"
    };
    private static readonly Lazy<(JsonObject Config, IReadOnlyDictionary<string, JsonObject> Owners)> Bundled = new(() =>
    {
        var config = JsonNode.Parse(WorkspaceJson.ReadResource("navigation_v3.json"))!.AsObject();
        return (config, Validate(config, Manifests(), InstallationPackages.Contract("plugin_architecture_v3.json")));
    });
    internal static JsonObject[] Manifests() => PluginSections.Keys.Order(StringComparer.Ordinal).Select(id =>
        InstallationPackages.Contract("plugin_packages/v3/" + (id == "sli.workstations" ? "sli.workstations.1.1.0" : id) + ".json")).ToArray();
    internal static JsonObject Configuration() => (JsonObject)Bundled.Value.Config.DeepClone();
    internal static IReadOnlyDictionary<string, JsonObject> Owners() => Bundled.Value.Owners.ToDictionary(p => p.Key, p => (JsonObject)p.Value.DeepClone(), StringComparer.Ordinal);
    private static string Text(JsonNode? node) => node?.GetValue<string>() ?? "";
    private static JsonNode[] Items(JsonNode? node) => node?.AsArray().Select(n => n!).ToArray() ?? [];
    private static HashSet<string> Strings(JsonNode? node) => Items(node).Select(Text).ToHashSet(StringComparer.Ordinal);
    private static void Check(bool valid, string code) { if (!valid) throw new InvalidDataException("navigation_" + code); }

    // Same declarative subset and error codes as reporting/navigation_registry.py.
    private static void Shape(JsonNode? value, JsonObject rule, JsonObject schema)
    {
        if (rule["$ref"] is {} reference) { Shape(value, schema["$defs"]![Text(reference).Split('/')[^1]]!.AsObject(), schema); return; }
        string Kind(JsonNode? n) => n?.GetValueKind() switch
        {
            null or JsonValueKind.Null => "null", JsonValueKind.Object => "object", JsonValueKind.Array => "array",
            JsonValueKind.String => "string", JsonValueKind.True or JsonValueKind.False => "boolean",
            JsonValueKind.Number when BigInteger.TryParse(n.ToJsonString(), CultureInfo.InvariantCulture, out _) => "integer", _ => "other"
        };
        if (rule["type"] is {} type)
            Check((type is JsonArray ? Strings(type) : new HashSet<string> { Text(type) }).Contains(Kind(value)), "manifest_type_invalid");
        if (rule.ContainsKey("const"))
        {
            Check(Kind(value) == Kind(rule["const"]), "manifest_type_invalid");
            Check(JsonNode.DeepEquals(value, rule["const"]), "manifest_value_invalid");
        }
        if (rule["enum"] is JsonArray choices) Check(choices.Any(c => JsonNode.DeepEquals(c, value)), "manifest_value_invalid");
        if (value is JsonObject obj)
        {
            var properties = rule["properties"] as JsonObject ?? new();
            Check(Strings(rule["required"]).IsSubsetOf(obj.Select(p => p.Key)), "manifest_field_required");
            if (rule["additionalProperties"]?.GetValueKind() == JsonValueKind.False)
                Check(obj.All(p => properties.ContainsKey(p.Key)), "manifest_unknown_field");
            foreach (var (key, item) in obj) if (properties[key] is JsonObject property) Shape(item, property, schema);
        }
        else if (value is JsonArray array)
        {
            Check(array.Count >= (rule["minItems"]?.GetValue<int>() ?? 0), "manifest_array_invalid");
            if (rule["uniqueItems"]?.GetValue<bool>() == true)
                Check(!array.Where((item, i) => array.Skip(i + 1).Any(other => JsonNode.DeepEquals(item, other))).Any(), "manifest_duplicate_item");
            foreach (var item in array) Shape(item, rule["items"] as JsonObject ?? new(), schema);
        }
        else if (Kind(value) == "string")
        {
            string text = Text(value); int length = text.EnumerateRunes().Count();
            Check(length >= (rule["minLength"]?.GetValue<int>() ?? 0) && length <= (rule["maxLength"]?.GetValue<int>() ?? length), "manifest_string_invalid");
            if (rule["pattern"] is {} pattern) Check(Regex.IsMatch(text, Text(pattern), RegexOptions.CultureInvariant), "manifest_string_invalid");
        }
        else if (Kind(value) == "integer")
        {
            var number = BigInteger.Parse(value!.ToJsonString(), CultureInfo.InvariantCulture);
            Check((rule["minimum"] is not {} min || number >= BigInteger.Parse(min.ToJsonString(), CultureInfo.InvariantCulture))
                && (rule["maximum"] is not {} max || number <= BigInteger.Parse(max.ToJsonString(), CultureInfo.InvariantCulture)), "manifest_number_invalid");
        }
    }

    internal static IReadOnlyDictionary<string, JsonObject> Validate(JsonObject config, IReadOnlyList<JsonObject> manifests, JsonObject schema)
    {
        var owners = config["core_reports"]!.AsObject().ToDictionary(p => p.Key,
            p => new JsonObject { ["owner_id"] = "sli.core", ["section_id"] = p.Value!.DeepClone() }, StringComparer.Ordinal);
        var sections = Items(config["sections"]);
        Check(sections.Select(s => Text(s["id"])).Distinct().Count() == sections.Length, "duplicate_section");
        Check(Text(config["contract_id"]) == "sli.navigation.v3" && owners.Values.All(o =>
            new[] { "overview", "investigation", "operations", "admin" }.Contains(Text(o["section_id"]))
            && sections.Any(s => Text(s["id"]) == Text(o["section_id"]))), "core_section_invalid");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var routes = new HashSet<string>(StringComparer.Ordinal);
        var datasetsByPlugin = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var manifest in manifests)
        {
            Shape(manifest, schema, schema);
            string id = Text(manifest["plugin_id"]);
            Check(PluginSections.ContainsKey(id) && seen.Add(id), "plugin_id_invalid");
            if (id is not ("sli.workstations" or "sli.file-audit"))
                Check(new[] { "sources", "agent_modules", "handlers", "schedules", "dependencies", "home_widgets" }.All(k => Items(manifest[k]).Length == 0)
                    && Items(manifest["data"]!["migrations"]).Length == 0, "manifest_not_in_place");
            if (id == "sli.workstations")
                Check(Items(manifest["agent_modules"]).Length == 0 && Items(manifest["home_widgets"]).Length == 0
                    && Items(manifest["handlers"]).Select(h => Text(h["handler_id"])).SequenceEqual(["workstations.evidence-retention"])
                    && Items(manifest["schedules"]).All(s => Text(s["handler_id"]) == "workstations.evidence-retention"), "workstation_declarations_invalid");
            static int CompareVersion(JsonNode? node)
            {
                var parts = Text(node).Split('.').Select(p => BigInteger.Parse(p, CultureInfo.InvariantCulture)).ToArray();
                for (int i = 0; i < 3; i++) { int compared = parts[i].CompareTo(i == 0 ? 3 : 0); if (compared != 0) return compared; }
                return 0;
            }
            Check(CompareVersion(manifest["core_api"]!["minimum"]) <= 0 && CompareVersion(manifest["core_api"]!["maximum_exclusive"]) > 0, "core_api_incompatible");
            var datasets = Items(manifest["datasets"]);
            datasetsByPlugin[id] = datasets.Select(d => Text(d["dataset_id"])).ToHashSet(StringComparer.Ordinal);
            Check(datasetsByPlugin[id].Count == datasets.Length, "duplicate_dataset");
            var navigation = Items(manifest["navigation"]);
            var contributed = navigation.Select(s => Text(s["section_id"])).ToHashSet(StringComparer.Ordinal);
            Check(contributed.Count == navigation.Length, "duplicate_section");
            Check(contributed.SetEquals([PluginSections[id]]), "plugin_section_invalid");
            foreach (var section in navigation)
                Check(sections.Any(s => Text(s["id"]) == Text(section["section_id"]) && Text(s["title"]) == Text(section["title_key"]))
                    && section["parent_section_id"] is null, "section_invalid");
            foreach (var report in Items(manifest["reports"]))
            {
                string key = Text(report["report_key"]);
                Check(!owners.ContainsKey(key), "duplicate_report_owner");
                var dataset = datasets.FirstOrDefault(d => Text(d["dataset_id"]) == Text(report["dataset_id"]));
                Check(contributed.Contains(Text(report["section_id"])) && dataset is not null, "report_reference_invalid");
                Check(Text(dataset!["reader_id"]) == Text(report["history_reader_id"]), "history_reader_invalid");
                var reportRoutes = Strings(report["routes"]);
                Check(!routes.Overlaps(reportRoutes), "duplicate_route"); routes.UnionWith(reportRoutes);
                owners[key] = (JsonObject)report.DeepClone(); owners[key]["owner_id"] = id;
            }
        }
        Check(seen.SetEquals(PluginSections.Keys) && Strings(config["enabled_plugins"]).IsSubsetOf(seen), "plugin_set_invalid");
        var entries = sections.SelectMany(s => Items(s["groups"])).SelectMany(g => Items(g["entries"])).ToArray();
        Check(entries.Select(e => Text(e["id"])).Distinct().Count() == entries.Length, "duplicate_entry");
        foreach (var section in sections)
        {
            string? owner = PluginSections.FirstOrDefault(p => p.Value == Text(section["id"])).Key;
            foreach (var entry in Items(section["groups"]).SelectMany(g => Items(g["entries"])))
            {
                Check(entry["plugin_id"]?.GetValue<string>() == owner, "entry_reference_invalid");
                Check(Strings(entry["datasets"]).IsSubsetOf(owner is null ? [] : datasetsByPlugin[owner]), "dataset_owner_invalid");
                if (owner is null) continue;
                var views = Items(entry["views"]);
                if (views.Length > 0) Check(views.Select(v => Text(v["id"])).Distinct().Count() == views.Length
                    && Text(entry["path"]) == Text(views[0]["path"])
                    && Strings(entry["reports"]).SetEquals(views.SelectMany(v => Strings(v["reports"]))), "view_reference_invalid");
                foreach (var contribution in views.Length > 0 ? views : [entry])
                {
                    var report = owners.Values.FirstOrDefault(r => Strings(r["routes"]).Contains(Text(contribution["path"])));
                    Check(report is not null && Text(report["owner_id"]) == owner && Text(report["section_id"]) == Text(section["id"])
                        && Text(report["title_key"]) == Text(contribution["label"]) && Strings(contribution["reports"]).Contains(Text(report["access_key"]))
                        && (views.Length == 0 || Text(report["report_key"]) == Text(contribution["report_key"])
                            && Strings(contribution["reports"]).IsSubsetOf(new[] { Text(report["report_key"]), Text(report["access_key"]) })), "entry_reference_invalid");
                }
            }
        }
        var redirects = Items(config["redirects"]);
        Check(redirects.Select(r => Text(r["from"])).Distinct().Count() == redirects.Length, "duplicate_redirect");
        foreach (var redirect in redirects)
        {
            string from = Text(redirect["from"]), to = Text(redirect["to"]);
            Check(from != to && !redirects.Any(r => Text(r["from"]) == to), "redirect_invalid");
            if (redirect.AsObject().ContainsKey("view"))
            {
                var target = entries.FirstOrDefault(e => Text(e["path"]) == to);
                var view = Items(target?["views"]).FirstOrDefault(v => Text(v["id"]) == Text(redirect["view"]));
                Check(view is not null && (!from.StartsWith("/report/", StringComparison.Ordinal) || Text(view["path"]) == from), "redirect_invalid");
            }
            else Check(to == Text(config["global_search"]!["path"]), "redirect_invalid");
        }
        foreach (var report in owners.Values.ToArray().Where(r => r.ContainsKey("access_key")))
        {
            string alias = Text(report["access_key"]);
            Check(!owners.TryGetValue(alias, out var existing) || Text(existing["owner_id"]) == Text(report["owner_id"]), "duplicate_access_owner");
            owners.TryAdd(alias, report);
        }
        return owners;
    }
}
