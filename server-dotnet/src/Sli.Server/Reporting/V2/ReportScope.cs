using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
namespace Sli.Server.Reporting.V2;

public sealed record ReportScope(string Mode, IReadOnlyList<JsonObject> Clauses)
{
    internal static readonly string[] Dimensions = ["plugin_ids", "source_instance_ids", "device_ids", "entity_ids", "collection_scope_ids"];
    public static ReportScope None { get; } = new("none", []);
    public static ReportScope All { get; } = new("all", []);
    internal static ReportScope FromGrant(JsonElement grant)
    {
        var parsed = ReportScopeResolver.ParseScope(grant);
        return parsed.Invalid ? None : parsed.All ? All : Merge(parsed.Clauses.Select(c => JsonNode.Parse(c.GetRawText())!.AsObject()));
    }
    internal static ReportScope Merge(IEnumerable<JsonObject> values)
    {
        var clauses = values.ToList();
        var pure = clauses.Where(c => !Dimensions.Take(4).Any(d => Values(c, d).Count > 0)).ToArray();
        var domains = pure.SelectMany(c => Values(c, "collection_scope_ids")).Distinct().Order(StringComparer.Ordinal).ToArray();
        if (domains.Length > 100) throw new ReportRequestException("invalid_scope_dimension");
        clauses.RemoveAll(c => pure.Contains(c));
        if (domains.Length > 0) clauses.Add(new JsonObject { ["collection_scope_ids"] = new JsonArray(domains.Select(s => JsonNode.Parse(s)).ToArray()) });
        if (clauses.Count > 100) throw new ReportRequestException("report_scope_not_executable", 403);
        return clauses.Count == 0 ? None : new("restricted", clauses);
    }
    private static HashSet<string> Values(JsonObject clause, string dimension) => (clause[dimension] as JsonArray)?.Select(n => n!.ToJsonString()).ToHashSet(StringComparer.Ordinal) ?? [];
    public bool Covers(ReportScope target) => target.Mode == "none" || Mode == "all" || Mode != "none" && target.Mode != "all"
        && target.Clauses.All(wanted => Clauses.Any(c => Dimensions.All(d => Values(c, d).Count == 0 || Values(wanted, d).Count > 0 && Values(wanted, d).IsSubsetOf(Values(c, d)))));
    public ReportScope Intersect(ReportScope target)
    {
        if (Mode == "none" || target.Mode == "none") return None;
        if (Mode == "all") return target;
        if (target.Mode == "all") return this;
        var clauses = new List<JsonObject>();
        foreach (var left in Clauses) foreach (var right in target.Clauses)
        {
            var clause = new JsonObject(); bool empty = false;
            foreach (string dimension in Dimensions)
            {
                var a = Values(left, dimension); var b = Values(right, dimension);
                var values = a.Count > 0 && b.Count > 0 ? a.Intersect(b).ToArray() : a.Union(b).ToArray();
                if (a.Count > 0 && b.Count > 0 && values.Length == 0) { empty = true; break; }
                if (values.Length > 0) clause[dimension] = new JsonArray(values.Select(s => JsonNode.Parse(s)).ToArray());
            }
            if (!empty && !clauses.Any(c => JsonNode.DeepEquals(c, clause))) clauses.Add(clause);
        }
        if (clauses.Count > 100) throw new ReportRequestException("invalid_access_scope");
        return clauses.Count == 0 ? None : new("restricted", clauses);
    }
    public long[]? DomainIds()
    {
        if (Mode == "all") return null;
        var ids = new HashSet<long>();
        foreach (var clause in Clauses)
        {
            if (Dimensions.Take(4).Any(d => Values(clause, d).Count > 0) || Values(clause, "collection_scope_ids").Count == 0)
                throw new ReportRequestException("report_scope_not_executable", 403);
            foreach (var value in (JsonArray)clause["collection_scope_ids"]!)
            {
                string text = value!.GetValue<string>();
                if (!System.Text.RegularExpressions.Regex.IsMatch(text, @"\Aad-domain:[1-9][0-9]*\z") || !long.TryParse(text.AsSpan(10), out long id))
                    throw new ReportRequestException("report_scope_not_executable", 403);
                ids.Add(id);
            }
        }
        if (ids.Count == 0) throw new ReportRequestException("report_scope_not_executable", 403);
        return ids.Order().ToArray();
    }
    public (string Sql, IReadOnlyDictionary<string, object> Parameters) SqlFilter(IReadOnlyDictionary<string, string> columns)
    {
        if (columns.Values.Any(c => !System.Text.RegularExpressions.Regex.IsMatch(c, @"\A[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?\z")))
            throw new ArgumentException("invalid_scope_column");
        var parameters = new Dictionary<string, object>();
        if (Mode != "restricted") return (Mode == "all" ? "TRUE" : "FALSE", parameters);
        var branches = new List<string>();
        foreach (var clause in Clauses)
        {
            var predicates = new List<string>();
            foreach (string d in Dimensions.Where(d => Values(clause, d).Count > 0))
            {
                if (!columns.TryGetValue(d, out string? column)) throw new ReportRequestException("report_scope_not_executable", 403);
                string name = "scope" + parameters.Count;
                parameters[name] = d == "entity_ids" ? ((JsonArray)clause[d]!).Select(n => n!.GetValue<long>()).ToArray() : ((JsonArray)clause[d]!).Select(n => n!.GetValue<string>()).ToArray();
                predicates.Add(column + " = ANY(@" + name + ")");
            }
            branches.Add("(" + string.Join(" AND ", predicates) + ")");
        }
        return ("(" + string.Join(" OR ", branches) + ")", parameters);
    }
    internal string Fingerprint => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Mode + string.Join("|", Clauses.Select(Canonical)))));
    internal static string Canonical(JsonNode? node) => node switch
    {
        JsonObject o => "{" + string.Join(",", o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => JsonSerializer.Serialize(p.Key) + ":" + Canonical(p.Value))) + "}",
        JsonArray a => "[" + string.Join(",", a.Select(Canonical)) + "]",
        _ => node?.ToJsonString() ?? "null"
    };
}
