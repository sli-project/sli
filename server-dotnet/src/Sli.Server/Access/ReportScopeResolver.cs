using System.Globalization;
using System.Text.Json;
using System.Text;
using System.Text.RegularExpressions;
using Sli.Server.Access.Administration;

namespace Sli.Server.Access;

public interface IReportScopeResolver { DomainGrant PermittedDomains(AccessDecision access, IReadOnlyList<ReportRule> rules); }

// Frozen Python raises ValueError while constructing the merged per-report clause.
// The domain HTTP route maps this precise composition failure to its legacy 400.
public sealed class DomainScopeCompositionException() : Exception("invalid_scope_dimension");

public sealed class ReportScopeResolver : IReportScopeResolver
{
    internal sealed record Scope(bool All, bool Invalid, IReadOnlyList<JsonElement> Clauses);
    private static readonly string[] Dimensions = ["plugin_ids", "source_instance_ids", "device_ids", "entity_ids", "collection_scope_ids"];

    public DomainGrant PermittedDomains(AccessDecision access, IReadOnlyList<ReportRule> rules)
    {
        var union = new HashSet<long>();
        foreach (var rule in rules.Where(r => r.Scope == "domain"))
        {
            if (rule.RequiredRole is not null && rule.RequiredRole != access.CoarseRole
                || !rule.RequiredCapabilities.IsSubsetOf(access.Capabilities.Capabilities)) continue;
            if (rule.GlobalScopeOnly && rule.RequiredCapabilities.Any(c => !access.Capabilities.Decide(c).Allowed)) continue;
            var report = access.Reports.FirstOrDefault(r => r.ReportKey == rule.ReportKey && r.Allowed);
            if (report is null) continue;
            var scopes = report.Grants.Where(g => g.AllowedActions.Contains("view") && rule.RequiredFields.IsSubsetOf(g.FieldCategories))
                .Select(g => ParseScope(g.Scope)).Where(s => !s.Invalid).ToArray();
            if (scopes.Any(s => s.All)) return DomainGrant.All;
            if (rule.GlobalScopeOnly) continue;
            var clauses = scopes.SelectMany(s => s.Clauses).ToArray();
            // reporting/v2/access.py first deduplicates pure collection scopes into
            // one per-report ScopeClause. Its dimension limit is checked before
            // the strict domain adapter, including when other clauses coexist.
            var mergedCollections = clauses.Where(c => !Dimensions.Take(4).Any(d => c.Get(d).Items().Any()))
                .SelectMany(c => c.Get("collection_scope_ids").Items()).Select(c => c.GetString()!)
                .ToHashSet(StringComparer.Ordinal);
            if (mergedCollections.Count > 100) throw new DomainScopeCompositionException();
            // One unsupported dimension makes the entire report union unexecutable.
            // Dropping that clause would change Python's strict domain adapter.
            var reportIds = new HashSet<long>();
            bool executable = clauses.Length > 0;
            foreach (var clause in clauses)
            {
                if (Dimensions.Take(4).Any(d => clause.Get(d).Items().Any())) { executable = false; break; }
                var collections = clause.Get("collection_scope_ids");
                if (!collections.Items().Any()) { executable = false; break; }
                foreach (var collection in collections.Items())
                {
                    var value = collection.GetString()!;
                    if (!Regex.IsMatch(value, @"\Aad-domain:[1-9][0-9]*\z", RegexOptions.CultureInvariant)
                        || !long.TryParse(value.AsSpan(10), NumberStyles.None, CultureInfo.InvariantCulture, out var id))
                    { executable = false; break; }
                    reportIds.Add(id);
                }
                if (!executable) break;
            }
            if (executable) union.UnionWith(reportIds);
        }
        return DomainGrant.Scoped(union);
    }

    internal static Scope ParseScope(JsonElement value)
    {
        if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return new(false, false, []);
        if (value.ValueKind != JsonValueKind.Object) return new(false, true, []);
        var keys = value.EnumerateObject().Select(p => p.Name).ToHashSet();
        if (keys.Contains("mode"))
        {
            if (keys.Except(["mode", "clauses", "decision_id", "policy_revision"]).Any()) return new(false, true, []);
            foreach (var key in new[] { "decision_id", "policy_revision" })
                if (keys.Contains(key) && (value.Get(key).ValueKind != JsonValueKind.String || AssignmentValidation.Strip(value.Text(key)).Length == 0 || value.Text(key).EnumerateRunes().Take(257).Count() > 256))
                    return new(false, true, []);
            var raw = value.Get("clauses");
            if (raw.ValueKind != JsonValueKind.Undefined && raw.ValueKind != JsonValueKind.Array) return new(false, true, []);
            var clauses = raw.Items().ToArray();
            var mode = value.Text("mode", "none");
            if (mode is not ("none" or "all" or "restricted") || (mode == "restricted") != (clauses.Length > 0)
                || clauses.Length > 100 || clauses.Any(c => !ValidClause(c))) return new(false, true, []);
            return new(mode == "all", false, clauses);
        }
        var kind = value.Text("kind");
        if (kind == "all" && keys.SetEquals(["kind"])) return new(true, false, []);
        if (kind is not ("domain" or "server" or "channel")) return new(false, keys.Count > 0, []);
        var listKey = kind == "channel" ? "values" : "ids";
        var ids = value.Get(listKey);
        if (!keys.SetEquals(["kind", listKey]) || ids.ValueKind != JsonValueKind.Array || ids.GetArrayLength() is < 1 or > 100)
            return new(false, true, []);
        if (kind == "channel" ? ids.Items().Any(i => i.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(i.GetString()))
            : ids.Items().Any(i => i.ValueKind != JsonValueKind.Number || !i.TryGetInt64(out var id) || id <= 0)) return new(false, true, []);
        var dimension = kind == "server" ? "device_ids" : "collection_scope_ids";
        var prefix = kind == "domain" ? "ad-domain" : kind;
        var legacyClauses = ids.Items().Select(id => JsonSerializer.SerializeToElement(new Dictionary<string, string[]>
            { [dimension] = [prefix + ":" + (id.ValueKind == JsonValueKind.String ? id.GetString() : id.GetInt64().ToString(CultureInfo.InvariantCulture))] }))
            .ToArray();
        return new(false, legacyClauses.Length == 0 || legacyClauses.Any(c => !ValidClause(c)), legacyClauses);
    }

    private static bool ValidClause(JsonElement clause)
    {
        if (clause.ValueKind != JsonValueKind.Object || clause.EnumerateObject().Any(p => !Dimensions.Contains(p.Name))) return false;
        bool populated = false;
        foreach (var property in clause.EnumerateObject())
        {
            var values = property.Value;
            if (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() > 100) return false;
            populated |= values.GetArrayLength() > 0;
            if (property.Name == "entity_ids")
            {
                if (values.Items().Any(i => !ResourceAccessDecisions.PositiveInteger(i, out _))
                    || values.Items().Select(i => i.GetRawText()).Distinct().Count() != values.GetArrayLength()) return false;
            }
            else if (values.Items().Any(i => i.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(i.GetString())
                || i.GetString()!.EnumerateRunes().Take(257).Count() > 256 || AssignmentValidation.Strip(i.GetString()!) != i.GetString())
                || values.Items().Select(i => i.GetString()).Distinct().Count() != values.GetArrayLength()) return false;
        }
        return populated;
    }
}
