using System.Globalization;
using System.Text;
using System.Text.Json;
using Sli.Server.Access.Administration;

namespace Sli.Server.Auth.ReportKeys;

public static class ExactEventScope
{
    private static readonly string[] Dimensions = ["plugin_ids", "source_instance_ids", "device_ids", "entity_ids", "collection_scope_ids"];

    public static bool AllowsDomain(JsonElement scope, long domainId)
    {
        if (scope.ValueKind != JsonValueKind.Object || domainId <= 0) return false;
        var keys = scope.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        if (!keys.Contains("mode"))
        {
            if (scope.TryGetProperty("kind", out var kind) && kind.ValueKind == JsonValueKind.String)
            {
                if (kind.GetString() == "all") return true;
                if (kind.GetString() != "domain" || !scope.TryGetProperty("ids", out var ids)
                    || ids.ValueKind != JsonValueKind.Array || ids.GetArrayLength() is < 1 or > 100) return false;
                bool domainMatch = false;
                foreach (var item in ids.EnumerateArray())
                {
                    long id;
                    if (item.ValueKind == JsonValueKind.Number)
                    {
                        if (!item.TryGetInt64(out id) || id <= 0) return false;
                    }
                    else if (item.ValueKind == JsonValueKind.String)
                    {
                        try
                        {
                            var value = AssignmentValidation.Integer(item);
                            if (value <= 0 || value > long.MaxValue) return false;
                            id = (long)value;
                        }
                        catch (Exception error) when (error is AssignmentValidationException or InvalidOperationException or OverflowException or FormatException)
                        { return false; }
                    }
                    else return false;
                    domainMatch |= id == domainId;
                }
                return domainMatch;
            }
            return false;
        }
        if (keys.Except(["mode", "clauses", "decision_id", "policy_revision"]).Any()) return false;
        foreach (var name in new[] { "decision_id", "policy_revision" })
            if (scope.TryGetProperty(name, out var metadata) && (metadata.ValueKind != JsonValueKind.String
                || AssignmentValidation.Strip(metadata.GetString()!).Length == 0 || metadata.GetString()!.EnumerateRunes().Take(257).Count() > 256)) return false;
        if (!scope.TryGetProperty("mode", out var mode) || mode.ValueKind != JsonValueKind.String) return false;
        var modeText = mode.GetString();
        JsonElement clauses = default;
        bool hasClauses = scope.TryGetProperty("clauses", out clauses);
        if (hasClauses && (clauses.ValueKind != JsonValueKind.Array || clauses.GetArrayLength() > 100)) return false;
        int count = hasClauses ? clauses.GetArrayLength() : 0;
        if (modeText is not ("all" or "none" or "restricted") || (modeText == "restricted") != (count > 0)) return false;
        bool match = false;
        if (hasClauses) foreach (var clause in clauses.EnumerateArray())
        {
            if (clause.ValueKind != JsonValueKind.Object || clause.EnumerateObject().Any(p => !Dimensions.Contains(p.Name))) return false;
            bool populated = false, clauseMatch = true;
            foreach (var property in clause.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.Array || property.Value.GetArrayLength() > 100) return false;
                var items = property.Value.EnumerateArray().ToArray();
                if (items.Length == 0) continue;
                populated = true;
                if (property.Name == "entity_ids")
                {
                    if (items.Any(i => i.ValueKind != JsonValueKind.Number || !i.TryGetInt64(out var id) || id <= 0)
                        || items.Select(i => i.GetInt64()).Distinct().Count() != items.Length) return false;
                    clauseMatch = false;
                }
                else
                {
                    if (items.Any(i => i.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(i.GetString())
                        || i.GetString()!.EnumerateRunes().Take(257).Count() > 256 || AssignmentValidation.Strip(i.GetString()!) != i.GetString())
                        || items.Select(i => i.GetString()).Distinct(StringComparer.Ordinal).Count() != items.Length) return false;
                    if (property.Name != "collection_scope_ids" || !items.Any(i => i.GetString() == "ad-domain:" + domainId.ToString(CultureInfo.InvariantCulture))) clauseMatch = false;
                }
            }
            if (!populated) return false;
            match |= clauseMatch;
        }
        return modeText == "all" || modeText == "restricted" && match;
    }
}
