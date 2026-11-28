using System.Text.Json.Nodes;
using Sli.Gpo.SnapshotModel;
using static Sli.Server.Gpo.GpoJson;
using static Sli.Server.Gpo.GpoPolicyCard;

namespace Sli.Server.Gpo;

internal static class GpoSettings
{
    internal const string Masked = "значение скрыто";

    internal static bool HasCount(JsonObject policy, JsonObject snapshot, int count) => count > 0
        || (policy["source_states"]?["report"] ?? snapshot["source_states"]?["report"]).Text("status") == "observed";

    internal static IEnumerable<JsonObject> RowsFor(IEnumerable<JsonObject> settings)
    {
        foreach (var group in settings.Where(row => row.Text("side") is "computer" or "user")
                     .GroupBy(row => (Side: row.Text("side"), Extension: row.Text("extension"))))
        {
            var rows = group.ToArray();
            foreach (var row in AuditRows(rows.Where(IsAudit).ToArray()))
                yield return row;
            foreach (var legacy in rows.Where(row => InPath(row, "RegistrySetting")).GroupBy(row => Parent(row, "RegistrySetting")))
                foreach (var row in LegacyRegistry(legacy.ToArray()))
                    yield return row;
            foreach (var legacy in rows.Where(row => InPath(row, "Account")).GroupBy(row => Parent(row, "Account")))
                foreach (var row in LegacyAccounts(legacy.ToArray()))
                    yield return row;
            foreach (var legacy in rows.Where(IsLegacyRight).GroupBy(row => Parent(row, "UserRightsAssignment")))
                foreach (var row in Rights(legacy.ToArray()))
                    yield return row;

            foreach (var row in rows.Where(row => !IsAudit(row) && !InPath(row, "RegistrySetting") && !InPath(row, "Account")
                         && !IsLegacyRight(row) && !MetadataRow(row)))
                yield return row.Text("category") == "Registry"
                    ? Registry(row, row.Text("path"), row.Text("setting_name"), row["value_display"])
                    : Project(row);
        }
    }

    private static bool MetadataRow(JsonObject row) =>
        row.Text("setting_name").ToLowerInvariant() is "blocked" or "admsetting" or "extension"
        || row.Text("category") == "Display" || InPath(row, "Display");

    private static bool InPath(JsonObject row, string segment) =>
        row.Text("category").Equals(segment, StringComparison.OrdinalIgnoreCase)
        || row.Text("path").Split('/').Contains(segment, StringComparer.OrdinalIgnoreCase);

    private static string Parent(JsonObject row, string segment)
    {
        var parts = row.Text("path").Split('/');
        var index = System.Array.FindIndex(parts, part => part.Equals(segment, StringComparison.OrdinalIgnoreCase));
        return index < 0 ? segment : string.Join('/', parts.Take(index + 1));
    }

    private static bool IsAudit(JsonObject row) => InPath(row, "AuditSetting")
        || row.Text("setting_name").ToLowerInvariant() is "subcategoryname" or "subcategoryguid";

    private static bool IsLegacyRight(JsonObject row) => row.Text("category") != "User Rights Assignment"
        && InPath(row, "UserRightsAssignment");

    private static string Leaf(JsonObject row) => row.Text("setting_name").ToLowerInvariant();
    private static string Value(JsonObject row) => row.Text("value_display");
    private static bool Hidden(string value) => value == Masked;

    private static IEnumerable<JsonObject> AuditRows(JsonObject[] rows)
    {
        var guids = rows.Where(row => Leaf(row) == "subcategoryguid").ToArray();
        // The collector writes the GUID and display name for the same entry, when a GUID exists.
        // Old reports with names only still need a row for each name.
        var names = rows.Where(row => Leaf(row) == "subcategoryname").ToArray();
        var identities = guids.Concat(guids.Length == 0 || guids.Length < names.Length
            ? names : names.Where(row => row.Text("audit_mode") is "0" or "1" or "2" or "3" or "4")).ToArray();
        var modes = rows.Where(row => Leaf(row) is "settingvalue" or "inclusionsetting").ToArray();
        foreach (var row in identities)
        {
            var result = Project(row);
            result["category"] = "AuditSetting";
            result["path"] = "AuditSetting";
            result["setting_name"] = Guid.TryParse(Value(row), out var guid) ? guid.ToString("D") : Value(row);
            result["value_display"] = row.Text("audit_mode") is "0" or "1" or "2" or "3" or "4" ? row["audit_mode"]!.DeepClone()
                : identities.Length == 1 && modes.Length == 1 ? Bounded(modes[0]["value_display"]) : null;
            result.Remove("audit_mode");
            yield return result;
        }
    }

    private static IEnumerable<JsonObject> LegacyRegistry(JsonObject[] rows)
    {
        var keys = rows.Where(row => Leaf(row) is "keypath" or "key").ToArray();
        var names = rows.Where(row => Leaf(row) == "valuename" || Leaf(row) == "name"
            && row.Text("path").EndsWith("/Value/Name", StringComparison.OrdinalIgnoreCase)).ToArray();
        var values = rows.Where(row => Leaf(row) is "value" or "number" or "string" or "data" or "valuedata").ToArray();
        var labels = rows.Where(row => Leaf(row) is "name" or "policyname" or "displayname").Except(names).ToArray();
        if (keys.Length == 1 && names.Length <= 1 && labels.Length <= 1)
        {
            var key = Value(keys[0]);
            var name = names.Length == 1 ? Value(names[0]) : "";
            var path = name.Length == 0 ? key : key.TrimEnd('\\') + "\\" + name;
            var value = Combine(values);
            if (Hidden(key) || Hidden(name) || labels.Any(label => Hidden(Value(label))))
            {
                path = "";
                value = JsonValue.Create(Masked);
            }
            else if (GpoSnapshotDocument.IsSensitiveField(path) || labels.Any(label => GpoSnapshotDocument.IsSensitiveField(Value(label))))
                value = JsonValue.Create(Masked);
            yield return Registry(keys[0], path, labels.Length == 1 ? Value(labels[0]) : "", value);
            yield break;
        }
        // Legacy records without an unambiguous common key cannot safely be paired.
        foreach (var row in rows.Where(row => !MetadataRow(row)))
            yield return Project(row);
    }

    private static JsonObject Registry(JsonObject row, string path, string name, JsonNode? value)
    {
        var result = Project(row);
        result["category"] = "Registry";
        result["path"] = Bounded(JsonValue.Create(path));
        result["setting_name"] = Bounded(JsonValue.Create(name.Length > 0 && !Hidden(name) ? name : path.Split('\\').Last()));
        result["value_display"] = Bounded(value);
        return result;
    }

    private static IEnumerable<JsonObject> LegacyAccounts(JsonObject[] rows)
    {
        var names = rows.Where(row => Leaf(row) == "name").ToArray();
        var values = rows.Where(row => Leaf(row) is "settingnumber" or "settingboolean" or "settingstring").ToArray();
        if (names.Length == 1 && values.Length <= 1 && !Hidden(Value(names[0])))
        {
            var result = Project(names[0]);
            result["category"] = "Account Policy";
            result["path"] = "";
            result["setting_name"] = names[0]["value_display"]?.DeepClone();
            result["value_display"] = values.Length != 1 ? null : GpoSnapshotDocument.IsSensitiveField(Value(names[0]))
                ? JsonValue.Create(Masked) : Bounded(values[0]["value_display"]);
            yield return result;
            yield break;
        }
        foreach (var row in rows.Where(row => !MetadataRow(row)))
            yield return Project(row);
    }

    private static IEnumerable<JsonObject> Rights(JsonObject[] rows)
    {
        var rights = rows.Where(row => Leaf(row) == "name" && !InPath(row, "Member")).ToArray();
        var members = rows.Where(row => Leaf(row) == "name" && InPath(row, "Member")).ToArray();
        if (members.Length == 0)
            members = rows.Where(row => Leaf(row) == "sid" && InPath(row, "Member")).ToArray();

        foreach (var row in rights.Where(row => !Hidden(Value(row))))
        {
            var result = Project(row);
            result["category"] = "User Rights Assignment";
            result["path"] = Parent(row, "UserRightsAssignment");
            result["setting_name"] = row["value_display"]?.DeepClone();
            result["value_display"] = rights.Length == 1 ? Combine(members) : null;
            yield return result;
        }
        if (rights.Length != 1 || rights.Any(row => Hidden(Value(row))))
        {
            // Historical leaf paths have no indices. Duplicate member values were discarded by the collector.
            // Only associate members when the parent is unique.
            if (members.FirstOrDefault() is { } member)
            {
                var result = Project(member);
                result["category"] = "User Rights Assignment";
                result["path"] = Parent(member, "UserRightsAssignment");
                result["setting_name"] = "Members";
                result["value_display"] = Combine(members);
                yield return result;
            }
        }
    }

    private static JsonNode? Combine(IEnumerable<JsonObject> rows)
    {
        var values = rows.Select(Value).Where(value => value.Length > 0).Distinct(StringComparer.Ordinal).ToArray();
        return values.Length == 0 ? null : JsonValue.Create(values.Any(Hidden) ? Masked : string.Join('\n', values.Order(StringComparer.Ordinal)));
    }

    private static JsonObject Project(JsonObject row) => new(new[] { "id", "side", "extension", "category", "path", "setting_name", "value_display" }
        .Where(row.ContainsKey).Select(key => KeyValuePair.Create(key, Bounded(row[key]))));
}
