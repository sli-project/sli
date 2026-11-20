using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text;
using Sli.Agent.Protocol;
using Sli.Gpo.SnapshotModel;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Storage.Lifecycle;

internal static class SnapshotChanges
{
    static readonly string[] UserFields = ("name displayName givenName surname samAccountName userPrincipalName distinguishedName canonicalName ou enabled lockedOut accountExpirationDate whenCreated whenChanged department title company office description employeeID employeeNumber mail proxyAddresses telephoneNumber otherTelephones mobile ipPhone fax streetAddress city state postalCode country scriptPath homeDirectory homeDrive profilePath passwordLastSet passwordExpiry passwordExpired passwordNeverExpires passwordNotRequired cannotChangePassword lastLogonTimestamp exactLastLogon lastBadPasswordAttempt badPasswordCountAtQueryDc smartcardLogonRequired accountNotDelegated allowReversiblePasswordEncryption trustedForDelegation trustedToAuthForDelegation doesNotRequirePreAuth useDesKeyOnly adminCount servicePrincipalNames userAccountControl msDSSupportedEncryptionTypes").Split(' ');
    static readonly string[] ComputerFields = ("name dnsHostName enabled deviceType ipv4s ipv6s osName osVersion osBuild osFamily servicePack ou distinguishedName canonicalName adSite lastLogonTimestamp exactLastLogon passwordLastSet whenCreated whenChanged description location userAccountControl spns trustedForDelegation trustedToAuthForDelegation").Split(' ');
    internal static bool Complete(JsonObject snapshot)
    {
        var status = Metadata(snapshot)["collection_status"];
        HashableStatus(status, "collection_status");
        return IsString(status, "complete", "completed") &&
            ObjectOrEmpty(snapshot["source_states"], "source_states").All(p =>
                IsString(Object(p.Value, "source_states")["status"], "observed"));
    }
    internal static bool Comparable(JsonObject before, JsonObject after)
    {
        var old = Metadata(before); var current = Metadata(after);
        return new[] { "search_base", "domain", "domain_dn" }.All(k => PythonMetadataEquality.Equal(old[k], current[k])) && PythonMetadataEquality.Equal(before["scope"], after["scope"]);
    }
    // Match Python's `or`, str(), iteration and equality, without casting an unknown
    // LDAP value to a JSON shape. Malformed structures fail closed, as in Python.
    static bool Truth(JsonNode? node) => node switch {
        null => false, JsonArray a => a.Count > 0, JsonObject o => o.Count > 0,
        JsonValue v => v.GetValueKind() switch {
            JsonValueKind.Null or JsonValueKind.False => false,
            JsonValueKind.String => v.GetValue<string>().Length > 0,
            JsonValueKind.Number => JsonRead.TryInteger(v, out var n) ? n != 0 : JsonSerializer.SerializeToElement(v).GetDouble() != 0,
            _ => true
        }, _ => false
    };
    static JsonNode? First(params JsonNode?[] nodes) => nodes.FirstOrDefault(Truth);
    static string PythonString(JsonNode? node) => GpoSnapshotDocument.PythonString(JsonSerializer.SerializeToElement(node));
    static bool IsString(JsonNode? node, params string[] choices) => JsonRead.TryString(node, out string text) && choices.Contains(text, StringComparer.Ordinal);
    static readonly HashSet<string> DiagnosticFields = new("metadata collection_status source_states users groups objects gpos links settings scopes sourceStates sourceState source_state memberships primary direct parentGroupIds computer user".Split(' '), StringComparer.Ordinal);
    static LifecycleBlocked Invalid(string field) => new("snapshot_history_field_invalid:" + (DiagnosticFields.Contains(field) ? field : "snapshot"));
    static JsonObject Object(JsonNode? node, string field) => node as JsonObject ?? throw Invalid(field);
    static JsonObject ObjectOrEmpty(JsonNode? node, string field) => Truth(node) ? Object(node, field) : new();
    static JsonObject Metadata(JsonObject snapshot) => Truth(snapshot["metadata"]) ? Object(snapshot["metadata"], "metadata") : snapshot;
    static void HashableStatus(JsonNode? node, string field) { if (node is JsonObject or JsonArray) throw Invalid(field); }
    static IEnumerable<JsonNode?> Iterate(JsonNode? node, string field)
    {
        if (node is JsonArray array) { foreach (var item in array) yield return item; }
        else if (node is JsonObject obj) { foreach (string key in obj.Select(p => p.Key)) yield return JsonValue.Create(key); }
        else if (JsonRead.TryString(node, out string text)) { foreach (var rune in text.EnumerateRunes()) yield return JsonValue.Create(rune.ToString()); }
        else throw Invalid(field);
    }
    static int CompareText(string x, string y)
    {
        var left = x.EnumerateRunes().GetEnumerator(); var right = y.EnumerateRunes().GetEnumerator();
        while (left.MoveNext()) {
            if (!right.MoveNext()) return 1;
            int comparison = left.Current.Value.CompareTo(right.Current.Value); if (comparison != 0) return comparison;
        }
        return right.MoveNext() ? -1 : 0;
    }
    static readonly IComparer<(string Kind, string Id)> IdentityOrder = Comparer<(string Kind, string Id)>.Create((x, y) => {
        int kind = CompareText(x.Kind, y.Kind); return kind == 0 ? CompareText(x.Id, y.Id) : kind;
    });
    sealed record SnapshotObject(JsonObject Attributes, HashSet<(string Kind, string Id)>? Members, string Related);
    static bool Scalar(JsonNode? value) => value is null or JsonValue || value is JsonArray array && array.All(v => v is null or JsonValue);
    static Dictionary<(string Kind, string Id), SnapshotObject> Objects(string family, JsonObject snapshot)
    {
        (string Collection, string Kind, string[] Fields)[] collections = family switch {
            "users_v2" => [("users", "ad_user", UserFields), ("groups", "ad_group", "name samAccountName distinguishedName canonicalName category scope".Split(' '))],
            "computers_v6" => [("objects", "ad_computer", ComputerFields)],
            "gpo_v2" => [("gpos", "gpo", "display_name gpo_status creation_time modification_time wmi_filter_id computer_enabled user_enabled versions".Split(' ')),
                ("links", "gpo_link", "gpo_id scope_id enabled enforced order".Split(' ')),
                ("settings", "gpo_setting", "gpo_id side category setting_name path value_display".Split(' ')),
                ("scopes", "gpo_scope", "name scope_type canonical_path gpo_inheritance_blocked".Split(' '))],
            _ => throw new LifecycleBlocked("snapshot_history_family_invalid")
        };
        if (family == "gpo_v2") snapshot = Object(JsonNode.Parse(GpoSnapshotDocument.Redact(JsonSerializer.SerializeToElement(snapshot)).GetRawText()), "snapshot");
        var result = new Dictionary<(string, string), SnapshotObject>();
        foreach (var (collection, kind, fields) in collections) foreach (var item in Iterate(First(snapshot[collection]) ?? new JsonArray(), collection)) {
            var row = Object(item, collection);
            var identity = First(row["objectGuid"], row["guid"], row["id"]);
            if (identity is null) throw new LifecycleBlocked("snapshot_history_object_identity_missing");
            string id = PythonString(identity);
            if (result.ContainsKey((kind, id))) throw new LifecycleBlocked("snapshot_history_object_identity_duplicate");
            var attrs = new JsonObject();
            foreach (string field in fields) if (row.ContainsKey(field) && Scalar(row[field])) attrs[field] = row[field]?.DeepClone();
            if (kind == "ad_user" && row["manager"] is JsonObject manager) {
                var value = new JsonObject(); foreach (string field in new[] { "id", "objectGuid" }) if (manager.ContainsKey(field)) value[field] = manager[field]?.DeepClone(); attrs["manager"] = value;
            }
            if (kind == "gpo") foreach (string side in new[] { "computer", "user" }) foreach (var p in ObjectOrEmpty(row[side], side))
                if (p.Key is "enabled" or "directory_version" or "sysvol_version" && Scalar(p.Value)) attrs[side + "." + p.Key] = p.Value?.DeepClone();
            var directory = ObjectOrEmpty(row["sourceStates"], "sourceStates")["directory"];
            var state = First(directory, row["sourceState"], row["source_state"]);
            string stateField = Truth(directory) ? "sourceStates" : Truth(row["sourceState"]) ? "sourceState" : "source_state";
            bool observed = !Truth(state) || IsString(Object(state, stateField)["status"], "observed");
            if (!observed) attrs.Clear();
            HashSet<(string, string)>? members = kind == "ad_user" && observed ? Members(row) : null;
            if (kind == "ad_group" && observed && row.ContainsKey("parentGroupIds")) members = Iterate(row["parentGroupIds"], "parentGroupIds").Select(n => ("parent", PythonString(n))).ToHashSet();
            result.Add((kind, id), new(attrs, members, family == "gpo_v2" && Truth(row["gpo_id"]) ? PythonString(row["gpo_id"]) : ""));
        }
        return result;
    }
    static HashSet<(string, string)>? Members(JsonObject row)
    {
        if (row["memberships"] is not JsonObject membership) return null;
        var status = membership.ContainsKey("status") ? membership["status"] : membership["state"];
        HashableStatus(status, "memberships");
        if (status is not null && !IsString(status, "observed", "complete", "completed")) return null;
        var result = new HashSet<(string, string)>();
        foreach (string kind in new[] { "primary", "direct" }) {
            var values = First(membership[kind]) ?? new JsonArray();
            IEnumerable<JsonNode?> items = values is JsonObject single ? [single] : Iterate(values, kind);
            foreach (var item in items) {
                var id = item is JsonObject obj ? First(obj["objectGuid"], obj["id"]) : item;
                if (Truth(id)) result.Add((kind, PythonString(id)));
            }
        }
        return result;
    }
    internal static List<JsonObject> Extract(string family, JsonObject previous, JsonObject current, Action<JsonNode?, JsonNode?>? captureValues = null)
    {
        var before = Objects(family, previous); var after = Objects(family, current);
        if (!Comparable(previous, current)) return [];
        bool complete = Complete(previous) && Complete(current); var rows = new List<JsonObject>();
        void Append((string Kind, string Id) key, string kind, string field = "", JsonNode? old = null, JsonNode? value = null, string? related = null) {
            if (rows.Count >= 100000) throw new LifecycleBlocked("snapshot_history_batch_too_large");
            rows.Add(new JsonObject { ["object_type"] = key.Kind, ["object_id"] = key.Id, ["kind"] = kind, ["field"] = field,
                ["related_object_id"] = related ?? after.GetValueOrDefault(key)?.Related ?? before[key].Related,
                ["before_sha256"] = old is null ? "" : LifecycleJson.Hash(old).ToLowerInvariant(), ["after_sha256"] = value is null ? "" : LifecycleJson.Hash(value).ToLowerInvariant() });
            captureValues?.Invoke(old, value);
        }
        if (complete) {
            foreach (var key in before.Keys.Except(after.Keys).Order(IdentityOrder)) Append(key, "object_removed");
            foreach (var key in after.Keys.Except(before.Keys).Order(IdentityOrder)) Append(key, "object_added");
        }
        foreach (var key in before.Keys.Intersect(after.Keys).Order(IdentityOrder)) {
            var old = before[key]; var value = after[key];
            foreach (string field in old.Attributes.Select(p => p.Key).Intersect(value.Attributes.Select(p => p.Key)).Order(StringComparer.Ordinal))
                if (!PythonMetadataEquality.Equal(old.Attributes[field], value.Attributes[field])) Append(key, "attribute_changed", field, old.Attributes[field], value.Attributes[field]);
            if (old.Members is null || value.Members is null) continue;
            if (complete) foreach (var member in old.Members.Except(value.Members).Order(IdentityOrder)) Append(key, "membership_removed", member.Kind, JsonValue.Create(member.Id), related: member.Id);
            foreach (var member in value.Members.Except(old.Members).Order(IdentityOrder)) Append(key, "membership_added", member.Kind, value: JsonValue.Create(member.Id), related: member.Id);
        }
        return rows;
    }
}
