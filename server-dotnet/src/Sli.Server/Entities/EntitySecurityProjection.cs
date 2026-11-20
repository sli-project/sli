using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
namespace Sli.Server.Entities;
internal static partial class EntitySecurityProjection
{
    static string? Clean(JsonObject row, string key) => row[key]?.ToString().Trim() is { Length: > 0 } value ? value : null;
    static JsonObject Unknown(string? reason = null) => reason is null ? new() { ["state"] = "unknown" } : new() { ["state"] = "unknown", ["reason"] = reason };
    static JsonObject Observed(string value) => new() { ["state"] = "observed", ["value"] = value };
    static JsonObject Principal(JsonObject row, string sidKey, string nameKey, string idKey)
    {
        string? sid = Clean(row, sidKey), name = Clean(row, nameKey);
        if (sid is null && name is null) return Unknown();
        var result = new JsonObject { ["state"] = "observed", ["sid"] = sid, ["name"] = name };
        if (row[idKey] is not null) result["entity_id"] = row[idKey]!.DeepClone();
        return result;
    }
    internal static JsonObject Present(JsonObject row)
    {
        int id = checked((int)EntityReader.Number(row, "event_id"));
        bool group = Families.GetValueOrDefault(id) is "group_membership" or "group_lifecycle";
        var evidence = EntityReader.Pick(row, "event_db_id", "event_record_id", "source_core_sha256", "source_facts_sha256");
        var missing = evidence.Where(p => p.Value is null).Select(p => p.Key).ToArray();
        evidence["state"] = missing.Length == 0 ? "complete" : "partial"; evidence["missing_fields"] = EntityReader.Strings(missing);
        var outcome = Unknown("event_outcome_not_proven_by_scoped_contract");
        if (Outcomes.TryGetValue(id, out var staticOutcome)) { outcome = Observed(staticOutcome); outcome["basis"] = "event_id"; }
        else
        {
            string? audit = Audit(Clean(row, "audit_keywords"));
            if (id is 4723 or 4724 or 4776 && audit is not null) { outcome = Observed(audit); outcome["basis"] = "audit_keywords"; }
            if (Clean(row, "result_code") is string code) outcome["result_code"] = code;
        }
        var change = Change(row, id);
        var result = EntityReader.Pick(row, "domain_id", "event_db_id", "event_record_id", "event_id", "time_created_utc");
        result["event_family"] = Families.GetValueOrDefault(id);
        result["actor"] = Principal(row, "subject_user_sid", "subject_user_name", "actor_entity_id");
        result["affected_account"] = group ? Unknown() : Principal(row, "target_user_sid", "target_user_name", "target_entity_id");
        result["member"] = Principal(row, "membership_member_sid", "membership_member_name", "member_entity_id");
        result["group"] = group ? Principal(row, "target_user_sid", "target_user_name", "target_entity_id") : Unknown();
        result["source_host"] = Clean(row, "source_host") is string host ? new JsonObject { ["state"] = "observed", ["hostname"] = host } : Unknown();
        result["outcome"] = outcome; result["evidence"] = evidence; result["change"] = change;
        if (id == 4740) result["caller_computer"] = Clean(row, "caller_computer") is string caller ? new JsonObject { ["state"] = "observed", ["hostname"] = caller } : Unknown();
        if (Clean(row, "archive_field_state") is string state) result["archive_fields"] = new JsonObject { ["state"] = "partial", ["reason"] = state.Replace("partial_archive_", "archive_", StringComparison.Ordinal) };
        if (AccountChanges.TryGetValue(id, out var kind))
        {
            var accountChange = new JsonObject { ["kind"] = kind };
            if (kind is "password_change_attempt" or "password_reset_attempt" && Clean(row, "result_code") is string code) accountChange["result"] = Observed(code);
            if (kind == "attributes_changed") accountChange["detail"] = Unknown("changed_attribute_fields_not_in_warm_contract");
            JsonObject before = Unknown("prior_account_state_not_observed"), after = AccountStates.TryGetValue(id, out var value) ? Observed(value) : Unknown("event_does_not_prove_account_state");
            if (id == 4781)
            {
                string? old = Clean(row, "account_name_before"), next = Clean(row, "account_name_after");
                before = old is not null && next is not null ? Observed(old) : Unknown("source_native_rename_names_not_observed");
                after = old is not null && next is not null ? Observed(next) : Unknown("source_native_rename_names_not_observed");
            }
            result["account_change"] = new JsonObject { ["change"] = accountChange, ["observed_transition"] = new JsonObject { ["before"] = before, ["after"] = after } };
        }
        return result;
    }
    internal static JsonObject? SourceChange(int id, JsonObject fields)
    {
        if (!Changes.TryGetValue(id, out var kind)) return null;
        string? Value(params string[] keys) => keys.Select(k => Clean(fields, k)).FirstOrDefault(v => v is { Length: > 0 } && v != "-") is string value ? string.Concat(value.EnumerateRunes().Take(512).Select(r => r.ToString())) : null;
        var values = new JsonObject();
        string? partial = null;
        if (kind is "attributes_changed" or "group_changed")
        {
            foreach (var field in kind == "attributes_changed" ? AccountFields : GroupFields) if (Value(field.First, field.Second) is string value) values[field.Public] = value;
            if (values.Count > 0) return new() { ["state"] = "observed", ["kind"] = kind, ["attributes"] = values };
            partial = kind == "attributes_changed" ? "account_attributes_not_present" : "group_change_attributes_not_present";
        }
        else if (kind == "group_type_changed")
        {
            if (Value("OldGroupType", "old_group_type") is string old) values["old_group_type"] = old;
            if (Value("NewGroupType", "new_group_type") is string next) values["new_group_type"] = next;
            if (values.Count == 0) partial = "group_type_values_not_present";
        }
        else if (kind == "audit_policy_changed")
        {
            foreach (var field in new[] { ("CategoryId", "audit_category_id", "category_id"), ("SubcategoryId", "audit_subcategory_id", "subcategory_id"), ("SubcategoryGuid", "audit_subcategory_guid", "subcategory_guid"), ("AuditPolicyChanges", "audit_policy_changes", "observed_value") })
                if (Value(field.Item1, field.Item2) is string value) values[field.Item3] = value;
            if (values.Count == 0) partial = "audit_policy_fields_not_present";
        }
        else if (kind == "security_log_cleared") { if (Value("Channel", "LogName", "cleared_log") is string cleared) values["observed_value"] = cleared; }
        else return null;
        if (partial is not null) return new() { ["state"] = "partial", ["kind"] = kind, ["detail"] = Unknown(partial) };
        values["state"] = "observed"; values["kind"] = kind; return values;
    }
    internal static void ApplyHistory(JsonArray items)
    {
        var priorBySid = new Dictionary<string, JsonObject>();
        foreach (var row in items.OfType<JsonObject>().OrderBy(r => TextTime(r)).ThenBy(r => EntityReader.Number(r, "event_db_id")))
        {
            if (row["account_change"] is not JsonObject observation || row["affected_account"]?["sid"]?.ToString().Trim() is not { Length: > 0 } sid) continue;
            if (!AccountStates.TryGetValue(checked((int)EntityReader.Number(row, "event_id")), out var after)) continue;
            if (priorBySid.TryGetValue(sid, out var prior)) observation["observed_transition"]!["before"] = new JsonObject { ["state"] = "partial", ["last_observed"] = prior.DeepClone(), ["reason"] = "intervening_account_state_not_proven" };
            priorBySid[sid] = new JsonObject { ["value"] = after, ["event_db_id"] = row["event_db_id"]?.DeepClone(), ["time_created_utc"] = row["time_created_utc"]?.DeepClone() };
        }
        static DateTimeOffset TextTime(JsonObject row) => DateTimeOffset.Parse(row["time_created_utc"]!.ToString(), CultureInfo.InvariantCulture);
    }
    static JsonObject Change(JsonObject row, int id)
    {
        if (row["source_native_change"] is JsonObject native) return (JsonObject)native.DeepClone();
        if (Changes.TryGetValue(id, out var change))
        {
            string? partial = change switch { "attributes_changed" => "account_attributes_not_present", "group_changed" => "group_change_attributes_not_present", "group_type_changed" => "group_type_values_not_present", "audit_policy_changed" => "audit_policy_fields_not_present", _ => null };
            return partial is null ? new() { ["state"] = "observed", ["kind"] = change } : new() { ["state"] = "partial", ["kind"] = change, ["detail"] = Unknown(partial) };
        }
        if (AccountChanges.TryGetValue(id, out var kind))
        {
            var result = new JsonObject { ["state"] = "observed", ["kind"] = kind };
            if (kind is "password_change_attempt" or "password_reset_attempt" && Clean(row, "result_code") is string code) result["result"] = Observed(code);
            return result;
        }
        return Unknown("source_change_not_established");
    }
    static string? Audit(string? keywords)
    {
        if (keywords is null) return null;
        string text = keywords.ToLowerInvariant().Replace(" ", "", StringComparison.Ordinal);
        if (text.Contains("auditsuccess", StringComparison.Ordinal)) return "success";
        if (text.Contains("auditfailure", StringComparison.Ordinal)) return "failure";
        ulong bits;
        if (text.StartsWith("0x", StringComparison.Ordinal)) { if (!ulong.TryParse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bits)) return null; }
        else if (long.TryParse(text, out long signed)) bits = unchecked((ulong)signed);
        else if (!ulong.TryParse(text, out bits)) return null;
        bool success = (bits & 0x0020000000000000) != 0, failure = (bits & 0x0010000000000000) != 0;
        return success == failure ? null : success ? "success" : "failure";
    }
    internal static JsonObject? IdentityBasis(string partition)
    {
        var pieces = new Dictionary<string, string>();
        foreach (var component in partition.Split('|'))
        {
            var pair = component.Split(':', 2);
            if (pair.Length != 2 || !pieces.TryAdd(pair[0], pair[1])) return null;
        }
        if (!pieces.TryGetValue("domain", out var domain) || !DomainRegex().IsMatch(domain) || !long.TryParse(domain, out long id)) return null;
        string? kind = pieces.Keys.ToHashSet().SetEquals(["domain", "account_sid"]) ? "exact_domain_account_sid"
            : pieces.Keys.ToHashSet().SetEquals(["domain", "member_sid", "group_sid"]) ? "exact_domain_member_group_sid"
            : pieces.Keys.ToHashSet().SetEquals(["domain", "account_member_sid"]) ? "exact_domain_account_member_sid" : null;
        if (kind is null || pieces.Any(p => p.Key != "domain" && (p.Value.Length > 184 || !SidRegex().IsMatch(p.Value)))) return null;
        var result = new JsonObject { ["kind"] = kind, ["domain_id"] = id };
        foreach (var (key, value) in pieces) if (key != "domain") result[key] = value;
        return result;
    }
    [GeneratedRegex(@"^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$")] private static partial Regex SidRegex();
    [GeneratedRegex(@"^[1-9][0-9]*$")] private static partial Regex DomainRegex();
    internal static readonly Dictionary<int,string> Families = new() { [4740]="account_lock",[4767]="account_lock",[4723]="password_operation",[4724]="password_operation",[4720]="account_lifecycle",[4722]="account_lifecycle",[4725]="account_lifecycle",[4726]="account_lifecycle",[4738]="account_change",[4781]="account_change",[4728]="group_membership",[4729]="group_membership",[4732]="group_membership",[4733]="group_membership",[4756]="group_membership",[4757]="group_membership",[4727]="group_lifecycle",[4730]="group_lifecycle",[4731]="group_lifecycle",[4734]="group_lifecycle",[4735]="group_lifecycle",[4737]="group_lifecycle",[4754]="group_lifecycle",[4755]="group_lifecycle",[4758]="group_lifecycle",[4764]="group_lifecycle",[4624]="authentication",[4625]="authentication",[4771]="authentication",[4776]="authentication",[4719]="audit_configuration",[1102]="audit_configuration" };
    internal static readonly Dictionary<int,string> Changes = new() { [4738]="attributes_changed",[4728]="member_added",[4732]="member_added",[4756]="member_added",[4729]="member_removed",[4733]="member_removed",[4757]="member_removed",[4727]="group_created",[4731]="group_created",[4754]="group_created",[4730]="group_deleted",[4734]="group_deleted",[4755]="group_deleted",[4737]="group_changed",[4735]="group_changed",[4758]="group_changed",[4764]="group_type_changed",[4719]="audit_policy_changed",[1102]="security_log_cleared" };
    internal static readonly Dictionary<int,string> AccountChanges = new() { [4720]="created",[4722]="enabled",[4723]="password_change_attempt",[4724]="password_reset_attempt",[4725]="disabled",[4726]="deleted",[4738]="attributes_changed",[4740]="locked",[4767]="unlocked",[4781]="renamed" };
    internal static readonly Dictionary<int,string> AccountStates = new() { [4720]="present",[4722]="enabled",[4725]="disabled",[4726]="deleted",[4740]="locked",[4767]="unlocked" };
    internal static readonly Dictionary<int,string> Outcomes = new() { [4624]="success",[4625]="failure",[4771]="failure" };
    internal static readonly int[] EventIds = [1102,4624,4625,4719,4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,4740,4754,4755,4756,4757,4758,4764,4767,4771,4776,4781];
    static readonly (string First,string Second,string Public)[] AccountFields = [("DisplayName","changed_display_name","display_name"),("SamAccountName","changed_sam_account_name","sam_account_name"),("UserPrincipalName","changed_user_principal_name","user_principal_name"),("HomeDirectory","changed_home_directory","home_directory"),("HomePath","changed_home_path","home_path"),("ScriptPath","changed_script_path","script_path"),("ProfilePath","changed_profile_path","profile_path"),("UserWorkstations","changed_user_workstations","user_workstations"),("PasswordLastSet","changed_password_last_set","password_last_set"),("AccountExpires","changed_account_expires","account_expires"),("PrimaryGroupId","changed_primary_group_id","primary_group_id"),("AllowedToDelegateTo","changed_allowed_to_delegate_to","allowed_to_delegate_to"),("UserAccountControl","changed_user_account_control","user_account_control"),("OldUacValue","old_user_account_control","old_user_account_control"),("NewUacValue","new_user_account_control","new_user_account_control")];
    static readonly (string First,string Second,string Public)[] GroupFields = [("Description","changed_description","description"),("DisplayName","changed_display_name","display_name"),("SamAccountName","changed_sam_account_name","sam_account_name"),("GroupType","changed_group_type","group_type")];
}
