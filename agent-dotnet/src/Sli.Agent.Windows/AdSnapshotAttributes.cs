using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;
using static Sli.Agent.Windows.SnapshotJson;

namespace Sli.Agent.Windows;

internal static class AdSnapshotAttributes
{
    internal static readonly JsonObject Schema = JsonNode.Parse(DirectorySnapshotReader.Resource("ad-schema.json"))!.AsObject();
    private static readonly string[] SecurityDates = ["pwdlastset", "mslaps-passwordexpirationtime", "ms-mcs-admpwdexpirationtime"];
    internal static JsonObject Attributes(JsonObject props, string kind, JsonNode? schema = null)
    {
        var attrs = new JsonObject();
        foreach (var source in Rows(Schema["attribute_order"]).Select(n => Text(n)))
            if (props.ContainsKey(source)) attrs[Text(Schema["attributes"]![source])] = Rows(Schema["multi"]).Any(n => Text(n) == source) ? Array(Values(props[source]).Select(n => n.ToString())) : Copy(props[source]);
        if (kind == "ad_user" && Text(props["displayname"]) != "") attrs["display_name"] = Copy(props["displayname"]);
        var account = kind is "ad_user" or "ad_computer";
        if (account) { attrs["object_class"] = kind == "ad_user" ? "user" : "computer"; attrs["object_classes"] = Array(Values(props["objectclass"]).Select(n => n.ToString())); }
        foreach (var (source, target) in Schema["dates"]!.AsObject()) if (!account || !SecurityDates.Contains(source)) attrs[Text(target)] = Utc(props[source]);
        foreach (var source in Rows(Schema["interval_order"]).Select(n => Text(n))) if (props[source] is not null)
        {
            var seconds = Math.Abs(Int(props[source])) / 10000000;
            attrs[Text(Schema["intervals"]![source])] = (seconds >= 86400 ? (seconds / 86400).ToString(System.Globalization.CultureInfo.InvariantCulture) + "." : "") + FormattableString.Invariant($"{seconds % 86400 / 3600:00}:{seconds % 3600 / 60:00}:{seconds % 60:00}");
        }
        if (account)
        {
            foreach (var source in SecurityDates)
            {
                var target = Text(Schema["dates"]![source]).Replace("_utc", "", StringComparison.Ordinal);
                string? stamp = null;
                var status = Text(schema?[source]) == "absent" ? "schema_absent" : "not_returned";
                if (props[source] is { } value)
                {
                    try
                    {
                        if (value is JsonValue v && v.TryGetValue<bool>(out _) || long.TryParse(value.ToString(), out var number) && number < 0) throw new FormatException();
                        stamp = Utc(value); status = stamp is null ? "not_set" : "observed";
                    }
                    catch (Exception e) when (e is FormatException or ArgumentOutOfRangeException or OverflowException) { status = "parse_error"; }
                }
                attrs[target + "_utc"] = stamp; attrs[target + "_status"] = status;
            }
            const string rbcd = "msds-allowedtoactonbehalfofotheridentity";
            var rb = props[rbcd]; bool? present = null; JsonNode? sids = null; string? digest = null;
            var rbStatus = Text(schema?[rbcd]) == "absent" ? "schema_absent" : "not_returned";
            if (rb is JsonValue flag && flag.TryGetValue<bool>(out var p)) { present = p; rbStatus = p ? "not_collected" : "observed"; if (!p) sids = new JsonArray(); }
            else if (rb is not null)
            {
                rbStatus = "parse_error";
                if (rb is JsonObject obj && Flag(obj["present"]))
                {
                    present = true;
                    if (Regex.IsMatch(Text(obj["descriptor_sha256"]), "\\A[0-9a-f]{64}\\z")) digest = Text(obj["descriptor_sha256"]);
                    if (Text(obj["status"]) is "observed" or "partial" && obj["sids"] is JsonArray candidates && candidates.Count <= 256
                        && candidates.All(n => JsonRead.TryString(n, out var s) && s.Length <= 256 && Regex.IsMatch(s, @"\AS-1-(?:\d+-)+\d+\z")))
                    { sids = Array(candidates.Select(n => Text(n)).Distinct().Order(StringComparer.Ordinal)); rbStatus = Text(obj["status"]); }
                }
            }
            attrs["resource_based_delegation_present"] = present; attrs["resource_based_delegation_sids"] = sids;
            attrs["resource_based_delegation_status"] = rbStatus; attrs["resource_based_delegation_descriptor_sha256"] = digest;
            long? uac = props["useraccountcontrol"] is null ? null : Int(props["useraccountcontrol"]);
            attrs["user_account_control"] = uac; attrs["enabled"] = uac is null ? null : (uac & 2) == 0;
            foreach (var (name, bit) in Schema["uac"]!.AsObject()) attrs[name] = uac is null ? null : (uac & Int(bit)) != 0;
            long? computed = props["msds-user-account-control-computed"] is null ? null : Int(props["msds-user-account-control-computed"]);
            attrs["locked_out"] = computed is null ? null : (computed & 16) != 0; attrs["password_expired"] = computed is null ? null : (computed & 8388608) != 0;
            attrs["kerberos_preauth_required"] = uac is null ? null : (uac & 4194304) == 0;
            attrs["password_expiry_status"] = attrs["password_expiry_utc"] is not null ? "observed" : (uac & 65536) != 0 && uac is not null ? "not_applicable" : "missing_in_source";
            attrs["effective_password_policy_dn"] = Copy(props["msds-resultantpso"]); attrs["effective_password_policy_source"] = Text(props["msds-resultantpso"]) != "" ? "fine_grained" : "default_domain";
            attrs["last_logon_utc"] = Copy(attrs["last_logon_timestamp_utc"]);
        }
        if (kind == "ad_computer")
        {
            attrs["created_utc"] = Copy(attrs["when_created_utc"]); attrs["technical_inventory_status"] = "not_collected";
            var states = new JsonObject();
            foreach (var key in Rows(Schema["computer_source_order"]).Select(n => Text(n))) states[key] = new JsonObject { ["state"] = attrs[key] is null ? "absent_in_source" : "present", ["source_attribute"] = Copy(Schema["computer_sources"]![key]) };
            attrs["attribute_states"] = new JsonObject(states.Take(5).Select(p => KeyValuePair.Create(p.Key, Copy(p.Value))));
            attrs["computer_reference_attribute_states"] = states;
        }
        if (kind == "ad_group")
        {
            var group = Int(props["grouptype"]);
            attrs["group_category"] = (group & 0x80000000L) != 0 ? "Security" : "Distribution";
            attrs["group_scope"] = (group & 2) != 0 ? "Global" : (group & 4) != 0 ? "DomainLocal" : (group & 8) != 0 ? "Universal" : null;
        }
        if (kind == "domain_trust")
        {
            attrs["trust_direction"] = Int(props["trustdirection"]) switch { 1 => "Inbound", 2 => "Outbound", 3 => "BiDirectional", _ => "Unknown" };
            attrs["trust_type"] = Int(props["trusttype"]) switch { 1 => "Downlevel", 2 => "Uplevel", 3 => "MIT", 4 => "DCE", _ => "Unknown" };
        }
        return attrs;
    }
}
