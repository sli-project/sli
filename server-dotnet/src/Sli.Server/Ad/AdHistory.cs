using System.Text.Json.Nodes;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

public static class AdHistory
{
    internal static readonly JsonObject Taxonomy = JsonNode.Parse(new StreamReader(typeof(AdHistory).Assembly.GetManifestResourceStream("Sli.Server.Ad.event-taxonomy.json")!).ReadToEnd())!.AsObject();
    internal static JsonObject Map(string key) => Taxonomy[key]!.AsObject();
    internal static int[] Ids(string key) => Taxonomy[key]!.AsArray().Select(n => n!.GetValue<int>()).ToArray();
    internal static string? Kind(long id) => Map("_AD_ACCOUNT_CHANGE_KIND_BY_EVENT_ID")[id.ToString()]?.GetValue<string>();
    internal static string? After(long id) => id switch { 4720 => "present", 4722 => "enabled", 4725 => "disabled", 4726 => "deleted", 4740 => "locked", 4767 => "unlocked", _ => null };
    public static JsonObject AccountObservation(JsonObject row)
    {
        long id = row.Int("event_id"); string? kind = Kind(id);
        var change = Obj(new { kind });
        if (kind is "password_change_attempt" or "password_reset_attempt" && row.Text("result_code") is {} code) change["result"] = Obj(new { state = "observed", value = code });
        if (kind == "attributes_changed") change["detail"] = Unknown("changed_attribute_fields_not_in_warm_contract");
        JsonObject before = Unknown("prior_account_state_not_observed"), after;
        if (id == 4781)
        {
            string? oldName = row.Text("account_name_before"), newName = row.Text("account_name_after");
            before = oldName is not null && newName is not null ? Obj(new { state = "observed", value = oldName }) : Unknown("source_native_rename_names_not_observed");
            after = oldName is not null && newName is not null ? Obj(new { state = "observed", value = newName }) : Unknown("source_native_rename_names_not_observed");
        }
        else after = After(id) is {} value ? Obj(new { state = "observed", value }) : Unknown("event_does_not_prove_account_state");
        return new JsonObject { ["change"] = change, ["observed_transition"] = new JsonObject { ["before"] = before, ["after"] = after } };
    }
    internal static void Prior(IEnumerable<JsonObject> items, string account = "account", string sid = "target_user_sid", string? observation = null)
    {
        var previous = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        foreach (var row in items.OrderBy(r => r.Time("time_created_utc")).ThenBy(r => r.Int("event_db_id")))
        {
            string? key = row[account]?.Text(sid); if (key is null) continue;
            string? after = After(row.Int("event_id"));
            var obs = observation is null ? row : row[observation]!;
            if (after is not null && previous.TryGetValue(key, out var prior)) obs["observed_transition"]!["before"] = new JsonObject { ["state"] = "partial", ["last_observed"] = prior.DeepClone(), ["reason"] = "intervening_account_state_not_proven" };
            if (after is not null) previous[key] = Obj(new { value = after, event_db_id = row.Int("event_db_id"), time_created_utc = row.Text("time_created_utc") });
        }
    }
    public static JsonObject Compose(string kind, long domain, AdPeriod period, IReadOnlyList<JsonObject> events, bool history, bool sensitive = false)
    {
        string prefix = Prefix(kind);
        var groups = events.GroupBy(e => e.Int("event_db_id")).ToArray();
        if (groups.Length > 500 || kind != "powershell" && groups.Length != events.Count || events.Count > (kind == "powershell" ? 1000 : 500)) throw new AdInputException(prefix + "_input_bound_exceeded");
        var items = new List<JsonObject>();
        foreach (var group in groups)
        {
            var e = group.First(); long id = e.Int("event_id");
            bool valid = kind switch { "account" => Kind(id) is not null, "membership" => Map("_GROUP_MEMBERSHIP_CHANGE_BY_EVENT_ID").ContainsKey(id.ToString()), _ => id is 4103 or 4104 };
            if (!valid) throw new AdInputException(prefix + "_event_invalid");
            if (e.Time("time_created_utc") < period.Start || e.Time("time_created_utc") >= period.End) throw new AdInputException(prefix + "_event_outside_bounds");
            if (group.Key <= 0) throw new AdInputException(prefix + "_event_identity_invalid");
            if (e.Text("domain_controller") is null) throw new AdInputException(prefix + "_domain_controller_missing");
            var row = new JsonObject();
            foreach (string key in new[] { "event_db_id", "event_record_id", "event_id", "domain_controller" }) row[key] = e[key]?.DeepClone();
            row["time_created_utc"] = Iso(e.Time("time_created_utc"));
            row["actor"] = Principal(e, "subject_user_sid", "subject_user_name", kind != "membership",kind=="membership");
            row["evidence"] = Evidence(e, kind == "account");
            if (kind == "account")
            {
                row["account"] = Principal(e, "target_user_sid", "target_user_name", true);
                foreach (var field in AccountObservation(e)) row[field.Key] = field.Value?.DeepClone();
            }
            else if (kind == "membership")
            {
                row["member"] = Principal(e, "membership_member_sid", "membership_member_name");
                row["group"] = Principal(e, "target_user_sid", "target_user_name",cleanSid:true);
                var change = Map("_GROUP_MEMBERSHIP_CHANGE_BY_EVENT_ID")[id.ToString()]!;
                row["change"] = new JsonObject { ["operation"] = change[0]!.DeepClone(), ["group_scope"] = change[1]!.DeepClone() };
                row["controlled_group"] = e.Text("target_user_sid") is null ? Unknown("group_sid_not_observed")
                    : e.Int("controlled_group_context_evidence_id") <= 0 || e["controlled_group_context_observed_at_utc"] is null ? Unknown("group_not_observed_in_controlled_privileged_context")
                    : Obj(new { state = "observed", basis = "exact_group_sid_in_persisted_controlled_scope", context_evidence_id = e.Int("controlled_group_context_evidence_id"), context_observed_at_utc = Iso(e.Time("controlled_group_context_observed_at_utc")) });
                row["membership_interval"] = Unknown("membership_identity_not_observed");
            }
            else
            {
                var actor = (JsonObject)row["actor"]!;
                if (e.Text("subject_user_name") is null && e.Text("powershell_user_name") is {} name)
                { actor["state"] = "observed"; actor["subject_user_sid"] = e.Text("subject_user_sid"); actor["subject_user_name"] = name; }
                string? text = e.Text(id == 4103 ? "powershell_command_name" : "powershell_script_block_text");
                var activity = Obj(new { state = text is null ? "unknown" : id == 4104 && !sensitive ? "restricted" : "observed", kind = id == 4103 ? "command" : "script_block" });
                if (text is not null && (id == 4103 || sensitive)) activity[id == 4103 ? "command_name" : "script_block_text"] = text;
                if (sensitive && e.Text("powershell_script_block_text") is {} script) {
                    activity["script_block_text"] = script; activity["state"] = "observed";
                }
                row["activity"] = activity;
                var origins = group.Select(Origin).ToArray();
                var resolved = origins.Where(o => o.Text("state") == "observed").DistinctBy(o => o.ToJsonString()).ToArray();
                row["origin"] = resolved.Length == 0 ? origins[0] : resolved.Length == 1 ? resolved[0] : Unknown("ambiguous_complete_native_origin_chain");
            }
            items.Add(row);
        }
        items = items.OrderBy(r => r.Time("time_created_utc")).ThenBy(r => r.Int("event_db_id")).ToList();
        if (kind == "account") Prior(items);
        if (kind == "membership") PairMembership(items);
        if (items.Count > 0 && !history) throw new AdInputException(prefix + "_collection_coverage_invalid");
        string state = items.Count > 0 ? "available" : history ? kind == "powershell" ? "coverage_unverified" : "empty_unverified" : "not_collected";
        var result = Base(kind, domain, period, 500, false);
        result["state"] = state; result["items"] = Array(items);
        if (kind != "powershell") result["history_state"] = items.Count > 0 ? "partial" : "unknown";
        result["collection_coverage"] = Obj(new { state, history_event_present = history, source_completeness = "not_proven" });
        result["limitations"] = Limitations(kind);
        if (kind == "account" && items.Any(r => r["evidence"]!.Text("state") == "partial")) result["limitations"]!.AsArray().Add("Some rows have partial source provenance; inspect each evidence.missing_fields value.");
        return result;
    }
    public static string Prefix(string kind) => kind switch { "account" => "ad_account_change_history", "membership" => "ad_group_membership_history", "powershell" => "dc_powershell_activity", _ => "security_events" };
    public static (string Contract, string Report) Identity(string kind) => kind switch
    {
        "account" => ("sli.ad-account-change-history.v1", "ad.state.account_changes"),
        "membership" => ("sli.ad-group-membership-history.v1", "ad.groups.membership_changes"),
        "powershell" => ("sli.dc-powershell-activity.v1", "dc.powershell.activity"),
        _ => ("sli.security-events.v1", "security.events.chains")
    };
    public static JsonObject Base(string kind, long domain, AdPeriod period, int limit, bool denied)
    {
        var (contract, report) = Identity(kind);
        var result = Obj(new { contract_id = contract, report_key = report, source_domain_id = domain, state = denied ? "not_authorized" : "not_collected", items = new object[0] });
        result["time_bounds"] = period.Bounds;
        if (kind == "powershell") result["limits"] = Obj(new { input_event_limit = limit, origin_context_days = 31, bounded = true });
        else
        {
            result["limits"] = Obj(new { max_period_days = 31, row_limit = limit, bounded = true });
            if (kind == "security") { result["limits"]!["max_row_limit"] = 500; result["has_more"] = false; result["next_cursor"] = null; }
            else result["history_state"] = "unknown";
        }
        return result;
    }
    private static JsonArray Limitations(string kind) => Array(kind switch
    {
        "account" => new[] { "Rows are source-event observations, not a reconstructed current AD account status.", "A prior account state remains unknown unless the same source event supplies it.", "An empty window does not prove complete source coverage." },
        "membership" => new[] { "Rows are membership-change observations, not a reconstructed current group roster.", "A closed interval requires exactly one exact observed MemberSid and TargetSid add-before-remove pair; repeated or out-of-order boundaries remain unpaired partial observations.", "Controlled-group scope is observed separately and does not prove event-time rights or their use.", "Older facts without source-native MemberSid remain unknown; this reader does not backfill them.", "An empty window does not prove complete source coverage." },
        _ => new[] { "PowerShell 4103/4104 are evidence facts, not process sessions.", "Origin remains unknown unless one complete source-native process and LogonId chain is present.", "An empty window does not prove complete source coverage." }
    });
    private static JsonObject Origin(JsonObject row)
    {
        string? kind = row.Text("origin_kind");
        if (row.Text("origin_basis") == "nearest_logon" && row.Int("origin_session_start_event_db_id") > 0) {
            var origin = Obj(new { state="observed",kind,basis="nearest_logon",
                evidence=new { session_start_event_db_id=row.Int("origin_session_start_event_db_id") } });
            if (row.Text("origin_source_ip") is {} source) {
                origin[System.Net.IPAddress.TryParse(source,out _) ? "source_ip" : "workstation_name"] = source;
            }
            return origin;
        }
        string[] names = ["process_start", "process_stop", "session_start", "session_end"];
        if (kind is not ("powershell_remoting" or "rdp" or "local") || names.Any(k => row.Int("origin_" + k + "_event_db_id") <= 0 || row.Int("origin_" + k + "_boot_event_db_id") <= 0)) return Unknown("no_complete_native_origin_chain");
        if (names.Select(k => row.Int("origin_" + k + "_boot_event_db_id")).Distinct().Count() != 1) return Unknown("origin_crosses_security_boot_boundary");
        if (kind == "rdp" && row.Text("origin_source_ip") is null && row.Text("origin_workstation_name") is null) return Unknown("native_rdp_source_missing");
        var evidence = new JsonObject(); foreach (string k in names) evidence[k + "_event_db_id"] = row.Int("origin_" + k + "_event_db_id");
        evidence["boot_start_event_db_id"] = row.Int("origin_process_start_boot_event_db_id");
        var result = new JsonObject { ["state"] = "observed", ["kind"] = kind, ["evidence"] = evidence };
        if (row.Text("origin_source_ip") is {} ip) result["source_ip"] = ip;
        if (row.Text("origin_workstation_name") is {} ws) result["workstation_name"] = ws;
        return result;
    }
    private static void PairMembership(List<JsonObject> items)
    {
        foreach (var group in items.Where(r => r["member"]!.Text("sid") is not null && r["group"]!.Text("sid") is not null).GroupBy(r => (r["member"]!.Text("sid")!.ToLowerInvariant(), r["group"]!.Text("sid")!.ToLowerInvariant())))
        {
            var adds = group.Where(r => r["change"]!.Text("operation") == "added").ToArray(); var removes = group.Except(adds).ToArray();
            JsonObject interval;
            if (adds.Length == 1 && removes.Length == 1 && items.IndexOf(adds[0]) < items.IndexOf(removes[0]))
            {
                JsonObject Ref(JsonObject row) => Obj(new { event_db_id = row.Int("event_db_id"), event_id = row.Int("event_id"), time_created_utc = row.Text("time_created_utc") });
                interval = new JsonObject { ["state"] = "closed_observed", ["start"] = Ref(adds[0]), ["end"] = Ref(removes[0]) };
            }
            else interval = adds.Length == 1 && removes.Length == 0 ? Obj(new { state = "open_observed", reason = "matching_remove_not_observed_in_window" })
                : adds.Length == 0 && removes.Length == 1 ? Obj(new { state = "partial", reason = "membership_add_not_observed_in_window" })
                : Obj(new { state = "partial", reason = adds.Length == 1 && removes.Length == 1 ? "exact_membership_boundaries_out_of_order" : "multiple_exact_membership_boundaries_unpairable" });
            foreach (var row in group) row["membership_interval"] = interval.DeepClone();
        }
    }
}
