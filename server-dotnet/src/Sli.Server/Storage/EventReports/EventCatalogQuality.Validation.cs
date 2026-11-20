using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Storage.EventReports;

internal static partial class EventCatalogQuality
{
    const string Severities="critical high medium low info";
    const string Operators="one_of prefix suffix contains regex equals";
    // Storage V2 write contract (core + facts); catalogue pivots cannot invent columns.
    static readonly HashSet<string> StorageFields=("id raw_log_file_id server_id domain_id site_id log_source_id event_record_id event_id version level task opcode keywords_id provider_id channel_id computer_id time_created_utc subject_user_sid subject_user_name subject_domain_id target_user_sid target_user_name target_domain_id ip_address workstation_name logon_id correlation_id normalized_at normalized_hash noise_class noise_catalog_version source_core_sha256 "+
        "process_name process_id target_server_name service_name task_name task_action task_author run_as logon_type result_code object_name share_name message_sample powershell_user_name powershell_command_name powershell_script_block_text powershell_process_id account_target_sid account_target_name account_name_before account_name_after membership_member_sid membership_member_name process_parent_id process_command_line process_user_sid process_user_name process_user_domain process_logon_id service_file service_account service_start_type task_content task_change native_process_id file_audit_facts_json source_facts_sha256").Split(' ').ToHashSet();
    static bool Integer(JsonNode? n,out long value) { value=0; return n is JsonValue v && v.TryGetValue<long>(out value); }
    static bool Positive(JsonNode? n)=>Integer(n,out long v) && v>0;
    static bool Pattern(JsonNode? n)
    {
        try { foreach(var pattern in n is JsonArray a?a:new JsonArray(n?.DeepClone())) _=new Regex(Text(pattern)); return true; }
        catch(ArgumentException) { return false; }
    }
    internal static JsonObject ValidateCatalogData(JsonObject data)
    {
        var errors=new JsonArray();
        if(data["entries"] is not JsonArray entries) return new() { ["valid"]=false,["entry_count"]=0,["errors"]=new JsonArray(new JsonObject { ["code"]="entries_must_be_array" }) };
        var seen=new Dictionary<(string,string,string),int>();
        for(int index=0;index<entries.Count;index++)
        {
            void Error(string code,string? field=null,int? rule=null,string? role=null,int? first=null)
            {
                var error=new JsonObject { ["code"]=code,["index"]=index };
                if(field is not null) error["field"]=field; if(rule.HasValue) error["rule"]=rule.Value;
                if(role is not null) error["role"]=role; if(first.HasValue) error["first_index"]=first.Value; errors.Add(error);
            }
            if(entries[index] is not JsonObject entry) { Error("entry_must_be_object"); continue; }
            var identity=Identity(entry); if(!Complete(identity)) Error("invalid_identity");
            if(seen.TryGetValue(identity,out int first)) Error("duplicate_identity",first:first); else seen[identity]=index;
            if(!In(entry["severity"],Severities)) Error("invalid_severity");
            foreach(var (key,allowed) in new[]{("base_risk",Severities+" important"),("purpose_tier","critical important technical"),("category","authentication account_management privilege_management policy_change service_task operations infrastructure other unknown")})
                if(entry[key] is {} value && !In(value,allowed)) Error("invalid_"+key);
            if(entry["noise_class"] is {} noise)
            {
                const string allowed="signal context noise unknown";
                if(noise is JsonValue) { if(!In(noise,allowed)) Error("invalid_noise_class"); }
                else if(noise is not JsonObject predicate || !predicate.ContainsKey("default")) Error("invalid_noise_class");
                else
                {
                    if(!In(predicate["default"],allowed)) Error("predicate_default_invalid","noise_class");
                    if(predicate["rules"] is not JsonArray rules) Error("predicate_rules_must_be_array","noise_class");
                    else for(int r=0;r<rules.Count;r++)
                    {
                        if(rules[r] is not JsonObject rule) { Error("predicate_rule_must_be_object","noise_class",r); continue; }
                        if(!Field(rule["field"])) Error("predicate_field_invalid","noise_class",r);
                        if(!In(rule["op"],Operators)) Error("predicate_operator_invalid","noise_class",r);
                        if(!In(rule["then"],allowed)) Error("predicate_then_invalid","noise_class",r);
                        if(Text(rule["op"])=="regex" && !Pattern(rule["value"])) Error("predicate_regex_invalid","noise_class",r);
                    }
                }
            }
            ValidateLifecycle(entry,(code,field)=>Error(code,field));
            if(entry.ContainsKey("correlation"))
            {
                if(entry["correlation"] is null) { if(Text(entry["correlation_absent_reason"]).Trim().Length==0) Error("correlation_absent_reason_required"); }
                else if(entry["correlation"] is not JsonObject {Count:>0} c) Error("correlation_must_be_nonempty_object_or_null");
                else
                {
                    if(!In(c["role"],"open close step standalone")) Error("correlation_role_invalid");
                    if(!In(c["cardinality"],"pair chain fan_out")) Error("correlation_cardinality_invalid");
                    var keys=c["key"] as JsonArray ?? new JsonArray(c["key"]?.DeepClone());
                    if(keys.Count==0 || keys.Any(k=>!Field(k))) Error("correlation_key_invalid");
                    if(c["terminators"] is not JsonArray terminators || terminators.Any(t=>Text(t).Trim().Length==0)) Error("correlation_terminators_invalid");
                    else { if(Text(c["role"])=="open" && terminators.Count==0) Error("correlation_open_requires_terminator"); if(Text(c["cardinality"])=="pair" && terminators.Count>1) Error("correlation_pair_has_multiple_terminators"); }
                    if(!Positive(c["close_timeout_seconds"])) Error("correlation_timeout_invalid");
                }
            }
            if(entry["required_fields"] is {} required && (required is not JsonArray {Count:>0} fields || fields.Any(f=>!StorageFields.Contains(Text(f))))) Error("required_fields_invalid");
            if(entry["card"] is not null && entry["card"] is not JsonObject) { Error("card_must_be_object"); continue; }
            var card=entry["card"] as JsonObject??[];
            if(card["field_roles"] is not null && card["field_roles"] is not JsonObject) Error("field_roles_must_be_object");
            else foreach(var (role,names) in card["field_roles"] as JsonObject??[])
            {
                if(!new[]{"initiator","object","account","result"}.Contains(role)) Error("invalid_field_role",role:role);
                if(names is not JsonArray {Count:>0} pivots || pivots.Any(p=>!Field(p))) Error("invalid_field_pivot",role:role);
            }
            if(card["related_event_ids"] is {} related && (related is not JsonArray ids || ids.Any(id=>!Positive(id)))) Error("invalid_related_event_ids");
            var riskRules=card["risk_rules"] as JsonArray??[];
            for(int r=0;r<riskRules.Count;r++)
            {
                if(riskRules[r] is not JsonObject rule) { Error("risk_rule_must_be_object",rule:r); continue; }
                if(!In(rule["severity"]??entry["severity"],Severities)) Error("invalid_risk_rule_severity",rule:r);
                if(rule["confidence"] is {} conf && !In(conf,"low medium high")) Error("invalid_risk_rule_confidence",rule:r);
                if(rule["all"] is {} all && (all is not JsonArray conditions || conditions.Any(c=>c is not JsonObject))) Error("invalid_risk_rule_conditions",rule:r);
            }
        }
        return new() { ["valid"]=errors.Count==0,["entry_count"]=entries.Count,["errors"]=errors };
    }

    static void ValidateLifecycle(JsonObject entry,Action<string,string?> error)
    {
        if(entry["lifecycle"] is null) return;
        if(entry["lifecycle"] is not JsonObject lifecycle) { error("lifecycle_must_be_object",null); return; }
        foreach(string field in new[]{"raw_payload_days","record_days","warm_record_days"})
        {
            if(!lifecycle.ContainsKey(field)) { error("lifecycle_field_missing",field); continue; }
            string? Period(JsonNode? value)
            {
                if(Integer(value,out long days)) return days>0?null:"period_must_be_positive_integer_or_predicate";
                if(value is not JsonObject p || !p.ContainsKey("default")) return "period_must_be_positive_integer_or_predicate";
                if(!Positive(p["default"])) return "predicate_default_must_be_positive_integer";
                if(p["rules"] is not JsonArray rules) return "predicate_rules_must_be_array";
                foreach(var raw in rules)
                {
                    if(raw is not JsonObject r) return "predicate_rule_must_be_object";
                    if(!Field(r["field"])) return "predicate_field_invalid";
                    if(!In(r["op"],Operators)) return "predicate_operator_invalid";
                    if(!Positive(r["then"])) return "predicate_then_must_be_positive_integer";
                    if(Text(r["op"])=="regex" && !Pattern(r["value"])) return "predicate_regex_invalid";
                }
                return null;
            }
            if(Period(lifecycle[field]) is {} code) error(code,field);
        }
        if(!lifecycle.ContainsKey("rollup")) error("lifecycle_field_missing","rollup");
        else if(lifecycle["rollup"] is {} rollup && !(rollup is JsonValue v && v.TryGetValue<string>(out _))) error("lifecycle_rollup_invalid",null);
        if(lifecycle["rollup_role"] is {} role && !In(role,"open close boot_scope")) error("lifecycle_rollup_role_invalid",null);
        if(lifecycle["promotion"] is null) return;
        if(lifecycle["promotion"] is not JsonObject promotion) { error("lifecycle_promotion_must_be_object",null); return; }
        string[] missing=new[]{"version","archive_requirement","post_promotion_disposition","read_representation","high_volume","semantic_role","hot_need","warm_value","executable_lifecycle","budget"}.Where(f=>!promotion.ContainsKey(f)).ToArray();
        foreach(string field in missing) error("lifecycle_promotion_field_missing",field); if(missing.Length>0) return;
        if(Text(promotion["version"])!="descriptor-lifecycle-v2") error("lifecycle_promotion_version_invalid",null);
        if(!In(promotion["archive_requirement"],"archive_required no_archive")) error("lifecycle_archive_requirement_invalid",null);
        if(Text(promotion["post_promotion_disposition"])!="delete_source") error("lifecycle_disposition_invalid",null);
        if(!In(promotion["read_representation"],"archived_atomic derived_only")) error("lifecycle_read_representation_invalid",null);
        bool high=promotion["high_volume"] is JsonValue flag && flag.TryGetValue<bool>(out bool b) && b;
        if(promotion["high_volume"] is not JsonValue boolean || !boolean.TryGetValue<bool>(out _)) error("lifecycle_high_volume_invalid",null);
        foreach(string field in new[]{"semantic_role","hot_need","warm_value"}) if(promotion[field] is not JsonValue term || !term.TryGetValue<string>(out string? s) || string.IsNullOrWhiteSpace(s)) error("lifecycle_promotion_term_invalid",field);
        if(!In(promotion["executable_lifecycle"],"existing_warm_then_retention_executor semantic_then_direct_retention_executor")) error("lifecycle_executable_target_invalid",null);
        if(Text(promotion["executable_lifecycle"])=="semantic_then_direct_retention_executor" && Text(promotion["archive_requirement"])!="no_archive") error("lifecycle_direct_retention_requires_no_archive",null);
        if(promotion["budget"] is not JsonObject budget) { error("lifecycle_budget_must_be_object",null); return; }
        foreach(string field in new[]{"events_per_day_upper","source_bytes_per_event_upper","derived_bytes_per_object_upper","calibration"}) if(!budget.ContainsKey(field)) error("lifecycle_budget_field_missing",field);
        foreach(string field in new[]{"events_per_day_upper","source_bytes_per_event_upper","derived_bytes_per_object_upper"})
        { if(!Integer(budget[field],out long value) || value<0) error("lifecycle_budget_value_invalid",field); else if(high && value==0) error("high_volume_budget_must_be_positive",field); }
        if(!In(budget["calibration"],"representative production")) error("lifecycle_budget_calibration_invalid",null);
        if(high && (lifecycle["rollup"] is null || lifecycle["rollup_role"] is null)) error("high_volume_lifecycle_role_required",null);
        if(Text(promotion["archive_requirement"])=="no_archive" && Text(promotion["read_representation"])!="derived_only") error("no_archive_requires_derived_only",null);
        if(Text(promotion["archive_requirement"])=="archive_required" && Text(promotion["read_representation"])!="archived_atomic") error("archive_required_requires_archived_atomic",null);
    }
}
