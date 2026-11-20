using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Semantic;

// event_catalog_quality.py: catalogue declarations are data, never executable code.
internal static class EventCatalogQuality
{
    internal static readonly string[] Classification = ["base_risk", "purpose_tier", "noise_class", "category"];
    internal static readonly string[] V2 = ["lifecycle", "correlation", "required_fields"];
    internal static readonly string[] Periods = ["raw_payload_days", "record_days", "warm_record_days"];
    internal static readonly string[] PromotionFields = ["version", "archive_requirement", "post_promotion_disposition", "read_representation", "high_volume", "semantic_role", "hot_need", "warm_value", "executable_lifecycle", "budget"];
    internal static readonly string[] BudgetFields = ["events_per_day_upper", "source_bytes_per_event_upper", "derived_bytes_per_object_upper", "calibration"];
    private static readonly HashSet<string> StorageFields = ("id raw_log_file_id server_id domain_id site_id log_source_id event_record_id event_id version level task opcode keywords_id provider_id channel_id computer_id time_created_utc subject_user_sid subject_user_name subject_domain_id target_user_sid target_user_name target_domain_id ip_address workstation_name logon_id correlation_id normalized_at normalized_hash noise_class noise_catalog_version source_core_sha256 " +
        "process_name process_id target_server_name service_name task_name task_action task_author run_as logon_type result_code object_name share_name message_sample powershell_user_name powershell_command_name powershell_script_block_text powershell_process_id account_target_sid account_target_name account_name_before account_name_after membership_member_sid membership_member_name process_parent_id process_command_line process_user_sid process_user_name process_user_domain process_logon_id service_file service_account service_start_type task_content task_change native_process_id file_audit_facts_json source_facts_sha256").Split(' ').ToHashSet(StringComparer.Ordinal);
    internal static string Text(JsonNode? n) => n?.ToString() ?? "";
    internal static bool Present(JsonNode? n) => n is not null && n.ToJsonString() is not ("\"\"" or "[]" or "{}");
    internal static bool Integer(JsonNode? n, out long value)
    {
        value = 0;
        if (n is not JsonValue v) return false;
        if (v.TryGetValue<long>(out value)) return true;
        if (v.TryGetValue<int>(out int number)) { value = number; return true; }
        return false;
    }
    private static bool In(JsonNode? n, string values) => values.Split(' ').Contains(Text(n));
    private static bool Field(JsonNode? n) => Regex.IsMatch(Text(n), @"\A[A-Za-z][A-Za-z0-9_.:-]{0,127}\z", RegexOptions.CultureInvariant);
    private static string Fold(JsonNode? n) => UnicodeCaseFold.TrimAndFold(Text(n));
    internal static string Identity(JsonObject e) => string.Join('/', IdentityParts(e));
    private static string[] IdentityParts(JsonObject e) =>
        (new[] { "source", "stream", "event_key" }.Any(e.ContainsKey) ? new[] { "source", "stream", "event_key" } : new[] { "channel", "event_id", "provider_name" }).Select(k => Fold(e[k])).ToArray();
    private static string LegacyIdentity(JsonObject e) => string.Join('/', new[] { "channel", "event_id", "provider_name" }.Select(k => Fold(e[k])));
    internal static string Fingerprint(JsonNode node) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson.Serialize(node, ensureAscii: false))));
    internal static JsonObject BuildBaseline(JsonObject data)
    {
        var fingerprints = new JsonObject();
        foreach (var entry in Entries(data)) fingerprints[Identity(entry)] = Fingerprint(entry);
        return new() { ["schema_version"] = 2, ["entry_count"] = fingerprints.Count, ["fingerprints"] = fingerprints };
    }
    internal static IEnumerable<JsonObject> Entries(JsonObject data) => (data["entries"] as JsonArray ?? []).OfType<JsonObject>();
    internal static JsonObject ValidateChanges(JsonObject data, JsonObject baseline)
    {
        var known = baseline["fingerprints"] as JsonObject ?? new();
        var violations = new JsonArray(); int added = 0, changed = 0, index = -1;
        foreach (var raw in data["entries"] as JsonArray ?? [])
        {
            index++; if (raw is not JsonObject e) continue;
            string identity = Identity(e), legacy = LegacyIdentity(e);
            string previous = Text(known[identity]);
            if (previous.Length == 0 && legacy.Split('/').All(s => s.Length > 0)) previous = Text(known[legacy]);
            string kind;
            if (previous.Length == 0) { added++; kind = "новая"; }
            else if (previous != Fingerprint(e)) { changed++; kind = "изменённая"; }
            else continue;
            var missing = Classification.Where(k => !Present(e[k])).Concat(V2.Where(k => !e.ContainsKey(k)))
                .Concat(new[] { "source", "stream", "event_key" }.Where(k => Text(e[k]).Trim().Length == 0)).ToList();
            if (e["lifecycle"] is JsonObject lifecycle) missing.AddRange(Periods.Append("rollup").Where(k => !lifecycle.ContainsKey(k)).Select(k => "lifecycle." + k));
            if (missing.Count > 0) violations.Add(new JsonObject { ["index"] = index, ["identity"] = identity, ["вид"] = kind, ["не_заполнено"] = Strings(missing) });
        }
        return new() { ["valid"] = violations.Count == 0, ["новых"] = added, ["изменённых"] = changed, ["освобождено_прежних"] = known.Count - changed, ["нарушений"] = violations.Count, ["violations"] = violations };
    }
    internal static JsonArray Strings(IEnumerable<string> strings) => new(strings.Select(s => JsonValue.Create(s)).ToArray());
    internal static JsonObject Completeness(JsonObject data)
    {
        var entries = Entries(data).ToArray(); var counts = new JsonObject();
        foreach (string key in Classification.Concat(V2)) counts[key] = entries.Count(e => Present(e[key]));
        int full = entries.Count(e => Classification.All(k => Present(e[k])));
        return new() { ["entry_count"] = entries.Length, ["fully_classified"] = full, ["classification_ratio"] = entries.Length == 0 ? 1 : (double)full / entries.Length,
            ["schema_v2_ready"] = entries.Count(e => V2.All(e.ContainsKey)), ["declared_per_field"] = counts };
    }
    internal static JsonObject Validate(JsonObject data)
    {
        var errors = new JsonArray();
        if (data["entries"] is not JsonArray entries) return new() { ["valid"] = false, ["entry_count"] = 0, ["errors"] = new JsonArray(new JsonObject { ["code"] = "entries_must_be_array" }) };
        var seen = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < entries.Count; i++)
        {
            void Error(string code, string? field = null) => errors.Add(new JsonObject { ["code"] = code, ["index"] = i, ["field"] = field });
            if (entries[i] is not JsonObject e) { Error("entry_must_be_object"); continue; }
            string identity = Identity(e);
            if (IdentityParts(e).Any(s => s.Length == 0)) Error("invalid_identity");
            if (!seen.TryAdd(identity, i)) errors.Add(new JsonObject { ["code"] = "duplicate_identity", ["index"] = i, ["first_index"] = seen[identity] });
            if (!In(Text(e["severity"]).ToLowerInvariant(), "critical high medium low info")) Error("invalid_severity");
            foreach (var (key, allowed) in new[] { ("base_risk", "critical high medium low info important"), ("purpose_tier", "critical important technical"), ("category", "authentication account_management privilege_management policy_change service_task operations infrastructure other unknown") })
                if (e[key] is not null && !In(Text(e[key]).ToLowerInvariant(), allowed)) Error("invalid_" + key);
            if (e["noise_class"] is { } noise) Predicate(noise, false, "noise_class", Error);
            if (e["lifecycle"] is { } lifecycleNode)
            {
                if (lifecycleNode is not JsonObject lifecycle) Error("lifecycle_must_be_object");
                else
                {
                    foreach (string key in Periods)
                        if (!lifecycle.ContainsKey(key)) Error("lifecycle_field_missing", key);
                        else Predicate(lifecycle[key], true, key, Error);
                    if (!lifecycle.ContainsKey("rollup")) Error("lifecycle_field_missing", "rollup");
                    else if (lifecycle["rollup"] is { } rollup && !IsString(rollup)) Error("lifecycle_rollup_invalid");
                    if (lifecycle["rollup_role"] is { } role && !In(role, "open close boot_scope")) Error("lifecycle_rollup_role_invalid");
                    PromotionErrors(lifecycle, Error);
                }
            }
            if (e.ContainsKey("correlation"))
            {
                if (e["correlation"] is null) { if (Text(e["correlation_absent_reason"]).Trim().Length == 0) Error("correlation_absent_reason_required"); }
                else if (e["correlation"] is not JsonObject { Count: > 0 } c) Error("correlation_must_be_nonempty_object_or_null");
                else
                {
                    if (!In(c["role"], "open close step standalone")) Error("correlation_role_invalid");
                    if (!In(c["cardinality"], "pair chain fan_out")) Error("correlation_cardinality_invalid");
                    var keys = c["key"] is JsonArray ka ? ka.ToArray() : new[] { c["key"] };
                    if (keys.Length == 0 || keys.Any(k => !Field(k))) Error("correlation_key_invalid");
                    if (c["terminators"] is not JsonArray terms || terms.Any(t => Text(t).Trim().Length == 0)) Error("correlation_terminators_invalid");
                    else
                    {
                        if (Text(c["role"]) == "open" && terms.Count == 0) Error("correlation_open_requires_terminator");
                        if (Text(c["cardinality"]) == "pair" && terms.Count > 1) Error("correlation_pair_has_multiple_terminators");
                    }
                    if (!Integer(c["close_timeout_seconds"], out long timeout) || timeout <= 0) Error("correlation_timeout_invalid");
                }
            }
            if (e["required_fields"] is { } fields && (fields is not JsonArray { Count: > 0 } a || a.Any(f => !StorageFields.Contains(Text(f))))) Error("required_fields_invalid");
            if (Present(e["card"]) && e["card"] is not JsonObject) { Error("card_must_be_object"); continue; }
            var card = e["card"] as JsonObject ?? new();
            if (Present(card["field_roles"]) && card["field_roles"] is not JsonObject) Error("field_roles_must_be_object");
            else foreach (var (role, pivots) in card["field_roles"] as JsonObject ?? new())
            {
                if (!new[] { "initiator", "object", "account", "result" }.Contains(role)) Error("invalid_field_role", role);
                if (pivots is not JsonArray { Count: > 0 } list || list.Any(p => !Field(p))) Error("invalid_field_pivot", role);
            }
            if (Present(card["related_event_ids"]) && (card["related_event_ids"] is not JsonArray related || related.Any(v => !Integer(v, out long id) || id <= 0))) Error("invalid_related_event_ids");
            foreach (var node in card["risk_rules"] as JsonArray ?? [])
            {
                if (node is not JsonObject rule) { Error("risk_rule_must_be_object"); continue; }
                if (!In(Text(rule["severity"] ?? e["severity"]).ToLowerInvariant(), "critical high medium low info")) Error("invalid_risk_rule_severity");
                if (rule["confidence"] is { } confidence && !In(Text(confidence).ToLowerInvariant(), "low medium high")) Error("invalid_risk_rule_confidence");
                if (Present(rule["all"]) && (rule["all"] is not JsonArray conditions || conditions.Any(c => c is not JsonObject))) Error("invalid_risk_rule_conditions");
            }
        }
        return new() { ["valid"] = errors.Count == 0, ["entry_count"] = entries.Count, ["errors"] = errors };
    }
    internal static bool IsString(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out _);
    private static void Predicate(JsonNode? value, bool period, string field, Action<string, string?> error)
    {
        if (period && Integer(value, out long days) && days > 0) return;
        if (!period && IsString(value)) { if (!In(Text(value).ToLowerInvariant(), "signal context noise unknown")) error("invalid_" + field, null); return; }
        if (value is not JsonObject p || !p.ContainsKey("default")) { error(period ? "period_must_be_positive_integer_or_predicate" : "invalid_" + field, field); return; }
        bool Valid(JsonNode? n) => period ? Integer(n, out long d) && d > 0 : In(Text(n).ToLowerInvariant(), "signal context noise unknown");
        if (!Valid(p["default"])) { error(period ? "predicate_default_must_be_positive_integer" : "predicate_default_invalid", field); if (period) return; }
        if (p["rules"] is not JsonArray rules) { error("predicate_rules_must_be_array", field); return; }
        foreach (var node in rules)
        {
            string? code = null;
            if (node is not JsonObject rule) code = "predicate_rule_must_be_object";
            else
            {
                if (!Field(rule["field"])) code = "predicate_field_invalid";
                else if (!In(rule["op"], "one_of prefix suffix contains regex equals")) code = "predicate_operator_invalid";
                else if (!Valid(rule["then"])) code = period ? "predicate_then_must_be_positive_integer" : "predicate_then_invalid";
                else if (Text(rule["op"]) == "regex")
                {
                    var patterns = rule["value"] is JsonArray values ? values.ToArray() : new[] { rule["value"] };
                    try { foreach (var pattern in patterns) _ = new Regex(Text(pattern), RegexOptions.CultureInvariant); }
                    catch (ArgumentException) { code = "predicate_regex_invalid"; }
                }
            }
            if (code is not null) { error(code, field); if (period) return; }
        }
    }
    internal static void PromotionErrors(JsonObject lifecycle, Action<string, string?> error)
    {
        if (lifecycle["promotion"] is null) return;
        if (lifecycle["promotion"] is not JsonObject p) { error("lifecycle_promotion_must_be_object", null); return; }
        var missing = PromotionFields.Where(k => !p.ContainsKey(k)).ToArray();
        foreach (string key in missing) error("lifecycle_promotion_field_missing", key);
        if (missing.Length > 0) return;
        if (Text(p["version"]) != "descriptor-lifecycle-v2") error("lifecycle_promotion_version_invalid", null);
        if (!In(p["archive_requirement"], "archive_required no_archive")) error("lifecycle_archive_requirement_invalid", null);
        if (Text(p["post_promotion_disposition"]) != "delete_source") error("lifecycle_disposition_invalid", null);
        if (!In(p["read_representation"], "archived_atomic derived_only")) error("lifecycle_read_representation_invalid", null);
        if (p["high_volume"] is not JsonValue b || !b.TryGetValue<bool>(out _)) error("lifecycle_high_volume_invalid", null);
        bool high = p["high_volume"] is JsonValue highValue && highValue.TryGetValue<bool>(out bool flag) && flag;
        foreach (string key in new[] { "semantic_role", "hot_need", "warm_value" })
            if (!IsString(p[key]) || Text(p[key]).Trim().Length == 0) error("lifecycle_promotion_term_invalid", key);
        if (!In(p["executable_lifecycle"], "existing_warm_then_retention_executor semantic_then_direct_retention_executor")) error("lifecycle_executable_target_invalid", null);
        if (Text(p["executable_lifecycle"]) == "semantic_then_direct_retention_executor" && Text(p["archive_requirement"]) != "no_archive") error("lifecycle_direct_retention_requires_no_archive", null);
        if (p["budget"] is not JsonObject budget) { error("lifecycle_budget_must_be_object", null); return; }
        foreach (string key in BudgetFields.Where(k => !budget.ContainsKey(k))) error("lifecycle_budget_field_missing", key);
        foreach (string key in BudgetFields.Take(3))
            if (!Integer(budget[key], out long n) || n < 0) error("lifecycle_budget_value_invalid", key);
            else if (high && n == 0) error("high_volume_budget_must_be_positive", key);
        if (!In(budget["calibration"], "representative production")) error("lifecycle_budget_calibration_invalid", null);
        if (high && (lifecycle["rollup"] is null || lifecycle["rollup_role"] is null)) error("high_volume_lifecycle_role_required", null);
        if (Text(p["archive_requirement"]) == "no_archive" && Text(p["read_representation"]) != "derived_only") error("no_archive_requires_derived_only", null);
        if (Text(p["archive_requirement"]) == "archive_required" && Text(p["read_representation"]) != "archived_atomic") error("archive_required_requires_archived_atomic", null);
    }
}
