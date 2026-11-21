using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Domains;

namespace Sli.Server.Problems;

public static class ProblemPresentation
{
    private static readonly Lazy<Dictionary<string, string>> Ru = new(() => Catalog("ru"));
    private static readonly Lazy<Dictionary<string, string>> En = new(() => Catalog("en"));
    private static Dictionary<string, string> Catalog(string locale)
    {
        using var stream = typeof(ProblemPresentation).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server." + locale + ".json")!;
        return JsonSerializer.Deserialize<Dictionary<string, string>>(stream)!;
    }
    public static JsonObject Message(string code, string language = "", JsonObject? parameters = null)
    {
        var catalog = DomainHttp.SelectEnglish(language) ? En.Value : Ru.Value;
        var alternate = DomainHttp.SelectEnglish(language) ? Ru.Value : En.Value; parameters ??= new();
        string text = catalog.GetValueOrDefault(code) ?? alternate.GetValueOrDefault(code) ?? code;
        if (code == "security.problems.presentation.t109.agent-tamper.what") {
            if (parameters["actor"] is null || string.IsNullOrWhiteSpace(parameters["actor"]!.ToString()))
                text = Regex.Replace(text, @"[,;]\s+[^,;]*\{actor\}[^.]*", "");
            if (parameters["computer"] is null) text = text.Replace(" на {computer}", "").Replace(" on {computer}", "");
            if (parameters["time"] is null) text = text.Replace(" в {time}", "").Replace(" at {time}", "");
        }
        if (code is "security.problems.presentation.kerberoasting_what" or "security.problems.presentation.asrep_what") {
            if (parameters["source"] is null) text = text.Replace(", запрос с {source}", "").Replace(", requested from {source}", "")
                .Replace(" с {source}", "").Replace(" from {source}", "");
            if (parameters["time"] is null) text = text.Replace(" в {time}", "").Replace(" at {time}", "");
            if (parameters["minutes"] is null) text = text.Replace(" за {minutes} мин", "").Replace(" in {minutes} min", "");
            if (parameters["count"] is null) text = text.Replace("{count} ", "");
        }
        text = Render(text, parameters);
        return new() { ["code"] = code, ["params"] = parameters, ["text"] = text };
    }
    internal static string Render(string text, JsonObject parameters)
    {
        // A clause with an absent fact must not turn into a claim about an unnamed object.
        text = string.Concat(Regex.Split(text, @"(?<=[.!?;])\s+").Where(clause =>
            Regex.Matches(clause, @"\{([^{}]+)\}").All(match =>
                parameters[match.Groups[1].Value] is {} node && !string.IsNullOrWhiteSpace(node.ToString()))).Select(clause => clause + " ")).Trim();
        text = Regex.Replace(text, @"\{([^{}]+)\}", match => parameters[match.Groups[1].Value]?.ToString() ?? "");
        return text;
    }

    internal static string RuleMessageCode(string rule, string suffix)
    {
        string id = rule.StartsWith("semantic.", StringComparison.Ordinal) ? rule[9..] : rule;
        string prefix = "security.problems.presentation.";
        string direct = prefix + id + "." + suffix;
        if (Ru.Value.ContainsKey(direct) || En.Value.ContainsKey(direct)) return direct;
        string? legacy = id switch {
            "qw.password-spray" => suffix is "why" or "next" ? "password" : "spray",
            "qw.password-brute-force" => suffix is "why" or "next" ? "password" : "brute",
            "qw.disabled-account-logon" => suffix is "why" or "next" ? "password" : "disabled",
            "qw.account-watch" => "watch", "qw.account-decoy" => "decoy", "qw.file-decoy" => "file_decoy",
            "qw.file-acl-broad-write" => "file_acl_broad",
            "security.audit_controls_changed" => "audit",
            "security.privileged_group_member_added" => "privileged_group",
            "security.scheduled_task_created" => "scheduled_task",
            _ => Semantic.Detections.IdentityAttacks.Rules.GetValueOrDefault(id)
        };
        if (legacy is not null) {
            string key = prefix + legacy + "_" + (legacy == "file_acl_broad" && suffix == "why" ? "what" : suffix);
            return Ru.Value.ContainsKey(key) || En.Value.ContainsKey(key) ? key : rule;
        }
        if (id.StartsWith("qw.", StringComparison.Ordinal)) {
            string precursor = prefix + "t109." + id[3..] + "." + suffix;
            if (Ru.Value.ContainsKey(precursor) || En.Value.ContainsKey(precursor)) return precursor;
        }
        return rule;
    }
    internal static bool HasRuleMessage(string rule, string suffix, string language) =>
        (DomainHttp.SelectEnglish(language) ? En.Value : Ru.Value).ContainsKey(RuleMessageCode(rule, suffix));

    internal static string? PresentationCode(JsonObject finding) => ProblemJson.Text(finding["rule_code"]) switch {
        "semantic.security.audit_controls_changed" => "audit_policy_changed",
        "semantic.security.privileged_group_member_added" => "privileged_group",
        "semantic.security.scheduled_task_created" => "scheduled_task",
        "semantic.qw.security-log-cleared" => "eventlog_cleared",
        "semantic.qw.password-spray" => "password_spray", "semantic.qw.password-brute-force" => "password_brute",
        "semantic.qw.disabled-account-logon" => "password_disabled", "semantic.qw.account-watch" => "account_watch_activity",
        "semantic.qw.account-decoy" => "account_decoy_used", "semantic.qw.file-decoy" => "file_decoy_touched",
        "semantic.qw.file-acl-broad-write" => "file_acl_broad_write", "" => null, var rule => rule };

    internal static bool CatalogDetection(string rule) => rule is "semantic.qw.privileged-group-addition" or "semantic.qw.security-log-cleared" or "semantic.qw.audit-disabled";
    internal static bool IsPasswordFinding(string rule) => rule is "semantic.qw.password-brute-force" or "semantic.qw.password-spray";
    internal static JsonObject RuleParameters(JsonObject finding, ProblemAccess? access = null, string language = "")
    {
        var parameters = new JsonObject();
        bool identity = access is null || access.Fields("identity_basic");
        bool technical = access is null || access.Fields("technical");
        string? Name(JsonNode? value) {
            string raw = ProblemJson.Text(value).Trim();
            return raw is "" or "-" or "—" ? null : ProblemJson.Text(finding["identity_context"]?["principals"]?[raw]?["label"]) is { Length: > 0 } label ? label :
                Regex.IsMatch(raw, @"\A(?:sid:(?:[^:]+:)*)?S-1-", RegexOptions.IgnoreCase) ? null : raw[..Math.Min(raw.Length, 2048)];
        }
        if (identity) {
            parameters["actor"] = Name(finding["identity_context"]?["actor"]?["label"] ?? finding["actor"] ?? finding["presentation_facts"]?["actor"]);
            parameters["account"] = Name(finding["presentation_facts"]?["account"] ?? finding["account"] ?? finding["target"]);
            parameters["target"] = Name(finding["target"]);
            var hosts = ProblemJson.Array(finding["evidence"]).OfType<JsonObject>().Select(e => Name(e["hostname"])).Where(h => h is not null).Distinct().ToArray();
            parameters["computer"] = Name(finding["computer"] ?? finding["hostname"] ?? finding["presentation_facts"]?["computer"]) ?? (hosts.Length == 1 ? hosts[0] : null);
            if (parameters["computer"] is null && ProblemJson.Text(finding["rule_code"]).StartsWith("semantic.qw.agent-", StringComparison.Ordinal)) parameters["computer"] = Name(finding["target"]);
            parameters["host"] = parameters["computer"]?.DeepClone();
            if (CatalogDetection(ProblemJson.Text(finding["rule_code"]))) {
                var facts = finding["presentation_facts"];
                parameters["actor"] = facts is null ? Name(finding["identity_context"]?["actor"]?["label"] ?? finding["actor"]) : Name(facts["actor"]);
                parameters["member"] = Name(facts?["member"]);
                parameters["group"] = Name(facts?["group"]);
                parameters["category"] = Name(facts?["category"]);
                string category = ProblemJson.Text(facts?["category_id"]);
                string categoryCode = "security.problems.presentation.audit_category." + category;
                if ((DomainHttp.SelectEnglish(language) ? En.Value : Ru.Value).ContainsKey(categoryCode))
                    parameters["category"] = Message(categoryCode, language)["text"]?.DeepClone();
                parameters["account"] = null;
                parameters["computer"] = Name(facts?["computer"]) ?? parameters["computer"]?.DeepClone();
            }
        }
        var source = finding["presentation_facts"]?["source"] ?? finding["source"];
        if (technical && !Regex.IsMatch(ProblemJson.Text(source), @"\A\d+\z")) parameters["source"] = Name(source);
        parameters["count"] = finding["presentation_facts"]?["count"]?.DeepClone() ?? finding["occurrence_count"]?.DeepClone() ?? finding["evidence_count"]?.DeepClone();
        parameters["time"] = finding["presentation_facts"]?["time"]?.DeepClone() ?? finding["last_seen_utc"]?.DeepClone();
        if (ProblemJson.Text(finding["rule_code"]) is "semantic.qw.kerberoasting" or "semantic.qw.asrep-roasting")
            parameters["minutes"] = finding["presentation_facts"]?["minutes"]?.DeepClone();
        foreach (string key in parameters.Where(p => p.Value is null).Select(p => p.Key).ToArray()) parameters.Remove(key);
        return parameters;
    }
    internal static JsonObject RuleMessage(JsonObject finding, string suffix, string language, ProblemAccess? access = null)
    {
        string rule = ProblemJson.Text(finding["rule_code"]);
        bool password = IsPasswordFinding(rule);
        if (password && ProblemJson.Bool(finding["presentation_facts"]?["password_success"])) rule = "semantic.qw.password-success";
        var parameters = RuleParameters(finding, access, language);
        string code = RuleMessageCode(rule, suffix);
        if (suffix == "next" && (CatalogDetection(rule) || rule == "semantic.qw.agent-tamper") &&
            (parameters["actor"] is null || rule == "semantic.qw.privileged-group-addition" && parameters["member"] is null))
            code += "_without_names";
        var message = Message(code, language, parameters);
        if (suffix == "what" && CatalogDetection(rule)) {
            bool english = DomainHttp.SelectEnglish(language);
            var catalog = english ? En.Value : Ru.Value;
            string template = catalog[code];
            if (parameters["actor"] is null) template = template.Replace("{actor} добавил", "Добавили").Replace("{actor} очистил", "Очистили")
                .Replace("{actor} отключил", "Отключили").Replace("{actor} added", "Added").Replace("{actor} cleared", "Cleared").Replace("{actor} turned", "Turned");
            if (parameters["member"] is null) template = template.Replace("{member}", english ? "an account" : "учётную запись");
            foreach (var (key, fragments) in new[] {
                ("group", new[] { " в группу {group}", " to {group}" }),
                ("category", new[] { " «{category}»", " of {category}" }),
                ("computer", new[] { " на {computer}", " on {computer}" }), ("time", new[] { " в {time}", " at {time}" }) })
                if (parameters[key] is null) foreach (string fragment in fragments) template = template.Replace(fragment, "");
            message["text"] = Render(template, parameters);
        }
        if (suffix == "what" && !CatalogDetection(rule) && rule != "semantic.qw.agent-tamper" && rule is not ("semantic.qw.kerberoasting" or "semantic.qw.asrep-roasting") && (!password || string.IsNullOrWhiteSpace(ProblemJson.Text(message["text"])))) {
            string rendered = ProblemJson.Text(message["text"]);
            var facts = new[] { "actor", "account", "computer", "source", "count", "time" }
                .Where(key => parameters[key] is not null && !rendered.Contains(parameters[key]!.ToString(), StringComparison.Ordinal))
                .Select(key => parameters[key]!.ToString()).Distinct().ToArray();
            message["text"] = string.Join(" · ", new[] { ProblemJson.Text(message["text"]) }.Concat(facts).Where(text => text.Length > 0));
        }
        message["rendered"] = true;
        return message;
    }
    public static JsonObject Runtime(JsonObject heartbeat, DateTimeOffset generated)
    {
        var details = ProblemJson.Object(heartbeat["details_json"]); int? age = null;
        if (ProblemJson.Stamp(heartbeat["heartbeat_at"], out var stamp)) age = (int)Math.Max(0, (generated - stamp).TotalSeconds);
        long expected = Math.Max(1, ProblemJson.Long(heartbeat["expected_interval_seconds"]) is var number && number != 0 ? number : 30);
        bool fresh = age.HasValue && age <= Math.Max(60, expected * 2 + 30);
        string? mode = ProblemJson.Text(details["runtime_mode"]).Trim(); if (mode.Length == 0) mode = null;
        bool active = Semantic.SemanticProduction.WorkerActive(heartbeat) && details["manual_runtime"] is JsonValue v && v.TryGetValue<bool>(out bool manual) && !manual;
        string State(bool enabled) => mode is not ("facts-v1" or "investigation-v1" or "findings-v1") ? "unknown" :
            !fresh ? enabled ? "stale" : "inactive" : active && enabled ? "active" : "inactive";
        string facts = State(true), relations = State(mode is "investigation-v1" or "findings-v1"), findings = State(mode == "findings-v1");
        return new() { ["state"] = findings, ["runtime_mode"] = mode, ["facts_state"] = facts, ["relations_state"] = relations, ["findings_state"] = findings,
            ["fresh"] = fresh, ["age_seconds"] = age, ["status"] = heartbeat["status"]?.DeepClone(), ["phase"] = heartbeat["phase"]?.DeepClone(),
            ["heartbeat_at"] = heartbeat["heartbeat_at"]?.DeepClone(), ["enabled_policy"] = details["enabled_policy"]?.DeepClone(), ["enabled_policies"] = details["enabled_policies"]?.DeepClone() };
    }
    private static readonly string[] FindingFields = ["id", "rule_code", "severity", "confidence", "status",
        "first_seen_utc", "last_seen_utc", "evidence_count", "repeat_count", "updated_at", "published_at_utc", "suppressed", "actor", "target", "source", "assigned_to", "status_reason", "decoy_id", "decoy_revision", "occurrence_count", "problem_cohort"];
    private static readonly string[] RiskFields = ["id", "finding_id", "state", "reason", "responsible_user_id", "responsible_username", "expires_at", "created_at", "created_by", "changed_by"];
    private static readonly string[] Buckets = ["machine_account", "system_account", "known_gpo_refresh", "interactive_admin", "unknown"];
    internal static JsonObject ClassifyAuditChange(JsonObject facts) => new()
    {
        ["bucket"] = ReviewBucket(facts), ["kind"] = "hint", ["verdict"] = false
    };
    private static string ReviewBucket(JsonObject hint)
    {
        if (ProblemJson.Bool(hint["mixed"]) || hint["has_audit_change"] is JsonValue v && v.TryGetValue<bool>(out var change) && !change) return "unknown";
        string process = ProblemJson.Text(hint["process_name"]).Replace('\\', '/').Split('/').Last().ToLowerInvariant();
        if (ProblemJson.Bool(hint["gpo_correlated"]) && process is "" or "gpupdate.exe" or "svchost.exe" or "gpscript.exe") return "known_gpo_refresh";
        if (ProblemJson.Text(hint["subject_sid"]) is "S-1-5-18" or "S-1-5-19" or "S-1-5-20") return "system_account";
        if (ProblemJson.Bool(hint["machine_account"])) return "machine_account";
        if ((ProblemJson.Python(hint["logon_type"]) is "2" or "10" || ProblemJson.Bool(hint["interactive_session"])) && ProblemJson.Bool(hint["privileged_session"])) return "interactive_admin";
        return "unknown";
    }
    internal static JsonObject IdentityObject(string value, JsonObject context, string? domain)
    {
        var source = context["principals"]?[value] as JsonObject;
        bool identifier = ProblemRepository.Sid(value) is not null || Regex.IsMatch(value.Trim(), @"\Asid:(?:[^:]+:)*S-1-", RegexOptions.IgnoreCase);
        string state = source is not null ? "named" : identifier ? ProblemJson.Text(context["principal_states"]?[value]) : "literal";
        if (identifier && source is null && state is not ("no_match" or "ambiguous" or "unverified" or "unavailable"))
            state = ProblemJson.Text(context["snapshot_state"]) == "unavailable" ? "unavailable" : "unverified";
        return new() { ["name"] = source is not null ? source["label"]?.DeepClone() : JsonValue.Create(identifier ? "" : value),
            ["name_state"] = state, ["identifier"] = value, ["source"] = source?.DeepClone(), ["domain"] = domain };
    }
    public static JsonObject Finding(JsonObject finding, ProblemAccess access, string language, bool queue = false, bool includeDescription = false)
    {
        JsonObject M(string key, JsonObject? args = null) => Message(key, language, args);
        JsonNode? Principal(string? value, bool sourceHost = false, bool hideSid = false)
        {
            string text = (value ?? "").Trim(); var system = Regex.Match(text, @"\Asid:([^:]+):S-1-5-18\z", RegexOptions.IgnoreCase);
            if (system.Success) return M("security.problems.entity.system", new() { ["name"] = system.Groups[1].Value.ToUpperInvariant() });
            if (hideSid && Regex.IsMatch(text, @"\A(?:sid:(?:[^:]+:)*)?S-1-", RegexOptions.IgnoreCase)) return null;
            if (sourceHost && Regex.IsMatch(text, @"\A[0-9]+\z")) return M("security.problems.entity.source_host");
            return text.Length == 0 ? null : JsonValue.Create(text);
        }
        var row = ProblemJson.Pick(finding, FindingFields); var messages = new JsonObject();
        var identity = ProblemJson.Object(finding["identity_context"]); string actorRaw = ProblemJson.Text(finding["actor"]).Trim();
        var actor = identity["actor"] as JsonObject ?? identity["principals"]?[actorRaw] as JsonObject;
        string rule = ProblemJson.Text(finding["rule_code"]);
        bool acl = rule == "semantic.qw.file-acl-broad-write";
        var fields = new Dictionary<string, JsonNode?> {
            ["title_text"] = RuleMessage(finding, "title", language, access),
            ["actor_text"] = actor is not null ? M("security.problems.identity.name", new() { ["name"] = actor["label"]?.DeepClone() }) : Principal(actorRaw, hideSid: true) ?? RuleParameters(finding, access)["actor"]?.DeepClone(),
            ["wording_limitation"] = null };
        if (!queue || includeDescription) {
            fields["what_happened"] = RuleMessage(finding, "what", language, access);
            fields["why_text"] = RuleMessage(finding, "why", language, access);
            fields["next_text"] = RuleMessage(finding, "next", language, access);
        }
        row["presentation_code"] = PresentationCode(finding);
        foreach (var (field, value) in fields)
        {
            row[field] = value is JsonObject message ? message["text"]?.DeepClone() : value?.DeepClone();
            if (value is JsonObject msg) messages[field] = msg.DeepClone();
        }
        foreach (var (code, field) in new[] { ("title_code", "title_text"), ("what_code", "what_happened"), ("why_code", "why_text"), ("next_step_code", "next_text") })
            if (fields.TryGetValue(field, out var value)) row[code] = (value as JsonObject)?["code"]?.DeepClone();
        row["title"] = row["title_text"]?.DeepClone();
        row["summary"] = row["what_happened"]?.DeepClone();
        row["why_it_matters"] = row["why_text"]?.DeepClone();
        row["recommended_action"] = row["next_text"]?.DeepClone();
        var hint = ProblemJson.Object(finding["review_hint"]);
        string? bucket = Buckets.Contains(ProblemJson.Text(hint["bucket"])) ? ProblemJson.Text(hint["bucket"]) : null;
        row["review_hint"] = new JsonObject { ["bucket"] = bucket };
        bool hasChange = !(hint["has_audit_change"] is JsonValue h && h.TryGetValue<bool>(out var b) && !b);
        var review = bucket is not null && Buckets.Contains(bucket) && hasChange ? M("reports.v2.security.problems.presentation." + bucket) : null;
        if (review is not null) messages["review_hint_text"] = review;
        row["review_hint_text"] = review?["text"]?.DeepClone();
        foreach (var (key, fieldsToKeep) in new[] {
            ("evidence", new[] { "event_db_id", "event_record_id", "event_id", "hostname", "channel", "time_created_utc", "evidence_role", "note" }),
            ("entities", new[] { "entity_type", "display_name", "entity_role" }), ("status_history", new[] { "id", "old_status", "new_status", "changed_at", "changed_by", "note" }) })
            row[key] = new JsonArray(ProblemJson.Array(finding[key]).OfType<JsonObject>().Select(r => (JsonNode)ProblemJson.Pick(r, fieldsToKeep)).ToArray());
        row["risk_acceptance"] = finding["risk_acceptance"] is JsonObject risk
            ? ProblemJson.Pick(risk, queue && !includeDescription ? ["state", "expires_at"] : RiskFields) : null;
        row["risk_audit"] = new JsonArray(ProblemJson.Array(finding["risk_audit"]).OfType<JsonObject>().Select(r => {
            var item = ProblemJson.Pick(r, "id", "action", "actor", "occurred_at"); item["details"] = new JsonObject { ["rule"] = ProblemJson.Pick(ProblemJson.Object(r["details"]?["rule"]), RiskFields) }; return (JsonNode)item;
        }).ToArray());
        row["identity_context"] = identity.DeepClone();
        var observations = ProblemJson.Object(identity["principals"]).Select(p => p.Value).OfType<JsonObject>().ToList(); if (identity["actor"] is JsonObject a) observations.Add(a);
        var sources = observations.Select(o => $"{ProblemJson.Text(o["label"])} [{(o["sid"] is null ? "—" : ProblemJson.Text(o["sid"]))}] · " +
            (ProblemJson.Text(o["source"]) == "ad_snapshot" ? "AD / " + ProblemJson.Text(o["source_run_id"]) : o["event_id"] + " / #" + o["event_db_id"]) + " · " + (o["observed_at_utc"]?.ToString() ?? "—")).Distinct().ToArray();
        bool unavailable = ProblemJson.Text(identity["snapshot_state"]) == "unavailable";
        if (sources.Length > 0) messages["identity_sources_text"] = M("security.problems.identity." + (unavailable ? "sources_partial" : "sources"), new() { ["details"] = string.Join("; ", sources) });
        else if (unavailable) messages["identity_sources_text"] = M("security.problems.identity.unavailable");
        row["identity_sources_text"] = messages["identity_sources_text"]?["text"]?.DeepClone();
        string assigned = ProblemJson.Text(finding["assigned_to"]).Trim();
        if (assigned.Length == 0) messages["assigned_to_text"] = M("security.problems.assignee.unassigned");
        row["assigned_to_text"] = assigned.Length > 0 ? assigned : ProblemJson.Text(messages["assigned_to_text"]?["text"]);
        var entities = ProblemJson.Array(finding["entities"]).OfType<JsonObject>();
        if (queue) entities = entities.Where(e => !(ProblemJson.Text(e["entity_role"]) == "source_host" && Regex.IsMatch(ProblemJson.Text(e["display_name"]), @"\A[0-9]+\z")));
        var entityMessages = entities.Select(e => {
            string value = ProblemJson.Text(e["display_name"]).Trim();
            if (queue && ProblemRepository.Sid(value) is not null)
                return finding["_queue_names"]?[value]?.DeepClone() ?? M("security.problems.actor.unknown");
            return identity["principals"]?[value]?["label"]?.DeepClone() ?? Principal(value, ProblemJson.Text(e["entity_role"]) == "source_host") ?? M("security.problems.entity.unknown");
        }).DistinctBy(e => e?.ToJsonString()).ToArray();
        row["entity_messages"] = new JsonArray(entityMessages);
        row["entity_text"] = entityMessages.Length > 0 ? string.Join(", ", entityMessages.Select(e => e is JsonObject m ? ProblemJson.Text(m["text"]) : ProblemJson.Text(e))) : null;
        string identifiers = string.Join(", ", ProblemJson.Array(finding["entities"]).OfType<JsonObject>().Select(e => ProblemJson.Text(e["display_name"])));
        row["entity_identifiers"] = identifiers.Length > 0 ? identifiers : null;
        string status = ProblemJson.Text(finding["status"]); if (status.Length == 0) status = "new"; row["status"] = status;
        row["status_message"] = FindingStatusInput.Statuses.Contains(status) ? M("security.problems.status." + status) : null;
        string severity = ProblemJson.Text(finding["severity"]); row["severity_message"] = new[] { "critical", "high", "medium", "low" }.Contains(severity) ? M("reports.v2.security.problems.columns.severity.labels." + severity) : null;
        row["allowed_statuses"] = new JsonArray(new[] { status }.Concat(FindingStatusInput.Transitions.GetValueOrDefault(status) ?? []).Distinct().Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
        row["evidence_total"] = finding["evidence_count"]?.DeepClone() ?? JsonValue.Create(ProblemJson.Array(finding["evidence"]).Count);
        if (acl) { row["evidence_count"] = null; row["evidence_total"] = null; row["evidence"] = new JsonArray(); }
        row["linked_case"] = finding["linked_case"]?.DeepClone(); row["presentation_messages"] = messages;
        if (row["linked_case"] is JsonObject linked && linked["status"] is {} caseStatus)
            linked["status_message"] = M("investigations.caseStatus." + caseStatus);
        if (queue) {
            var parameters = RuleParameters(finding, access, language);
            if (IsPasswordFinding(rule)) {
                var source = access.Fields("identity_basic", "technical") ? parameters["source"] : null;
                row["actor_text"] = source?.DeepClone();
                messages.Remove("actor_text");
                JsonNode? entity = parameters["account"];
                if (rule == "semantic.qw.password-spray") {
                    var count = finding["presentation_facts"]?["account_count"];
                    entity = source is not null && ProblemJson.Long(count) > 0
                        ? M("security.problems.presentation.spray_object", new() { ["source"] = source.DeepClone(), ["count"] = count!.DeepClone() })
                        : source;
                }
                row["entity_text"] = (entity is JsonObject message ? message["text"] : entity)?.DeepClone();
                if (includeDescription) row["entity_messages"] = entity is null ? new JsonArray() : new JsonArray(entity.DeepClone());
            } else if (row["entity_text"] is null) {
                row["entity_text"] = (parameters["target"] ?? parameters["member"] ?? parameters["computer"])?.DeepClone();
                if (row["entity_text"] is not null) row.Remove("entity_messages");
            }
        }
        void Hide(string path, params string[] categories)
        {
            if (access.Fields(categories)) return;
            string[] parts = path.Split('.'); JsonNode? current = row;
            foreach (string part in parts[..^1]) current = current?[part];
            if (current is JsonObject parent) parent.Remove(parts[^1]);
        }
        foreach (string field in new[] { "actor", "actor_text", "presentation_messages.actor_text", "target", "problem_cohort", "entities", "entity_text", "entity_messages", "assigned_to", "assigned_to_text", "presentation_messages.assigned_to_text", "entity_identifiers", "risk_acceptance.responsible_user_id", "risk_acceptance.responsible_username", "risk_acceptance.created_by", "risk_acceptance.changed_by" }) Hide(field, "identity_basic");
        foreach (string field in new[] { "source", "decoy_id", "decoy_revision" }) Hide(field, "technical");
        foreach (string field in new[] { "identity_context", "identity_sources_text", "presentation_messages.identity_sources_text", "risk_audit", "status_history" }) Hide(field, "identity_basic", "raw_evidence");
        foreach (string field in new[] { "evidence", "status_reason", "risk_acceptance.reason" }) Hide(field, "raw_evidence");
        if (!access.Fields("raw_evidence", "technical") && row["evidence"] is JsonArray visible) foreach (var e in visible.OfType<JsonObject>()) { e.Remove("hostname"); e.Remove("channel"); }
        if (!queue) return row;
        var queueRow = ProblemJson.Pick(row, "id", "status", "severity", "title_text", "entity_text", "actor_text", "last_seen_utc",
            "published_at_utc", "occurrence_count", "problem_cohort", "risk_acceptance", "review_hint_text", "suppressed", "assigned_to",
            "assigned_to_text", "evidence_total", "first_seen_utc", "repeat_count", "decoy_id", "decoy_revision");
        if (includeDescription) {
            foreach (string field in new[] { "title", "what_happened", "why_text", "next_text", "actor", "entity_identifiers",
                "identity_sources_text", "status_history", "risk_audit", "linked_case", "evidence", "presentation_messages",
                "entity_messages", "status_message", "severity_message" })
                if (row.TryGetPropertyValue(field, out var value)) queueRow[field] = value?.DeepClone();
            if (IsPasswordFinding(rule)) queueRow.Remove("actor");
        }
        return queueRow;
    }
}
