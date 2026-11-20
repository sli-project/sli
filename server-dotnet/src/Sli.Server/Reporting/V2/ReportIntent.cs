using System.Collections.Frozen;
using System.Text.Json.Nodes;
namespace Sli.Server.Reporting.V2;

// Product metadata only: neither source access nor claims of installed acceptance.
public static class ReportIntent
{
    public static IReadOnlySet<string> RequiredSections { get; } = new HashSet<string>([
        "identity", "user_need", "scope", "sources", "access", "data_quality", "observation",
        "qualification", "risk", "confidence", "result_limits", "views", "acceptance_lanes",
        "ai_assistance", "fallback_and_non_goals"], StringComparer.Ordinal);
    public static IReadOnlySet<string> RequiredLanes { get; } = new HashSet<string>([
        "product_user", "authorization", "deterministic_interpretation", "api_view_model",
        "ui_honest_states", "evidence_audit"], StringComparer.Ordinal);
    public static IReadOnlySet<string> HonestStates { get; } = new HashSet<string>([
        "empty", "denied", "partial", "stale", "unavailable"], StringComparer.Ordinal);
    private static readonly HashSet<string> Archetypes = ["inventory-status", "monitoring-operations",
        "investigation-evidence", "compliance-control", "decision-support-recommendation"];

    private static bool Nonempty(JsonNode? value) => value is JsonValue scalar
        && scalar.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text);
    private static JsonObject Object(JsonNode? value, string error) => value as JsonObject ?? throw new ReportRequestException(error);
    private static void Fields(JsonObject value, string error, params string[] fields)
    {
        if (fields.Any(field => !Nonempty(value[field]))) throw new ReportRequestException(error);
    }
    private static void Interpretation(JsonNode? value, string error)
    {
        var item = Object(value, error);
        if (item.Text("status") == "not_applicable") Fields(item, error, "reason");
        else if (item.Text("status") == "measured") Fields(item, error, "definition");
        else throw new ReportRequestException(error);
    }
    private static JsonObject Intent(ReportDefinition definition) => definition.Declaration["intent"] as JsonObject
        ?? throw new ReportRequestException("report_intent_missing:" + definition.Key);

    public static void ValidateDeclaration(ReportDefinition definition)
    {
        var intent = Intent(definition);
        if (intent["version"] is not JsonValue version || !version.TryGetValue<int>(out var number) || number < 1)
            throw new ReportRequestException("report_intent_invalid:version");
        foreach (string field in new[] { "user_role", "question", "action", "scope", "exclusions", "freshness_expectation",
            "rights", "coverage", "completeness", "denominator", "retention", "provenance", "primary_archetype",
            "product_archetype", "deterministic_policy", "result_limits", "fallback" })
            Fields(intent, "report_intent_invalid:" + field, field);
        foreach (string field in new[] { "sources", "field_classes" })
            if (intent[field] is not JsonArray { Count: > 0 } values || values.Any(value => !Nonempty(value)))
                throw new ReportRequestException("report_intent_invalid:" + field);
        foreach (string field in new[] { "acceptance_lanes", "qualification", "risk", "confidence" })
        {
            var values = Object(intent[field], "report_intent_invalid:" + field);
            if (values.Count == 0 || values.Any(value => !Nonempty(value.Value))
                || field == "acceptance_lanes" && !RequiredLanes.IsSubsetOf(values.Select(value => value.Key)))
                throw new ReportRequestException("report_intent_invalid:" + field);
        }
        if (!new[] { "list", "timeline", "matrix", "summary", "detail", "queue" }.Contains(intent.Text("primary_archetype")))
            throw new ReportRequestException("report_intent_invalid:primary_archetype");
        if (!Archetypes.Contains(intent.Text("product_archetype"))) throw new ReportRequestException("report_intent_invalid:product_archetype");
        var sources = intent.Strings("sources");
        if (!sources.Any(source => source.StartsWith("Canonical:", StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(source[10..]))
            || sources.Any(source => !source.StartsWith("Canonical:", StringComparison.Ordinal) && !source.StartsWith("Supplemental:", StringComparison.Ordinal)))
            throw new ReportRequestException("report_intent_invalid:sources");
    }

    public static JsonObject Contract(ReportDefinition definition)
    {
        var intent = Intent(definition);
        var periods = definition.Params.Where(param => param.Text("kind") == "period").ToArray();
        var periodLimits = new JsonObject();
        foreach (var param in periods) periodLimits[param.Text("key")] = param["max_days"]?.DeepClone();
        JsonArray Sources(string prefix) => new(intent["sources"]!.AsArray()
            .Select(source => source!.GetValue<string>()).Where(source => source.StartsWith(prefix, StringComparison.Ordinal))
            .Select(source => (JsonNode)new JsonObject { ["source_id"] = source, ["authority"] = source,
                ["permitted_scope"] = intent.Text("scope"), ["freshness_contract"] = intent.Text("freshness_expectation") }).ToArray());
        string canonical = string.Join("; ", intent["sources"]!.AsArray().Select(source => source!.GetValue<string>())
            .Where(source => source.StartsWith("Canonical:", StringComparison.Ordinal)));
        string capabilities = string.Join(", ", definition.Rule.Strings("required_capabilities").Order(StringComparer.Ordinal));
        var actions = new JsonArray("view");
        if (definition.HasExport) actions.Add(definition.Rule.Text("export_action", "export"));
        return new()
        {
            ["identity"] = new JsonObject { ["report_id"] = definition.Key, ["name"] = definition.Declaration.Text("title"),
                ["version"] = intent["version"]!.ToString(), ["primary_archetype"] = intent.Text("product_archetype"), ["product_status"] = "existing" },
            ["user_need"] = new JsonObject { ["primary_user"] = intent.Text("user_role"), ["question"] = intent.Text("question"), ["authorized_action"] = intent.Text("action") },
            ["scope"] = new JsonObject { ["subjects"] = intent.Text("scope"), ["time_window"] = periods.Length == 0
                ? "Latest available snapshot or current projection; see declared source freshness."
                : string.Join("; ", periods.Select(param => $"{param.Text("key")}: default={param["default"]?.ToString() ?? "None"}, max_days={param["max_days"]?.ToString() ?? "None"}")),
                ["domain_server_scope"] = intent.Text("rights"), ["exclusions"] = intent.Text("exclusions") },
            ["sources"] = new JsonObject { ["canonical"] = Sources("Canonical:"), ["supplemental"] = Sources("Supplemental:") },
            ["access"] = new JsonObject { ["required_capability"] = capabilities.Length > 0 ? capabilities : "Server report grant; no extra capability required.",
                ["dataset_or_report_grant"] = definition.AccessKey, ["server_enforced_scope"] = intent.Text("rights"),
                ["permitted_field_classes"] = intent["field_classes"]?.DeepClone(), ["allowed_actions"] = actions },
            ["data_quality"] = new JsonObject { ["coverage_definition"] = intent.Text("coverage"), ["completeness_definition"] = intent.Text("completeness"),
                ["freshness_definition"] = intent.Text("freshness_expectation"), ["expected_population_or_window"] = intent.Text("denominator"), ["denominator"] = intent.Text("denominator") },
            ["observation"] = new JsonObject { ["server_owned_observations"] = intent.Text("provenance"), ["source_identity"] = canonical, ["evidence_retention_boundary"] = intent.Text("retention") },
            ["deterministic_policy"] = intent.Text("deterministic_policy"),
            ["qualification"] = intent["qualification"]?.DeepClone(), ["risk"] = intent["risk"]?.DeepClone(), ["confidence"] = intent["confidence"]?.DeepClone(),
            ["result_limits"] = new JsonObject { ["honest_states"] = new JsonArray(HonestStates.Order(StringComparer.Ordinal).Select(state => (JsonNode?)JsonValue.Create(state)).ToArray()),
                ["provenance"] = intent.Text("provenance"), ["coverage_completeness_freshness"] = intent.Text("result_limits"),
                ["retention_limits"] = intent.Text("retention"), ["safe_next_actions"] = intent.Text("action"),
                ["execution"] = new JsonObject { ["default"] = definition.DefaultLimit, ["max"] = definition.MaxLimit,
                    ["period_max_days"] = periodLimits, ["detail_default"] = definition.Detail?["default_limit"]?.DeepClone() } },
            ["views"] = new JsonObject { ["owner_view"] = intent.Text("question"), ["architecture_review_view"] = intent.Text("deterministic_policy"), ["auditor_evidence_view"] = intent.Text("provenance") },
            ["acceptance_lanes"] = intent["acceptance_lanes"]?.DeepClone(),
            ["ai_assistance"] = new JsonObject { ["mode"] = "not_applicable", ["reason"] = "Report authority remains deterministic server code." },
            ["fallback_and_non_goals"] = new JsonObject { ["deterministic_fallback"] = intent.Text("fallback"), ["non_goals"] = intent.Text("exclusions") }
        };
    }

    public static string Validate(JsonObject intent)
    {
        if (!RequiredSections.IsSubsetOf(intent.Select(item => item.Key))) throw new ReportRequestException("intent_section_required");
        var identity = Object(intent["identity"], "identity_invalid");
        Fields(identity, "identity_invalid", "report_id", "name", "primary_archetype", "version");
        if (!Archetypes.Contains(identity.Text("primary_archetype"))) throw new ReportRequestException("primary_archetype_invalid");
        if (identity["secondary_archetype"] is not null && !Archetypes.Contains(identity.Text("secondary_archetype"))) throw new ReportRequestException("secondary_archetype_invalid");
        Fields(Object(intent["user_need"], "user_need_single_value_required"), "user_need_single_value_required", "primary_user", "question", "authorized_action");
        Fields(Object(intent["scope"], "scope_invalid"), "scope_invalid", "subjects", "time_window", "domain_server_scope", "exclusions");
        var sources = Object(intent["sources"], "canonical_source_required");
        if (sources["canonical"] is not JsonArray { Count: > 0 } canonical || sources["supplemental"] is not JsonArray) throw new ReportRequestException("canonical_source_required");
        foreach (var source in canonical) Fields(Object(source, "canonical_source_required"), "canonical_source_required", "source_id", "authority", "permitted_scope", "freshness_contract");
        var access = Object(intent["access"], "access_contract_invalid");
        Fields(access, "access_contract_invalid", "required_capability", "dataset_or_report_grant", "server_enforced_scope");
        if (access["permitted_field_classes"] is not JsonArray || access["allowed_actions"] is not JsonArray) throw new ReportRequestException("access_contract_invalid");
        Fields(Object(intent["data_quality"], "data_quality_invalid"), "data_quality_invalid", "coverage_definition", "completeness_definition", "freshness_definition", "expected_population_or_window", "denominator");
        Fields(Object(intent["observation"], "observation_invalid"), "observation_invalid", "server_owned_observations", "source_identity", "evidence_retention_boundary");
        Interpretation(intent["qualification"], "qualification_invalid");
        Interpretation(intent["risk"], "risk_invalid");
        if (identity.Text("primary_archetype") == "compliance-control")
        {
            var qualification = Object(intent["qualification"], "qualification_invalid");
            if (qualification.Text("status") != "measured") throw new ReportRequestException("compliance_policy_required");
            Fields(qualification, "compliance_policy_required", "policy_id", "control_matrix");
        }
        Interpretation(intent["confidence"], "confidence_invalid");
        var limits = Object(intent["result_limits"], "honest_states_incomplete");
        if (limits["honest_states"] is not JsonArray || !HonestStates.IsSubsetOf(limits.Strings("honest_states"))) throw new ReportRequestException("honest_states_incomplete");
        Fields(limits, "honest_states_incomplete", "provenance", "coverage_completeness_freshness", "retention_limits", "safe_next_actions");
        Fields(Object(intent["views"], "views_invalid"), "views_invalid", "owner_view", "architecture_review_view", "auditor_evidence_view");
        Fields(Object(intent["acceptance_lanes"], "acceptance_lanes_invalid"), "acceptance_lanes_invalid", RequiredLanes.ToArray());
        var ai = Object(intent["ai_assistance"], "ai_assistance_invalid");
        if (ai.Text("mode") is not ("not_applicable" or "draft_only")) throw new ReportRequestException("ai_assistance_invalid");
        Fields(ai, "ai_assistance_invalid", "reason");
        Fields(Object(intent["fallback_and_non_goals"], "fallback_invalid"), "fallback_invalid", "deterministic_fallback", "non_goals");
        return identity.Text("report_id");
    }

    // Compatibility API for declaration discovery; keep the integration validator authoritative.
    internal static readonly IReadOnlySet<string> UnmigratedReportIntents = Array.Empty<string>().ToFrozenSet(StringComparer.Ordinal);

    internal static void ValidateReports(IEnumerable<ReportDefinition> definitions, IReadOnlySet<string>? unmigrated = null)
    {
        unmigrated ??= UnmigratedReportIntents;
        var missing = new HashSet<string>(StringComparer.Ordinal);
        foreach (var definition in definitions)
        {
            if (definition.Declaration["intent"] is not { } intent)
            {
                missing.Add(definition.Key);
                if (!unmigrated.Contains(definition.Key)) throw new InvalidOperationException("report_intent_missing:" + definition.Key);
            }
            else Validate(intent);
        }
        if (unmigrated.Except(missing).Any()) throw new InvalidOperationException("report_intent_allowlist_obsolete");
    }

    // JsonNode is the declaration passport; JsonObject overload validates the full contract.
    internal static void Validate(JsonNode intent)
    {
        if (intent is not JsonObject passport) throw new InvalidOperationException("report_intent_invalid:version");
        try
        {
            ValidateDeclaration(new ReportDefinition(new JsonObject { ["intent"] = passport.DeepClone() }));
        }
        catch (ReportRequestException error)
        {
            throw new InvalidOperationException(error.Message, error);
        }
    }
}
