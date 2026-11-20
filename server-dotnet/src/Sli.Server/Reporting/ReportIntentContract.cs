using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Reporting;

public sealed class ReportIntentContractError(string code) : Exception(code);

// Port of reporting/report_intent_contract.py. This validates the bounded
// architecture package; it neither activates collection nor changes report grants.
public static class ReportIntentContract
{
    static readonly string[] Archetypes = ["inventory-status", "monitoring-operations", "investigation-evidence", "compliance-control", "decision-support-recommendation"];
    static readonly string[] Sections = ["identity", "user_need", "scope", "sources", "access", "data_quality", "observation", "qualification", "risk", "confidence", "result_limits", "views", "acceptance_lanes", "ai_assistance", "fallback_and_non_goals"];
    static readonly string[] HonestStates = ["empty", "denied", "partial", "stale", "unavailable"];
    static readonly string[] AcceptanceLanes = ["product_user", "authorization", "deterministic_interpretation", "api_view_model", "ui_honest_states", "evidence_audit"];
    static readonly string[] DeferredSurfaces = ["ai-redaction-preview", "ai-prompt-preview", "ai-reports", "ai-analysis"];
    static readonly string[] ForbiddenFlags = ["new_source", "rbac_redesign", "universal_graph", "arbitrary_report_builder", "mass_redesign", "schema_migration", "runtime_activation"];
    static readonly Dictionary<string, int> Dispositions = new(StringComparer.Ordinal)
    {
        ["keep"] = 14, ["redesign"] = 0, ["merge"] = 10, ["remove"] = 0, ["defer"] = 4
    };

    static JsonObject Object(JsonNode? value, string code) => value as JsonObject ?? throw new ReportIntentContractError(code);
    static string? Text(JsonNode? value) => value?.GetValueKind() == JsonValueKind.String ? value.GetValue<string>() : null;
    static bool Nonempty(JsonNode? value) => !string.IsNullOrWhiteSpace(Text(value));
    static void Require(JsonObject value, string code, params string[] fields)
    {
        if (fields.Any(field => !Nonempty(value[field]))) throw new ReportIntentContractError(code);
    }

    static void NotApplicableOrMeasured(JsonNode? value, string code)
    {
        var item = Object(value, code);
        if (Text(item["status"]) == "not_applicable")
        {
            if (!Nonempty(item["reason"])) throw new ReportIntentContractError(code);
        }
        else if (Text(item["status"]) != "measured" || !Nonempty(item["definition"]))
            throw new ReportIntentContractError(code);
    }

    public static string ValidateReportIntent(JsonNode? value)
    {
        var intent = Object(value, "intent_section_required");
        if (Sections.Any(section => !intent.ContainsKey(section))) throw new ReportIntentContractError("intent_section_required");
        var identity = Object(intent["identity"], "identity_invalid");
        Require(identity, "identity_invalid", "report_id", "name", "primary_archetype", "version");
        string archetype = Text(identity["primary_archetype"])!;
        if (!Archetypes.Contains(archetype)) throw new ReportIntentContractError("primary_archetype_invalid");
        if (identity["secondary_archetype"] is not null && !Archetypes.Contains(Text(identity["secondary_archetype"])))
            throw new ReportIntentContractError("secondary_archetype_invalid");

        Require(Object(intent["user_need"], "user_need_single_value_required"), "user_need_single_value_required", "primary_user", "question", "authorized_action");
        Require(Object(intent["scope"], "scope_invalid"), "scope_invalid", "subjects", "time_window", "domain_server_scope", "exclusions");

        var sources = Object(intent["sources"], "canonical_source_required");
        if (sources["canonical"] is not JsonArray canonical || canonical.Count == 0) throw new ReportIntentContractError("canonical_source_required");
        foreach (var source in canonical)
            Require(Object(source, "canonical_source_required"), "canonical_source_required", "source_id", "authority", "permitted_scope", "freshness_contract");
        if (sources["supplemental"] is not JsonArray) throw new ReportIntentContractError("canonical_source_required");

        var access = Object(intent["access"], "access_contract_invalid");
        Require(access, "access_contract_invalid", "required_capability", "dataset_or_report_grant", "server_enforced_scope");
        if (access["permitted_field_classes"] is not JsonArray || access["allowed_actions"] is not JsonArray)
            throw new ReportIntentContractError("access_contract_invalid");
        Require(Object(intent["data_quality"], "data_quality_invalid"), "data_quality_invalid", "coverage_definition", "completeness_definition", "freshness_definition", "expected_population_or_window", "denominator");
        Require(Object(intent["observation"], "observation_invalid"), "observation_invalid", "server_owned_observations", "source_identity", "evidence_retention_boundary");

        var qualification = Object(intent["qualification"], "qualification_invalid");
        var risk = Object(intent["risk"], "risk_invalid");
        NotApplicableOrMeasured(qualification, "qualification_invalid");
        NotApplicableOrMeasured(risk, "risk_invalid");
        if (archetype == "compliance-control" && (Text(qualification["status"]) != "measured" || !Nonempty(qualification["policy_id"]) || !Nonempty(qualification["control_matrix"])))
            throw new ReportIntentContractError("compliance_policy_required");
        NotApplicableOrMeasured(intent["confidence"], "confidence_invalid");

        var limits = Object(intent["result_limits"], "honest_states_incomplete");
        if (limits["honest_states"] is not JsonArray states || HonestStates.Any(state => !states.Any(item => Text(item) == state)))
            throw new ReportIntentContractError("honest_states_incomplete");
        Require(limits, "honest_states_incomplete", "provenance", "coverage_completeness_freshness", "retention_limits", "safe_next_actions");
        Require(Object(intent["views"], "views_invalid"), "views_invalid", "owner_view", "architecture_review_view", "auditor_evidence_view");
        Require(Object(intent["acceptance_lanes"], "acceptance_lanes_invalid"), "acceptance_lanes_invalid", AcceptanceLanes);
        var ai = Object(intent["ai_assistance"], "ai_assistance_invalid");
        if (Text(ai["mode"]) is not ("not_applicable" or "draft_only") || !Nonempty(ai["reason"]))
            throw new ReportIntentContractError("ai_assistance_invalid");
        Require(Object(intent["fallback_and_non_goals"], "fallback_invalid"), "fallback_invalid", "deterministic_fallback", "non_goals");
        return Text(identity["report_id"])!;
    }

    public static JsonObject ValidateReportingProductContract(JsonNode? value)
    {
        var contract = Object(value, "contract_object_required");
        if (!JsonNode.DeepEquals(contract["schema_version"], JsonValue.Create(1)) || Text(contract["contract_id"]) != "sli.stage11a.reporting-product.v1" || Text(contract["stage"]) != "G11A-2")
            throw new ReportIntentContractError("contract_identity_invalid");
        if (contract["selected_report_set"] is not JsonArray reports || reports.Count == 0) throw new ReportIntentContractError("selected_report_set_required");
        var ids = reports.Select(ValidateReportIntent).ToArray();
        if (ids.Length != ids.Distinct(StringComparer.Ordinal).Count()) throw new ReportIntentContractError("selected_report_ids_unique");
        if (ids.Any(DeferredSurfaces.Contains)) throw new ReportIntentContractError("selected_deferred_surface");
        if (Text(contract["primary_g11a3_vertical"]) != "vpn.audit" || !ids.Contains("vpn.audit")) throw new ReportIntentContractError("primary_vertical_invalid");

        var reconciliation = Object(contract["inventory_reconciliation"], "inventory_counts_mismatch");
        var expected = new JsonObject(Dispositions.Select(p => new KeyValuePair<string, JsonNode?>(p.Key, JsonValue.Create(p.Value))));
        if (!JsonNode.DeepEquals(reconciliation["accepted_counts"], expected) || reconciliation["surfaces"] is not JsonArray surfaces || surfaces.Count != 28)
            throw new ReportIntentContractError("inventory_counts_mismatch");
        var actual = Dispositions.ToDictionary(p => p.Key, _ => 0, StringComparer.Ordinal);
        foreach (var surface in surfaces)
        {
            var item = Object(surface, "inventory_counts_mismatch");
            string? disposition = Text(item["g11a0_disposition"]);
            if (disposition is null || !actual.ContainsKey(disposition) || !Nonempty(item["surface"]) || !Nonempty(item["stage11a_role"]))
                throw new ReportIntentContractError("inventory_counts_mismatch");
            actual[disposition]++;
        }
        if (actual.Any(p => p.Value != Dispositions[p.Key])) throw new ReportIntentContractError("inventory_counts_mismatch");
        if (contract["deferred_set"] is not JsonArray deferred || !new HashSet<string?>(DeferredSurfaces, StringComparer.Ordinal).SetEquals(deferred.Select(Text)))
            throw new ReportIntentContractError("deferred_set_invalid");
        if (contract["merge_map"] is not JsonArray mergeMap || mergeMap.Count != 10) throw new ReportIntentContractError("merge_map_invalid");
        var flags = Object(contract["change_flags"], "forbidden_change_flag");
        if (ForbiddenFlags.Any(flag => flags[flag]?.GetValueKind() != JsonValueKind.False)) throw new ReportIntentContractError("forbidden_change_flag");
        if (Text(contract["collection"]) != "OFF") throw new ReportIntentContractError("collection_must_remain_off");
        return new JsonObject
        {
            ["contract_id"] = Text(contract["contract_id"]),
            ["selected_report_ids"] = new JsonArray(ids.Select(id => (JsonNode?)JsonValue.Create(id)).ToArray()),
            ["selected_count"] = ids.Length,
            ["primary_g11a3_vertical"] = Text(contract["primary_g11a3_vertical"]),
            ["inventory_counts"] = expected
        };
    }

    public static JsonObject LoadReportingProductContract(string? path = null)
    {
        JsonNode? value;
        try
        {
            using var stream = path is null
                ? typeof(ReportIntentContract).Assembly.GetManifestResourceStream("Sli.Server.Reporting.stage11a_reporting_product_v1.json")
                    ?? throw new ReportIntentContractError("contract_unreadable")
                : File.OpenRead(path);
            value = JsonNode.Parse(stream);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new ReportIntentContractError("contract_unreadable");
        }
        return ValidateReportingProductContract(value);
    }
}
