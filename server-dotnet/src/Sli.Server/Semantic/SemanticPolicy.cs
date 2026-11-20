using System.Globalization;
using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

internal sealed record SemanticPolicy(string Id, int Version, string Source, JsonObject Definition, string Sha, string Selector, string Kind, string Result, string[] Roles, int Window, string Title, string Explanation, string Risk, decimal Raw, int Points, bool Hard, string Rationale, int Expected, string[] Controls, int? Lateness)
{
    internal static readonly string[] CanonicalRoles = ["actor", "session_principal", "affected_entity", "target_entity", "container_entity", "source_host", "source_ip"];
    internal static void ValidateDsl(JsonNode? node)
    {
        if (node is JsonObject obj) foreach (var item in obj)
        { if (new[] { "sql", "shell", "powershell", "python", "csharp", "command", "script", "network_call", "http", "url" }.Contains(item.Key.Trim().ToLowerInvariant())) throw new InvalidDataException("forbidden_semantic_dsl_field"); ValidateDsl(item.Value); }
        else if (node is JsonArray array) foreach (var child in array) ValidateDsl(child);
    }
    internal static SemanticPolicy Compile(JsonNode row)
    {
        var d = row["definition_json"]!.AsObject(); ValidateDsl(d); string id = row.Text("policy_id")!, source = row.Text("source_kind")!;
        if (id.Length is < 1 or > 160 || row.Number("policy_version") <= 0 || d.Text("type") != "scenario_policy" || System.Text.Encoding.UTF8.GetByteCount(d.ToJsonString()) > 65536) throw new InvalidDataException("risk_policy_invalid");
        var selector = d["source_selector"]!.AsObject();
        string selectorKey = source switch { "canonical_action" => "action_kind", "correlation_candidate" => "relation_kind", "control_health" => "control_id", "detection_match" or "qw_signal" => "rule_id", _ => throw new InvalidDataException("risk_source_kind_invalid") };
        string value = SemanticGovernance.Required(selector, selectorKey, 1, 200, "risk_policy_selector_invalid");
        string[] roles = d["strict_roles"]?.AsArray().Select(x => x!.GetValue<string>()).ToArray() ?? [];
        if (roles.Length > 4 || roles.Distinct().Count() != roles.Length || roles.Except(CanonicalRoles).Any() || source == "correlation_candidate" && roles.Length == 0) throw new InvalidDataException("risk_policy_roles_invalid");
        if (source is "detection_match" or "qw_signal")
        {
            if (selector.Count != 2 || selector["execution"] is not JsonObject pin || (source == "detection_match" ? !SigmaProjection.ValidPin(pin, value) : pin.Text("rule_id") != value)) throw new InvalidDataException("risk_execution_pin_invalid");
            roles = [];
        }
        string kind = SemanticGovernance.Required(d, "scenario_kind", 1, 200, "risk_policy_kind_invalid"), result = d.Text("result_class")!;
        if (result is not ("security_incident" or "security_exposure" or "control_gap")) throw new InvalidDataException("risk_result_class_invalid");
        int window = (int)d.Number("merge_window_seconds"), expected = d["expected_evidence_count"] is null ? 1 : (int)d.Number("expected_evidence_count");
        var risk = d["risk"]!.AsObject(); string riskClass = risk.Text("class") ?? "unknown";
        if (!decimal.TryParse(risk["raw_score"]?.ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out decimal raw)) throw new InvalidDataException("risk_score_invalid");
        int points = (int)risk.Number("display_points"); bool hard = risk.Flag("hard_critical");
        var controls = d["required_controls"]?.AsArray().Select(x => x!.GetValue<string>()).ToArray() ?? [];
        int? lateness = d["allowed_lateness_seconds"] is null ? null : (int)d.Number("allowed_lateness_seconds");
        if (window is < 1 or > 86400 || expected is < 1 or > 32768 || raw is < 0 or > 100000 || points is < 0 or > 100 || riskClass is not ("info" or "low" or "medium" or "high" or "critical") || hard && riskClass != "critical" || controls.Length > 64 || controls.Distinct().Count() != controls.Length || controls.Any(x => x.Length is < 1 or > 160) || lateness is < 0 or > 86400) throw new InvalidDataException("risk_policy_bounds_invalid");
        string sha = SemanticJson.Hash(d); if (row.Text("definition_sha256") is { } hash && hash != sha) throw new InvalidDataException("risk_policy_hash_mismatch");
        return new(id, (int)row.Number("policy_version"), source, d, sha, value, kind, result, roles, window,
            SemanticGovernance.Required(d, "title", 1, 300, "risk_title_required"), SemanticGovernance.Required(d, "explanation", 1, 2000, "risk_explanation_required"), riskClass, raw, points, hard,
            SemanticGovernance.Required(risk, "rationale", 1, 2000, "risk_rationale_required"), expected, controls, lateness);
    }
}
