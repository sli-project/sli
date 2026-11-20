using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

public sealed partial class SemanticWorkspace
{
    private static async Task<JsonArray> ScenarioRows(ISemanticSession session, JsonObject filters, int limit, string? id, JsonObject? after,
        JsonObject? evidenceAfter, JsonObject execution, JsonArray? itemIds, long[]? evidenceIds, CancellationToken ct)
    {
        if (itemIds is { Count: 0 }) return new();
        bool metadata = itemIds is not null;
        var parameters = new List<object?>(); var clauses = new List<string>();
        string Param(object? value) { parameters.Add(value); return "$" + parameters.Count; }
        if (id is not null) clauses.Add("scenario.scenario_id=" + Param(Guid.Parse(id)));
        if (after is not null) clauses.Add("(scenario.updated_at,scenario.scenario_id)<(" + Param(SemanticQuery.Time(after.Text("time")!, "UTC", "invalid_cursor")) + "," + Param(Guid.Parse(after.Text("id")!)) + ")");
        foreach (var (key, column) in new[] { ("status", "scenario_status"), ("result_class", "result_class"), ("risk_class", "risk_class") })
            if (filters.Text(key) is { } value) clauses.Add("scenario." + column + "=" + Param(value));
        if (itemIds is not null)
        {
            clauses.Add("scenario.scenario_id=any(" + Param(itemIds.Select(x => Guid.Parse(x!.GetValue<string>())).ToArray()) + ")");
            clauses.Add("not exists(select 1 from semantic_scenario_evidence guard_link left join normalized_events guard_event on guard_event.normalized_event_id=guard_link.normalized_event_id where guard_link.scenario_id=scenario.scenario_id and (guard_event.source_event_id is null or not(guard_event.source_event_id=any(" + Param(evidenceIds) + "))))");
        }
        if (execution.Flag("identity_merge_schema_ready")) clauses.Add("not exists(select 1 from entity_identity_scenario_supersessions_v2 where old_scenario_id=scenario.scenario_id)");
        string evidenceWhere = evidenceAfter is null ? "" : "and (item.evidence_order,item.normalized_event_id)>(" + Param((int)evidenceAfter.Number("order")) + "," + Param(Guid.Parse(evidenceAfter.Text("id")!)) + ")";
        string limitSql = Param(limit + 1), where = clauses.Count == 0 ? "" : "where " + string.Join(" and ", clauses);
        string identity = metadata ? "''::text as partition_key,'{}'::jsonb as strict_keys_json,''::text as title,''::text as explanation" : "scenario.partition_key,scenario.strict_keys_json,scenario.title,scenario.explanation";
        string confidence = metadata ? "'{}'::jsonb as confidence_factors_json" : "scenario.confidence_factors_json";
        bool review = !metadata && execution.Flag("analyst_review_schema_ready"), conclusion = execution.Flag("conclusion_completeness_schema_ready");
        string reviewColumns = review ? "review.review_id as latest_review_id,review.review_request_id,review.verdict as review_verdict,review.review_confidence,review.rationale as review_rationale,encode(review.scenario_snapshot_sha256,'hex') as review_snapshot_sha256,review.reviewed_by,review.reviewer_role,review.reviewed_at,coalesce(review.review_count,0)::integer as review_count" : "null::uuid as latest_review_id,0::integer as review_count";
        string reviewJoin = review ? """
            left join lateral(select latest.*,(select count(*) from semantic_scenario_reviews counted where counted.scenario_id=scenario.scenario_id) as review_count
              from semantic_scenario_reviews latest where latest.scenario_id=scenario.scenario_id order by latest.reviewed_at desc,latest.review_id desc limit 1) review on true
            """ : "";
        string conclusionColumns = conclusion ? "conclusion.conclusion_state,conclusion.completeness_snapshot_json" : "'not_checked'::text as conclusion_state,'{\"legacy_missing\":true,\"supports_negative_conclusion\":false}'::jsonb as completeness_snapshot_json";
        string conclusionJoin = conclusion ? "left join lateral(select result.conclusion_state," + (metadata ? "'{}'::jsonb as completeness_snapshot_json" : "result.completeness_snapshot_json") + " from semantic_risk_evaluation_results result where result.scenario_id=scenario.scenario_id order by result.created_at desc,result.job_id desc limit 1) conclusion on true" : "";
        return await session.QueryAsync($"""
            select scenario.scenario_id,scenario.scenario_kind,scenario.result_class,scenario.scenario_status,{identity},scenario.first_seen_utc,scenario.last_seen_utc,
              scenario.risk_class,scenario.raw_score,scenario.display_score,scenario.hard_critical,scenario.confidence,scenario.confidence_score,{confidence},scenario.coverage_status,
              scenario.step_count,scenario.evidence_count,scenario.contribution_count,scenario.updated_at,{conclusionColumns},{reviewColumns},coalesce(evidence.items,'[]'::jsonb) as evidence
            from semantic_security_scenarios scenario {reviewJoin} {conclusionJoin}
            left join lateral(select jsonb_agg(jsonb_build_object('normalized_event_id',bounded.normalized_event_id,'event_db_id',bounded.source_event_id,'evidence_order',bounded.evidence_order)
              order by bounded.evidence_order,bounded.normalized_event_id) as items from(select item.normalized_event_id,normalized.source_event_id,item.evidence_order
              from semantic_scenario_evidence item join normalized_events normalized on normalized.normalized_event_id=item.normalized_event_id
              where item.scenario_id=scenario.scenario_id {evidenceWhere} order by item.evidence_order,item.normalized_event_id limit 6) bounded) evidence on true
            {where} order by scenario.updated_at desc,scenario.scenario_id desc limit {limitSql}
            """, ct, parameters.ToArray());
    }
    internal static JsonObject ScenarioItem(JsonObject row, bool metadata)
    {
        var item = new JsonObject();
        foreach (string key in new[] { "scenario_id", "scenario_kind", "result_class", "partition_key", "title", "explanation", "first_seen_utc", "last_seen_utc", "risk_class", "raw_score", "display_score", "hard_critical", "confidence", "confidence_score", "coverage_status", "step_count", "evidence_count", "contribution_count", "updated_at", "conclusion_state", "review_count" }) item[key] = row[key].Copy();
        item["status"] = row["scenario_status"].Copy(); item["strict_keys"] = row["strict_keys_json"].Copy() ?? new JsonObject();
        item["confidence_factors"] = row["confidence_factors_json"].Copy() ?? new JsonObject();
        item["completeness_snapshot"] = row["completeness_snapshot_json"].Copy() ?? new JsonObject { ["legacy_missing"] = true, ["supports_negative_conclusion"] = false };
        var evidence = row["evidence"]?.AsArray() ?? new JsonArray(); bool more = evidence.Count > 5;
        item["evidence"] = SemanticJson.Array(evidence.Take(5)); item["evidence_has_more"] = more;
        item["evidence_next_cursor"] = more ? SemanticJson.Cursor(new JsonArray("scenario-evidence", row.Text("scenario_id")),
            new JsonObject { ["order"] = evidence[4]!["evidence_order"].Copy(), ["id"] = evidence[4]!["normalized_event_id"].Copy() }) : null;
        JsonObject? review = null;
        if (row.Text("latest_review_id") is { } reviewId)
        {
            review = new JsonObject { ["review_id"] = reviewId, ["scenario_id"] = row["scenario_id"].Copy(), ["verdict"] = row["review_verdict"].Copy(), ["rationale"] = row["review_rationale"].Copy(), ["scenario_snapshot_sha256"] = row["review_snapshot_sha256"].Copy() };
            foreach (string key in new[] { "review_request_id", "review_confidence", "reviewed_by", "reviewer_role", "reviewed_at" }) review[key] = row[key].Copy();
        }
        item["latest_review"] = review;
        if (metadata)
        {
            item["partition_key"] = ""; item["strict_keys"] = new JsonObject(); item["confidence_factors"] = new JsonObject();
            item["title"] = "Сохранённый сценарий"; item["explanation"] = "Текстовые подробности скрыты в этом представлении.";
            item["completeness_snapshot"] = new JsonObject { ["payload_state"] = "metadata_only" }; item["latest_review"] = null; item["review_count"] = 0; item["payload_state"] = "metadata_only";
        }
        return item;
    }
    private static async Task<JsonArray> ActionRows(ISemanticSession session, JsonObject filters, int limit, JsonArray? itemIds, long[]? evidenceIds, CancellationToken ct)
    {
        if (itemIds is { Count: 0 }) return new();
        bool metadata = itemIds is not null; var clauses = new List<string>(); var parameters = new List<object?>();
        string Param(object? value) { parameters.Add(value); return "$" + parameters.Count; }
        if (filters.Text("status") is { } status) clauses.Add("action.action_status=" + Param(status));
        if (filters.Text("action_kind") is { } kind) clauses.Add("action.action_kind=" + Param(kind));
        if (metadata)
        {
            clauses.Add("action.canonical_action_id=any(" + Param(itemIds!.Select(x => Guid.Parse(x!.GetValue<string>())).ToArray()) + ")");
            clauses.Add("not exists(select 1 from canonical_action_evidence guard_link left join normalized_events guard_event on guard_event.normalized_event_id=guard_link.normalized_event_id where guard_link.canonical_action_id=action.canonical_action_id and (guard_event.source_event_id is null or not(guard_event.source_event_id=any(" + Param(evidenceIds) + "))))");
        }
        string where = clauses.Count == 0 ? "" : "where " + string.Join(" and ", clauses), attributes = metadata ? "'{}'::jsonb as attributes_json" : "action.attributes_json", limitSql = Param(limit + 1);
        return await session.QueryAsync($"""
            select action.canonical_action_id,action.action_kind,action.action_status,action.semantic_contract_version,action.assembler_id,action.assembler_version,
              action.occurred_at_utc,{attributes},action.created_at,action.updated_at,coalesce(evidence.items,'[]'::jsonb) as evidence
            from canonical_actions action left join lateral(select jsonb_agg(jsonb_build_object('normalized_event_id',bounded.normalized_event_id,'event_db_id',bounded.source_event_id,
              'evidence_role',bounded.evidence_role,'entity_role',bounded.entity_role,'evidence_order',bounded.evidence_order,'relation_confidence',bounded.relation_confidence) order by bounded.evidence_order) as items
              from(select item.normalized_event_id,normalized.source_event_id,item.evidence_role,item.entity_role,item.evidence_order,item.relation_confidence
              from canonical_action_evidence item join normalized_events normalized on normalized.normalized_event_id=item.normalized_event_id
              where item.canonical_action_id=action.canonical_action_id order by item.evidence_order limit 5) bounded) evidence on true
            {where} order by action.occurred_at_utc desc,action.canonical_action_id desc limit {limitSql}
            """, ct, parameters.ToArray());
    }
    internal static JsonObject ActionItem(JsonObject row, bool metadata)
    {
        var result = (JsonObject)row.DeepClone(); result["status"] = row["action_status"].Copy(); result.Remove("action_status");
        result["attributes"] = metadata ? new JsonObject() : row["attributes_json"].Copy() ?? new JsonObject(); result.Remove("attributes_json");
        if (metadata) result["payload_state"] = "metadata_only"; return result;
    }
}
