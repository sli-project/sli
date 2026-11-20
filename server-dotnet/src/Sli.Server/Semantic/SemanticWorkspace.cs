using System.Text.Json.Nodes;
using Sli.Server.Access;

namespace Sli.Server.Semantic;

public sealed partial class SemanticWorkspace(ISemanticDatabase database, IConfiguration? configuration = null)
{
    internal static readonly string[] ExactCapabilities = ["semantic.review", "evidence.exact", "field.security"];
    public async Task<JsonObject> ReadAsync(string kind, SemanticQuery q, CapabilityDecisionSet access, CancellationToken ct)
    {
        if (kind == "calibration")
        {
            int requestedHours = q.Integer("window_hours", 24, "invalid_semantic_calibration_window");
            int hours = Math.Clamp(requestedHours == 0 ? 24 : requestedHours, 1, 168);
            await using var calibrationSession = await database.OpenAsync(false, ct);
            var calibrationExecution = await ExecutionAsync(calibrationSession, ct);
            return await CalibrationAsync(calibrationSession, calibrationExecution, hours, ct);
        }
        // Validate before opening a data connection, including pagination context.
        bool scenarios = kind == "scenarios";
        int requestedLimit = q.Integer("limit", 30, scenarios ? "invalid_semantic_scenario_filter" : "invalid_semantic_action_filter");
        int limit = Math.Clamp(requestedLimit == 0 ? 30 : requestedLimit, 1, 100);
        var filters = new JsonObject();
        JsonArray cursorContext = new(); JsonObject? after = null, evidenceAfter = null;
        string? scenarioId = null;
        if (scenarios)
        {
            filters["status"] = q.Filter("status", "invalid_scenario_status", "open", "under_review", "resolved", "dismissed");
            filters["result_class"] = q.Filter("result_class", "invalid_result_class", "security_incident", "security_exposure", "control_gap");
            filters["risk_class"] = q.Filter("risk_class", "invalid_risk_class", "critical", "high", "medium", "low", "info", "unknown");
            if (q.Get("scenario_id") is { } raw) scenarioId = SemanticQuery.Uuid(raw, "invalid_scenario_id");
            if (q.Get("evidence_cursor") is { } evidenceCursor)
            {
                if (scenarioId is null || q.Get("cursor") is not null) throw new SemanticInputException("invalid_cursor");
                evidenceAfter = SemanticJson.Position(evidenceCursor, new JsonArray("scenario-evidence", scenarioId));
                if (evidenceAfter?["order"] is not JsonValue order || !order.TryGetValue<int>(out int n) || n < 0) throw new SemanticInputException("invalid_cursor");
                _ = SemanticQuery.Uuid(CursorText(evidenceAfter, "id"), "invalid_cursor");
            }
        }
        else if (kind == "actions")
        {
            filters["status"] = q.Filter("status", "invalid_action_status", "observed", "partially_confirmed", "state_confirmed", "multi_source_confirmed", "contradicted", "superseded", "quarantined");
            string? actionKind = q.Get("action_kind"); if (actionKind?.EnumerateRunes().Count() > 160) throw new SemanticInputException("invalid_action_kind");
            filters["action_kind"] = string.IsNullOrEmpty(actionKind) ? null : actionKind;
        }
        long? eventId = q.ExactEventId();
        if (eventId is not null)
        {
            foreach (string cap in ExactCapabilities) if (!access.IsOwner && !access.Capabilities.Contains(cap) && !access.ResourceCapabilities.Contains(cap))
                throw new SemanticInputException("insufficient_capability", 403);
        }
        var bounds = eventId is not null ? q.Bounds("invalid_semantic_context", exclusiveDateEnd: true) : ((DateTimeOffset? Start, DateTimeOffset? End))(null, null);
        if (scenarios && eventId is null)
            after = ScenarioPosition(q.Get("cursor"), new JsonArray("scenarios", filters["status"].Copy(), filters["result_class"].Copy(), filters["risk_class"].Copy(), JsonValue.Create(scenarioId), null));
        await using var postgres = await database.OpenAsync(false, ct);
        var execution = await ExecutionAsync(postgres, ct);
        await using var session = await SemanticHistorySession.CreateAsync(postgres,configuration,ct);
        JsonArray? itemIds = null; long[]? evidenceIds = null;
        if (eventId is { } id)
        {
            if (!await EventAllowed(session, id, access, ct)) throw new SemanticInputException("not_found", 404);
            var preflight = await PreflightAsync(session, scenarios, id, bounds, execution, ct);
            if (preflight.Text("state") != "ready") return new JsonObject { ["api_version"] = "v1", ["generated_at_utc"] = SemanticJson.Stamp(DateTimeOffset.UtcNow), ["read_only"] = true,
                ["execution"] = execution, ["state"] = "unavailable", ["items"] = new JsonArray(), ["has_more"] = false, ["filters"] = new JsonObject(),
                ["limits"] = new JsonObject { ["coverage_state"] = "unavailable", ["reason"] = preflight.Text("reason"), ["time_from_utc"] = bounds.Start is { } s ? SemanticJson.Stamp(s) : null, ["time_to_utc_exclusive"] = bounds.End is { } e ? SemanticJson.Stamp(e) : null } };
            itemIds = preflight["item_ids"]!.AsArray(); evidenceIds = preflight["resource_event_ids"]!.AsArray().Select(x => x!.GetValue<long>()).ToArray();
            foreach (long proof in evidenceIds) if (proof != id && !await EventAllowed(session, proof, access, ct)) throw new SemanticInputException("not_found", 404);
        }
        if (scenarios)
        {
            cursorContext = new("scenarios", filters["status"].Copy(), filters["result_class"].Copy(), filters["risk_class"].Copy(), JsonValue.Create(scenarioId), itemIds.Copy());
            if (eventId is not null) after = ScenarioPosition(q.Get("cursor"), cursorContext);
        }
        if (scenarioId is not null && execution.Number("semantic_schema_marker") == 29) limit = 1;
        var result = Base(execution, filters, limit, scenarios);
        if (execution.Number("semantic_schema_marker") != 29) return result;
        JsonArray rows = scenarios ? await ScenarioRows(session, filters, limit, scenarioId, after, evidenceAfter, execution, itemIds, evidenceIds, ct) :
            await ActionRows(session, filters, limit, itemIds, evidenceIds, ct);
        bool more = rows.Count > limit;
        result["has_more"] = more;
        if (scenarios && more) result["next_cursor"] = SemanticJson.Cursor(cursorContext, new JsonObject { ["time"] = rows[limit - 1]!["updated_at"].Copy(), ["id"] = rows[limit - 1]!["scenario_id"].Copy() });
        var items = new JsonArray();
        foreach (var row in rows.Take(limit)) items.Add(scenarios ? ScenarioItem(row!.AsObject(), eventId is not null) : ActionItem(row!.AsObject(), eventId is not null));
        result["items"] = items; result["state"] = items.Count > 0 ? "available" : "empty";
        if (eventId is not null)
        {
            var limits = result["limits"]!.AsObject(); limits["coverage_state"] = itemIds!.Count > 0 ? "bounded_exact_matches" : "no_exact_proof";
            if (itemIds.Count == 0)
            {
                limits[scenarios ? "evidence_per_scenario" : "evidence_per_action"] = 0;
                limits["payload_state"] = "metadata_only";
            }
            limits["time_from_utc"] = bounds.Start is { } s ? SemanticJson.Stamp(s) : null; limits["time_to_utc_exclusive"] = bounds.End is { } e ? SemanticJson.Stamp(e) : null;
        }
        return result;
    }
    private static string CursorText(JsonObject position, string key) => position[key] is JsonValue value && value.TryGetValue<string>(out var text) ? text : throw new SemanticInputException("invalid_cursor");
    private static JsonObject? ScenarioPosition(string? cursor, JsonArray context)
    {
        var position = SemanticJson.Position(cursor, context);
        if (position is not null)
        {
            string stamp = CursorText(position, "time");
            if (!System.Text.RegularExpressions.Regex.IsMatch(stamp, @"(?:Z|[+-]\d{2}:?\d{2})$")) throw new SemanticInputException("invalid_cursor");
            _ = SemanticQuery.Time(stamp, "UTC", "invalid_cursor");
            _ = SemanticQuery.Uuid(CursorText(position, "id"), "invalid_cursor");
        }
        return position;
    }
    internal static JsonObject Base(JsonObject execution, JsonObject filters, int limit, bool scenarios) => new()
    {
        ["api_version"] = "v1", ["generated_at_utc"] = SemanticJson.Stamp(DateTimeOffset.UtcNow), ["read_only"] = true, ["execution"] = execution.Copy(),
        ["state"] = "schema_unavailable", ["items"] = new JsonArray(), ["has_more"] = false, ["next_cursor"] = null, ["filters"] = filters.Copy(),
        ["limits"] = new JsonObject { ["items"] = limit, [scenarios ? "evidence_per_scenario" : "evidence_per_action"] = 5, ["total_count"] = "not_calculated" }
    };
    internal static async Task<JsonObject> ExecutionAsync(ISemanticSession session, CancellationToken ct)
    {
        var markers = await session.QueryAsync("select max(version) as runtime_marker,max(version) filter(where version between 22 and 29) as semantic_marker,bool_or(version=68 and name='entity_identity_merge_r7') as identity_merge_schema_ready from schema_migrations", ct);
        var workers = await session.QueryAsync("select status,heartbeat_at,expected_interval_seconds,details_json from runtime_worker_heartbeats where worker_name='semantic' order by heartbeat_at desc limit 1", ct);
        var marker = markers.FirstOrDefault(); var worker = workers.FirstOrDefault();
        string workerState = "not_registered";
        if (worker is not null)
        {
            DateTimeOffset heartbeat = SemanticQuery.Time(worker.Text("heartbeat_at")!, "UTC", "worker_heartbeat_invalid");
            bool fresh = (DateTimeOffset.UtcNow - heartbeat).TotalSeconds <= Math.Max(60, worker.Number("expected_interval_seconds") * 2 + 30);
            workerState = !fresh ? "stale" : SemanticProduction.WorkerActive(worker) ? "active" : "warning";
        }
        var settings = SemanticRuntimeSettings.Read(Environment.GetEnvironmentVariable); string? mode = null; string state;
        try { mode = SemanticRuntimeSettings.Mode(Environment.GetEnvironmentVariable); settings.Validate(mode, Environment.GetEnvironmentVariable); state = workerState == "active" && (worker?["details_json"].Text("runtime_mode") ?? SemanticRuntimeSettings.FindingsMode) == mode ? "active" : "enabled_without_worker"; }
        catch (InvalidOperationException e) { state = e.Message == "semantic production admission is required" ? "disabled" : "partially_enabled"; }
        return new JsonObject { ["state"] = state, ["runtime_mode"] = mode, ["schema_state"] = marker.Number("semantic_marker") == 29 ? "ready" : "unavailable",
            ["runtime_marker"] = marker?["runtime_marker"].Copy(), ["semantic_schema_marker"] = marker?["semantic_marker"].Copy(), ["feature_chain"] = settings.Document,
            ["worker"] = new JsonObject { ["state"] = workerState, ["status"] = worker.Text("status") ?? "not_observed", ["heartbeat_at"] = worker?["heartbeat_at"].Copy(), ["runtime_mode"] = worker?["details_json"]?["runtime_mode"].Copy() },
            ["finding_path_live"] = state == "active" && mode == SemanticRuntimeSettings.FindingsMode && settings.Findings,
            ["analyst_review_schema_ready"] = marker.Number("runtime_marker") >= 33, ["conclusion_completeness_schema_ready"] = marker.Number("runtime_marker") >= 52,
            ["identity_merge_schema_ready"] = marker.Flag("identity_merge_schema_ready") };
    }
    internal static async Task<bool> EventAllowed(ISemanticSession session, long id, CapabilityDecisionSet access, CancellationToken ct)
    {
        var rows = await session.QueryAsync("select e.domain_id,e.server_id,c.value as channel from semantic_event_rows e join storage_v2_channel c on c.id=e.channel_id where e.id=$1", ct, id);
        if (rows.Count != 1) return false;
        IReadOnlyList<IReadOnlyList<AccessResource>> groups = [[new("domain", rows[0].Number("domain_id")), new("server", rows[0].Number("server_id")), new("channel", Value: rows[0].Text("channel"))]];
        return ExactCapabilities.All(cap => access.DecideForResourceGroups(cap, groups).Allowed);
    }
    private static async Task<JsonObject> PreflightAsync(ISemanticSession session, bool scenarios, long id, (DateTimeOffset? Start, DateTimeOffset? End) bounds, JsonObject execution, CancellationToken ct)
    {
        JsonObject Unavailable(string reason) => new() { ["state"] = "unavailable", ["reason"] = reason };
        if (execution.Number("semantic_schema_marker") != 29) return Unavailable("schema_unavailable");
        string table = scenarios ? "semantic_security_scenarios" : "canonical_actions", links = scenarios ? "semantic_scenario_evidence" : "canonical_action_evidence", key = scenarios ? "scenario_id" : "canonical_action_id";
        var rows = await session.QueryAsync($"""
            with candidates as(select distinct item.{key} as item_id from {table} item
              join {links} link on link.{key}=item.{key} join normalized_events anchor on anchor.normalized_event_id=link.normalized_event_id
              where anchor.source_event_id=$1 and ($2::timestamptz is null or anchor.occurred_at_utc >= $2::timestamptz)
              and ($3::timestamptz is null or anchor.occurred_at_utc < $3::timestamptz) order by item_id limit 101)
            select candidate.item_id,array(select proof.source_event_id from {links} link left join normalized_events proof on proof.normalized_event_id=link.normalized_event_id
              where link.{key}=candidate.item_id order by link.normalized_event_id limit 65) as evidence_event_ids from candidates candidate order by candidate.item_id
            """, ct, id, bounds.Start, bounds.End);
        if (rows.Count > 100) return Unavailable("candidate_limit_exceeded");
        var evidence = new HashSet<long> { id };
        foreach (var row in rows)
        {
            var ids = row!["evidence_event_ids"]!.AsArray(); if (ids.Count > 64) return Unavailable("evidence_limit_exceeded");
            if (ids.Count == 0 || ids.Any(x => x is null || x.GetValue<long>() <= 0)) return Unavailable("evidence_unavailable");
            foreach (var proof in ids) evidence.Add(proof!.GetValue<long>());
        }
        if (evidence.Count > 128) return Unavailable("evidence_limit_exceeded");
        return new JsonObject { ["state"] = "ready", ["item_ids"] = SemanticJson.Array(rows.Select(x => x!["item_id"])), ["resource_event_ids"] = new JsonArray(evidence.Order().Select(x => JsonValue.Create(x)).ToArray()) };
    }
}
