using System.Text.Json.Nodes;
using Sli.Server.Auth.Lifecycle.Security;

namespace Sli.Server.Semantic;

// Append-only repair of the frozen v2 terminal cohort. Every gate is rechecked under the source locks.
internal sealed partial class SemanticQuarantineRepairController(ISemanticDatabase database, Func<JsonObject> readManifest,
    Func<string,string?> get, Func<string>? releaseFingerprint = null, IConfiguration? configuration = null)
{
    internal const string JobKind = "semantic_v2_quarantine_repair";
    internal const string ConfirmationPrefix = "REPAIR-SECURITY-HISTORY-V2-QUARANTINE:";
    private string Fingerprint() => releaseFingerprint?.Invoke() ?? SemanticWorkerContract.ReleaseFingerprint();
    private void Admission()
    {
        string mode = SemanticRuntimeSettings.Mode(get);
        if (mode != SemanticRuntimeSettings.InvestigationMode) throw new InvalidOperationException("security history requires explicit investigation-v1 admission");
        SemanticRuntimeSettings.Read(get).Validate(mode, get);
    }
    internal async Task<JsonObject> PlanAsync(CancellationToken ct)
    {
        Admission(); var manifest = readManifest();
        await using var session = await database.OpenAsync(false, ct);
        await RequireMigration(session, ct);
        var (pairs, context) = await Snapshot(session, manifest, ct);
        var rows = await Rows(session, pairs, ct);
        string fingerprint = Fingerprint(), digest = Digest(manifest, rows, context, fingerprint);
        return new JsonObject { ["status"] = "security_history_v2_quarantine_repair_plan_ready", ["history_plan_digest"] = manifest["plan_digest"].Copy(),
            ["repair_plan_digest"] = digest, ["confirmation"] = ConfirmationPrefix + digest, ["target_events"] = rows.Count,
            ["worker_release_fingerprint"] = fingerprint, ["production_changed"] = false, ["collection_changed"] = false };
    }
    internal async Task<JsonObject> ApplyAsync(string planDigest, string confirmation, CancellationToken ct)
    {
        var plan = await PlanAsync(ct);
        if (planDigest != plan.Text("repair_plan_digest") || confirmation != plan.Text("confirmation"))
            throw new InvalidOperationException("security history v2 repair confirmation required");
        await using var session = await database.OpenAsync(true, ct);
        // Same PostgreSQL key as the Python session lock. Transaction ownership releases it on every exit.
        var locked = await session.QueryAsync("select pg_try_advisory_xact_lock(hashtext($1)::bigint) as acquired", ct,
            "semantic_retained_security_history_vocabulary_controller");
        if (locked.Count != 1 || !locked[0].Flag("acquired")) throw new InvalidOperationException("security history controller lock is busy");
        Admission(); var manifest = readManifest();
        await RequireMigration(session, ct);
        await session.QueryAsync("set local role adlog_storage_worker", ct);
        var selected = await Snapshot(session, manifest, ct);
        await SemanticWorkerContract.LockSourcesAsync(session, selected.Pairs.Select(x => x.Id), ct);
        var (pairs, context) = await Snapshot(session, manifest, ct);
        var rows = await Rows(session, pairs, ct);
        if (Digest(manifest, rows, context, Fingerprint()) != planDigest) throw new InvalidOperationException("security history v2 repair plan changed");
        await RequireWorker(session, planDigest, ct);
        var pending = new List<(JsonObject Payload, bool Existed)>();
        foreach (var row in rows.OfType<JsonObject>()) {
            var payload = row.DeepClone().AsObject(); payload["repair_plan_digest"] = planDigest; payload["history_plan_digest"] = manifest["plan_digest"].Copy();
            var existing = await session.QueryAsync("select payload_json from semantic_processing_outbox where source_event_id=$1 and job_kind=$2", ct, row.Number("source_event_id"), JobKind);
            foreach (var item in existing) {
                JsonNode? stored = item?["payload_json"];
                if (stored is JsonValue text && text.TryGetValue<string>(out string? json)) stored = JsonNode.Parse(json);
                if (!JsonNode.DeepEquals(stored, payload)) throw new InvalidOperationException("security history v2 repair work conflicts with exact replay");
            }
            if (existing.Count > 1) throw new InvalidOperationException("security history v2 repair work is duplicate");
            pending.Add((payload, existing.Count == 1));
        }
        foreach (var item in pending) await Enqueue(session, item.Payload, ct);
        await session.CommitAsync(ct);
        int queued = pending.Count(x => !x.Existed);
        return new JsonObject { ["status"] = "security_history_v2_quarantine_repair_queued", ["history_plan_digest"] = manifest["plan_digest"].Copy(),
            ["repair_plan_digest"] = planDigest, ["target_events"] = rows.Count, ["newly_queued"] = queued,
            ["production_changed"] = queued > 0, ["collection_changed"] = false };
    }
    private static async Task RequireMigration(ISemanticSession session, CancellationToken ct)
    {
        var marker = await session.QueryAsync("select name from public.schema_migrations where version=143", ct);
        if (marker.Count != 1 || marker[0].Text("name") != "semantic_v2_quarantine_repair")
            throw new InvalidOperationException("security history v2 repair requires exact migration143 marker");
    }
    private async Task RequireWorker(ISemanticSession session, string digest, CancellationToken ct)
    {
        var rows = await session.QueryAsync("""
            select details_json from runtime_worker_heartbeats where worker_name='semantic'
              and status in ('running','idle') and heartbeat_at >= now() -
              (greatest(180,expected_interval_seconds*3) * interval '1 second')
              and details_json->'repair_scope'->>'repair_plan_digest'=$1 for share
            """, ct, digest);
        JsonNode? details = rows.FirstOrDefault()?["details_json"];
        if (details is JsonValue value && value.TryGetValue<string>(out string? json)) {
            try { details = JsonNode.Parse(json); } catch (System.Text.Json.JsonException) { details = null; }
        }
        var contract = (details as JsonObject)?["processing_contract"] as JsonObject;
        if (contract.Text("release_fingerprint") != Fingerprint()) throw new InvalidOperationException("security history v2 repair requires a fresh managed worker release fingerprint");
        if (details.Text("runtime_mode") != SemanticRuntimeSettings.InvestigationMode ||
            details?["manual_runtime"] is not JsonValue manual || !manual.TryGetValue<bool>(out bool isManual) || isManual ||
            contract.Number("claim_protocol_version") != 1 || contract.Number("semantic_contract_version") != 1 ||
            contract.Text("processor_id") != "semantic-shadow" || contract.Text("processor_version") != SemanticEvent.Version ||
            !JsonNode.DeepEquals(contract?["normalizer"], SemanticWorkerContract.Normalizer) || !JsonNode.DeepEquals(contract?["assembler"], SemanticWorkerContract.Assembler))
            throw new InvalidOperationException("security history v2 repair requires a fresh compatible managed investigation worker");
        if (!JsonNode.DeepEquals(details?["repair_scope"], new JsonObject { ["job_kind"] = JobKind, ["repair_plan_digest"] = digest }))
            throw new InvalidOperationException("security history v2 repair requires a fresh managed worker with exact scope");
    }
    private static async Task<JsonArray> Rows(ISemanticSession session, IReadOnlyList<(long Id,string Hash)> pairs, CancellationToken ct)
    {
        long[] ids = pairs.Select(x => x.Id).ToArray(); var hashes = pairs.ToDictionary(x => x.Id, x => x.Hash);
        var originals = await session.QueryAsync("""
            select job_id::text as original_job_id,source_event_id,source_identity_json->>'normalized_hash' as original_source_hash,
              status,attempt_count,max_attempts,last_error_code,last_error_detail from public.semantic_processing_outbox
            where source_event_id=any($1) and job_kind='normalize_event' and semantic_contract_version=1
              and processor_id='semantic-shadow' and processor_version=$2 order by source_event_id,job_id
            """, ct, ids, SemanticEvent.Version);
        if (originals.Count != ids.Length || !originals.Select(x => x.Number("source_event_id")).ToHashSet().SetEquals(ids))
            throw new InvalidOperationException("security history v2 repair originals are missing, extra, or duplicate");
        var normalized = await session.QueryAsync("""
            select source_event_id,count(*) as normalized_count from public.normalized_events
            where source_event_id=any($1) and semantic_contract_version=1 and normalizer_id=$2 and normalizer_version=$3 group by source_event_id
            """, ct, ids, SemanticEvent.Normalizer, SemanticEvent.Version);
        if (normalized.Count > 0) throw new InvalidOperationException("security history v2 repair selected rows are already normalized");
        var rows = new JsonArray();
        foreach (var row in originals) {
            long source = row.Number("source_event_id"); string hash = (row.Text("original_source_hash") ?? "").ToLowerInvariant(), detail = row.Text("last_error_detail") ?? "";
            if (!hashes.TryGetValue(source, out string? expected) || hash != expected || row.Text("status") != "quarantined" ||
                row.Number("attempt_count") != row.Number("max_attempts") || row.Number("max_attempts") <= 0 || row.Text("last_error_code") != "UniqueViolation" ||
                !detail.Contains("\"canonical_actions_pkey\"", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(row.Text("original_job_id")))
                throw new InvalidOperationException("security history v2 repair original terminal contract changed");
            rows.Add(new JsonObject { ["original_job_id"] = row!["original_job_id"].Copy(), ["source_event_id"] = source, ["original_source_hash"] = hash,
                ["original_attempt_count"] = row.Number("attempt_count"), ["original_max_attempts"] = row.Number("max_attempts"),
                ["original_error_code"] = "UniqueViolation", ["original_error_detail_sha256"] = SemanticProposal.HashText(detail) });
        }
        return rows;
    }
    internal static string Digest(JsonObject manifest, JsonArray rows, JsonObject context, string fingerprint)
    {
        var raw = new JsonObject();
        foreach (var entry in manifest["events"]!.AsObject().OrderBy(x => x.Key, StringComparer.Ordinal))
            raw[entry.Key] = Fields(entry.Value!, "count", "high_watermark", "cohort_digest");
        return Password.PasswordJson.Hash(new JsonObject { ["repair_type"] = "semantic_v2_quarantine_repair_v1", ["history_plan_digest"] = manifest["plan_digest"].Copy(),
            ["database_identity"] = manifest["database_identity"].Copy(), ["raw_cohorts"] = raw,
            ["context"] = Fields(context, "count", "cohort_digest", "reset_high_watermark"),
            ["processor"] = new JsonObject { ["id"] = "semantic-shadow", ["version"] = SemanticEvent.Version },
            ["normalizer"] = SemanticWorkerContract.Normalizer, ["assembler"] = SemanticWorkerContract.Assembler, ["worker_release_fingerprint"] = fingerprint,
            ["rows"] = new JsonArray(rows.Select(row => (JsonNode)new JsonArray(new[] { "original_job_id", "source_event_id", "original_source_hash", "original_attempt_count", "original_max_attempts", "original_error_code", "original_error_detail_sha256" }.Select(key => row![key].Copy()).ToArray())).ToArray()) });
    }
    private static JsonObject Fields(JsonNode node, params string[] keys) => new(keys.Select(key => KeyValuePair.Create(key, node[key].Copy())));
    private async Task Enqueue(ISemanticSession session, JsonObject payload, CancellationToken ct)
    {
        long source = payload.Number("source_event_id");
        string hash = Password.PasswordJson.Hash(new JsonObject { ["event"] = source, ["kind"] = JobKind, ["contract"] = 1,
            ["processor"] = "semantic-shadow", ["version"] = SemanticEvent.Version, ["identity_resolution_version"] = "1.0" });
        await new SemanticHistorySession(session,configuration).QueryAsync("""
            insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,idempotency_key,
              payload_json,source_id,domain_id,partition_key,occurred_at_utc,source_identity_json)
            select $1,e.id,$6,1,'semantic-shadow',$2,$3,$4,e.log_source_id,e.domain_id,e.server_id::text||':'||e.channel_id::text,e.time_created_utc,
              jsonb_build_object('id',e.id,'server_id',e.server_id,'domain_id',e.domain_id,'log_source_id',e.log_source_id,'event_id',e.event_id,
                'time_created_utc',e.time_created_utc,'normalized_hash',encode(e.normalized_hash,'hex'),'correlation_id',e.correlation_id,
                'migrated_at',e.migrated_at,'provider_name',p.value,'channel',c.value,'computer',computer.value)
            from semantic_event_rows e join storage_v2_channel c on c.id=e.channel_id left join storage_v2_provider p on p.id=e.provider_id
              left join storage_v2_computer computer on computer.id=e.computer_id where e.id=$5
            on conflict(idempotency_key) do nothing returning job_id
            """, ct, AuthAudit.Uuid5("adlog:semantic:" + hash), SemanticEvent.Version, Convert.FromHexString(hash), payload, source, JobKind);
    }
}
