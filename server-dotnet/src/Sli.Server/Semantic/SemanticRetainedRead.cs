using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using static Sli.Server.Semantic.SemanticRetainedManifest;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticRetainedControl
{
    internal static string RulesFingerprint()
    {
        var assembly = typeof(SemanticProducer).Assembly; const string prefix = "Sli.Installation.source_packs.";
        var manifests = assembly.GetManifestResourceNames().Where(n => n.StartsWith(prefix, StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToArray();
        var catalogues = new SortedSet<string>(StringComparer.Ordinal) { "event_catalog.json" }; var fingerprints = new JsonArray();
        string ReadResource(string resource) { using var stream = assembly.GetManifestResourceStream(resource) ?? throw new InvalidOperationException("semantic facts catalog input is unavailable"); using var reader = new StreamReader(stream); return reader.ReadToEnd().Replace("\r\n", "\n"); }
        foreach (string resource in manifests) {
            string text = ReadResource(resource); var manifest = JsonNode.Parse(text)!.AsObject();
            if (manifest.Text("event_catalog") is { } catalogue) { if (Path.GetFileName(catalogue) != catalogue || string.IsNullOrWhiteSpace(catalogue)) throw new InvalidOperationException("semantic facts source-pack catalog escapes config"); catalogues.Add(catalogue); }
            fingerprints.Add(new JsonObject { ["path"] = "config/source_packs/" + resource[prefix.Length..], ["sha256"] = Hash(text) });
        }
        foreach (string catalogue in catalogues) fingerprints.Add(new JsonObject { ["path"] = "config/" + catalogue, ["sha256"] = Hash(ReadResource("Sli.Server.Semantic.Risk." + catalogue)) });
        var normalizer = Normalizer; normalizer["semantic_contract_version"] = 1;
        return Digest(new JsonObject { ["selector"] = new JsonObject { ["owner"] = "publish_semantic_candidates", ["source"] = "semantic_event_rows", ["ordered_by"] = "id_ascending", ["include_context"] = true, ["max_batch"] = SemanticProducer.MaxBatch },
            ["catalog"] = fingerprints, ["normalizer"] = normalizer, ["assemblers"] = new JsonArray(Assembler, new JsonObject { ["id"] = "process-episode-assembler", ["version"] = "1.0" }) });
    }
    internal static async Task<JsonObject> Publish(ISemanticSession session, long[] ids, bool exactContext, CancellationToken ct)
    {
        var rows = ids.Length == 0 ? new JsonArray() : await session.QueryAsync("select e.id,e.event_id::text as event_key,c.value as stream,coalesce(p.value,'') as provider_name from semantic_event_rows e join storage_v2_channel c on c.id=e.channel_id left join storage_v2_provider p on p.id=e.provider_id where e.id=any($1) order by e.id", ct, ids);
        if (!rows.Select(r => r.Number("id")).SequenceEqual(ids)) throw new InvalidOperationException("semantic_producer_source_rows_missing");
        var selection = SemanticProducer.Select(rows.Select(r => new SemanticProducer.Source(r.Number("id"), r.Text("event_key")!, r.Text("stream")!, r.Text("provider_name")!)).ToArray(), true, exactContext ? ids.ToHashSet() : null);
        await session.QueryAsync("set local role adlog_storage_worker", ct);
        await SemanticProducer.Enqueue(session, selection.Jobs, ct); return selection.Counters;
    }
    internal async Task<JsonObject> Snapshot(JsonObject? highs, bool context, CancellationToken ct)
    {
        await using var session = await database.OpenAsync(false, ct); var identity = await Identity(session, false, ct); var cohorts = new JsonObject();
        foreach (int id in Vocabulary) {
            long after = 0, count = 0, high = highs?[id.ToString()]?.GetValue<long>() ?? long.MaxValue; long? min = null;
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            while (true) {
                var page = await session.QueryAsync("select core.id,encode(core.normalized_hash,'hex') as normalized_hash from semantic_event_rows core join storage_v2_channel channel on channel.id=core.channel_id join storage_v2_provider provider on provider.id=core.provider_id where channel.value='Security' and provider.value=$1 and core.event_id=$2 and core.id>$3 and core.id<=$4 order by core.id limit 256", ct, Provider(id), id, after, high);
                if (page.Count == 0) break;
                foreach (var row in page) { long next = row.Number("id"); string hash = row.Text("normalized_hash") ?? ""; if (next <= after || !IsHash(hash)) throw new InvalidOperationException("security history cohort order or hash is invalid"); after = next; min ??= next; count++; digest.AppendData(Encoding.ASCII.GetBytes(next + ":" + hash + "\n")); }
            }
            cohorts[id.ToString()] = new JsonObject { ["count"] = count, ["high_watermark"] = after, ["cohort_digest"] = Convert.ToHexStringLower(digest.GetHashAndReset()), ["min_id"] = min, ["max_id"] = count == 0 ? null : after };
        }
        var result = new JsonObject { ["database_identity"] = identity, ["cohorts"] = cohorts };
        if (context) {
            long reset = cohorts["4724"].Number("high_watermark"), count = 0; using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await foreach (var pair in ReadContextPairs(session, 0, cohorts["4624"].Number("high_watermark"), reset, false, ct)) { digest.AppendData(Encoding.ASCII.GetBytes(pair.Id + ":" + pair.Hash + "\n")); count++; }
            result["semantic_context_cohort"] = new JsonObject { ["count"] = count, ["cohort_digest"] = Convert.ToHexStringLower(digest.GetHashAndReset()), ["reset_high_watermark"] = reset };
        }
        return result;
    }
    // Page by raw login ID before filtering. Failed resets cannot consume the selected page.
    private static async IAsyncEnumerable<(long Id, string Hash)> ReadContextPairs(ISemanticSession session, long after, long high, long reset, bool excludeCurrent,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        while (after < high) {
            var page = await session.QueryAsync("""
                with page as (
                  select login.* from semantic_event_rows login
                  join storage_v2_channel c on c.id=login.channel_id and c.value='Security'
                  join storage_v2_provider p on p.id=login.provider_id and p.value='Microsoft-Windows-Security-Auditing'
                  where login.event_id=4624 and login.id>$1 and login.id<=$2 order by login.id limit 256
                )
                select login.id,encode(login.normalized_hash,'hex') as normalized_hash,
                  coalesce((select jsonb_agg(k.value) from semantic_event_rows reset
                    join storage_v2_channel c on c.id=reset.channel_id and c.value='Security'
                    join storage_v2_provider p on p.id=reset.provider_id and p.value='Microsoft-Windows-Security-Auditing'
                    left join storage_v2_keywords k on k.id=reset.keywords_id
                    where reset.event_id=4724 and reset.id<=$3 and reset.domain_id=login.domain_id
                      and reset.target_user_sid=login.target_user_sid
                      and login.target_user_sid ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' and length(login.target_user_sid)<=184
                      and login.time_created_utc>reset.time_created_utc and login.time_created_utc<=reset.time_created_utc+interval '1 hour'), '[]'::jsonb) as reset_keywords,
                  exists(select 1 from normalized_events n where n.source_event_id=login.id and n.semantic_contract_version=1
                    and n.normalizer_id='windows.named-eventdata' and n.normalizer_version=$4 and n.processing_status='normalized'
                    and n.source_event_sha256=login.normalized_hash and n.semantic_type<>'event.unknown') as current
                from page login order by login.id
                """, ct, after, high, reset, SemanticEvent.Version);
            if (page.Count == 0) yield break;
            foreach (var row in page) {
                long id = row.Number("id"); if (id <= after || id > high) throw new InvalidOperationException("security history context cohort order is invalid"); after = id;
                if ((!excludeCurrent || !row.Flag("current")) && row?["reset_keywords"] is JsonArray keywords && keywords.Any(k => SemanticProducer.AuditOutcome(k?.ToString()) == "success")) {
                    string hash = row.Text("normalized_hash") ?? ""; if (!IsHash(hash)) throw new InvalidOperationException("security history normalized hash is invalid"); yield return (id, hash);
                }
            }
        }
    }
    internal static async Task<List<(long Id, string Hash)>> ContextPairs(ISemanticSession session, long after, long high, long reset, bool excludeCurrent, CancellationToken ct)
    {
        var result = new List<(long, string)>(); await foreach (var pair in ReadContextPairs(session, after, high, reset, excludeCurrent, ct)) { result.Add(pair); if (excludeCurrent && result.Count == SemanticProducer.MaxBatch) break; } return result;
    }
    internal static readonly string[] RepairStates = ["absent", "queued", "leased", "completed", "failed", "quarantined", "conflict"];
    internal static string RepairState(JsonNode row, string sourceHash, string historyDigest)
    {
        string detail = row.Text("original_error_detail") ?? "", detailHash = Hash(detail), status = row.Text("repair_status") ?? "";
        bool original = row.Number("original_job_count") == 1 && row.Text("original_status") == "quarantined" && row.Number("original_attempt_count") > 0 && row.Number("original_attempt_count") == row.Number("original_max_attempts") && row.Text("original_error_code") == "UniqueViolation" && detail.Contains("\"canonical_actions_pkey\"", StringComparison.Ordinal) && row.Text("original_source_hash")?.ToLowerInvariant() == sourceHash && !string.IsNullOrWhiteSpace(row.Text("original_job_id"));
        if (row.Number("repair_job_count") == 0) return original ? "absent" : "conflict";
        bool repair = row.Number("repair_job_count") == 1 && status is "queued" or "leased" or "completed" or "failed" or "quarantined" && row.Number("repair_semantic_contract_version") == 1 &&
            row.Text("repair_source_hash")?.ToLowerInvariant() == sourceHash && row.Text("repair_payload_source_hash")?.ToLowerInvariant() == sourceHash && row.Text("repair_original_job_id") == row.Text("original_job_id") && row.Text("repair_history_plan_digest")?.ToLowerInvariant() == historyDigest && IsHash(row.Text("repair_plan_digest")) && row.Text("repair_original_error_detail_sha256")?.ToLowerInvariant() == detailHash &&
            row.Number("repair_original_attempt_count") == row.Number("original_attempt_count") && row.Number("repair_original_max_attempts") == row.Number("original_max_attempts") && row.Text("repair_original_error_code") == "UniqueViolation" && row.Text("repair_processor_id") == "semantic-shadow" && row.Text("repair_processor_version") == SemanticEvent.Version;
        if (!original || !repair) return "conflict";
        if (status == "completed") return row.Number("normalized_current_count") == 1 && row.Number("normalized_proof_count") == 1 && row.Number("normalized_action_count") == 1 && row.Text("normalized_proof_hash")?.ToLowerInvariant() == sourceHash ? "completed" : "conflict";
        return row.Number("normalized_current_count") == 0 ? status : "conflict";
    }
    private static async Task<(JsonObject Current, JsonObject Repairs)> ReconcileContext(ISemanticSession session, JsonObject entry, string digest, CancellationToken ct)
    {
        var pairs = await ContextPairs(session, 0, entry.Number("high_watermark"), entry.Number("semantic_context_reset_high_watermark"), false, ct);
        var current = new JsonObject(); var repairs = new JsonObject(RepairStates.Select(s => new KeyValuePair<string, JsonNode?>(s, JsonValue.Create(0L))));
        foreach (var page in pairs.Chunk(SemanticProducer.MaxBatch)) {
            var totals = (await session.QueryAsync(SemanticRetainedSql.ContextReconcile, ct, 1, SemanticEvent.Normalizer, SemanticEvent.Version, 1, "semantic-shadow", SemanticEvent.Version, page.Select(p => p.Id).ToArray())).Single()!.AsObject();
            foreach (var p in totals) current[p.Key] = current.Number(p.Key) + totals.Number(p.Key);
            var rows = await session.QueryAsync(SemanticRetainedSql.RepairRows, ct, page.Select(p => p.Id).ToArray(), page.Select(p => p.Hash).ToArray(), 1, "semantic-shadow", SemanticEvent.Version, 1, SemanticEvent.Normalizer, SemanticEvent.Version);
            if (rows.Count != page.Length || !rows.Select(r => r.Number("source_event_id")).Order().SequenceEqual(page.Select(p => p.Id).Order())) throw new InvalidOperationException("security history v2 repair reconciliation is incomplete");
            foreach (var row in rows) { string state = RepairState(row!, page.Single(p => p.Id == row.Number("source_event_id")).Hash, digest); repairs[state] = repairs.Number(state) + 1; }
        }
        return (current, repairs);
    }
}
