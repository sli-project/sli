using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Semantic;

internal sealed record QuarantineSelection(string[] Reasons, long? SourceIdMin = null, long? SourceIdMax = null,
    DateTimeOffset? Since = null, DateTimeOffset? Until = null, int Limit = 100, string? CloseReason = null, bool Dispatch = false)
{
    internal static readonly string[] CloseReasons = ["source_unavailable", "canonical_conflict", "superseded", "unsupported_failure"];
    internal void Validate()
    {
        if (Reasons.Length == 0 || Reasons.Any(x => x is null || !Regex.IsMatch(x, @"\A[A-Za-z][A-Za-z0-9_]{0,127}\z"))) throw new SemanticInputException("invalid_reason");
        if (Limit is < 1 or > 1000) throw new SemanticInputException("invalid_limit");
        if (SourceIdMin <= 0 || SourceIdMax <= 0 || SourceIdMin > SourceIdMax) throw new SemanticInputException("invalid_source_range");
        if (Since >= Until) throw new SemanticInputException("invalid_time_range");
        if (CloseReason is not null && !CloseReasons.Contains(CloseReason, StringComparer.Ordinal)) throw new SemanticInputException("invalid_close_reason");
    }
    internal JsonObject Document => new() {
        ["reasons"] = new JsonArray(Reasons.Select(x => JsonValue.Create(x)).ToArray()), ["source_id_min"] = SourceIdMin,
        ["source_id_max"] = SourceIdMax, ["since"] = Since, ["until"] = Until, ["limit"] = Limit,
        ["close_reason"] = CloseReason, ["dispatch"] = Dispatch
    };
}

internal sealed class SemanticSourceIntegrityException(Exception inner) : Exception("source_integrity_failed", inner);
internal sealed class SemanticSourceAbsentException() : FileNotFoundException("semantic_source_absent");
internal sealed class SemanticSourceDeletedException() : Exception("source_deleted");
internal sealed class SemanticSourceUnavailableException() : Exception("source_unavailable");

// Preserve original job provenance; a closed receipt binds both terminal fingerprints.
internal sealed class SemanticQuarantineReplay(ISemanticDatabase database,
    Func<ISemanticSession, JsonObject, bool, CancellationToken, Task<int>> replay)
{
    internal const string AuditAction = "semantic_quarantine_resolution", AssemblerVersion = "1.1";
    private static readonly string[] FingerprintFields = ["job_id", "source_event_id", "job_kind", "status", "semantic_contract_version",
        "processor_id", "processor_version", "attempt_count", "max_attempts", "updated_at", "last_error_code", "last_error_detail", "payload_json", "source_identity_json"];
    internal static string Fingerprint(JsonNode row) => SemanticJson.Hash(new JsonObject(FingerprintFields.Select(k => new KeyValuePair<string, JsonNode?>(k, row[k].Copy()))));
    internal static bool IsDigest(string? value) => value is not null && Regex.IsMatch(value, @"\A[0-9a-f]{64}\z");

    internal static string? RetryReason(JsonObject row)
    {
        if (row.Text("job_kind") != "normalize_event" || row.Text("processor_id") != "semantic-shadow" || row.Number("semantic_contract_version") != 1) return null;
        if (row["source_identity_json"] is not JsonObject identity) return null;
        foreach (string field in new[] { "id", "server_id", "domain_id", "log_source_id", "event_id" })
            if (!long.TryParse(identity[field]?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out _)) return null;
        if (identity.Number("id") != row.Number("source_event_id") || !IsDigest(identity.Text("normalized_hash")?.ToLowerInvariant())
            || new[] { "time_created_utc", "migrated_at", "channel" }.Any(k => identity[k] is null)
            || Encoding.UTF8.GetByteCount(identity.ToJsonString()) > 4096) return null;
        string detail = row.Text("last_error_detail") ?? "", code = row.Text("last_error_code") ?? "";
        if (code == "semantic_processing_failed") {
            JsonNode? failure;
            try { failure = JsonNode.Parse(detail); } catch (System.Text.Json.JsonException) { return null; }
            // Re-run the real reader and its provenance checks. This grants no
            // permission to replace missing or conflicting source evidence.
            if (failure is JsonObject document && document.Count == 3
                && document.Text("code") == code && document["sql_state"] is null
                && document.Text("step") is "source_read" or "retained_normalization") return "retry_normalization_source";
            return null;
        }
        if (code == "QueryCanceled" && detail.Trim() is "canceling statement due to statement timeout" or "cancelling statement due to statement timeout") return "retry_statement_timeout";
        if (code == "UniqueViolation" && Regex.IsMatch(detail, "['\"]canonical_actions_pkey['\"]")) return "fixed_canonical_identity";
        string missing = $"published archive block not found for event {row.Number("source_event_id")}";
        if (code == "KeyError" && (detail == missing || detail == "'" + missing + "'" || detail is "'sli.windows.ad-dc'" or "\"sli.windows.ad-dc\"")) return "fixed_source_lookup";
        return null;
    }

    private static async Task<JsonArray> Select(ISemanticSession session, QuarantineSelection selection, CancellationToken ct,
        (long Source, Guid Job)? cursor = null, bool batch = false)
    {
        var filters = new List<string> { "status in ('quarantined','closed')", "last_error_code=any($1)" };
        var values = new List<object?> { selection.Reasons };
        foreach (var (column, op, value) in new (string, string, object?)[] {
            ("source_event_id", ">=", selection.SourceIdMin), ("source_event_id", "<=", selection.SourceIdMax),
            ("updated_at", ">=", selection.Since?.UtcDateTime), ("updated_at", "<", selection.Until?.UtcDateTime) })
            if (value is not null) { values.Add(value); filters.Add($"{column} {op} ${values.Count}"); }
        if (cursor is { } after) {
            values.Add(after.Source); values.Add(after.Job);
            filters.Add($"(source_event_id,job_id) > (${values.Count - 1},${values.Count})");
        }
        values.Add(batch ? selection.Limit : selection.Limit + 1);
        var rows = await session.QueryAsync("select * from semantic_processing_outbox where " + string.Join(" and ", filters)
            + $" order by source_event_id,job_id limit ${values.Count}", ct, values.ToArray());
        // The requested selection is indivisible: never silently apply a truncated plan.
        if (!batch && rows.Count > selection.Limit) throw new SemanticInputException("selection_limit_exceeded");
        return rows;
    }

    private static async Task<HashSet<string>> Resolved(ISemanticSession session, JsonArray rows, bool dispatch, CancellationToken ct)
    {
        var fingerprints = rows.ToDictionary(r => r.Text("job_id")!, r => Fingerprint(r!), StringComparer.Ordinal);
        if (rows.Count == 0) return [];
        var receipts = await session.QueryAsync("""
            select target,details from semantic_control_audit where action=$1 and target=any($2)
              and (details->>'outcome'='closed' or ((details->>'outcome'='replayed'
                or (details->>'outcome'='failed' and details->>'final'='true'))
                and details->>'processor_version'=$3 and details->>'assembler_version'=$4))
            """, ct, AuditAction, fingerprints.Keys.ToArray(), SemanticEvent.Version, AssemblerVersion);
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var receipt in receipts)
        {
            var details = receipt?["details"] is JsonValue text ? JsonNode.Parse(text.GetValue<string>())! : receipt!["details"]!;
            string target = receipt.Text("target")!;
            if (fingerprints.TryGetValue(target, out string? fingerprint)
                && (details.Text("original_fingerprint") == fingerprint || details.Text("outcome") == "closed" && details.Text("closed_fingerprint") == fingerprint)
                && (details.Text("outcome") != "replayed" || !dispatch || details.Flag("dispatch"))) result.Add(target);
        }
        return result;
    }

    internal static string FailureReason(Exception error) => error switch {
        SemanticSourceIntegrityException => "source_integrity_failed",
        FileNotFoundException or KeyNotFoundException => "source_unavailable",
        InvalidDataException e when e.Message.StartsWith("canonical_action_", StringComparison.Ordinal) || e.Message.StartsWith("canonical_evidence_", StringComparison.Ordinal) => "canonical_conflict",
        _ => "replay_failed"
    };

    private static Task<JsonArray> Record(ISemanticSession session, JsonObject row, string outcome, string reason, string digest, bool dispatch, int actions, CancellationToken ct, JsonNode? closed = null) =>
        session.QueryAsync("select public.record_semantic_quarantine_resolution368($1,$2::jsonb)", ct,
            row.Text("job_id"), new JsonObject {
                ["job_id"] = row.Text("job_id"), ["source_event_id"] = row.Number("source_event_id"), ["outcome"] = outcome,
                ["reason"] = reason, ["plan_digest"] = digest, ["original_fingerprint"] = Fingerprint(row),
                ["final"] = outcome == "closed" || outcome == "failed" && reason is "source_integrity_failed" or "canonical_conflict",
                ["processor_version"] = SemanticEvent.Version, ["assembler_version"] = AssemblerVersion, ["actions"] = actions, ["dispatch"] = dispatch,
                ["closed_fingerprint"] = closed is null ? null : Fingerprint(closed), ["original_updated_at"] = row["updated_at"].Copy()
            });

    internal async Task<JsonObject> RunAsync(QuarantineSelection selection, bool apply = false, string planDigest = "", CancellationToken ct = default,
        Action<JsonObject>? progress = null)
    {
        selection.Validate();
        if (apply && !IsDigest(planDigest)) throw new SemanticInputException("plan_digest_required");
        JsonArray rows; HashSet<string> resolved;
        await using (var session = await database.OpenAsync(false, ct)) {
            rows = await Select(session, selection, ct); resolved = await Resolved(session, rows, selection.Dispatch, ct); await session.CommitAsync(ct);
        }
        string digest = PlanDigest(selection, rows);
        if (apply && planDigest != digest) throw new SemanticInputException("plan_changed");
        return await RunRowsAsync(selection, rows, resolved, apply, digest, ct, progress);
    }

    private static string PlanDigest(QuarantineSelection selection, JsonArray rows) => SemanticJson.Hash(new JsonObject {
        ["selection"] = selection.Document, ["rows"] = new JsonArray(rows.Select(r => JsonValue.Create(Fingerprint(r!))).ToArray()),
        ["processor_version"] = SemanticEvent.Version, ["assembler_version"] = AssemblerVersion });

    // This release fixes source lookup/retained normalization and stable canonical identity.
    // A batch bounds memory, not the amount of work. Failed or unsupported rows never
    // stall the cursor; successful receipts survive restart with their effects.
    internal async Task<JsonObject> ReplayFixedAsync(int batchSize, bool dispatch, CancellationToken ct,
        Action<JsonObject>? progress = null, Func<bool>? stopping = null)
    {
        var selection = new QuarantineSelection(["semantic_processing_failed", "KeyError", "UniqueViolation"], Limit: batchSize, Dispatch: dispatch);
        selection.Validate();
        (long Source, Guid Job)? cursor = null;
        var totals = new JsonObject { ["selected"] = 0, ["replayed"] = 0, ["closed"] = 0, ["failed"] = 0, ["blocked"] = 0, ["already_resolved"] = 0, ["changed"] = 0, ["actions"] = 0 };
        while (stopping?.Invoke() != true) {
            ct.ThrowIfCancellationRequested();
            JsonArray rows; HashSet<string> resolved;
            await using (var session = await database.OpenAsync(false, ct)) {
                rows = await Select(session, selection, ct, cursor, batch: true);
                resolved = await Resolved(session, rows, dispatch, ct); await session.CommitAsync(ct);
            }
            if (rows.Count == 0) break;
            var result = await RunRowsAsync(selection, rows, resolved, true, PlanDigest(selection, rows), ct, progress, stopping);
            foreach (string key in totals.Select(pair => pair.Key).ToArray()) Increment(totals, key, result.Number(key));
            var last = rows[^1]!; cursor = (last.Number("source_event_id"), Guid.Parse(last.Text("job_id")!));
        }
        return totals;
    }

    private async Task<JsonObject> RunRowsAsync(QuarantineSelection selection, JsonArray rows, HashSet<string> resolved,
        bool apply, string digest, CancellationToken ct, Action<JsonObject>? progress, Func<bool>? stopping = null)
    {
        var decisions = new JsonObject(); var failures = new JsonObject();
        var result = new JsonObject { ["mode"] = apply ? "apply" : "dry_run", ["plan_digest"] = digest, ["decisions"] = decisions, ["failures"] = failures, ["selected"] = rows.Count };
        foreach (string key in new[] { "retryable", "blocked", "already_resolved", "replayed", "closed", "failed", "changed", "actions" }) result[key] = 0;
        void Count(string key, long n = 1) => Increment(result, key, n);
        foreach (var node in rows)
        {
            ct.ThrowIfCancellationRequested(); if (stopping?.Invoke() == true) break; var row = node!.AsObject(); string id = row.Text("job_id")!;
            progress?.Invoke(new JsonObject { ["cursor"] = row.Number("source_event_id"), ["heartbeat"] = DateTimeOffset.UtcNow });
            if (resolved.Contains(id)) { Count("already_resolved"); continue; }
            if (row.Text("status") == "closed") { Count("blocked"); continue; }
            string? reason = selection.CloseReason ?? RetryReason(row);
            if (reason is null) { Count("blocked"); Increment(decisions, "unsupported_failure"); continue; }
            Increment(decisions, reason);
            if (!apply) { Count(selection.CloseReason is null ? "retryable" : "closed"); continue; }
            await using var session = await database.OpenAsync(true, ct);
            await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, "semantic_source:" + row.Number("source_event_id"));
            var current = (await session.QueryAsync("select * from semantic_processing_outbox where job_id=$1 for update", ct, Guid.Parse(id))).FirstOrDefault();
            if (current is null || Fingerprint(current) != Fingerprint(row)) { Count("changed"); await session.CommitAsync(ct); continue; }
            if ((await Resolved(session, new JsonArray(row.DeepClone()), selection.Dispatch, ct)).Contains(id)) { Count("already_resolved"); await session.CommitAsync(ct); continue; }
            if (selection.CloseReason is not null) {
                await Record(session, row, "closed", reason, digest, selection.Dispatch, 0, ct); Count("closed");
            }
            else {
                await session.QueryAsync("savepoint quarantine_replay", ct);
                try {
                    int actions = await replay(session, row, selection.Dispatch, ct);
                    await Record(session, row, "replayed", reason, digest, selection.Dispatch, actions, ct);
                    await session.QueryAsync("release savepoint quarantine_replay", ct); Count("replayed"); Count("actions", actions);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception error) {
                    await session.QueryAsync("rollback to savepoint quarantine_replay", ct);
                    await session.QueryAsync("release savepoint quarantine_replay", ct);
                    if (error is SemanticSourceDeletedException or SemanticSourceUnavailableException) {
                        var closed = (await session.QueryAsync("update semantic_processing_outbox set status='closed',completed_at=now(),updated_at=now() where job_id=$1 and status='quarantined' returning *", ct, Guid.Parse(id))).Single()!;
                        await Record(session, row, "closed", error.Message, digest, selection.Dispatch, 0, ct, closed); Count("closed");
                        await session.CommitAsync(ct); continue;
                    }
                    string failure = FailureReason(error);
                    await Record(session, row, "failed", failure, digest, selection.Dispatch, 0, ct); Count("failed"); Increment(failures, failure);
                }
            }
            await session.CommitAsync(ct);
        }
        return result;
    }
    private static void Increment(JsonObject counts, string key, long n = 1) => counts[key] = counts.Number(key) + n;
}
