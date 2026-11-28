using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Storage.Archive;
using Sli.Server.Storage.Direct;
using Sli.Server.Storage.History;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticProduction
{
    private int outboxClaimTurn;
    internal const string OutboxLane = "(case when job_kind in ('normalize_event','investigation_context') and payload_json->>'queue_lane'='live' then 1 else 0 end)";
    internal const string OutboxVersion = "(case when job_kind='semantic_replay' then split_part(processor_version,'+r7-',1) else processor_version end)";
    internal const string PendingOutboxJobs = """
        semantic_contract_version=1 and processor_id='semantic-shadow'
        and status in('queued','failed','leased') and (attempt_count<max_attempts or status='leased')
        and job_kind<>'semantic_v2_quarantine_repair'
        """;

    internal static string ClaimFilter(string? repair, long[]? exact, out object?[] values)
    {
        var arguments = new List<object?> { Guid.NewGuid() };
        string filter = repair is null ? "and job_kind<>'semantic_v2_quarantine_repair'" : "and job_kind='semantic_v2_quarantine_repair' and payload_json->>'repair_plan_digest'=$2";
        if (repair is not null) arguments.Add(repair);
        if (exact is not null) {
            if (exact.Length == 0 || exact.Any(id => id <= 0) || exact.Distinct().Count() != exact.Length) throw new InvalidOperationException("facts check IDs are invalid");
            arguments.Add(exact); filter += " and job_kind='normalize_event' and source_event_id=any($" + arguments.Count + ")";
        }
        values = arguments.ToArray(); return filter;
    }
    internal async Task<int> ReplayQuarantined(ISemanticSession session, JsonObject job, bool dispatch, CancellationToken ct)
    {
        SemanticEvent ev;
        var identity = job["source_identity_json"]!.AsObject();
        try {
            JsonObject source;
            try {
                source = await LoadSource(session, job.Number("source_event_id"), identity, ct);
            }
            catch (IOException error) when (error is FileNotFoundException or DirectoryNotFoundException) {
                if ((await session.QueryAsync("select public.semantic_source_exists374($1) as present", ct, job.Number("source_event_id"))).Single().Flag("present"))
                    throw new InvalidDataException("semantic_source_integrity_conflict");
                // A retained interpretation is not the original source. Closing leaves
                // all existing facts intact and must not assemble or dispatch new ones.
                if (error is SemanticSourceAbsentException) throw new SemanticSourceDeletedException();
                throw new SemanticSourceUnavailableException();
            }
            await AdmitBundle(source, ct);
            ev = SemanticNormalization.Normalize(source);
        }
        catch (InvalidDataException error) { throw new SemanticSourceIntegrityException(error); }
        ev = await IdentityOverrides(session, ev, job, ct);
        await PersistNormalized(session, ev, identity, SemanticEvent.Version, ct);
        var actions = SemanticAssembly.Assemble([ev]);
        foreach (var action in actions) await PersistAction(session, action, SemanticEvent.Version, ct);
        if (dispatch) await EnqueueDispatch(session, ev, SemanticEvent.Version, ct);
        return actions.Count;
    }
    private static async Task AdmitBundle(JsonObject source, CancellationToken ct)
    {
        string? lockRoot = Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR");
        string root = SourceBundleRoot(lockRoot, Directory.GetCurrentDirectory());
        await new KnownBundleNormalizer(root, Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"), lockRoot).ResolveAsync(source, ct);
    }
    internal async Task<int> ReplaySource(ISemanticSession session, JsonObject job, JsonObject source, bool dispatch, CancellationToken ct)
    {
        var ev = await IdentityOverrides(session, SemanticNormalization.Normalize(source), job, ct);
        await PersistNormalized(session, ev, job["source_identity_json"]!.AsObject(), SemanticEvent.Version, ct);
        var actions = SemanticAssembly.Assemble([ev]);
        foreach (var action in actions) await PersistAction(session, action, SemanticEvent.Version, ct);
        if (dispatch) await EnqueueDispatch(session, ev, SemanticEvent.Version, ct);
        return actions.Count;
    }
    internal Task<JsonObject> ProcessOutbox(NpgsqlConnection db, CancellationToken ct, Action<SemanticProcessingStep, TimeSpan>? timing = null,
        IReadOnlyList<long>? sourceEventIds = null, bool prioritizeLive = false)
        => ProcessOutbox(token => Transaction(db, token), ct, timing, sourceEventIds, batch: true, prioritizeLive: prioritizeLive);

    internal async Task<JsonObject> ProcessOutbox(Func<CancellationToken, Task<ISemanticSession>> open,
        CancellationToken stopping, Action<SemanticProcessingStep, TimeSpan>? timing = null, IReadOnlyList<long>? sourceEventIds = null,
        bool batch = false, bool prioritizeLive = false)
    {
        sourceEventIds ??= exactSourceIds;
        ValidateExactSources(mode, sourceEventIds, repairDigest);
        ValidateRepairMode(mode, repairDigest);
        int claimed = 0, completed = 0, failed = 0, normalized = 0, actions = 0;
        // A stop prevents the next claim. Finish the bounded lease already taken.
        int budget = repairDigest is null ? Math.Clamp(limit, 1, 128) : Math.Max(limit, 1);
        bool batchClaims = batch && repairDigest is null && sourceEventIds is null;
        CancellationToken ct = CancellationToken.None;
        while (settings.Normalization && claimed < budget && !stopping.IsCancellationRequested)
        {
            JsonArray jobs;
            long claimStarted = System.Diagnostics.Stopwatch.GetTimestamp();
            await using (var session = await open(ct))
            {
                jobs = prioritizeLive && batchClaims
                    ? await ClaimScheduled(session, budget - claimed, ct)
                    : await Claim(session, ct, repairDigest, sourceEventIds?.ToArray(), batchClaims ? budget - claimed : 1);
                await session.CommitAsync(ct);
            }
            timing?.Invoke(SemanticProcessingStep.Claim, System.Diagnostics.Stopwatch.GetElapsedTime(claimStarted));
            if (jobs.Count == 0) break;
            claimed += jobs.Count;

            // Keep scoped repairs and exact replays on their single-job path.
            // Ordinary batches isolate each job's writes with a savepoint and
            // commit its facts and lease completion in the same transaction.
            await using var shared = jobs.Count > 1 ? (SemanticSession)await open(ct) : null;
            var successful = new List<JsonNode>(jobs.Count);
            if (shared is not null)
            {
                await SemanticWorkerContract.LockSourcesAsync(shared, jobs.Select(job => job.Number("source_event_id")), ct);
                var renewed = await Change(shared, """
                    update semantic_processing_outbox set heartbeat_at=now(),lease_until=now()+interval '300 seconds',updated_at=now()
                    where job_id=any($1) and status='leased' and lease_token=$2 returning job_id
                    """, ct, jobs.Select(JobId).ToArray(), LeaseToken(jobs[0]));
                if (renewed.Count != jobs.Count) throw new InvalidOperationException("semantic batch lease was lost");
            }

            foreach (var claimedJob in jobs)
            {
                var job = claimedJob!;
                if (job.Text("job_kind") == "semantic_repair" && successful.Count > 0)
                {
                    // A repair can verify a normalize job earlier in this lease.
                    await CompleteBatch(shared!, successful, ct);
                    successful.Clear();
                }
                var step = SemanticProcessingStep.RepairScope;
                long stamp = System.Diagnostics.Stopwatch.GetTimestamp();
                void Mark(SemanticProcessingStep next) {
                    timing?.Invoke(step, System.Diagnostics.Stopwatch.GetElapsedTime(stamp));
                    step = next; stamp = System.Diagnostics.Stopwatch.GetTimestamp();
                }
                if (shared is not null) await shared.ExecuteAsync("savepoint semantic_job", ct);
                try
                {
                    await using var single = shared is null ? await open(ct) : null;
                    var (done, assembled) = await ProcessJob(shared ?? single!, job, shared is null, Mark, ct);
                    if (single is not null) { Mark(SemanticProcessingStep.Commit); await single.CommitAsync(ct); }
                    if (done) { completed++; if (shared is not null) successful.Add(job); }
                    if (assembled is int count) { normalized++; actions += count; }
                }
                catch (Exception error)
                {
                    if (shared is null) await Fail(open, "semantic_processing_outbox", "status", job, ct, error, step);
                    else {
                        await shared.ExecuteAsync("rollback to savepoint semantic_job", ct);
                        await Fail(shared, "semantic_processing_outbox", "status", job, ct, error, step);
                    }
                    failed++;
                }
                finally { timing?.Invoke(step, System.Diagnostics.Stopwatch.GetElapsedTime(stamp)); }
                if (shared is not null) await shared.ExecuteAsync("release savepoint semantic_job", ct);
            }

            if (shared is not null)
            {
                long stamp = System.Diagnostics.Stopwatch.GetTimestamp();
                await CompleteBatch(shared, successful, ct);
                timing?.Invoke(SemanticProcessingStep.Complete, System.Diagnostics.Stopwatch.GetElapsedTime(stamp));
                stamp = System.Diagnostics.Stopwatch.GetTimestamp();
                await shared.CommitAsync(ct);
                timing?.Invoke(SemanticProcessingStep.Commit, System.Diagnostics.Stopwatch.GetElapsedTime(stamp));
            }
        }
        return new JsonObject { ["claimed"] = claimed, ["completed"] = completed, ["failed"] = failed, ["normalized"] = normalized, ["actions"] = actions };
    }

    private async Task<(bool Completed, int? Actions)> ProcessJob(ISemanticSession session, JsonNode job, bool finish,
        Action<SemanticProcessingStep> Mark, CancellationToken ct)
    {
        if (repairDigest is not null
            ? job.Text("job_kind") != "semantic_v2_quarantine_repair" || job["payload_json"].Text("repair_plan_digest") != repairDigest
            : job.Text("job_kind") == "semantic_v2_quarantine_repair")
            throw new InvalidDataException("semantic_repair_scope_mismatch");
        Mark(SemanticProcessingStep.SourceLock);
        if (job.Text("job_kind") is not ("normalize_event" or "semantic_replay" or "semantic_repair" or "investigation_context" or "semantic_v2_quarantine_repair"))
            throw new InvalidDataException("semantic_job_kind_unsupported");
        long sourceId = job.Number("source_event_id");
        if (finish) {
            await SemanticWorkerContract.LockSourcesAsync(session, [sourceId], ct);
            if (!await HeartbeatJob(session, job, ct)) throw new InvalidOperationException("semantic lease was lost");
        }
        if (job.Text("job_kind") == "investigation_context")
        {
            Mark(SemanticProcessingStep.Context);
            return (await ExpandContext(session, sourceId, job, ct, finish), null);
        }
        Mark(SemanticProcessingStep.Identity);
        JsonObject identity = job["source_identity_json"]!.AsObject();
        if (identity.Number("id") != sourceId) throw new InvalidDataException("semantic_source_identity_conflict");
        Mark(SemanticProcessingStep.Repair);
        if (job.Text("job_kind") == "semantic_v2_quarantine_repair")
            await ValidateQuarantineRepair(session, job, repairDigest, ct);
        if (job.Text("job_kind") == "semantic_repair")
        {
            var payload = job["payload_json"]!;
            foreach (string field in new[] { "repair_plan_digest", "history_plan_digest", "original_source_hash" })
                if (payload.Text(field) is not { Length: 64 } digest || digest.Any(c => c is not (>= 'a' and <= 'f' or >= '0' and <= '9'))) throw new InvalidDataException("semantic_repair_payload_invalid");
            var original = (await session.QueryAsync("select source_event_id,job_kind,status,processor_id,processor_version,source_identity_json->>'normalized_hash' as source_hash from semantic_processing_outbox where job_id=$1", ct, Guid.Parse(payload.Text("original_job_id")!))).Single()!;
            if (payload.Text("original_source_hash") != identity.Text("normalized_hash") || original.Number("source_event_id") != sourceId || original.Text("job_kind") != "normalize_event" || original.Text("status") != "completed" || original.Text("processor_id") != job.Text("processor_id") || original.Text("processor_version") != job.Text("processor_version") || original.Text("source_hash") != identity.Text("normalized_hash")) throw new InvalidDataException("semantic_repair_original_conflict");
        }
        SemanticEvent ev;
        try
        {
            Mark(SemanticProcessingStep.SourceRead);
            var source = await LoadSource(session, sourceId, identity, ct);
            Mark(SemanticProcessingStep.BundleAdmission);
            await AdmitBundle(source, ct);
            Mark(SemanticProcessingStep.Normalize); ev = SemanticNormalization.Normalize(source);
        }
        // .NET distinguishes an expired directory from an expired file;
        // both correspond to Python's FileNotFoundError, never integrity errors.
        catch (IOException error) when ((error is FileNotFoundException or DirectoryNotFoundException) && job.Text("job_kind") == "normalize_event")
        {
            Mark(SemanticProcessingStep.RetainedNormalization);
            ev = await ReadRetainedNormalization(session, sourceId, identity, ct);
        }
        Mark(SemanticProcessingStep.IdentityOverrides); ev = await IdentityOverrides(session, ev, job, ct);
        string version = job.Text("job_kind") == "semantic_replay" ? job.Text("processor_version")! : SemanticEvent.Version;
        return (true, await PersistProcessedEvent(session, ev, identity, job, version, ct, Mark, finish));
    }
    private static async Task<SemanticEvent> ReadRetainedNormalization(ISemanticSession session, long sourceId, JsonObject identity, CancellationToken ct)
    {
        identity = SourceIdentity(identity);
        if (identity.Number("id") != sourceId) throw new InvalidDataException("semantic_source_identity_conflict");
        var retained = (await session.QueryAsync("select *,encode(semantic_sha256,'hex') as semantic_sha256,encode(source_event_sha256,'hex') as source_event_sha256 from normalized_events where source_event_id=$1 and semantic_contract_version=1 and normalizer_id='windows.named-eventdata' and normalizer_version=$2 and processing_status='normalized'", ct, sourceId, SemanticEvent.Version)).SingleOrDefault() ?? throw new FileNotFoundException();
        var ev = SemanticEvent.Read(retained);
        if (ev.Source != sourceId || retained.Text("source_event_sha256") != identity.Text("normalized_hash") || ev.At != SigmaProjection.At(identity, "time_created_utc") || ev.Quality.Text("identity_resolution_version") != "1.0" || retained.Text("normalized_event_id") != ev.Id().ToString() || ev.Sha != SemanticJson.Hash(new JsonObject { ["source_event_id"] = sourceId, ["semantic_type"] = ev.Type, ["roles"] = ev.Roles.Copy(), ["facts"] = ev.Facts.Copy(), ["identity_resolution_version"] = "1.0" })) throw new InvalidDataException("retained_normalization_integrity_conflict");
        return ev;
    }
    internal static async Task ValidateQuarantineRepair(ISemanticSession session, JsonNode job, string? repairDigest, CancellationToken ct)
    {
        // Immutable terminal evidence is checked before loading any source/archive data.
        // An admitted worker release may change without changing this lineage.
        if (job["payload_json"] is not JsonObject payload) throw new InvalidDataException("semantic_repair_payload_invalid");
        foreach (string field in new[] { "repair_plan_digest", "history_plan_digest", "original_source_hash", "original_error_detail_sha256" })
            if (payload.Text(field) is not { Length: 64 } digest || digest.Any(c => c is not (>= 'a' and <= 'f' or >= '0' and <= '9'))) throw new InvalidDataException("semantic_repair_payload_invalid");
        string? originalId = payload.Text("original_job_id");
        if (!Guid.TryParseExact(originalId, "D", out Guid originalJobId) || originalJobId.ToString("D") != originalId) throw new InvalidDataException("semantic_repair_original_job_id_invalid");
        static long Attempts(JsonNode? node) => node is JsonValue value && value.GetValueKind() == System.Text.Json.JsonValueKind.Number
            && long.TryParse(value.ToJsonString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long count)
            ? count : throw new InvalidDataException("semantic_repair_attempts_invalid");
        long attempts = Attempts(payload["original_attempt_count"]), maximum = Attempts(payload["original_max_attempts"]);
        var identity = job["source_identity_json"]!;
        if (repairDigest != payload.Text("repair_plan_digest") || attempts <= 0 || attempts != maximum || payload.Text("original_error_code") != "UniqueViolation" || payload.Text("original_source_hash") != identity.Text("normalized_hash")) throw new InvalidDataException("semantic_repair_terminal_evidence_invalid");
        var original = (await session.QueryAsync("select source_event_id,job_kind,status,semantic_contract_version,processor_id,processor_version,source_identity_json->>'normalized_hash' as source_hash,attempt_count,max_attempts,last_error_code,last_error_detail from semantic_processing_outbox where job_id=$1", ct, originalJobId)).SingleOrDefault();
        string detail = original.Text("last_error_detail") ?? "";
        if (original is null || original.Number("source_event_id") != job.Number("source_event_id") || original.Text("job_kind") != "normalize_event" || original.Text("status") != "quarantined" || original.Number("semantic_contract_version") != job.Number("semantic_contract_version") || original.Text("processor_id") != job.Text("processor_id") || original.Text("processor_version") != job.Text("processor_version") || original.Text("source_hash") != identity.Text("normalized_hash") || original.Number("attempt_count") != attempts || original.Number("max_attempts") != maximum || original.Text("last_error_code") != "UniqueViolation" || SemanticProposal.HashText(detail) != payload.Text("original_error_detail_sha256") || !System.Text.RegularExpressions.Regex.IsMatch(detail, "['\"]canonical_actions_pkey['\"]")) throw new InvalidDataException("semantic_repair_original_terminal_conflict");
        if ((await session.QueryAsync("select 1 from normalized_events where source_event_id=$1 and semantic_contract_version=$2 and normalizer_id=$3 and normalizer_version=$4", ct, job.Number("source_event_id"), job.Number("semantic_contract_version"), SemanticEvent.Normalizer, SemanticEvent.Version)).Count > 0) throw new InvalidDataException("semantic_repair_source_already_normalized");
    }
    internal async Task<int> PersistProcessedEvent(ISemanticSession session, SemanticEvent ev, JsonObject identity, JsonNode job, string version, CancellationToken ct, Action<SemanticProcessingStep>? mark = null, bool finish = true)
    {
        mark?.Invoke(SemanticProcessingStep.PersistNormalized); await PersistNormalized(session, ev, identity, version, ct);
        mark?.Invoke(SemanticProcessingStep.IdentityReplay);
        if (job.Text("job_kind") == "semantic_replay") await RecordIdentityReplay(session, ev, job, version, ct);
        mark?.Invoke(SemanticProcessingStep.Assemble); var assembled = settings.Assembly ? SemanticAssembly.Assemble([ev]) : [];
        mark?.Invoke(SemanticProcessingStep.PersistAction);
        foreach (var action in assembled) await PersistAction(session, action, version, ct);
        mark?.Invoke(SemanticProcessingStep.EnqueueDispatch);
        if (settings.Correlation && repairDigest is null) await EnqueueDispatch(session, ev, version, ct);
        if (finish) { mark?.Invoke(SemanticProcessingStep.Complete); await Complete(session, "semantic_processing_outbox", "status", job, ct); }
        return assembled.Count;
    }
    internal static string SourceBundleRoot(string? lockRoot, string workingDirectory)
    {
        // Native .NET WorkingDirectory is /opt/sli/dotnet/<release>; the reviewed
        // bundle and admission inodes remain at /opt/sli/current/config/... .
        var root = new DirectoryInfo(string.IsNullOrWhiteSpace(lockRoot) ? workingDirectory : lockRoot.Trim());
        while (root is not null && !Directory.Exists(Path.Combine(root.FullName, "config", "plugin_packages", "v3"))) root = root.Parent;
        return root?.FullName ?? throw new InvalidOperationException("source_normalizer_bundle_unsupported");
    }
    internal static async Task<string> AuthorizedArchiveRoot(ISemanticSession session, DateTime now, CancellationToken ct)
    {
        var readiness = await session.QueryAsync("select case when to_regclass('public.storage_v2_runtime_authorizations') is null then false else has_table_privilege(current_user,'public.storage_v2_runtime_authorizations','SELECT') end as available", ct);
        if (readiness.Count != 1 || !readiness[0].Flag("available")) throw new InvalidOperationException("semantic_archive_authorization_schema_not_ready");
        var row = (await session.QueryAsync("select route,authority,preflight_digest,archive_root,evidence,authorized_by,authorized_at,expires_at,revoked_at,authorization_digest from public.storage_v2_runtime_authorizations where singleton=true", ct)).SingleOrDefault();
        if (row is null) throw new InvalidOperationException("storage_v2_admission_required");
        var record = new DirectRuntimeRecord(row.Text("route")!, row.Text("authority")!, row.Text("preflight_digest")!, row.Text("archive_root")!,
            row["evidence"]!.AsObject(), row.Text("authorized_by")!, SigmaProjection.At(row, "authorized_at").UtcDateTime,
            SigmaProjection.At(row, "expires_at").UtcDateTime, row["revoked_at"] is null ? null : SigmaProjection.At(row, "revoked_at").UtcDateTime, row.Text("authorization_digest")!);
        return DirectRuntimeAuthorization.Validate(record, now).ArchiveRoot;
    }
    internal async Task<JsonArray> ClaimScheduled(ISemanticSession session, int count, CancellationToken ct)
    {
        // Keep one full historical turn in four even when both lanes are busy.
        // A vacant turn goes to the other lane. Each lane retains its FIFO key.
        bool live = outboxClaimTurn != 3;
        var jobs = await Claim(session, ct, count: count, live: live);
        if (jobs.Count == 0) jobs = await Claim(session, ct, count: count, live: !live);
        if (jobs.Count > 0) outboxClaimTurn = (outboxClaimTurn + 1) % 4;
        return jobs;
    }

    internal static async Task<JsonArray> Claim(ISemanticSession session, CancellationToken ct, string? repairDigest = null,
        long[]? sourceEventIds = null, int count = 1, bool? live = null)
    {
        repairDigest = string.IsNullOrWhiteSpace(repairDigest) ? null : repairDigest.Trim();
        if (repairDigest is not null && !System.Text.RegularExpressions.Regex.IsMatch(repairDigest, @"\A[0-9a-f]{64}\z")) throw new InvalidDataException("semantic_repair_digest_invalid");
        var args = new List<object?> { Guid.NewGuid(), SemanticEvent.Version, SemanticEvent.Version + "+r7-%" };
        string filter = "and job_kind<>'semantic_v2_quarantine_repair'";
        if (repairDigest is not null) { args.Add(repairDigest); filter = "and job_kind='semantic_v2_quarantine_repair' and payload_json->>'repair_plan_digest'=$4"; }
        if (sourceEventIds is not null) { if (repairDigest is null) filter += " and job_kind='normalize_event'"; args.Add(sourceEventIds.Distinct().Order().ToArray()); filter += " and source_event_id=any($" + args.Count + ")"; }
        if (live is bool isLive) filter += " and " + OutboxLane + (isLive ? "=1" : "=0");
        string take = "1";
        if (count != 1) { args.Add(Math.Clamp(count, 1, 128)); take = "$" + args.Count; }
        return await session.QueryAsync($"""
            with candidates as(select job_id from semantic_processing_outbox where semantic_contract_version=1
              and status in('queued','failed','leased') and processor_id='semantic-shadow'
              and (attempt_count<max_attempts or status='leased')
              and {OutboxVersion}=$2
              and ((job_kind='semantic_replay' and processor_version like $3) or(job_kind<>'semantic_replay' and processor_version=$2))
              and available_at<=now() and((status in('queued','failed') and attempt_count<max_attempts) or(status='leased' and lease_until<now()))
              {filter} order by available_at,created_at,job_id for update skip locked limit {take}),
            leased as(update semantic_processing_outbox job set status='leased',attempt_count=case when job.attempt_count<job.max_attempts then job.attempt_count+1 else job.attempt_count end,lease_token=$1,lease_until=now()+interval '300 seconds',heartbeat_at=now(),updated_at=now(),last_error_code=null,last_error_detail=null
              from candidates where job.job_id=candidates.job_id returning job.*) select * from leased order by available_at,created_at,job_id
            """, ct, args.ToArray());
    }
    private static Guid JobId(JsonNode? job) => Guid.Parse(job.Text("job_id")!);
    private static Guid LeaseToken(JsonNode? job) => Guid.Parse(job.Text("lease_token")!);
    internal static async Task CompleteBatch(ISemanticSession session, IReadOnlyList<JsonNode> jobs, CancellationToken ct)
    {
        if (jobs.Count == 0) return;
        var rows = await Change(session, """
            update semantic_processing_outbox set status='completed',completed_at=statement_timestamp(),
              lease_token=null,lease_until=null,heartbeat_at=statement_timestamp(),updated_at=statement_timestamp()
            where job_id=any($1) and status='leased' and lease_token=$2 returning job_id
            """, ct, jobs.Select(JobId).ToArray(), LeaseToken(jobs[0]));
        if (rows.Count != jobs.Count) throw new InvalidOperationException("semantic batch lease was lost");
    }
    internal static async Task<bool> HeartbeatJob(ISemanticSession session, JsonNode job, CancellationToken ct) =>
        (await Change(session, "update semantic_processing_outbox set heartbeat_at=now(),lease_until=now()+interval '300 seconds',updated_at=now() where job_id=$1 and status='leased' and lease_token=$2 returning job_id", ct, Guid.Parse(job.Text("job_id")!), Guid.Parse(job.Text("lease_token")!))).Count == 1;

    internal static JsonObject SourceIdentity(JsonObject value)
    {
        string[] required = ["id", "server_id", "domain_id", "log_source_id", "event_id", "time_created_utc", "normalized_hash", "migrated_at", "channel"];
        if (required.Any(field => value[field] is null)) throw new InvalidDataException("semantic_source_identity_incomplete");
        var identity = new JsonObject();
        foreach (string field in required.Concat(["correlation_id", "provider_name", "computer"])) identity[field] = value[field].Copy();
        foreach (string field in new[] { "id", "server_id", "domain_id", "log_source_id", "event_id" }) identity[field] = long.Parse(value[field]!.ToString(), CultureInfo.InvariantCulture);
        string hash = identity.Text("normalized_hash")!.ToLowerInvariant();
        if (!System.Text.RegularExpressions.Regex.IsMatch(hash, @"\A[0-9a-f]{64}\z")) throw new InvalidDataException("semantic_source_identity_hash_invalid");
        identity["normalized_hash"] = hash;
        if (Encoding.UTF8.GetByteCount(SourceJson.SerializeSorted(identity)) > 4096) throw new InvalidDataException("semantic_source_identity_too_large");
        return identity;
    }
    internal static JsonObject HydrateSource(long id, JsonObject identity, JsonObject source)
    {
        identity = SourceIdentity(identity);
        if (identity.Number("id") != id) throw new InvalidDataException("semantic_source_identity_conflict");
        EventDetailIdentity.Verify(identity, source);
        foreach (string key in new[] { "provider_name", "channel", "computer" }) source[key] ??= identity[key].Copy();
        source["source_host_id"] = identity["server_id"].Copy(); source["source_ingested_at"] = identity["migrated_at"].Copy(); source["source_event_sha256"] = identity["normalized_hash"].Copy(); return source;
    }
    internal async Task<JsonObject> LoadSource(ISemanticSession session, long id, JsonObject identity, CancellationToken ct, Dictionary<ArchiveBlock, IReadOnlyList<JsonObject>>? cache = null)
    {
        identity = SourceIdentity(identity);
        if (identity.Number("id") != id) throw new InvalidDataException("semantic_source_identity_conflict");
        if (authorizedArchive is not null)
        {
            // Controller authorization owns both the root and manifest routing.
            // A read or integrity failure must not fall back to environment routing.
            var authorized = (await authorizedArchive.ReadRowsForEventAsync("event", id, ct)).Single();
            return HydrateSource(id, identity, authorized);
        }
        var shortSource=(await session.QueryAsync("select *,encode(normalized_hash,'hex') as normalized_hash from public.semantic_event_source355 where id=$1",ct,id)).SingleOrDefault();
        if(shortSource is not null) {
            if(shortSource.Text("normalized_hash")!=identity.Text("normalized_hash")) throw new InvalidDataException("semantic_source_hash_mismatch");
            return HydrateSource(id,identity,shortSource.AsObject());
        }
        // Previously queued jobs can still refer to an archived/native source.
        // Keep its integrity checks; new jobs use the attested short row above.
        var blocks = await session.QueryAsync("select *,encode(raw_sha256,'hex') as raw_sha256,encode(archive_sha256,'hex') as archive_sha256 from storage_v2_archive_blocks where archive_kind='event' and state='published' and first_event_id<=$1 and last_event_id>=$1 order by first_event_id desc,block_index desc limit 1", ct, id);
        JsonObject? source = null;
        if (blocks.Count > 0)
        {
            string root = await AuthorizedArchiveRoot(session, DateTime.UtcNow, ct);
            if (!ArchiveObjectStore.SupportsRoot(root)) throw new FileNotFoundException("archive_root_absolute_required");
            var b = blocks[0]!;
            var block = new ArchiveBlock(Guid.Parse(b.Text("archive_set_id")!), "event", (int)b.Number("format_version"), (int)b.Number("block_index"), b.Number("first_event_id"), b.Number("last_event_id"), (int)b.Number("row_count"), b.Number("raw_bytes"), b.Number("compressed_bytes"), b.Text("raw_sha256")!, b.Text("archive_sha256")!, b.Text("object_location")!, "published", SigmaProjection.At(b, "created_at").UtcDateTime, null);
            source = new ArchiveReader(root, new PostgresArchiveManifestStore(runtime.DataSource)).ReadEventFromBlock(block, id, cache ?? new(), ct);
            EventDetailIdentity.Verify(identity, source);
        }
        else throw new SemanticSourceAbsentException();
        return HydrateSource(id, identity, source);
    }
    internal static async Task PersistNormalized(ISemanticSession session, SemanticEvent ev, JsonObject identity, string version, CancellationToken ct)
    {
        identity = SourceIdentity(identity);
        if (identity.Number("id") != ev.Source) throw new InvalidDataException("normalized_source_identity_conflict");
        await Change(session, """
            insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,processing_status,
              source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,source_ingested_at,roles_json,facts_json,quality_json,source_identity_json)
            values($1,$2,1,'windows.named-eventdata',$3,'normalized',$4,$5,$6,$7,$8,$9,$10,$11,$12)
            on conflict(source_event_id,semantic_contract_version,normalizer_id,normalizer_version) do nothing returning normalized_event_id
            """, ct, ev.Id(version), ev.Source, version, Convert.FromHexString(identity.Text("normalized_hash")!), Convert.FromHexString(ev.Sha), ev.Type, ev.At, SigmaProjection.At(identity, "migrated_at"), ev.Roles, ev.Facts, ev.Quality, identity);
        var stored = (await session.QueryAsync("select normalized_event_id,semantic_type,occurred_at_utc,roles_json,facts_json,quality_json,encode(semantic_sha256,'hex') as semantic_sha256 from normalized_events where source_event_id=$1 and semantic_contract_version=1 and normalizer_id='windows.named-eventdata' and normalizer_version=$2", ct, ev.Source, version)).Single();
        if (stored.Text("normalized_event_id") != ev.Id(version).ToString() || stored.Text("semantic_sha256") != ev.Sha || stored.Text("semantic_type") != ev.Type || SigmaProjection.At(stored!, "occurred_at_utc") != ev.At || !JsonNode.DeepEquals(stored!["roles_json"], ev.Roles) || !JsonNode.DeepEquals(stored["facts_json"], ev.Facts) || !JsonNode.DeepEquals(stored["quality_json"], ev.Quality)) throw new InvalidDataException("normalized_event_replay_conflict");
    }
    internal static async Task<SemanticEvent> IdentityOverrides(ISemanticSession session, SemanticEvent ev, JsonNode job, CancellationToken ct)
    {
        string? mergeId = job.Text("job_kind") == "semantic_replay" ? job["payload_json"].Text("identity_merge_id") : null;
        if (job.Text("job_kind") == "semantic_replay" && string.IsNullOrWhiteSpace(mergeId)) throw new InvalidDataException("semantic_replay_merge_required");
        var identities = ev.Quality["identity_roles"]?.AsObject(); var keys = identities?.Where(x => x.Value.Text("state") == "provisional" && x.Value.Flag("provisional")).Select(x => x.Value.Text("key")!).ToArray() ?? [];
        if (keys.Length == 0) { if (mergeId is not null) throw new InvalidDataException("semantic_replay_source_not_provisional"); return ev; }
        var available = await session.QueryAsync("select to_regclass('entity_identity_merges_v2') is not null as available", ct);
        if (!available[0].Flag("available")) { if (mergeId is not null) throw new InvalidDataException("semantic_replay_schema_unavailable"); return ev; }
        var merges = await session.QueryAsync("select merge_id::text,source_natural_key,target_natural_key from entity_identity_merges_v2 where source_natural_key=any($1) and($2::uuid is null or merge_id=$2::uuid) order by source_natural_key", ct, keys, mergeId is null ? null : Guid.Parse(mergeId));
        if (mergeId is not null && merges.Count == 0) throw new InvalidDataException("semantic_replay_merge_missing");
        // A replay creates a new interpretation; the original evidence stays immutable.
        ev = ev with { Roles = ev.Roles.DeepClone().AsObject(), Quality = ev.Quality.DeepClone().AsObject() };
        identities = ev.Quality["identity_roles"]!.AsObject();
        var applied = new JsonArray();
        foreach (var role in ev.Roles.ToArray())
        {
            var match = merges.SingleOrDefault(x => x.Text("source_natural_key") == role.Value?.ToString()); if (match is null) continue;
            string target = match.Text("target_natural_key")!; if (!target.StartsWith("sid:", StringComparison.Ordinal)) throw new InvalidDataException("semantic_replay_target_not_exact");
            var metadata = identities![role.Key]?.AsObject() ?? throw new InvalidDataException("semantic_replay_role_metadata_missing");
            if (metadata.Text("key") != role.Value?.ToString() || metadata.Text("state") != "provisional" || !metadata.Flag("provisional")) throw new InvalidDataException("semantic_replay_role_not_provisional");
            var aliases = (metadata["aliases"]?.AsArray().Select(x => x!.GetValue<string>()) ?? []).Append(role.Value!.ToString()).Distinct().Order(StringComparer.Ordinal);
            metadata["aliases"] = new JsonArray(aliases.Select(x => JsonValue.Create(x)).ToArray()); metadata["resolution_evidence"] = "identity_merge_r7"; metadata["identity_merge_id"] = match["merge_id"].Copy();
            ev.Roles[role.Key] = target; metadata["key"] = target; metadata["state"] = "resolved"; metadata["provisional"] = false; metadata["confidence"] = 1.0; metadata["reason"] = null;
            applied.Add(new JsonObject { ["role"] = role.Key, ["source_key"] = role.Value.Copy(), ["target_key"] = target, ["merge_id"] = match["merge_id"].Copy() });
        }
        if (applied.Count == 0) return ev;
        ev.Quality["identity_merge_replays"] = applied; ev.Quality["provisional_identity_roles"] = new JsonArray(identities!.Where(x => x.Value.Flag("provisional")).Select(x => JsonValue.Create(x.Key)).OrderBy(x => x!.GetValue<string>(), StringComparer.Ordinal).ToArray());
        ev.Quality["unresolved_identity_roles"] = new JsonArray(identities.Where(x => x.Value.Text("state") == "unresolved").Select(x => JsonValue.Create(x.Key)).OrderBy(x => x!.GetValue<string>(), StringComparer.Ordinal).ToArray());
        string sha = SemanticJson.Hash(new JsonObject { ["source_event_id"] = ev.Source, ["semantic_type"] = ev.Type, ["roles"] = ev.Roles.Copy(), ["facts"] = ev.Facts.Copy(), ["identity_resolution_version"] = "1.0" }); return ev with { Sha = sha };
    }
    private static async Task RecordIdentityReplay(ISemanticSession session, SemanticEvent ev, JsonNode job, string version, CancellationToken ct)
    {
        Guid merge = Guid.Parse(job["payload_json"].Text("identity_merge_id")!); Guid next = ev.Id(version), replay = Guid.Parse(job.Text("job_id")!);
        var keys = ev.Quality["identity_merge_replays"]!.AsArray().Select(x => x.Text("source_key")!).Distinct().Order(StringComparer.Ordinal).ToArray();
        var prior = await session.QueryAsync("select distinct n.normalized_event_id::text from normalized_events n cross join lateral jsonb_each_text(n.roles_json) role where n.source_event_id=$1 and role.value=any($2) order by n.normalized_event_id::text", ct, ev.Source, keys);
        if (prior.Count == 0 || prior.Any(x => x.Text("normalized_event_id") == next.ToString())) throw new InvalidDataException("semantic_replay_prior_fact_missing");
        foreach (var row in prior)
        {
            Guid old = Guid.Parse(row.Text("normalized_event_id")!);
            await session.QueryAsync("insert into entity_identity_semantic_replays_v2(merge_id,source_event_id,old_normalized_event_id,new_normalized_event_id,replay_job_id,source_event_sha256,source_occurred_at_utc) select $1,$2,$3,$4,$5,source_event_sha256,occurred_at_utc from normalized_events where normalized_event_id=$3 on conflict(merge_id,source_event_id,old_normalized_event_id) do nothing", ct, merge, ev.Source, old, next, replay);
            var stored = (await session.QueryAsync("select new_normalized_event_id,replay_job_id from entity_identity_semantic_replays_v2 where merge_id=$1 and source_event_id=$2 and old_normalized_event_id=$3", ct, merge, ev.Source, old)).Single()!;
            if (stored.Text("new_normalized_event_id") != next.ToString() || stored.Text("replay_job_id") != replay.ToString()) throw new InvalidDataException("semantic_replay_provenance_conflict");
        }
    }
    internal static async Task PersistAction(ISemanticSession session, SemanticAction action, string version, CancellationToken ct)
    {
        await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, action.Key);
        var old = (await session.QueryAsync("select *,encode(canonical_deduplication_key,'hex') as dedup from canonical_actions where canonical_action_id=$1 for update", ct, action.Id)).FirstOrDefault();
        old ??= (await session.QueryAsync("select *,encode(canonical_deduplication_key,'hex') as dedup from canonical_actions where semantic_contract_version=1 and assembler_id='semantic-action-assembler' and assembler_version='1.1' and canonical_deduplication_key=$1 for update", ct, Convert.FromHexString(action.Key))).FirstOrDefault();
        var attributes = action.Attributes.DeepClone().AsObject();
        bool versionChanged = old is not null && old.Text("assembler_version") != "1.1";
        if (old is not null)
        {
            if (old.Text("canonical_action_id") != action.Id.ToString() || old.Number("semantic_contract_version") != 1 || old.Text("action_kind") != action.Kind || old.Text("assembler_id") != "semantic-action-assembler" || old.Text("dedup") != action.Key) throw new InvalidDataException("canonical_action_replay_conflict");
            var prior = old["attributes_json"]!.AsObject();
            if (versionChanged && action.Evidence.Count == 1 && prior.ContainsKey("source_evidence") && attributes.ContainsKey("source_evidence"))
            {
                long source = action.Evidence[0].Source;
                if (!JsonNode.DeepEquals(prior["material_identity"], attributes["material_identity"]) || attributes.ContainsKey("prior_interpretations")) throw new InvalidDataException("canonical_action_interpretation_conflict");
                foreach (var value in new[] { prior, attributes })
                    if (value["material_identity"].Number("source_event_id") != source || value["source_evidence"] is not JsonArray { Count: 1 } refs || refs[0].Number("source_event_id") != source || value["observed_facts"] is not JsonArray { Count: 1 } || value["observed_roles"] is not JsonArray { Count: 1 }) throw new InvalidDataException("canonical_action_interpretation_source_conflict");
            }
            else
            {
                var merged = prior.DeepClone().AsObject();
                if (prior["material_identity"] is not null && !JsonNode.DeepEquals(prior["material_identity"], attributes["material_identity"])) throw new InvalidDataException("canonical_action_material_identity_conflict");
                foreach (var pair in attributes)
                {
                    if (pair.Key is "added_values" or "removed_values") merged[pair.Key] = new JsonArray((merged[pair.Key]?.AsArray().Select(x => x!.ToString()) ?? []).Concat(pair.Value!.AsArray().Select(x => x!.ToString())).Distinct().Order(StringComparer.Ordinal).Select(x => JsonValue.Create(x)).ToArray());
                    else if (merged[pair.Key] is null || merged[pair.Key]?.ToString() == "") merged[pair.Key] = pair.Value.Copy();
                    else if (!JsonNode.DeepEquals(merged[pair.Key], pair.Value) && pair.Key is not ("quality" or "identity_quality")) throw new InvalidDataException("canonical_action_attributes_replay_conflict");
                }
                attributes = merged;
            }
            if (versionChanged)
            {
                var links = await session.QueryAsync("select n.source_event_id,e.normalized_event_id,e.evidence_role,e.entity_role,e.evidence_order,e.relation_confidence::text from canonical_action_evidence e join normalized_events n using(normalized_event_id) where e.canonical_action_id=$1 order by e.evidence_order for update of e", ct, action.Id);
                if (links.GroupBy(x => x.Number("source_event_id")).Any(x => x.Count() != 1) || action.Evidence.Count == 1 && attributes.ContainsKey("source_evidence") && !links.Any(x => x.Number("source_event_id") == action.Evidence[0].Source)) throw new InvalidDataException("canonical_action_prior_evidence_conflict");
                var history = prior["prior_interpretations"]?.AsArray().DeepClone().AsArray() ?? new JsonArray(); var saved = prior.DeepClone().AsObject(); saved.Remove("prior_interpretations");
                history.Add(new JsonObject { ["assembler_id"] = old["assembler_id"].Copy(), ["assembler_version"] = old["assembler_version"].Copy(), ["action_sha256"] = old["action_sha256"].Copy(), ["evidence"] = links, ["attributes"] = saved }); attributes["prior_interpretations"] = history;
            }
            if (action.Kind == "directory.attribute.changed") attributes["quality"] = attributes["added_values"] is JsonArray { Count: > 0 } && attributes["removed_values"] is JsonArray { Count: > 0 } ? "complete" : "partial";
            string hash = SemanticJson.Hash(new JsonObject { ["action_kind"] = action.Kind, ["deduplication_key"] = action.Key, ["attributes"] = attributes.Copy() });
            await Change(session, "update canonical_actions set attributes_json=$1,action_sha256=$2,assembler_version='1.1',occurred_at_utc=least(occurred_at_utc,$3),updated_at=now() where canonical_action_id=$4 returning canonical_action_id", ct, attributes, Convert.FromHexString(hash), action.At, action.Id);
        }
        else await Change(session, "insert into canonical_actions(canonical_action_id,action_kind,action_status,semantic_contract_version,assembler_id,assembler_version,occurred_at_utc,contribution_key,canonical_deduplication_key,action_sha256,attributes_json) values($1,$2,$7,1,'semantic-action-assembler','1.1',$3,$4,$4,$5,$6) returning canonical_action_id", ct, action.Id, action.Kind, action.At, Convert.FromHexString(action.Key), Convert.FromHexString(action.Sha), attributes, action.Status);
        foreach (var ev in action.Evidence)
        {
            var link = await session.QueryAsync("select normalized_event_id from canonical_action_evidence e join normalized_events n using(normalized_event_id) where e.canonical_action_id=$1 and n.source_event_id=$2", ct, action.Id, ev.Source);
            if (link.Count > 0)
            {
                if (link.Count != 1) throw new InvalidDataException("canonical_evidence_replay_conflict");
                if (link[0].Text("normalized_event_id") != ev.Id(version).ToString())
                {
                    if (!versionChanged) throw new InvalidDataException("canonical_evidence_replay_conflict");
                    await session.QueryAsync("update canonical_action_evidence set normalized_event_id=$1 where canonical_action_id=$2 and normalized_event_id=$3", ct, ev.Id(version), action.Id, Guid.Parse(link[0].Text("normalized_event_id")!));
                }
                continue;
            }
            await Change(session, "insert into canonical_action_evidence(canonical_action_id,normalized_event_id,evidence_role,entity_role,evidence_order,relation_confidence) select $1,$2,case when coalesce(max(evidence_order),-1)<0 then 'primary' else 'supporting' end,null,coalesce(max(evidence_order),-1)+1,1.000 from canonical_action_evidence where canonical_action_id=$1 returning canonical_action_id", ct, action.Id, ev.Id(version));
        }
        await Change(session, "update canonical_actions action set action_status='multi_source_confirmed',updated_at=now() where canonical_action_id=$1 and action_status in('observed','partially_confirmed') and(select count(distinct normalized.source_event_id) from canonical_action_evidence evidence join normalized_events normalized using(normalized_event_id) where evidence.canonical_action_id=$1 and evidence.evidence_role in('primary','supporting'))>1 returning canonical_action_id", ct, action.Id);
    }
    private static async Task<bool> ExpandContext(ISemanticSession session, long id, JsonNode job, CancellationToken ct, bool finish)
    {
        // Exact SID and domain context only; no source contact or broad temporal join.
        var anchors = await session.QueryAsync("select e.domain_id,e.target_user_sid,e.time_created_utc,e.event_id,e.channel,e.provider_name,e.keywords from public.semantic_event_source355 e where e.id=$1", ct, id);
        var anchor = anchors.FirstOrDefault();
        bool valid = anchor is not null && anchor.Number("event_id") == 4724 && anchor.Number("domain_id") > 0 && anchor.Text("channel") == "Security" && anchor.Text("provider_name") == "Microsoft-Windows-Security-Auditing" && SemanticProducer.AuditOutcome(anchor.Text("keywords")) == "success" && (anchor.Text("target_user_sid")?.Length ?? 0) <= 184 && System.Text.RegularExpressions.Regex.IsMatch(anchor.Text("target_user_sid") ?? "", @"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z");
        var rows = valid ? await session.QueryAsync("select e.id from public.semantic_event_source355 e where e.domain_id=$1 and e.target_user_sid=$2 and e.event_id=4624 and e.channel='Security' and e.provider_name='Microsoft-Windows-Security-Auditing' and e.time_created_utc>$3 and e.time_created_utc<=$3+interval '1 hour' and not exists(select 1 from semantic_processing_outbox j where j.source_event_id=e.id and j.semantic_contract_version=1 and j.processor_id='semantic-shadow' and j.processor_version=$4 and j.job_kind='normalize_event') order by e.id limit 101", ct, anchor.Number("domain_id"), anchor.Text("target_user_sid"), SigmaProjection.At(anchor!, "time_created_utc"), SemanticEvent.Version) : new JsonArray();
        foreach (var row in rows.Take(100)) await EnqueueSource(session, row.Number("id"), "late_related_context", ct);
        if (rows.Count > 100)
            await Defer(session, job, ct);
        else if (finish) await Complete(session, "semantic_processing_outbox", "status", job, ct);
        return rows.Count <= 100;
    }
    internal static async Task Defer(ISemanticSession session, JsonNode job, CancellationToken ct)
    {
        var rows = await Change(session, "update semantic_processing_outbox set status='queued',attempt_count=greatest(attempt_count-1,0),available_at=now()+interval '1 second',lease_token=null,lease_until=null,heartbeat_at=now(),updated_at=now() where job_id=$1 and status='leased' and lease_token=$2 returning job_id", ct, Guid.Parse(job.Text("job_id")!), Guid.Parse(job.Text("lease_token")!));
        if (rows.Count != 1) throw new InvalidOperationException("semantic lease was lost while deferring");
    }
    internal static async Task EnqueueSource(ISemanticSession session, long id, string reason, CancellationToken ct)
    {
        string hash = SemanticProducer.JobIdentity(id);
        await Change(session, """
            insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,idempotency_key,payload_json,source_id,domain_id,partition_key,occurred_at_utc,source_identity_json)
            select $1,e.id,'normalize_event',1,'semantic-shadow',$2,$3,$4,e.log_source_id,e.domain_id,e.server_id::text||':'||e.channel_id::text,e.time_created_utc,
              jsonb_build_object('id',e.id,'server_id',e.server_id,'domain_id',e.domain_id,'log_source_id',e.log_source_id,'event_id',e.event_id,'time_created_utc',e.time_created_utc,'normalized_hash',encode(e.normalized_hash,'hex'),'correlation_id',e.correlation_id,'migrated_at',e.migrated_at,'provider_name',e.provider_name,'channel',e.channel,'computer',e.computer)
            from public.semantic_event_source355 e where e.id=$5
            on conflict(idempotency_key) do nothing returning job_id
            """, ct, Sli.Server.Auth.Lifecycle.Security.AuthAudit.Uuid5("adlog:semantic:" + hash), SemanticEvent.Version, Convert.FromHexString(hash), new JsonObject { ["selection_reason"] = reason }, id);
        var row = (await session.QueryAsync("select job_id,payload_json,source_identity_json from semantic_processing_outbox where idempotency_key=$1", ct, Convert.FromHexString(hash))).SingleOrDefault() ?? throw new KeyNotFoundException("semantic source event is missing from the short event store");
        if (!JsonNode.DeepEquals(row["payload_json"], new JsonObject { ["selection_reason"] = reason })) throw new InvalidDataException("semantic_job_replay_payload_conflict");
        if (SourceIdentity(row["source_identity_json"]!.AsObject()).Number("id") != id) throw new InvalidDataException("semantic_job_source_identity_conflict");
    }
}
