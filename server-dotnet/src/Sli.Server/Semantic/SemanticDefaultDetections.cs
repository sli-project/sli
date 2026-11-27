using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticProduction
{
    private static string Digest(JsonNode? value) => Password.PasswordJson.Hash(value);
    internal static JsonObject Definition(string rule, JsonObject scope, string? agent = null, JsonObject? config = null)
    {
        var definition = DefaultDetectionDefinitions.Read()[rule]!.DeepClone().AsObject(); var pin = definition["source_selector"]!["execution"]!.AsObject(); pin["scope"] = scope.Copy();
        if (rule == "qw.file-decoy") pin["rule_sha256"] = Digest(new JsonObject { ["version"] = 1, ["agent_id"] = agent, ["events"] = new JsonArray(4656, 5145, 4663, 4660, 4670), ["identity"] = "exact-event-time-path", ["session_window_seconds"] = 300 });
        if (rule == "qw.file-ransom")
        {
            int threshold = config?["mass_operation_files"] is null ? 100 : (int)config.Number("mass_operation_files"), window = config?["mass_operation_seconds"] is null ? 300 : (int)config.Number("mass_operation_seconds");
            if (threshold is < 1 or > 1000000 || window is < 1 or > 86400) throw new InvalidDataException("file_ransom_rule_invalid");
            pin["rule_sha256"] = Digest(new JsonObject { ["version"] = 1, ["agent_id"] = agent, ["source_policy_revision"] = config?["policy_revision"].Copy() ?? JsonValue.Create("1"), ["threshold"] = threshold, ["window_seconds"] = window }); definition["merge_window_seconds"] = window; definition["expected_evidence_count"] = threshold;
        }
        return definition;
    }
    private static string PolicyId(JsonObject definition)
    {
        var pin = definition["source_selector"]!["execution"]!;
        JsonNode identity = definition.Text("scenario_kind") == "qw.nps-denials" ? new JsonObject { ["rule_id"] = pin["rule_id"].Copy(), ["scope"] = pin["scope"].Copy(), ["rule_sha256"] = pin["rule_sha256"].Copy() } : pin;
        return "default:" + pin.Text("rule_id") + ":" + Digest(identity)[..32];
    }
    private static async Task<bool> AdmitDefault(ISemanticSession session, JsonObject definition, CancellationToken ct)
    {
        var result = await session.QueryAsync("select public.ensure_default_qw_policy($1,1,$2) as admitted", ct, PolicyId(definition), CanonicalJson.Serialize(definition, ensureAscii: false)); return result.Count == 1 && result[0].Flag("admitted");
    }
    private static JsonArray ReferenceParams(JsonNode reference)
    {
        var s = reference["scope"]!; return new JsonArray(s["installation_id"].Copy(), s["plugin_id"].Copy(), s["source_instance_id"].Copy(), s["source_generation"].Copy(), s["collection_scope_id"].Copy(), reference["storage_kind"].Copy(), reference["native_id"].Copy(), reference["sha256"].Copy());
    }
    private static JsonObject Reference(JsonNode scope, string storage, string id, string hash) => new() { ["storage_kind"] = storage, ["native_id"] = id, ["sha256"] = hash, ["scope"] = scope.Copy() };
    internal static JsonObject Signal(JsonObject definition, string entity, string episode, DateTimeOffset at, DateTimeOffset now, JsonArray refs, string severity = "high", string? reason = null, string quality = "good", string? contextKey = null, JsonObject? context = null, int total = 0)
    {
        var pin = definition["source_selector"]!["execution"]!; var document = new JsonObject
        {
            ["kind"] = pin["kind"].Copy(), ["rule_id"] = pin["rule_id"].Copy(), ["rule_version"] = pin["rule_version"].Copy(), ["rule_sha256"] = pin["rule_sha256"].Copy(), ["policy_revision"] = 1, ["evaluation_mode"] = "enabled", ["entity_key"] = entity, ["episode_key"] = episode,
            ["occurred_at_utc"] = SemanticJson.Stamp(at), ["received_at_utc"] = SemanticJson.Stamp(now), ["evidence_refs"] = SemanticJson.Array(refs.OrderBy(x => x.Text("storage_kind"), StringComparer.Ordinal).ThenBy(x => x.Text("native_id"), StringComparer.Ordinal)),
            ["base_severity"] = severity, ["effective_severity"] = severity, ["severity_reasons"] = reason is null ? new JsonArray() : new JsonArray(reason), ["quality"] = quality, ["conclusion_state"] = "observed"
        };
        if (total > 0) document["evidence_total"] = total; if (contextKey is not null) document[contextKey] = context.Copy(); return document;
    }
    internal static async Task<int> EnqueueQW(ISemanticSession session, JsonObject document, CancellationToken ct)
    {
        if (document["evidence_refs"] is not JsonArray { Count: > 0 and <= 256 } refs || EncodingSize(document) > 524288) throw new InvalidDataException("qw_signal_invalid");
        await VerifyNative(session, refs, ct); await VerifyQWContext(session, document, ct);
        var material = document.DeepClone().AsObject(); material.Remove("received_at_utc"); string id = Digest(material);
        await session.QueryAsync("insert into semantic_qw_signals(signal_id,evaluation_mode,document_json) values($1,$2,$3) on conflict(signal_id) do nothing", ct, id, document.Text("evaluation_mode"), document);
        var stored = (await session.QueryAsync("select document_json from semantic_qw_signals where signal_id=$1", ct, id)).Single()!["document_json"]!.DeepClone().AsObject(); stored.Remove("received_at_utc");
        if (!JsonNode.DeepEquals(stored, material)) throw new InvalidDataException("qw_signal_replay_conflict"); return await EnqueueRiskSource(session, "qw_signal", id, ct);
    }
    private static int EncodingSize(JsonNode node) => System.Text.Encoding.UTF8.GetByteCount(CanonicalJson.Serialize(node));
    // Integration tests can decorate source queries while retaining the owned PostgreSQL transaction and COMMIT.
    internal async Task<(JsonObject Result, JsonArray Sources)> ProcessDefaultDetections(NpgsqlConnection db, CancellationToken ct,
        Func<ISemanticSession, ISemanticSession>? sourceSession = null)
    {
        int jobs = 0, failed = 0, waiting = 0, resources = 0, completed = 0; JsonArray sources = []; JsonNode? importProgress = null; var diagnostics = new DetectionDiagnostics();
        try { await using var tx = await db.BeginTransactionAsync(ct); sources = await new SemanticSession(db,tx,diagnostics:diagnostics).QueryAsync("select source from public.default_detection_sources()",ct); importProgress = await Detections.DetectionProducer.ReadImportProgress(new Detections.DetectionSql(db,tx),ct); await tx.CommitAsync(ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) { diagnostics.Add(error); failed++; }
        foreach (var row in sources)
        {
            ct.ThrowIfCancellationRequested();diagnostics.Step="source_begin";
            try
            {
                var source = row!["source"]!.DeepClone();
                var outcome = await Source("default_source:" + Digest(source["scope"]), db, async connection => {
                    var sourceDiagnostics = new DetectionDiagnostics();
                    int accountJobs = 0, evaluated = 0, batches = 0;
                    if (source["scope"].Text("plugin_id") == "sli.windows.ad-dc")
                    {
                        bool more;
                        do
                        {
                            if (Stopping) return new DetectionOutcome(accountJobs) { Diagnostics = sourceDiagnostics };
                            await using var batch = await connection.BeginTransactionAsync(ct);
                            var accountSession = new SemanticSession(connection, batch, diagnostics: sourceDiagnostics);
                            await accountSession.ExecuteAsync("set local statement_timeout=0;set local lock_timeout=0", ct);
                            var result = await RunDefaultAccounts(sourceSession?.Invoke(accountSession) ?? accountSession,
                                source["scope"]!.AsObject(), ct);
                            await batch.CommitAsync(ct);
                            accountJobs += result.Jobs;
                            evaluated += result.Events;
                            batches++;
                            more = result.More;
                            SemanticWork.Progress(new JsonObject {
                                ["cursor"] = new JsonObject { ["account_batches_committed"] = batches, ["account_events_evaluated"] = evaluated },
                                ["heartbeat"] = SemanticJson.Stamp(DateTimeOffset.UtcNow)
                            });
                        } while (more);
                    }
                    await using var tx = await connection.BeginTransactionAsync(ct);
                    var session = new SemanticSession(connection,tx,diagnostics:sourceDiagnostics);
                    await session.ExecuteAsync("set local statement_timeout=0;set local lock_timeout=0",ct);
                    var portion = await RunDefaultSource(sourceSession?.Invoke(session) ?? session,source,ct,sourceDiagnostics, accountsAlreadyRun: true);
                    await tx.CommitAsync(ct);
                    portion = portion with { Jobs = accountJobs + portion.Jobs };
                    sourceDiagnostics.Write("default_source"); return portion with { Diagnostics = sourceDiagnostics };
                }, ct);
                if (outcome is not null) { diagnostics.Merge(outcome.Diagnostics); jobs += outcome.Jobs; failed += outcome.Failed; waiting += outcome.Waiting; if (outcome.Failed == 0) completed++; }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { diagnostics.Add(error); failed++; }
        }
        try { var acl = await Source("file_acl",db,async connection => {
            var sourceDiagnostics = new DetectionDiagnostics();
            var portion = await ProcessFileAcl(connection,ct,sourceDiagnostics);
            sourceDiagnostics.Write("file_acl"); return portion with { Diagnostics = sourceDiagnostics };
        },ct) ?? new DetectionOutcome(); diagnostics.Merge(acl.Diagnostics); jobs += acl.Jobs; failed += acl.Failed; resources += acl.Sources; completed += acl.Sources - acl.Failed; }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) { diagnostics.Add(error); failed++; }
        var result = new JsonObject { ["sources"] = sources.Count + resources, ["completed"] = completed, ["jobs"] = jobs, ["failed"] = failed, ["failure_reasons"] = diagnostics.Counts };
        if (importProgress is not null) result["import_summary"] = importProgress;
        if (waiting > 0) result["file_ransom_status"] = new JsonObject { ["code"] = "source_policy_waiting", ["sources"] = waiting, ["message_code"] = "operations.actions.fileRansomPolicyWaiting", ["retry_after_seconds"] = 60 };
        diagnostics.Write("default_detections"); return (result, sources);
    }
    internal sealed record DetectionOutcome(int Jobs = 0, int Failed = 0, int Waiting = 0, int Sources = 0)
    {
        internal DetectionDiagnostics? Diagnostics { get; init; }
    }
    internal static async Task<DetectionOutcome> RunDefaultSource(ISemanticSession session, JsonNode source, CancellationToken ct,
        DetectionDiagnostics? diagnostics = null, bool accountsAlreadyRun = false)
    {
        var scope = source["scope"]!.AsObject();
        // DC rules own distinct policy/checkpoint locks. Holding the shared
        // source lock across their native scans starves password publication.
        // No DC path takes that lock after a rule lock: password writers retain
        // family -> policy rows -> source -> checkpoint -> sorted entities.
        if (scope.Text("plugin_id") != "sli.windows.ad-dc")
            await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))",ct,Digest(scope));
        int added = 0;
                if (scope.Text("plugin_id") == "sli.windows.ad-dc")
                {
                    if (!accountsAlreadyRun) added += (await RunDefaultAccounts(session, scope, ct)).Jobs;
                    added += await DisabledAccount(session, scope, ct);
                }
                if (scope.Text("plugin_id") is "sli.windows.ad-dc" or "sli.vpn-nps") added += await ProcessNpsThreshold(session, scope, ct);
                if (scope.Text("plugin_id") == "sli.file-audit")
                {
                    added += await ProcessFileDecoy(session, source, ct);
                    var ransom = await ManagedRansom(session,source,DateTimeOffset.UtcNow,ct,diagnostics); added += ransom.Jobs;
                    return new(added,ransom.Failed,ransom.Waiting);
                }
        return new(added);
    }
    private const int AccountBatchSize = 128;

    private static async Task<(int Jobs, int Events, bool More)> RunDefaultAccounts(
        ISemanticSession session, JsonObject scope, CancellationToken ct)
    {
        bool queueAvailable = (await session.QueryAsync("""
            select to_regprocedure('public.subscribe_account_checkpoint455(text,text,jsonb)') is not null as available
            """, ct)).Single().Flag("available");
        int jobs = 0, evaluated = 0;
        bool more = false;
        foreach (string family in new[] { "decoy", "watch" })
        {
            bool watch = family == "watch";
            var definition = Definition("qw.account-" + family, scope);
            if (!await AdmitDefault(session, definition, ct))
                continue;
            string checkpoint = AccountCheckpoint(scope, watch, "enabled", 1);
            await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, checkpoint);
            bool seeding = queueAvailable && (await session.QueryAsync(
                "select public.subscribe_account_checkpoint455($1,$2,$3::jsonb) as more", ct, family, checkpoint, scope)).Single().Flag("more");
            var events = await session.QueryAsync($"select * from public.read_account_{family}_events($1,$2,$3,$4,$5,null::uuid)",
                ct, Guid.Parse(scope.Text("installation_id")!), scope.Text("plugin_id"), scope.Text("source_instance_id"),
                scope.Text("source_generation"), checkpoint);
            if (events.Count > AccountBatchSize)
                throw new InvalidDataException("account_detection_batch_invalid");
            var checks = new JsonArray();
            foreach (var ev in events)
            {
                var (signals, state) = EvaluateAccount(definition, ev!, DateTimeOffset.UtcNow, watch);
                foreach (var signal in signals)
                {
                    int count = await EnqueueQW(session, signal!.AsObject(), ct);
                    if (count == 0) throw new InvalidOperationException("account_detection_policy_unavailable");
                    jobs += count;
                }
                checks.Add(new JsonObject { ["id"] = ev!["normalized_event_id"].Copy(), ["state"] = state });
            }
            if (checks.Count > 0)
                await session.QueryAsync($"""
                    insert into semantic_account_{family}_checks(checkpoint_key,normalized_event_id,scope_json,result_code)
                    select $1,c.id,$2,c.state from jsonb_to_recordset($3) as c(id uuid,state text)
                    on conflict do nothing
                    """, ct, checkpoint, scope, checks);
            evaluated += events.Count;
            more |= queueAvailable && (seeding || events.Count == AccountBatchSize);
        }
        return (jobs, evaluated, more);
    }
    private static readonly Dictionary<string,(DateTimeOffset From,DateTimeOffset To)> RansomWaits = new();
    internal static async Task<DetectionOutcome> ManagedRansom(ISemanticSession session, JsonNode source, DateTimeOffset now, CancellationToken ct, DetectionDiagnostics? diagnostics = null)
    {
        await session.QueryAsync("savepoint default_file_ransom",ct); string? key = null;
        try
        {
            var scope = source["scope"]!.AsObject(); string agent = source.Text("agent_id")!; var config = source["config"]!.AsObject(); var definition = Definition("qw.file-ransom",scope,agent,config);
            if (!await AdmitDefault(session,definition,ct)) { await session.QueryAsync("release savepoint default_file_ransom",ct); return new(); }
            key = FileCheckpoint(scope,agent,"qw.file-ransom",config:config);
            bool pending; lock (RansomWaits) pending = RansomWaits.TryGetValue(key,out var wait) && wait.From <= now && now < wait.To;
            if (pending || source["ransom_policy"] is not null && source["ransom_policy"].Text("state") != "ready")
            {
                diagnostics?.Add(new InvalidOperationException("source_policy_waiting")); if (!pending) RememberRansomWait(key,now); await session.QueryAsync("release savepoint default_file_ransom",ct); return new(Failed:1,Waiting:1);
            }
            var rule = DetectorRule.Read("file-ransom", new JsonObject { ["scope"] = scope.Copy(), ["agent_id"] = agent, ["source_policy_revision"] = config["policy_revision"].Copy() ?? JsonValue.Create("1"), ["threshold"] = config["mass_operation_files"].Copy() ?? JsonValue.Create(100), ["window_seconds"] = config["mass_operation_seconds"].Copy() ?? JsonValue.Create(300), ["evaluation_mode"] = "enabled" });
            var result = await RunFileRansom(session,source,ct,rule,now); await session.QueryAsync("release savepoint default_file_ransom",ct); lock (RansomWaits) RansomWaits.Remove(key); return new((int)result.Number("jobs"));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception e)
        {
            diagnostics?.Add(e);
            await session.QueryAsync("rollback to savepoint default_file_ransom",ct); await session.QueryAsync("release savepoint default_file_ransom",ct);
            bool waiting = e is PostgresException p && p.SqlState == "P0001" && p.MessageText == "file_ransom_source_policy_mismatch";
            if (waiting && key is not null) RememberRansomWait(key,now); return new(Failed:1,Waiting:waiting ? 1 : 0);
        }
    }
    private static void RememberRansomWait(string key, DateTimeOffset now)
    {
        lock (RansomWaits) { RansomWaits.Remove(key); RansomWaits[key] = (now,now.AddSeconds(60)); while (RansomWaits.Count > 1024) RansomWaits.Remove(RansomWaits.First().Key); }
    }
    private static string AccountCheckpoint(JsonObject scope, bool watch, string mode, int revision, string processing = "live")
    {
        var key = new JsonObject { ["scope"] = scope.Copy(), ["policy_revision"] = revision, ["evaluation_mode"] = mode };
        if (watch || processing != "live") key["processing_mode"] = processing; return Digest(key);
    }
    internal static async Task<JsonObject> RunDetector(ISemanticSession session, DetectorRule rule, DateTimeOffset now, CancellationToken ct)
    {
        if (rule.Kind is "account-watch" or "account-decoy")
        {
            bool watch = rule.Kind == "account-watch"; string family = watch ? "watch" : "decoy", checkpoint = AccountCheckpoint(rule.Scope,watch,rule.Mode,rule.Revision,rule.Processing);
            await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, checkpoint);
            var rows = await session.QueryAsync($"select * from public.read_account_{family}_events($1,$2,$3,$4,$5,null::uuid)",ct,Guid.Parse(rule.Scope.Text("installation_id")!),rule.Scope.Text("plugin_id"),rule.Scope.Text("source_instance_id"),rule.Scope.Text("source_generation"),checkpoint);
            if (rows.Count > 128) throw new InvalidDataException("account_detection_batch_invalid"); int jobs = 0; var states = new JsonObject();
            foreach (var row in rows)
            {
                var (signals,state) = EvaluateAccount(rule.Definition(),row!,now,watch);
                foreach (var signal in signals) { int count = await EnqueueQW(session,rule.Apply(signal!.AsObject()),ct); if (count == 0) throw new InvalidOperationException("account_detection_policy_unavailable"); jobs += count; }
                await session.QueryAsync($"insert into semantic_account_{family}_checks(checkpoint_key,normalized_event_id,scope_json,result_code) values($1,$2,$3,$4) on conflict do nothing",ct,checkpoint,Guid.Parse(row.Text("normalized_event_id")!),rule.Scope,state);
                states[state] = (states[state]?.GetValue<int>() ?? 0) + 1;
            }
            return new() { ["state"] = "processed", ["events"] = rows.Count, ["results"] = states, ["jobs"] = jobs };
        }
        var source = new JsonObject { ["scope"] = rule.Scope.Copy(), ["agent_id"] = rule.Agent, ["config"] = rule.Config.Copy() };
        if (rule.Kind == "file-decoy") return await RunFileDecoy(session,source,ct,rule,now);
        if (rule.Kind == "file-ransom") return await RunFileRansom(session,source,ct,rule,now);
        return await RunNpsThreshold(session,rule.Scope,ct,rule,now);
    }
    internal static (JsonArray Signals, string State) EvaluateAccount(JsonObject definition, JsonNode row, DateTimeOffset now, bool watch)
    {
        var signals = new JsonArray(); var scope = definition["source_selector"]!["execution"]!["scope"]!; DateTimeOffset occurred = SigmaProjection.At(row, "occurred_at_utc"); string semantic = row.Text("semantic_type")!; int eventId = (int)row.Number("event_id");
        int[] auth = [4624, 4625, 4768, 4769, 4771, 4776]; int[] watched = [.. auth, 4634, 4647, 4648, 4672, 4740, 4767, 4770, 4773, 4720, 4722, 4725, 4726, 4738, 4781, 4723, 4724, 4728, 4732, 4756, 4729, 4733, 4757];
        string? expectedType = eventId switch { 4624 => "authentication.session.created", 4625 => "authentication.session.failed", 4768 => "authentication.kerberos.tgt.requested", 4769 => "authentication.kerberos.service_ticket.requested", 4771 => "authentication.kerberos.preauthentication.failed", 4776 => "authentication.credentials.validated", 4634 => "authentication.session.ended", 4647 => "authentication.logout.requested", 4648 => "authentication.explicit_credentials.used", 4672 => "authentication.privileged_session.created", 4740 => "authentication.account.locked", 4767 => "authentication.account.unlocked", 4770 => "authentication.kerberos.service_ticket.renewed", 4773 => "authentication.kerberos.service_ticket.failed", 4720 => "directory.account.created", 4722 => "directory.account.enabled", 4725 => "directory.account.disabled", 4726 => "directory.account.deleted", 4738 => "directory.account.changed", 4781 => "directory.account.renamed", 4728 or 4732 or 4756 => "group.member.added", 4729 or 4733 or 4757 => "group.member.removed", _ => null };
        bool passwordType = eventId == 4723 && semantic is "account.password.changed.succeeded" or "account.password.change.attempted" || eventId == 4724 && semantic is "account.password.reset.succeeded" or "account.password.reset.attempted";
        if (occurred > now || !(watch ? watched : auth).Contains(eventId) || !(expectedType == semantic || watch && passwordType)) return (signals, "not_applicable");
        var labels = row[watch ? "entries" : "labels"]!.AsArray(); var identities = row["identities"]!.AsArray(); if (labels.Count > 128 || identities.Count > 256) throw new InvalidDataException("account_identity_limit"); bool review = false;
        var matched = new Dictionary<(string Id, long Revision), JsonNode>();
        foreach (string role in watch ? new[] { "actor", "affected_entity", "session_principal" } : new[] { "actor", "affected_entity" })
        {
            string? key = row["roles_json"].Text(role); var metadata = row["quality_json"]?["identity_roles"]?[role]; if (string.IsNullOrEmpty(key) || metadata.Text("key") != key) continue;
            bool exact = metadata.Text("state") == "resolved" && metadata?["provisional"] is not null && !metadata.Flag("provisional"); bool fallback = !watch && eventId == 4625 && key.StartsWith("sam:", StringComparison.Ordinal) && metadata.Text("state") == "provisional" && metadata.Flag("provisional");
            var candidates = identities.Where(x => x.Text("role") == role && x.Text("key") == key).ToArray();
            foreach (var label in labels)
            {
                if (!label.Flag("active") || (!watch && label.Text("kind") != "account") || SigmaProjection.At(label!, "active_from") > occurred) continue;
                if (watch ? occurred >= SigmaProjection.At(label!, "expires_at") || SigmaProjection.At(label!, "valid_from") > occurred || label!["valid_to"] is not null && occurred >= SigmaProjection.At(label, "valid_to") : label!["active_to"] is not null && occurred >= SigmaProjection.At(label, "active_to")) continue;
                var identity = label!["identity"]!; if (!candidates.Any(x => JsonNode.DeepEquals(x!["identity"], identity))) continue;
                if (candidates.Length != 1 || !(exact || fallback) || exact && key != "sid:" + identity.Text("sid") && key != "guid:" + identity.Text("guid")) { review = !watch; continue; }
                matched[(label.Text("id")!, label.Number("revision"))] = label;
            }
        }
        foreach (var label in matched.Values)
        {
            string entity = Digest(new JsonArray(scope.Copy(), label["identity"].Copy())); var reference = Reference(scope, "core_event", row.Number("source_event_id").ToString(CultureInfo.InvariantCulture), row.Text("sha256")!); var context = new JsonObject { [watch ? "entry_id" : "label_id"] = label["id"].Copy(), [watch ? "entry_revision" : "label_revision"] = label["revision"].Copy(), ["normalized_event_id"] = row["normalized_event_id"].Copy(), ["identity_sha256"] = Digest(label["identity"]) };
            string episode, severity = "high"; if (watch)
            {
                string family = semantic.StartsWith("authentication.", StringComparison.Ordinal) ? "authentication" : "directory"; var bucket = occurred.AddTicks(-(occurred.Ticks % TimeSpan.TicksPerSecond)).AddSeconds(-occurred.Second).AddMinutes(-(occurred.Minute % 5));
                episode = Digest(new JsonArray(entity, family, SemanticJson.Stamp(bucket), SemanticJson.Stamp(bucket.AddMinutes(5)))); context["source_event_id"] = row["source_event_id"].Copy(); context["family"] = family; severity = EventSeverity(row["event_item"]!.AsObject());
            }
            else episode = Digest(new JsonArray(label["id"].Copy(), label["revision"].Copy(), ReferenceParams(reference)));
            var signal = Signal(definition, entity, episode, occurred, now, new JsonArray(reference), severity, watch ? "watch" : "decoy_authentication", contextKey: watch ? "watch_context" : "decoy_context", context: context);
            if (watch) { string[] levels = ["info", "low", "medium", "high", "critical"]; signal["effective_severity"] = levels[Math.Min(Array.IndexOf(levels, severity) + 1, 4)]; } signals.Add(signal);
        }
        return (signals, signals.Count > 0 ? "observed" : review ? "requires_review" : "no_match");
    }
    private static string EventSeverity(JsonObject item)
    {
        using var stream = typeof(SemanticProduction).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")!;
        var entry = JsonNode.Parse(stream)!["entries"]!.AsArray().FirstOrDefault(x => x?["event_key"]?.ToString() == item["event_id"]?.ToString() && string.Equals(x.Text("stream"), item.Text("channel"), StringComparison.OrdinalIgnoreCase) && string.Equals(x.Text("provider_name"), item.Text("provider_name"), StringComparison.OrdinalIgnoreCase));
        if (entry is null) throw new InvalidDataException("watch_source_catalog_unavailable");
        var card = entry["card"]; var data = item["event_data"]?.AsObject() ?? new JsonObject();
        string First(JsonNode? names) => names is JsonArray array ? array.Select(n => (item[n!.GetValue<string>()] ?? data[n.GetValue<string>()])?.ToString().Trim()).FirstOrDefault(x => !string.IsNullOrEmpty(x) && x is not ("-" or "\u2014")) ?? "" : "";
        foreach (var rule in card?["risk_rules"]?.AsArray() ?? [])
        {
            bool matches = true; foreach (var condition in rule!["all"]?.AsArray() ?? [])
            {
                string value = First(card?["field_roles"]?[condition.Text("role") ?? ""]).ToLowerInvariant(); if (value.Length == 0) value = First(condition?["fields"]).ToLowerInvariant();
                if (condition.Flag("microsoft_namespace") && !value.StartsWith("\\microsoft\\windows\\", StringComparison.Ordinal) || condition.Flag("machine_or_system") && !(value.EndsWith('$') || value is "system" or "nt authority\\system") || condition.Flag("dc") && !(item.Text("server") ?? "").ToLowerInvariant().StartsWith("dc", StringComparison.Ordinal)) matches = false;
                if (condition?["contains_any"] is JsonArray { Count: > 0 } contains && !contains.Any(x => string.Join(" ", data.Select(p => p.Value?.ToString())).ToLowerInvariant().Contains(x!.GetValue<string>().ToLowerInvariant(), StringComparison.Ordinal))) matches = false;
            }
            if (matches) return (rule.Text("severity") ?? entry.Text("severity") ?? "info") is "important" ? "medium" : rule.Text("severity") ?? entry.Text("severity") ?? "info";
        }
        return entry.Text("severity") is "important" ? "medium" : entry.Text("severity") ?? "info";
    }
    private static async Task<int> DisabledAccount(ISemanticSession session, JsonObject scope, CancellationToken ct)
    {
        var definition = Definition("qw.disabled-account-logon", scope); if (!await AdmitDefault(session, definition, ct)) return 0;
        var rows = await session.QueryAsync("select * from public.read_default_password_events($1::jsonb)", ct, scope); if (rows.Count > 10000) throw new InvalidDataException("password_window_truncated"); var groups = new Dictionary<(string Entity, long Bucket), List<JsonNode>>();
        foreach (var row in rows.DistinctBy(x => x.Number("source_event_id")))
        {
            int id = (int)row.Number("event_id"); if (id is not (4625 or 4776)) continue;
            string payload = row.Text("source_xml")!;
            var compact = payload.StartsWith('{') ? Detections.DetectionNative.ShortDocument(Password.PasswordScope.Read(scope),
                row.Number("source_event_id"), id, SigmaProjection.At(row!, "occurred_at_utc"), payload) : null;
            var ev = compact is null ? SigmaEvent.Map(payload) : null;
            var at = compact is null ? ev!.At : SigmaProjection.At(compact, "occurred_at_utc");
            var fields = compact is null ? ev!.Fields : compact["fields"]!.AsObject();
            if (at > DateTimeOffset.UtcNow) continue;
            bool Code(string key) => fields.Text(key) is { } code && uint.TryParse(code.Replace("0x", "", StringComparison.OrdinalIgnoreCase), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint n) && n == 0xc0000072;
            if (!(Code("Status") || Code("SubStatus"))) continue;
            string name = UnicodeCaseFold.TrimAndFold(fields.Text("TargetUserName") ?? ""); if (name is "" or "-" or "n/a") continue;
            string entity = Digest(new JsonArray(UnicodeCaseFold.TrimAndFold(fields.Text("TargetDomainName") ?? ""), name)); var key = (entity, at.ToUnixTimeSeconds() / 300);
            if (!groups.TryGetValue(key, out var group)) groups[key] = group = new(); var member = row!.DeepClone().AsObject(); member["at"] = SemanticJson.Stamp(at); group.Add(member);
        }
        int jobs = 0; foreach (var (key, group) in groups)
        {
            var refs = new JsonArray(group.OrderBy(x => x.Number("source_event_id")).Select(x => (JsonNode)Reference(scope, "core_event", x.Number("source_event_id").ToString(CultureInfo.InvariantCulture), x.Text("sha256")!)).ToArray());
            for (int offset = 0; offset < refs.Count; offset += 256) jobs += await EnqueueQW(session, Signal(definition, Digest(JsonValue.Create(key.Entity)), Digest(new JsonArray("qw.disabled-account-logon", key.Entity, key.Bucket)), group.Max(x => SigmaProjection.At(x, "at")), DateTimeOffset.UtcNow, SemanticJson.Array(refs.Skip(offset).Take(256)), total: refs.Count), ct);
        }
        return jobs;
    }
}
