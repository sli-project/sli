using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Auth.Lifecycle.Security;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticProduction
{
    private static readonly IReadOnlyDictionary<string, (int Version, string Sha)> InvestigationRules = ReadInvestigationRules();
    internal static IReadOnlyList<JsonObject> ReadDispatchRulePack()
    {
        using var stream = typeof(SemanticProduction).Assembly.GetManifestResourceStream("Sli.Server.Semantic.chain_pack.json")!;
        return ReadDispatchRulePack(JsonNode.Parse(stream));
    }
    internal static IReadOnlyList<JsonObject> ReadDispatchRulePack(JsonNode? pack)
    {
        if (pack is not JsonObject root || root.Text("owner") != "semantic_worker") throw new InvalidDataException("semantic_chain_pack_owner_invalid");
        if (root.Text("default_lifecycle") != "draft") throw new InvalidDataException("semantic_chain_pack_default_lifecycle_invalid");
        if (root["rules"] is not JsonArray { Count: > 0 } items) throw new InvalidDataException("semantic_chain_pack_rules_required");
        var rules = new List<JsonObject>(); var seen = new HashSet<(string, int)>();
        foreach (var item in items)
        {
            if (item is not JsonObject entry || entry.Text("rule_kind") == "worker_assembler") continue;
            if (entry.Text("lifecycle_status") != "draft") throw new InvalidDataException("semantic_chain_pack_dispatcher_must_remain_draft");
            string id = entry.Text("rule_id") ?? ""; int version = (int)entry.Number("rule_version");
            if (string.IsNullOrWhiteSpace(id) || id.Length > 160 || version <= 0) throw new InvalidDataException("semantic_chain_pack_rule_identity_invalid");
            if (!seen.Add((id, version))) throw new InvalidDataException("semantic_chain_pack_duplicate_rule_version");
            var row = new JsonObject { ["rule_id"] = id, ["rule_version"] = version, ["rule_kind"] = entry.Text("rule_kind"), ["definition_json"] = entry["definition"]?.DeepClone() ?? new JsonObject() };
            SemanticCorrelation.Compile(row);
            rules.Add(row);
        }
        if (rules.Count == 0) throw new InvalidDataException("semantic_chain_pack_no_dispatcher_rules");
        return rules;
    }
    internal static IReadOnlyDictionary<string, (int, string)> ReadInvestigationRules()
    {
        // The Python pack selector retains the last version for each ID.
        return ReadDispatchRulePack().Where(x => SemanticRelations.RuleIds.Contains(x.Text("rule_id"))).GroupBy(x => x.Text("rule_id")!).ToDictionary(g => g.Key, g => ((int)g.Last().Number("rule_version"), SemanticJson.Hash(g.Last()["definition_json"])));
    }
    private bool RuleAllowed(JsonNode rule) => mode != SemanticRuntimeSettings.InvestigationMode || InvestigationRules.TryGetValue(rule.Text("rule_id")!, out var pin) && rule.Number("rule_version") == pin.Version && rule.Text("definition_sha256") == pin.Sha;
    // TEST execution belongs only to the explicitly admitted development worker.
    private string[] DispatchRuleStates => development && mode == DevelopmentMode ? ["test", "shadow", "enabled"] : ["shadow", "enabled"];
    internal static async Task ReplaceRuleSubscriptions(ISemanticSession session, SemanticCorrelation rule, CancellationToken ct)
    {
        var parent = (await session.QueryAsync("select lifecycle_status,encode(definition_sha256,'hex') as definition_sha256 from semantic_correlation_rules where rule_id=$1 and rule_version=$2 for update", ct, rule.Id, rule.Version)).SingleOrDefault();
        if (parent is null) throw new InvalidOperationException("semantic_correlation_rule_not_found");
        if (parent.Text("lifecycle_status") != "draft") throw new InvalidOperationException("semantic_correlation_subscriptions_require_draft");
        if (parent.Text("definition_sha256") != rule.Sha) throw new InvalidDataException("semantic_correlation_subscription_hash_mismatch");
        var existing = await session.QueryAsync("select semantic_type,subscription_order,encode(definition_sha256,'hex') as definition_sha256 from semantic_correlation_subscriptions where rule_id=$1 and rule_version=$2 order by subscription_order", ct, rule.Id, rule.Version);
        if (existing.Count == rule.Inputs.Length && existing.Select((row, i) => row.Text("semantic_type") == rule.Inputs[i] && row.Number("subscription_order") == i && row.Text("definition_sha256") == rule.Sha).All(x => x)) return;
        await session.QueryAsync("delete from semantic_correlation_subscriptions where rule_id=$1 and rule_version=$2", ct, rule.Id, rule.Version);
        for (int i = 0; i < rule.Inputs.Length; i++)
            await session.QueryAsync("insert into semantic_correlation_subscriptions(rule_id,rule_version,semantic_type,subscription_order,definition_sha256) values($1,$2,$3,$4,$5)", ct, rule.Id, rule.Version, rule.Inputs[i], (short)i, Convert.FromHexString(rule.Sha));
    }
    internal static async Task<Guid[]> ExpireCorrelationCandidates(ISemanticSession session, DateTimeOffset before, CancellationToken ct)
    {
        var rows = await session.QueryAsync("""
            with expiring as(select candidate_id from semantic_correlation_candidates
              where candidate_status='matched' and window_end_utc<$1 order by window_end_utc,candidate_id for update skip locked)
            update semantic_correlation_candidates candidate set candidate_status='expired',closed_at=now(),updated_at=now()
              from expiring where candidate.candidate_id=expiring.candidate_id returning candidate.candidate_id
            """, ct, before.ToUniversalTime());
        return rows.Select(x => Guid.Parse(x.Text("candidate_id")!)).ToArray();
    }
    internal Task EnqueueDispatch(ISemanticSession session, SemanticEvent ev, string version, CancellationToken ct)
        => EnqueueDispatchForRules(session, ev, version, ct, allowedRuleIdentities: DispatchRulePins(), allowedStates: DispatchRuleStates);

    internal static async Task EnqueueDispatchForRules(ISemanticSession session, SemanticEvent ev, string version, CancellationToken ct,
        IReadOnlyList<string>? allowedRuleIds = null, IReadOnlyList<(string Id, int Version, string Sha)>? allowedRuleIdentities = null, string[]? allowedStates = null)
    {
        var values = new List<object?> { ev.Type };
        string filter = DispatchRuleFilter(values, allowedRuleIds, allowedRuleIdentities);
        string states = "rule.lifecycle_status in('shadow','enabled')";
        if (allowedStates is not null) { values.Add(allowedStates); states = $"rule.lifecycle_status=any(${values.Count})"; }
        var subscriptions = await session.QueryAsync("select s.rule_id,s.rule_version,encode(s.definition_sha256,'hex') as definition_sha256,rule.rule_kind,rule.definition_json from semantic_correlation_subscriptions s join semantic_correlation_rules rule on rule.rule_id=s.rule_id and rule.rule_version=s.rule_version and rule.definition_sha256=s.definition_sha256 where s.semantic_type=$1 and " + states + " " + filter + " order by s.rule_id,s.rule_version", ct, values.ToArray());
        foreach (var subscription in subscriptions)
        {
            var rule = SemanticCorrelation.Compile(subscription!); string? partition = rule.Partition(ev); if (partition is null) continue;
            if (partition.Length > 512) throw new InvalidDataException("semantic_partition_too_long");
            string hash = Password.PasswordJson.Hash(new JsonObject { ["normalized_event_id"] = ev.Id(version).ToString(), ["rule_id"] = rule.Id, ["rule_version"] = rule.Version, ["definition_sha256"] = rule.Sha });
            Guid jobId = AuthAudit.Uuid5("adlog:semantic-dispatch:" + hash);
            var source = (await session.QueryAsync("select source_ingested_at from normalized_events where normalized_event_id=$1", ct, ev.Id(version)))[0]!;
            bool late = SigmaProjection.At(source, "source_ingested_at") - ev.At > TimeSpan.FromMinutes(5);
            await Change(session, "insert into semantic_correlation_dispatch_jobs(job_id,normalized_event_id,rule_id,rule_version,idempotency_key,partition_key,occurred_at_utc,is_late) values($1,$2,$3,$4,$5,$6,$7,$8) on conflict(idempotency_key) do nothing returning job_id", ct, jobId, ev.Id(version), rule.Id, rule.Version, Convert.FromHexString(hash), partition, ev.At, late);
            var stored = (await session.QueryAsync("select job_id,normalized_event_id,partition_key,is_late from semantic_correlation_dispatch_jobs where idempotency_key=$1", ct, Convert.FromHexString(hash))).Single()!;
            if (stored.Text("job_id") != jobId.ToString() || stored.Text("normalized_event_id") != ev.Id(version).ToString() || stored.Text("partition_key") != partition || stored.Flag("is_late") != late) throw new InvalidDataException("semantic_dispatch_replay_conflict");
        }
    }
    internal static Task<JsonObject> RecoverDispatchAsync(Password.PasswordProducerRuntime runtime, NpgsqlConnection db, SemanticRecoveryScope scope, CancellationToken ct) =>
        new SemanticProduction(runtime, scope.Settings, scope.Mode, scope.JobIds.Length).ProcessDispatch(db, ct, recovery: scope);

    internal Task<JsonObject> ProcessDispatch(NpgsqlConnection db, CancellationToken ct, Guid[]? allowedJobIds = null,
        Func<ISemanticSession, JsonNode, CancellationToken, Task>? completeJob = null, SemanticRecoveryScope? recovery = null)
        => ProcessDispatch(token => Transaction(db, token), ct, allowedJobIds, completeJob, recovery);

    internal async Task<JsonObject> ProcessDispatch(Func<CancellationToken, Task<ISemanticSession>> open,
        CancellationToken stopping, Guid[]? allowedJobIds = null,
        Func<ISemanticSession, JsonNode, CancellationToken, Task>? completeJob = null, SemanticRecoveryScope? recovery = null)
    {
        int claimed = 0, completed = 0, failed = 0, relations = 0;
        CancellationToken ct = CancellationToken.None;
        for (int i = 0; settings.Correlation && i < Math.Clamp(limit, 1, 128); i++)
        {
            if (stopping.IsCancellationRequested) break;
            JsonNode? job;
            await using (var session = await open(ct))
            {
                var rows = recovery is not null
                    ? await SemanticDispatchRecovery.ClaimAsync(session, recovery.JobIds, ct)
                    : await ClaimDispatchJobs(session, ct, allowedRuleIdentities: DispatchRulePins(), allowedJobIds: allowedJobIds);
                job = rows.FirstOrDefault(); await session.CommitAsync(ct);
            }
            if (job is null) break; claimed++;
            try
            {
                await using var session = await open(ct);
                var ruleRow = (await session.QueryAsync("select rule_id,rule_version,rule_kind,lifecycle_status,definition_json,encode(definition_sha256,'hex') as definition_sha256 from semantic_correlation_rules where rule_id=$1 and rule_version=$2 for share", ct, job.Text("rule_id"), (int)job.Number("rule_version"))).Single()!;
                if (!DispatchRuleStates.Contains(ruleRow.Text("lifecycle_status")) || !RuleAllowed(ruleRow)) throw new InvalidOperationException("semantic_dispatch_rule_not_executable");
                var rule = SemanticCorrelation.Compile(ruleRow);
                var trigger = (await session.QueryAsync("select *,encode(semantic_sha256,'hex') as semantic_sha256 from normalized_events where normalized_event_id=$1", ct, Guid.Parse(job.Text("normalized_event_id")!))).Single()!;
                if (recovery is not null && (rule.Id != SemanticDispatchRecovery.RuleId || rule.Version != SemanticDispatchRecovery.RuleVersion || rule.Sha != SemanticDispatchRecovery.RuleSha || SigmaProjection.At(trigger, "normalized_at") > recovery.NormalizedBefore))
                    throw new InvalidOperationException("semantic dispatch recovery frozen contract changed");
                var triggerEvent = SemanticEvent.Read(trigger); string version = trigger.Text("normalizer_version")!;
                var events = await LoadDispatchEvents(session, rule, trigger, job.Text("partition_key")!, (identities, token) => LoadContextSources(session, identities, token), ct, recovery);
                var matched = rule.Match(events);
                foreach (var relation in matched) await PersistRelation(session, rule.Id, rule.Version, relation, version, job.Flag("is_late") && relation.Evidence.Any(x => x.Source == triggerEvent.Source) ? triggerEvent.Source : null, ct);
                if (recovery is not null) await SemanticDispatchRecovery.CompleteAsync(session, Guid.Parse(job.Text("job_id")!), Guid.Parse(job.Text("lease_token")!), ct);
                else if (completeJob is not null) await completeJob(session, job, ct);
                else await Complete(session, "semantic_correlation_dispatch_jobs", "dispatch_status", job, ct);
                await session.CommitAsync(ct); completed++; relations += matched.Count;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { await Fail(open, "semantic_correlation_dispatch_jobs", "dispatch_status", job, ct, error, SemanticProcessingStep.Dispatch); failed++; }
        }
        return new JsonObject { ["claimed"] = claimed, ["completed"] = completed, ["failed"] = failed, ["relations"] = relations };
    }
    internal static Task<Guid> PersistRelation(ISemanticSession session, SemanticCorrelation rule, SemanticRelation relation, string version, long? lateSource, CancellationToken ct) =>
        PersistRelation(session, rule.Id, rule.Version, relation, version, lateSource, ct);

    internal static async Task<IReadOnlyList<SemanticEvent>> LoadDispatchEvents(ISemanticSession session, SemanticCorrelation rule, JsonNode trigger, string partition,
        Func<IReadOnlyList<JsonObject>, CancellationToken, Task<IReadOnlyDictionary<long, JsonObject>>> loadSources, CancellationToken ct, SemanticRecoveryScope? recovery = null, ISemanticSession? contextSession = null)
    {
        var triggerEvent = SemanticEvent.Read(trigger); string version = trigger.Text("normalizer_version")!;
        var contextArgs = new List<object?> { (int)trigger.Number("semantic_contract_version"), trigger.Text("normalizer_id"), version, rule.Inputs, triggerEvent.At.AddSeconds(-rule.Window), triggerEvent.At.AddSeconds(rule.Window) };
        string partitionPredicate;
        if (rule.PartitionKind == "source_host")
        {
            var requiredRoles = new JsonObject(); foreach (string role in rule.Roles) requiredRoles[role] = triggerEvent.Roles[role].Copy();
            if (requiredRoles.Any(x => x.Value is null || string.IsNullOrWhiteSpace(x.Value.ToString()))) throw new InvalidDataException("semantic_context_identity_missing");
            await HydrateDispatchContext(session, rule, triggerEvent, partition, triggerEvent.At.AddSeconds(-rule.Window), triggerEvent.At.AddSeconds(rule.Window), loadSources, ct);
            contextArgs.Add(requiredRoles); partitionPredicate = "roles_json @> $7::jsonb";
        }
        else
        {
            var context = CrossDcContextPredicate(rule.PartitionKind, partition);
            contextArgs.AddRange(context.Parameters); partitionPredicate = context.Predicate;
        }
        string boundaryPredicate = "";
        if (recovery is not null) { contextArgs.Add(recovery.NormalizedBefore); boundaryPredicate = $" and normalized_at<=${contextArgs.Count}"; }
        var rows = await (contextSession ?? session).QueryAsync("select *,encode(semantic_sha256,'hex') as semantic_sha256 from normalized_events where processing_status='normalized' and semantic_contract_version=$1 and normalizer_id=$2 and normalizer_version=$3 and semantic_type=any($4) and occurred_at_utc between $5 and $6 and " + partitionPredicate + boundaryPredicate + " order by occurred_at_utc,source_event_id" + (recovery is null ? " limit 5001" : ""), ct, contextArgs.ToArray());
        // The DB predicate and the pure partition check both preserve exact source identities.
        var events = rows.Select(x => SemanticEvent.Read(x!)).Where(x => rule.Partition(x) == partition).ToArray();
        if (recovery is null && rows.Count > 5000) throw new InvalidDataException("semantic_dispatch_context_limit_exceeded");
        return events;
    }

    internal static async Task<Guid> PersistRelation(ISemanticSession session, string ruleId, int ruleVersion, SemanticRelation relation, string version, long? lateSource, CancellationToken ct)
    {
        if (lateSource is not null && !relation.Evidence.Any(x => x.Source == lateSource)) throw new ArgumentException("Late evidence must belong to the dispatched relation", nameof(lateSource));
        if (relation.Evidence.Count == 0) throw new InvalidDataException("correlation_candidate_requires_evidence");
        if (relation.Confidence is not ("low" or "medium" or "high")) throw new InvalidDataException("correlation_confidence_invalid");
        if (string.IsNullOrWhiteSpace(version)) throw new InvalidDataException("correlation_evidence_contract_invalid");
        await SemanticCorrelationRepository.EnsureExecutableAsync(session, ruleId, ruleVersion, ct);
        var sources = relation.Evidence.Select(x => x.Source).Distinct().ToArray();
        var evidence = await session.QueryAsync("select normalized_event_id,source_event_id,occurred_at_utc,roles_json from normalized_events where source_event_id=any($1) and semantic_contract_version=$2 and normalizer_id=$3 and normalizer_version=$4 order by occurred_at_utc,source_event_id", ct, sources, 1, SemanticEvent.Normalizer, version);
        var bySource = evidence.ToDictionary(x => x.Number("source_event_id"));
        if (sources.Any(x => !bySource.ContainsKey(x))) throw new InvalidDataException("correlation_evidence_not_normalized");
        var times = evidence.Select(x => SigmaProjection.At(x!, "occurred_at_utc")).ToArray();
        string key = SemanticJson.Hash(new JsonObject { ["rule_id"] = ruleId, ["rule_version"] = ruleVersion, ["contribution_key"] = relation.Key });
        Guid candidate = AuthAudit.Uuid5("adlog:correlation:" + key); string partition = SemanticCorrelationRepository.CandidatePartition(relation, evidence);
        await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, key);
        await Change(session, "insert into semantic_correlation_candidates(candidate_id,rule_id,rule_version,relation_kind,candidate_status,candidate_key,partition_key,window_start_utc,window_end_utc,confidence,explanation) values($1,$2,$3,$4,'matched',$5,$6,$7,$8,$9,$10) on conflict(rule_id,rule_version,candidate_key) do nothing returning candidate_id", ct, candidate, ruleId, ruleVersion, relation.Kind, Convert.FromHexString(key), partition, times.Min(), times.Max(), relation.Confidence, relation.Explanation);
        var existing = (await session.QueryAsync("select candidate_id,relation_kind,partition_key from semantic_correlation_candidates where rule_id=$1 and rule_version=$2 and candidate_key=$3 for update", ct, ruleId, ruleVersion, Convert.FromHexString(key))).Single()!;
        if (existing.Text("candidate_id") != candidate.ToString() || existing.Text("relation_kind") != relation.Kind || existing.Text("partition_key") != partition) throw new InvalidDataException("semantic_candidate_replay_conflict");
        foreach (long source in sources)
            await Change(session, "insert into semantic_correlation_candidate_evidence(candidate_id,normalized_event_id,evidence_order) select $1,$2,coalesce(max(evidence_order),-1)+1 from semantic_correlation_candidate_evidence where candidate_id=$1 on conflict(candidate_id,normalized_event_id) do nothing returning candidate_id", ct, candidate, Guid.Parse(bySource[source].Text("normalized_event_id")!));
        var state = (await session.QueryAsync("select count(*) as evidence_count,max(evidence_order) as maximum_order from semantic_correlation_candidate_evidence where candidate_id=$1", ct, candidate))[0]!;
        if (state.Number("evidence_count") > 16384 || state.Number("maximum_order") >= 16384) throw new InvalidDataException("semantic_candidate_evidence_limit_exceeded");
        await Change(session, "update semantic_correlation_candidate_evidence set evidence_order=evidence_order+16384 where candidate_id=$1 returning candidate_id", ct, candidate);
        await Change(session, "with ordered as(select e.normalized_event_id,row_number() over(order by n.occurred_at_utc,n.source_event_id)-1 as evidence_order from semantic_correlation_candidate_evidence e join normalized_events n using(normalized_event_id) where e.candidate_id=$1) update semantic_correlation_candidate_evidence e set evidence_order=ordered.evidence_order from ordered where e.candidate_id=$1 and e.normalized_event_id=ordered.normalized_event_id returning candidate_id", ct, candidate);
        await Change(session, "update semantic_correlation_candidates candidate set window_start_utc=least(window_start_utc,$1),window_end_utc=greatest(window_end_utc,$2),confidence=case when confidence='high' or $3='high' then 'high' when confidence='medium' or $3='medium' then 'medium' else 'low' end,explanation=$4,last_matched_at=now(),updated_at=now(),evidence_count=(select count(*) from semantic_correlation_candidate_evidence where candidate_id=$5) where candidate_id=$5 returning candidate_id", ct, times.Min(), times.Max(), relation.Confidence, relation.Explanation, candidate);
        // This statement already has a data-modifying CTE, which PostgreSQL
        // requires at the top level (Change would nest it in another CTE).
        await session.QueryAsync("""
            with prior as(select count(*) filter(where e.is_late) as prior_late_count,max(n.occurred_at_utc) as last_evidence_occurred_at from semantic_correlation_candidate_evidence e join normalized_events n using(normalized_event_id) where candidate_id=$1),
            marked as(update semantic_correlation_candidate_evidence e set is_late=true from normalized_events n where e.candidate_id=$1 and e.normalized_event_id=n.normalized_event_id and n.source_event_id=$2::bigint and not e.is_late returning 1),
            changed as(select count(*) as changed_count from marked)
            update semantic_correlation_candidates c set reopen_count=c.reopen_count+case when c.candidate_status='expired' and changed.changed_count>0 then 1 else 0 end,
              candidate_status=case when c.candidate_status='expired' and changed.changed_count>0 then 'matched' else c.candidate_status end,
              closed_at=case when c.candidate_status='expired' and changed.changed_count>0 then null else c.closed_at end,
              late_evidence_count=(prior.prior_late_count+changed.changed_count)::integer,last_evidence_occurred_at=prior.last_evidence_occurred_at,updated_at=now()
            from prior,changed where candidate_id=$1 returning candidate_id
            """, ct, candidate, lateSource);
        return candidate;
    }
}
