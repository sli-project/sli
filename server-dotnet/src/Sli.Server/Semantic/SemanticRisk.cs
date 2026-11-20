using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Semantic.Risk;

namespace Sli.Server.Semantic;

internal sealed record SemanticProposal(SemanticPolicy Policy, string SourceId, DateTimeOffset At, string Partition, JsonObject Strict, JsonObject Factors, Guid[] Evidence, JsonArray Native, JsonArray Coverage, string Conclusion = "observed")
{
    internal string Contribution => HashText($"risk-policy:{Policy.Id}:{Policy.Version}:{Policy.Source}:{SourceId}");
    internal string Step => HashText($"policy-step:risk-policy:{Policy.Id}:{Policy.Version}:{Policy.Source}:{SourceId}");
    internal string Identity => SemanticJson.Hash(new JsonObject { ["scenario_kind"] = Policy.Kind, ["result_class"] = Policy.Result, ["partition_key"] = Partition, ["strict_keys"] = Strict.Copy(), ["merge_window_seconds"] = Policy.Window });
    internal static string HashText(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    internal object?[] SourceValues => [Policy.Source == "canonical_action" ? Guid.Parse(SourceId) : null, Policy.Source == "correlation_candidate" ? Guid.Parse(SourceId) : null, Policy.Source == "control_health" ? SourceId : null, Policy.Source == "detection_match" ? SourceId : null, Policy.Source == "qw_signal" ? SourceId : null];
}
internal sealed partial class SemanticProduction
{
    internal static int RiskBatchSize(int processingLimit) => Math.Min(processingLimit, 16);
    internal async Task<JsonObject> ProcessRisk(NpgsqlConnection db, CancellationToken ct)
    {
        int queued = 0, claimed = 0, completed = 0, failed = 0, published = 0;
        var modes = development ? new JsonObject { ["test"] = 0, ["shadow"] = 0 } : new JsonObject { ["shadow"] = 0, ["enabled"] = 0 };
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var session = new SemanticSession(db, tx); int count = development ? limit : RiskBatchSize(limit);
            string[] executable = development ? ["test", "shadow"] : ["test", "shadow", "enabled"];
            var sources = await session.QueryAsync(SemanticProductionSql.Backlog0, ct, count, executable, executable, executable, count);
            foreach (var source in sources) queued += await EnqueueRiskSource(session, source.Text("source_kind")!, source.Text("source_id")!, ct, development);
            await tx.CommitAsync(ct);
        }
        for (int i = 0; i < (development ? limit : RiskBatchSize(limit)); i++)
        {
            if (Stopping) break;
            ct.ThrowIfCancellationRequested(); JsonNode? job;
            await using (var tx = await db.BeginTransactionAsync(ct))
            {
                // Managed password v2 is leased exclusively by the existing exact-proof consumer.
                string sql = SemanticProductionSql.RiskClaim0.Replace("where attempt_count < max_attempts", "where not exists(select 1 from semantic_risk_policies password where password.policy_id=job.policy_id and password.policy_version=job.policy_version and password.source_kind='qw_signal' and password.definition_json#>'{source_selector,execution,rule_version}'>='2'::jsonb and password.definition_json#>>'{source_selector,rule_id}' in('qw.password-brute-force','qw.password-spray')) and attempt_count < max_attempts");
                if (development) sql = sql.Replace("where not exists", "where job.evaluation_mode in('test','shadow') and not exists");
                var rows = await new SemanticSession(db, tx).QueryAsync("with leased as(" + sql + ") select * from leased", ct, 1, Guid.NewGuid(), 300); job = rows.FirstOrDefault(); await tx.CommitAsync(ct);
            }
            if (job is null) break; claimed++;
            try
            {
                await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db, tx);
                var row = (await session.QueryAsync("select p.*,encode(p.definition_sha256,'hex') as definition_sha256,semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status) as effective_mode from semantic_risk_policies p where p.policy_id=$1 and p.policy_version=$2 for share", ct, job.Text("policy_id"), (int)job.Number("policy_version"))).Single()!;
                var policy = SemanticPolicy.Compile(row); string evaluationMode = job.Text("evaluation_mode")!;
                if (development) RequireDevelopmentEvaluation(evaluationMode);
                if (row.Text("effective_mode") != evaluationMode || row.Text("source_kind") != job.Text("source_kind")) throw new InvalidOperationException("semantic_risk_admission_changed");
                if (evaluationMode == "enabled" && !(await session.QueryAsync("select enabled from semantic_policy_admission where policy_id=$1 and policy_version=$2", ct, policy.Id, policy.Version)).Single().Flag("enabled")) throw new InvalidOperationException("semantic_policy_admission_required");
                var proposal = await Proposal(session, policy, job.Text("source_reference")!, evaluationMode, ct);
                var snapshot = await Completeness(session, proposal, ct);
                string conclusion = ResolveConclusionState(proposal.Conclusion, snapshot);
                Guid? scenario = null; JsonObject? persisted = null;
                var assessment = PasswordRiskProposal.Assess(proposal.Policy.Raw, proposal.Policy.Points, proposal.Policy.Hard, proposal.Policy.Risk, proposal.Factors, CoverageStatus(proposal.Coverage));
                if (evaluationMode != "test" && (policy.Source is not ("detection_match" or "qw_signal") || evaluationMode == "enabled") && (policy.Source != "qw_signal" || proposal.Conclusion == "observed"))
                {
                    persisted = await PersistProposal(session, proposal, ct); scenario = Guid.Parse(persisted.Text("scenario_id")!);
                    assessment = new(persisted["raw_score"]!.GetValue<decimal>(), (int)persisted.Number("display_score"), persisted.Text("risk_class")!, persisted.Flag("hard_critical"), persisted.Text("confidence")!, (int)persisted.Number("confidence_score"), persisted["confidence_factors_json"]!.AsObject(), persisted.Text("coverage_status")!);
                }
                await session.QueryAsync("insert into semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,hard_critical,confidence,confidence_score,coverage_status,evaluation_ms,conclusion_state,completeness_snapshot_json) values($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,0,$11,$12) on conflict(job_id) do nothing", ct,
                    Guid.Parse(job.Text("job_id")!), scenario, evaluationMode, assessment.Risk, assessment.Raw, assessment.Display, assessment.HardCritical, assessment.Confidence, assessment.Score, assessment.Coverage, conclusion, snapshot);
                bool created = false;
                if (!development && evaluationMode == "enabled" && persisted is not null && persisted.Text("evidence_state") != "evidence_pending" && proposal.Conclusion == "observed") created = await PublishFinding(session, proposal, persisted, Guid.Parse(job.Text("job_id")!), ct);
                await Complete(session, "semantic_risk_evaluation_jobs", "evaluation_status", job, ct); await tx.CommitAsync(ct); completed++; if (created) published++;
                modes[evaluationMode] = modes.Number(evaluationMode) + 1;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { await Fail(db, "semantic_risk_evaluation_jobs", "evaluation_status", job, ct, error, SemanticProcessingStep.Risk); failed++; }
        }
        return new JsonObject { ["queued"] = queued, ["claimed"] = claimed, ["completed"] = completed, ["failed"] = failed, ["published"] = published, ["modes"] = modes };
    }
    internal static void RequireDevelopmentEvaluation(string mode)
    {
        if (mode is not ("test" or "shadow")) throw new InvalidOperationException("semantic_development_scope_required");
    }
    internal static async Task<int> EnqueueRiskSource(ISemanticSession session, string kind, string id, CancellationToken ct, bool development = false)
    {
        string sql = kind switch
        {
            "canonical_action" => "select action_kind as selector from canonical_actions where canonical_action_id=$1::uuid and action_status not in('contradicted','superseded','quarantined')",
            "correlation_candidate" => "select relation_kind as selector from semantic_correlation_candidates where candidate_id=$1::uuid and candidate_status='matched'",
            "control_health" => "select control_id as selector from semantic_control_health_observations where observation_id=$1::uuid",
            "detection_match" => "select rule_id as selector,evaluation_mode,document_json from semantic_detection_matches where match_id=$1",
            "qw_signal" => "select document_json->>'rule_id' as selector,evaluation_mode,document_json from semantic_qw_signals where signal_id=$1",
            _ => throw new InvalidDataException("semantic_source_kind_invalid")
        };
        var source = (await session.QueryAsync(sql, ct, id)).Single(); if (source is null) return 0;
        var policies = await session.QueryAsync("select p.*,encode(p.definition_sha256,'hex') as definition_sha256,semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status) as effective_mode from semantic_risk_policy_subscriptions s join semantic_risk_policies p on p.policy_id=s.policy_id and p.policy_version=s.policy_version and p.definition_sha256=s.definition_sha256 where s.source_kind=$1 and s.selector_value=$2 and semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status) in('test','shadow','enabled') and(semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)<>'enabled' or exists(select 1 from semantic_policy_admission a where a.policy_id=p.policy_id and a.policy_version=p.policy_version and a.enabled is true)) order by p.policy_id,p.policy_version", ct, kind, source.Text("selector"));
        int count = 0;
        foreach (var row in policies)
        {
            string evaluationMode = row.Text("effective_mode")!;
            if (development && evaluationMode is not ("test" or "shadow")) continue;
            var policy = SemanticPolicy.Compile(row!);
            if (kind is "detection_match" or "qw_signal")
            {
                var execution = NativeExecution(source!["document_json"]!.AsObject(), kind); if (source.Text("evaluation_mode") != evaluationMode || !JsonNode.DeepEquals(execution, policy.Definition["source_selector"]!["execution"]) || kind == "qw_signal" && source["document_json"].Number("policy_revision") != policy.Version) continue;
            }
            string hash = Password.PasswordJson.Hash(new JsonObject { ["policy_id"] = policy.Id, ["policy_version"] = policy.Version, ["policy_sha256"] = policy.Sha, ["source_kind"] = kind, ["source_id"] = id, ["evaluation_mode"] = evaluationMode });
            Guid job = AuthAudit.Uuid5("adlog:risk-evaluation:" + hash);
            await session.QueryAsync("insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,canonical_action_id,correlation_candidate_id,control_health_id,source_reference,evaluation_mode,idempotency_key,detection_match_id,qw_signal_id) values($1,$2,$3,$4,$5::uuid,$6::uuid,$7::uuid,$8,$9,$10,$11,$12) on conflict(idempotency_key) do nothing", ct,
                job, policy.Id, policy.Version, kind, kind == "canonical_action" ? Guid.Parse(id) : null, kind == "correlation_candidate" ? Guid.Parse(id) : null, kind == "control_health" ? Guid.Parse(id) : null, id, evaluationMode, Convert.FromHexString(hash), kind == "detection_match" ? id : null, kind == "qw_signal" ? id : null);
            var stored = (await session.QueryAsync("select job_id from semantic_risk_evaluation_jobs where idempotency_key=$1", ct, Convert.FromHexString(hash))).Single(); if (stored.Text("job_id") != job.ToString()) throw new InvalidDataException("semantic_risk_job_replay_conflict"); count++;
        }
        return count;
    }
    private static JsonObject NativeExecution(JsonObject document, string kind)
    {
        var pin = new JsonObject { ["version"] = kind == "detection_match" ? "sli.sigma.execution.v1" : "sli.qw.execution.v1" };
        foreach (string key in kind == "detection_match" ? new[] { "rule_id", "rule_sha256", "manifest_sha256", "compiler_version", "mapping_version", "overlay_sha256" } : new[] { "kind", "rule_id", "rule_version", "rule_sha256" }) pin[key] = document[key].Copy();
        pin["scope"] = kind == "detection_match" ? document["evidence"]!["scope"].Copy() : document["evidence_refs"]![0]!["scope"].Copy();
        if (document["acl_context"] is not null) { pin.Remove("scope"); pin["version"] = "sli.qw.file-acl-execution.v1"; pin["resource"] = document["acl_context"]!["resource"].Copy(); }
        return pin;
    }
    internal static async Task<SemanticProposal> Proposal(ISemanticSession session, SemanticPolicy policy, string id, string mode, CancellationToken ct)
    {
        JsonArray evidence = new(), native = new(), coverage = new(); var strict = new JsonObject(); DateTimeOffset at; string partition, identity = "exact"; bool confirmed = false; int completeness = 100; string parser = "good", timeQuality = "good", conclusion = "observed";
        if (policy.Source is "canonical_action" or "correlation_candidate")
        {
            bool action = policy.Source == "canonical_action";
            string table = action ? "canonical_actions" : "semantic_correlation_candidates", key = action ? "canonical_action_id" : "candidate_id", links = action ? "canonical_action_evidence" : "semantic_correlation_candidate_evidence";
            var source = (await session.QueryAsync($"select * from {table} where {key}=$1 for share", ct, Guid.Parse(id))).Single()!;
            if (source.Text(action ? "action_kind" : "relation_kind") != policy.Selector || action && source.Text("action_status") is "contradicted" or "superseded" or "quarantined" || !action && source.Text("candidate_status") != "matched") throw new InvalidDataException("semantic_risk_source_not_eligible");
            evidence = await session.QueryAsync($"select n.* from {links} e join normalized_events n using(normalized_event_id) where e.{key}=$1 order by e.evidence_order", ct, Guid.Parse(id));
            if (evidence.Count == 0) throw new InvalidDataException("semantic_risk_source_without_evidence");
            if (action)
            {
                var hosts = evidence.Select(x => x!["roles_json"].Text("source_host")?.Trim()).Where(x => !string.IsNullOrEmpty(x)).ToHashSet();
                if (source["attributes_json"]?["material_identity"].Text("source_host")?.Trim() is { Length: > 0 } materialHost) hosts.Add(materialHost);
                if (hosts.Count != 1) throw new InvalidDataException("semantic_risk_source_host_not_exact");
                partition = hosts.Single()!;
            }
            else partition = source.Text("partition_key")!;
            if (policy.Roles.Length == 0) throw new InvalidDataException("scenario_requires_strict_keys");
            foreach (string role in policy.Roles)
            {
                var values = evidence.Select(x => x!["roles_json"].Text(role)).Where(x => !string.IsNullOrEmpty(x)).Distinct().ToArray(); if (values.Length != 1) throw new InvalidDataException("semantic_risk_strict_role_not_exact"); strict[role] = values[0];
            }
            foreach (var atom in evidence)
            {
                if (atom!["quality_json"].Flag("unknown_event_mapping") || atom["quality_json"].Text("event_data_encoding") != "named") parser = "degraded";
            }
            identity = CandidateIdentityResolution(evidence, policy.Roles);
            completeness = Math.Min(action ? 100 : source.Text("confidence") switch { "high" => 100, "medium" => 70, _ => 40 }, 100 * evidence.Count / policy.Expected);
            confirmed = action && source.Text("action_status") is "state_confirmed" or "multi_source_confirmed"; at = SigmaProjection.At(source, action ? "occurred_at_utc" : "window_end_utc");
        }
        else if (policy.Source == "control_health")
        {
            var source = (await session.QueryAsync("select * from semantic_control_health_observations where observation_id=$1", ct, Guid.Parse(id))).FirstOrDefault();
            if (source is null || source.Text("control_id") != policy.Selector) throw new InvalidDataException("semantic_control_selector_mismatch"); partition = source.Text("partition_key")!; strict["control_id"] = source["control_id"].Copy(); at = SigmaProjection.At(source, "observed_at_utc"); coverage.Add(source.Copy()); confirmed = true;
        }
        else
        {
            string table = policy.Source == "detection_match" ? "semantic_detection_matches" : "semantic_qw_signals", key = policy.Source == "detection_match" ? "match_id" : "signal_id";
            var source = (await session.QueryAsync($"select * from {table} where {key}=$1", ct, id)).Single()!; var document = source["document_json"]!.AsObject();
            var hashed = document.DeepClone().AsObject(); if (policy.Source == "qw_signal") hashed.Remove("received_at_utc");
            if (Password.PasswordJson.Hash(hashed) != id || document.Text("rule_id") != policy.Selector || document.Text("evaluation_mode") != mode || !JsonNode.DeepEquals(NativeExecution(document, policy.Source), policy.Definition["source_selector"]!["execution"])) throw new InvalidDataException("semantic_native_input_conflict");
            if (policy.Source == "detection_match")
            {
                if (document.Text("conclusion_state") != "observed" || document.Text("quality") != "good" || document.Flag("suppressed")) throw new InvalidDataException("sigma_detection_not_eligible");
                native.Add(document["evidence"].Copy()); strict["policy"] = policy.Id; strict["entity"] = document["entity_key"].Copy(); strict["episode"] = (SigmaProjection.At(document, "occurred_at_utc").ToUnixTimeSeconds() / policy.Window).ToString(System.Globalization.CultureInfo.InvariantCulture);
            }
            else
            {
                if (document.Number("policy_revision") != policy.Version || document["password_context"] is not null) throw new InvalidDataException("semantic_qw_policy_mismatch");
                await VerifyQWContext(session, document, ct);
                var allowed = await session.QueryAsync("select public.qw_signal_evidence_allowed($1,true) as verified", ct, document); if (!allowed[0].Flag("verified")) throw new InvalidDataException("semantic_qw_evidence_denied");
                native = (JsonArray)document["evidence_refs"]!.DeepClone(); strict["kind"] = document["kind"].Copy(); strict["entity"] = document["entity_key"].Copy(); strict["episode"] = document["episode_key"].Copy(); conclusion = document.Text("conclusion_state")!;
                if (document.Text("rule_id") == "qw.agent-tamper")
                {
                    Detections.AttackPrecursors.Validate(document);
                    // Each event contributes evidence to the same rule/computer problem.
                    // Keep event identity out of the problem identity.
                    strict["episode"] = document["entity_key"].Copy();
                    if (document["attack_context"].Text("host") is { Length: > 0 } host) strict["target_entity"] = host;
                }
                if (document.Text("quality") != "good") { parser = "degraded"; timeQuality = "degraded"; }
                if (document["watch_context"] is not null)
                {
                    if (policy.Risk != "critical" || policy.Kind != document.Text("rule_id") || policy.Hard || policy.Window != 300 || policy.Expected != 1) throw new InvalidDataException("account_watch_policy_invalid");
                    int points = document.Text("effective_severity") switch { "low" => 10, "medium" => 25, "high" => 60, "critical" => 80, _ => throw new InvalidDataException("account_watch_severity_invalid") };
                    policy = policy with { Risk = document.Text("effective_severity")!, Raw = Math.Min(policy.Raw, points), Points = Math.Min(policy.Points, points) };
                }
                if (document["decoy_context"] is not null || document["file_decoy_context"] is not null)
                    if (policy.Risk != "high" || policy.Kind != document.Text("rule_id")) throw new InvalidDataException("decoy_policy_invalid");
                if (document["acl_context"] is not null && (policy.Risk != "medium" || policy.Kind != document.Text("rule_id") || policy.Hard || policy.Raw > 25 || policy.Points > 25)) throw new InvalidDataException("file_acl_medium_policy_required");
                if (document.Text("rule_id") == "qw.file-ransom" && (policy.Risk != "high" || policy.Kind != "qw.file-ransom")) throw new InvalidDataException("file_ransom_policy_invalid");
                if (document["threshold_context"] is { } threshold)
                {
                    if (threshold.Text("identity_state") == "unknown") identity = "unknown";
                    if (policy.Risk != "high" || policy.Kind != "qw.nps-denials" || policy.Window != threshold.Number("window_seconds") || policy.Expected != threshold.Number("threshold")) throw new InvalidDataException("nps_threshold_policy_invalid");
                    if (document.Text("effective_severity") == "medium") policy = policy with { Risk = "medium", Raw = Math.Min(policy.Raw, 25), Points = Math.Min(policy.Points, 25) };
                    policy = policy with { Explanation = $"NPS 6273: {threshold.Number("count")} unique denials in {threshold.Number("window_seconds")} seconds; threshold {threshold.Number("threshold")}; previous {threshold.Number("previous_count")}; comparison {threshold.Text("comparison")}; coverage {threshold.Text("current_quality")}/{threshold.Text("previous_quality")}; period [{threshold.Text("from_utc")}, {threshold.Text("to_utc")}); policy revision {policy.Version}." };
                }
            }
            if (native.Count is < 1 or > 256) throw new InvalidDataException("semantic_native_evidence_limit");
            await VerifyNative(session, native, ct); partition = document["acl_context"].Text("resource_key") ?? Password.PasswordJson.Hash(native[0]!["scope"]); at = SigmaProjection.At(document, "occurred_at_utc"); completeness = Math.Min(100, 100 * native.Count / policy.Expected);
        }
        // Control-health proposals use the selected immutable observation itself.
        if (policy.Source != "control_health") foreach (string control in policy.Controls)
        {
            var latest = (await session.QueryAsync("select control_id,coverage_status,reason,observed_at_utc from semantic_control_health_observations where partition_key=$1 and control_id=$2 and observed_at_utc<=$3 order by observed_at_utc desc,observation_id desc limit 1", ct, partition, control, at)).FirstOrDefault();
            coverage.Add(latest.Copy() ?? new JsonObject { ["control_id"] = control, ["coverage_status"] = "unknown", ["reason"] = "No control health observation is available", ["observed_at_utc"] = SemanticJson.Stamp(at) });
        }
        var factors = new JsonObject { ["identity_resolution"] = identity, ["state_confirmed"] = confirmed, ["multi_source_confirmed"] = false, ["sequence_completeness"] = completeness, ["time_quality"] = timeQuality, ["parser_quality"] = parser };
        return new(policy, id, at, partition, strict, factors, evidence.Select(x => Guid.Parse(x.Text("normalized_event_id")!)).ToArray(), native, coverage, conclusion);
    }
    internal static string CandidateIdentityResolution(JsonArray evidence, string[] strictRoles)
    {
        int rank = 3; bool hasResolution = false;
        foreach (var atom in evidence)
        {
            foreach (string role in strictRoles)
            {
                string? value = atom!["roles_json"].Text(role)?.Trim();
                if (string.IsNullOrEmpty(value)) return "unresolved";
                hasResolution = true;
                if (role is "source_host" or "source_ip" or "session_principal") continue;
                var metadata = atom["quality_json"]?["identity_roles"]?[role];
                if (metadata.Text("key")?.Trim() is { Length: > 0 } key && key != value) throw new InvalidDataException("semantic_identity_metadata_conflict");
                rank = Math.Min(rank, metadata.Text("state")?.Trim() switch { "resolved" or "external" => 3, "provisional" => 2, "unresolved" => 0, _ => 1 });
            }
        }
        return !hasResolution ? "unknown" : rank switch { 3 => "exact", 2 => "partial", 1 => "unknown", _ => "unresolved" };
    }
    internal static async Task VerifyNative(ISemanticSession session, JsonArray refs, CancellationToken ct)
    {
        foreach (var reference in refs)
        {
            var scope = reference!["scope"]!; var result = await session.QueryAsync("select public.resolve_finding_evidence_ref($1,$2,$3,$4,$5,$6,$7,$8) as verified", ct,
                Guid.Parse(scope.Text("installation_id")!), scope.Text("plugin_id"), scope.Text("source_instance_id"), scope.Text("source_generation"), scope.Text("collection_scope_id"), reference.Text("storage_kind"), reference.Text("native_id"), reference.Text("sha256"));
            if (result.Count != 1 || !result[0].Flag("verified")) throw new InvalidDataException("evidence_unavailable_or_denied");
        }
    }
    internal static string CoverageStatus(JsonArray rows)
    {
        var latest = rows.GroupBy(x => x.Text("control_id")).Select(g => g.OrderByDescending(x => SigmaProjection.At(x!, "observed_at_utc")).First());
        var statuses = latest.Select(x => x.Text("coverage_status")).ToHashSet(); return statuses.Count == 0 || statuses.SetEquals(["unknown"]) ? "unknown" : statuses.SetEquals(["complete"]) ? "complete" : statuses.All(x => x is "unknown" or "unavailable") ? "unavailable" : "partial";
    }
}
