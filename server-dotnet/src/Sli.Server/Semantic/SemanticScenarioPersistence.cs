using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Semantic.Risk;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticProduction
{
    internal static async Task<JsonObject> PersistProposal(ISemanticSession session, SemanticProposal p, CancellationToken ct)
    {
        if (p.Policy.Source == "control_health") await VerifyControlHealthEvidence(session, p, ct);
        if (p.Policy.Source == "correlation_candidate")
        {
            var source = (await session.QueryAsync("select candidate_status,partition_key,window_start_utc,window_end_utc from semantic_correlation_candidates where candidate_id=$1 for share", ct, Guid.Parse(p.SourceId))).FirstOrDefault();
            if (source is null) throw new InvalidDataException("correlation_candidate_source_not_found");
            if (source.Text("candidate_status") != "matched") throw new InvalidDataException("semantic_risk_source_not_eligible");
            if (source.Text("partition_key") != p.Partition) throw new InvalidDataException("scenario_partition_does_not_match_correlation_candidate");
            if (p.At < SigmaProjection.At(source, "window_start_utc") || p.At > SigmaProjection.At(source, "window_end_utc")) throw new InvalidDataException("scenario_step_outside_correlation_candidate");
            var linked = await session.QueryAsync("select normalized_event_id from semantic_correlation_candidate_evidence where candidate_id=$1", ct, Guid.Parse(p.SourceId));
            var available = linked.Select(x => Guid.Parse(x.Text("normalized_event_id")!)).ToHashSet();
            if (p.Evidence.Length == 0 || p.Evidence.Any(id => !available.Contains(id))) throw new InvalidDataException("scenario_evidence_not_linked_to_source");
        }
        await VerifyNative(session, p.Native, ct);
        await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, p.Identity);
        byte[] identity = Convert.FromHexString(p.Identity), contribution = Convert.FromHexString(p.Contribution), step = Convert.FromHexString(p.Step);
        var replay = (await session.QueryAsync("select * from semantic_risk_contributions where contribution_key=$1", ct, contribution)).FirstOrDefault();
        JsonNode? existing;
        if (replay is not null)
        {
            VerifyContribution(replay, p);
            existing = (await session.QueryAsync("select * from semantic_security_scenarios where scenario_id=$1 for update", ct, Guid.Parse(replay.Text("scenario_id")!))).Single();
        }
        else existing = (await session.QueryAsync("select * from semantic_security_scenarios where identity_key=$1 and(scenario_status in('open','under_review') or $2) and($3 or(first_seen_utc >= $4-($5*interval '1 second') and last_seen_utc<=$4+($5*interval '1 second'))) order by last_seen_utc desc,scenario_id for update limit 1", ct,
            identity, p.Policy.Source is "qw_signal" or "detection_match", p.Policy.Source == "qw_signal", p.At, p.Policy.Window)).FirstOrDefault();
        if (existing is null)
        {
            byte[] scenarioKey = p.Policy.Source == "qw_signal" ? identity : SHA256.HashData([.. identity, .. contribution]);
            Guid scenarioId = AuthAudit.Uuid5("adlog:semantic-scenario:" + Convert.ToHexStringLower(scenarioKey));
            var score = PasswordRiskProposal.Assess(p.Policy.Raw, p.Policy.Points, p.Policy.Hard, p.Policy.Risk, p.Factors, CoverageStatus(p.Coverage));
            await session.QueryAsync(SemanticRiskSql.select_scenario0, ct, scenarioId, p.Policy.Kind, p.Policy.Result, identity, scenarioKey, p.Partition, p.Strict, p.Policy.Window, p.Policy.Title, p.Policy.Explanation, p.At, p.At, score.Risk, score.Raw, score.Display, score.HardCritical, score.Confidence, score.Score, score.Factors, score.Coverage);
            existing = (await session.QueryAsync(SemanticRiskSql.select_scenario1, ct, scenarioKey)).Single(); if (existing.Text("scenario_id") != scenarioId.ToString()) throw new InvalidDataException("scenario_identity_conflict");
        }
        if (existing.Text("identity_key") != p.Identity || existing.Text("scenario_kind") != p.Policy.Kind || existing.Text("result_class") != p.Policy.Result || existing.Text("partition_key") != p.Partition || !JsonNode.DeepEquals(existing!["strict_keys_json"], p.Strict) || existing.Number("merge_window_seconds") != p.Policy.Window) throw new InvalidDataException("scenario_identity_replay_conflict");
        if (p.Policy.Source != "qw_signal" && (p.At - SigmaProjection.At(existing!, "first_seen_utc") > TimeSpan.FromSeconds(p.Policy.Window) || SigmaProjection.At(existing!, "last_seen_utc") - p.At > TimeSpan.FromSeconds(p.Policy.Window))) throw new InvalidDataException("scenario_merge_window_exceeded");
        Guid scenario = Guid.Parse(existing.Text("scenario_id")!); var sv = p.SourceValues;
        var intrinsic = PasswordRiskProposal.Assess(p.Policy.Raw, p.Policy.Points, p.Policy.Hard, p.Policy.Risk, p.Factors, "unknown");
        Guid stepId = AuthAudit.Uuid5("adlog:scenario-step:" + p.Step);
        await session.QueryAsync(SemanticRiskSql.persist_step0, ct, stepId, scenario, step, p.Policy.Source, sv[0], sv[1], sv[2], p.At, p.Policy.Title, p.Policy.Explanation, intrinsic.Confidence, intrinsic.Score, p.Factors, sv[3], sv[4]);
        var storedStep = (await session.QueryAsync(SemanticRiskSql.persist_step1, ct, step)).Single()!;
        if (storedStep.Text("step_id") != stepId.ToString() || storedStep.Text("scenario_id") != scenario.ToString() || storedStep.Text("source_kind") != p.Policy.Source || SigmaProjection.At(storedStep, "occurred_at_utc") != p.At || storedStep.Text("title") != p.Policy.Title || storedStep.Text("explanation") != p.Policy.Explanation || !JsonNode.DeepEquals(storedStep["confidence_factors_json"], p.Factors)) throw new InvalidDataException("scenario_step_replay_conflict");
        foreach (Guid atom in p.Evidence)
            await session.QueryAsync("insert into semantic_scenario_evidence(scenario_id,normalized_event_id,evidence_order) select $1,$2,coalesce(max(evidence_order),-1)+1 from semantic_scenario_evidence where scenario_id=$1 on conflict(scenario_id,normalized_event_id) do nothing", ct, scenario, atom);
        Guid contributionId = AuthAudit.Uuid5("adlog:risk-contribution:" + p.Contribution);
        await session.QueryAsync(SemanticRiskSql.persist_contribution0, ct, contributionId, scenario, contribution, p.Policy.Source, sv[0], sv[1], sv[2], p.Policy.Id, p.Policy.Version, Convert.FromHexString(p.Policy.Sha), p.Policy.Risk, p.Policy.Raw, p.Policy.Points, p.Policy.Hard, p.Policy.Rationale, sv[3], sv[4]);
        var stored = (await session.QueryAsync(SemanticRiskSql.persist_contribution1, ct, contribution)).Single()!;
        if (stored.Text("contribution_id") != contributionId.ToString() || stored.Text("scenario_id") != scenario.ToString()) throw new InvalidDataException("scenario_contribution_assignment_conflict"); VerifyContribution(stored, p);
        if (p.PasswordThresholdFacts is { } password)
        {
            bool critical = p.Policy.Risk == "critical" || existing.Text("risk_class") == "critical";
            string riskClass = critical ? "critical" : "high";
            int points = critical ? 80 : 60;
            var score = PasswordRiskProposal.Assess(points, points, false, riskClass, p.Factors, "unknown");
            var first = SigmaProjection.At(password, "first");
            var last = SigmaProjection.At(password, "last");
            var oldFirst = SigmaProjection.At(existing, "first_seen_utc");
            var oldLast = SigmaProjection.At(existing, "last_seen_utc");
            first = first < oldFirst ? first : oldFirst;
            last = last > oldLast ? last : oldLast;
            // Keep the scenario's bounded time window. The open password
            // problem retains its original first observation in its facts.
            if (last - first > TimeSpan.FromHours(24))
                first = last.AddHours(-24);
            int increment = replay is null ? 1 : 0;
            await session.QueryAsync(SemanticRiskSql.refresh_scenario4, ct, first, last,
                riskClass, score.Raw, score.Display, score.HardCritical, score.Confidence, score.Score, score.Factors, score.Coverage,
                (int)existing.Number("step_count") + increment, Math.Max((int)existing.Number("evidence_count"), p.Native.Count),
                (int)existing.Number("contribution_count") + increment, "ready", scenario);
            return (await session.QueryAsync("select * from semantic_security_scenarios where scenario_id=$1", ct, scenario)).Single()!.AsObject();
        }
        foreach (var coverage in p.Coverage)
        {
            var at = SigmaProjection.At(coverage!, "observed_at_utc");
            byte[] assessment = Convert.FromHexString(SemanticJson.Hash(new JsonObject { ["control_id"] = coverage!["control_id"].Copy(), ["status"] = coverage["coverage_status"].Copy(), ["reason"] = coverage["reason"].Copy(), ["observed_at_utc"] = SemanticJson.Stamp(at) }));
            byte[] key = SHA256.HashData([.. Encoding.UTF8.GetBytes(scenario.ToString()), .. assessment]);
            await session.QueryAsync(SemanticRiskSql.persist_coverage0, ct, AuthAudit.Uuid5("adlog:scenario-coverage:" + Convert.ToHexStringLower(key)), scenario, key, coverage.Text("control_id"), coverage.Text("coverage_status"), coverage.Text("reason"), at);
        }
        var contributions = await session.QueryAsync(SemanticRiskSql.refresh_scenario0, ct, scenario);
        var factors = await session.QueryAsync(SemanticRiskSql.refresh_scenario1, ct, scenario);
        if (factors.Count == 0) throw new InvalidDataException("semantic_scenario_no_durable_step");
        var observations = await session.QueryAsync(SemanticRiskSql.refresh_scenario2, ct, scenario); string status = CoverageStatus(observations);
        string[] severity = ["unknown", "info", "low", "medium", "high", "critical"];
        var groups = contributions.GroupBy(c => (c.Text("source_kind"), c.Text("source_kind") is "qw_signal" or "detection_match" ? c.Text("evidence_key") : c.Text("canonical_action_id") ?? c.Text("correlation_candidate_id") ?? c.Text("control_reference")));
        decimal raw = Math.Min(100000, groups.Sum(g => g.Max(x => x!["raw_score"]!.GetValue<decimal>()))); int display = Math.Min(100, groups.Sum(g => g.Max(x => (int)x.Number("display_points")))); bool hard = contributions.Any(x => x.Flag("hard_critical"));
        string risk = hard ? "critical" : contributions.MaxBy(x => Array.IndexOf(severity, x.Text("risk_class"))).Text("risk_class")!;
        var confidence = factors.Select(x => PasswordRiskProposal.Assess(raw, display, hard, risk, x!["confidence_factors_json"]!.AsObject(), status)).MinBy(x => x.Score)!;
        var counts = (await session.QueryAsync(SemanticRiskSql.refresh_scenario3, ct, scenario, scenario, scenario, scenario, scenario, scenario))[0]!;
        await session.QueryAsync(SemanticRiskSql.refresh_scenario4, ct, SigmaProjection.At(counts, "first_seen_utc"), SigmaProjection.At(counts, "last_seen_utc"), risk, raw, display, hard, confidence.Confidence, confidence.Score, confidence.Factors, status,
            (int)counts.Number("step_count"), (int)counts.Number("evidence_count"), (int)counts.Number("contribution_count"), counts.Number("evidence_count") < counts.Number("expected_evidence_count") ? "evidence_pending" : "ready", scenario);
        var persisted = (await session.QueryAsync("select * from semantic_security_scenarios where scenario_id=$1", ct, scenario)).Single()!.AsObject();
        await RecordScenarioIdentitySupersessions(session, scenario, ct);
        return persisted;
    }
    internal static async Task VerifyControlHealthEvidence(ISemanticSession session, SemanticProposal p, CancellationToken ct)
    {
        if (p.Evidence.Length != 0) throw new InvalidDataException("semantic_control_event_evidence_forbidden");
        // Observations are immutable. Row locks would unnecessarily require UPDATE rights.
        var source = (await session.QueryAsync("select observation_id,control_id,partition_key,coverage_status,reason,observed_at_utc from semantic_control_health_observations where observation_id=$1", ct, Guid.Parse(p.SourceId))).FirstOrDefault();
        if (source is null) throw new InvalidDataException("semantic_control_source_not_found");
        if (source.Text("partition_key") != p.Partition) throw new InvalidDataException("semantic_control_partition_mismatch");
        if (SigmaProjection.At(source, "observed_at_utc") != p.At) throw new InvalidDataException("semantic_control_time_mismatch");
        if (!p.Coverage.Any(item => item.Text("control_id") == source.Text("control_id") && item.Text("coverage_status") == source.Text("coverage_status") && item.Text("reason") == source.Text("reason") && SigmaProjection.At(item!, "observed_at_utc") == SigmaProjection.At(source, "observed_at_utc")))
            throw new InvalidDataException("semantic_control_coverage_mismatch");
    }
    private static void VerifyContribution(JsonNode stored, SemanticProposal p)
    {
        string source = stored.Text("canonical_action_id") ?? stored.Text("correlation_candidate_id") ?? stored.Text("control_reference") ?? stored.Text("detection_match_id") ?? stored.Text("qw_signal_id") ?? "";
        if (stored.Text("source_kind") != p.Policy.Source || source != p.SourceId || stored.Text("policy_id") != p.Policy.Id || stored.Number("policy_version") != p.Policy.Version || stored.Text("policy_sha256") != p.Policy.Sha || stored.Text("risk_class") != p.Policy.Risk || stored["raw_score"]!.GetValue<decimal>() != p.Policy.Raw || stored.Number("display_points") != p.Policy.Points || stored.Flag("hard_critical") != p.Policy.Hard || stored.Text("rationale") != p.Policy.Rationale) throw new InvalidDataException("risk_contribution_replay_conflict");
    }
    internal static async Task<JsonObject> Completeness(ISemanticSession session, SemanticProposal p, CancellationToken ct,
        DateTimeOffset? capturedAt = null, JsonArray? catalogEntries = null)
    {
        var captured = capturedAt ?? DateTimeOffset.UtcNow; var snapshot = PasswordRiskCompleteness.Capture(captured, p.At, catalogEntries); var measurements = new JsonArray();
        if (p.Policy.Source is "canonical_action" or "correlation_candidate")
        {
            bool action = p.Policy.Source == "canonical_action";
            measurements = await session.QueryAsync($"select distinct coalesce(source.computer,$1) as server_name,source.channel as channel_name,source.event_id,source.provider_name from {(action ? "canonical_action_evidence" : "semantic_correlation_candidate_evidence")} evidence join normalized_events n using(normalized_event_id) join public.semantic_event_source355 source on source.id=n.source_event_id where evidence.{(action ? "canonical_action_id" : "candidate_id")}=$2 order by server_name,channel_name,source.event_id,provider_name limit 64", ct, p.Partition, Guid.Parse(p.SourceId));
        }
        else if (p.Policy.Source == "control_health") measurements.Add(new JsonObject { ["server_name"] = p.Partition, ["channel_name"] = "Security" });
        var required = measurements.Select(x => x.Text("server_name") + "|" + x.Text("channel_name")).Distinct().ToArray(); var available = new List<string>(); var ages = new List<int>();
        foreach (string reference in required)
        {
            var parts = reference.Split('|', 2); var row = (await session.QueryAsync("select last_successful_collection_utc,backfill_completed from collection_channel_state where lower(server_hostname)=lower($1) and lower(channel)=lower($2) limit 1", ct, parts[0], parts[1])).FirstOrDefault();
            if (row.Text("last_successful_collection_utc") is not null) { int age = Math.Max(0, (int)(captured - SigmaProjection.At(row!, "last_successful_collection_utc")).TotalSeconds); ages.Add(age); if (age <= 1800 && row.Flag("backfill_completed")) available.Add(reference); }
        }
        using var stream = catalogEntries is null ? typeof(SemanticProduction).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")! : null;
        var catalog = catalogEntries ?? JsonNode.Parse(stream!)!["entries"]!.AsArray(); var timeouts = new List<int>(); bool missing = measurements.Count == 0;
        foreach (var row in measurements)
        {
            var descriptor = catalog.FirstOrDefault(x => x?["event_key"]?.ToString() == row!["event_id"]?.ToString() && string.Equals(x.Text("stream"), row.Text("channel_name"), StringComparison.OrdinalIgnoreCase) && string.Equals(x.Text("provider_name"), row.Text("provider_name"), StringComparison.OrdinalIgnoreCase));
            long timeout = descriptor?["correlation"].Number("close_timeout_seconds") ?? 0; if (timeout <= 0) missing = true; else timeouts.Add((int)timeout);
        }
        int? closeTimeout = !missing && timeouts.Count > 0 ? timeouts.Max() : null; DateTimeOffset? deadline = closeTimeout is { } seconds && p.Policy.Lateness is { } lateness ? p.At.AddSeconds(seconds + lateness) : null;
        snapshot["collection_freshness"] = new JsonObject { ["max_age_seconds"] = ages.Count == required.Length && ages.Count > 0 ? ages.Max() : null, ["budget_seconds"] = 1800, ["complete"] = required.Length > 0 && ages.Count == required.Length && ages.All(x => x <= 1800) };
        snapshot["channel_availability"] = new JsonObject { ["required"] = new JsonArray(required.Select(x => JsonValue.Create(x)).ToArray()), ["available"] = new JsonArray(available.Select(x => JsonValue.Create(x)).ToArray()), ["available_count"] = available.Count, ["required_count"] = required.Length, ["complete"] = required.Length > 0 && available.Count == required.Length };
        snapshot["window_closure"] = new JsonObject { ["window_end_utc"] = SemanticJson.Stamp(p.At), ["descriptor_close_timeout_seconds"] = closeTimeout, ["allowed_lateness_seconds"] = p.Policy.Lateness, ["close_deadline_utc"] = deadline is { } d ? SemanticJson.Stamp(d) : null, ["closed"] = deadline is not null && captured >= deadline };
        snapshot["supports_negative_conclusion"] = SupportsNegativeConclusion(snapshot); return snapshot;
    }
    internal static bool SupportsNegativeConclusion(JsonObject snapshot)
    {
        var catalog = snapshot["catalog_completeness"]; var freshness = snapshot["collection_freshness"];
        var channels = snapshot["channel_availability"]; var closure = snapshot["window_closure"];
        var required = channels?["required"] as JsonArray; var available = channels?["available"] as JsonArray;
        // Derive the conclusion from captured measurements, never from summary flags alone.
        return catalog is not null && catalog.Number("fully_classified") == catalog.Number("entry_count") && catalog.Number("schema_v2_ready") == catalog.Number("entry_count")
            && freshness?["max_age_seconds"] is not null && freshness.Number("max_age_seconds") <= freshness.Number("budget_seconds")
            && required is { Count: > 0 } && available is not null && required.Select(x => x!.GetValue<string>()).ToHashSet(StringComparer.Ordinal).SetEquals(available.Select(x => x!.GetValue<string>()))
            && closure?["descriptor_close_timeout_seconds"] is not null && closure["allowed_lateness_seconds"] is not null && closure["close_deadline_utc"] is not null && closure.Flag("closed");
    }

    internal static string ResolveConclusionState(string requested, JsonObject snapshot) =>
        requested == "not_found" && !SupportsNegativeConclusion(snapshot) ? "not_checked" : requested;
    internal static async Task<bool> PublishFinding(ISemanticSession session, SemanticProposal p, JsonObject scenario, Guid job, CancellationToken ct)
    {
        Guid sid = Guid.Parse(scenario.Text("scenario_id")!);
        var result = (await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding0, ct, job)).SingleOrDefault();
        if (result is null || result.Text("evaluation_mode") != "enabled" || result.Text("conclusion_state") != "observed" || result.Text("scenario_id") != sid.ToString() || !result.Flag("policy_admitted")) throw new InvalidOperationException("finding_requires_enabled_observed_result");
        bool passwordThreshold = p.PasswordThresholdFacts is not null;
        string? findingFirst = scenario.Text("first_seen_utc"), findingLast = scenario.Text("last_seen_utc");
        if (!passwordThreshold)
        {
            await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding3, ct, sid);
            var contributions = await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding4, ct, sid);
            if (contributions.Count == 0 || contributions.Any(x => !x.Flag("admitted") || x.Text("lifecycle_status") is not ("shadow" or "enabled") || string.IsNullOrEmpty(x.Text("policy_sha256")) || x.Text("policy_sha256") != x.Text("definition_sha256"))) throw new InvalidOperationException("finding_contributions_not_admitted");
            await VerifyNative(session, await ScenarioNative(session, sid, ct), ct);
        }
        string fingerprint = "semantic:" + scenario.Text("scenario_key"), rule = "semantic." + scenario.Text("scenario_kind"); var strict = scenario["strict_keys_json"]!.AsObject(); string? actor = strict.Text("actor") ?? strict.Text("session_principal"), target = strict.Text("target_entity") ?? strict.Text("container_entity"), source = strict.Text("source_host") ?? strict.Text("source_ip");
        if (p.DcCatalogEvidence is { } dcEvidence)
        {
            actor = dcEvidence.Text("actor");
            target = dcEvidence.Text("name");
            source = dcEvidence.Text("host");
        }
        var campaign = passwordThreshold || rule == "semantic.qw.audit-disabled"
            ? await CampaignFingerprint(session, job, ct) : null;
        if (campaign is not null) fingerprint = campaign;
        await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, fingerprint);
        var created = await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding7, ct, fingerprint, rule, scenario.Text("title"), scenario.Text("risk_class"), scenario.Number("confidence_score") / 100.0, scenario.Text("first_seen_utc"), scenario.Text("last_seen_utc"), actor, target, source, scenario.Text("explanation"), scenario.Text("explanation"), "Review the linked evidence and validate the security impact.");
        var finding = (await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding8, ct, fingerprint)).Single()!; if (finding.Text("rule_code") != rule) throw new InvalidDataException("finding_fingerprint_conflict"); long id = finding.Number("id");
        if (!passwordThreshold && campaign is not null &&
            !string.Equals((await session.QueryAsync("select public.problem_campaign_route444($1,$2) as fingerprint", ct, job, id)).Single().Text("fingerprint"), campaign, StringComparison.Ordinal))
            throw new InvalidDataException("finding_campaign_conflict");
        await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding9, ct, id, sid);
        int? dcRepeats = null;
        if (p.DcCatalogEvidence is not null)
        {
            var proof = (await session.QueryAsync("select public.copy_dc_catalog_evidence401($1,$2) as repeats", ct, id, sid)).Single();
            dcRepeats = proof?["repeats"]?.GetValue<int>() ?? throw new InvalidDataException("dc_catalog_finding_evidence_unavailable");
        }
        if (passwordThreshold)
        {
            var facts = (await session.QueryAsync("select public.publish_password_threshold_facts418($1,$2) as facts", ct, id, job)).Single()!["facts"]!;
            if (campaign is not null && !facts.Flag("campaign")) throw new InvalidDataException("finding_campaign_conflict");
            target = facts.Text("account"); source = facts.Text("source");
            if (campaign is not null || facts is JsonObject password && Detections.PasswordAttacks.ScenarioPartition(p.Policy.Selector, password) is not null)
            {
                findingFirst = facts.Text("first");
                findingLast = facts.Text("last");
            }
        }
        else
        {
            var native = await ScenarioNative(session, sid, ct); await VerifyNative(session, native, ct);
            foreach (var reference in native)
            {
                var scope = reference!["scope"]!; await session.QueryAsync("select public.link_finding_evidence_ref($1,$2,$3,$4,$5,$6,$7,$8,$9) as added", ct, id, Guid.Parse(scope.Text("installation_id")!), scope.Text("plugin_id"), scope.Text("source_instance_id"), scope.Text("source_generation"), scope.Text("collection_scope_id"), reference.Text("storage_kind"), reference.Text("native_id"), reference.Text("sha256"));
            }
        }
        foreach (var pair in strict)
        {
            if (p.Policy.Source == "qw_signal" && pair.Key is "kind" or "entity" or "episode") continue;
            if (p.DcCatalogEvidence is not null && pair.Key is ("domain_id" or "target_entity")) continue;
            string type = pair.Key switch { "source_host" => "host", "target_entity" when rule == "semantic.qw.agent-tamper" => "host", "source_ip" => "ip", "container_entity" => "group", _ => "account" };
            await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding10, ct, id, type, pair.Value!.ToString(), pair.Key, id, type, pair.Value.ToString(), pair.Key);
        }
        var evidence = (await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding11, ct, id, id)).Single()!;
        if (evidence.Number("count") <= 0) throw new InvalidOperationException("finding_without_exact_evidence");
        int? repeats = dcRepeats ?? (rule == "semantic.qw.agent-tamper"
            ? Math.Max(0, (int)evidence.Number("count") - 1) : (int?)null);
        string? severity = campaign is not null && finding.Text("severity") == "critical" ? "critical" : scenario.Text("risk_class");
        if (campaign is not null && rule == "semantic.qw.audit-disabled" && created.Count == 0)
            await session.QueryAsync("""
                update public.findings set last_seen_utc=greatest(last_seen_utc::timestamptz,$1::timestamptz),
                    updated_at=now() where id=$2
                """, ct, findingLast, id);
        else
            await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding12, ct, scenario.Text("title"), severity, scenario.Number("confidence_score") / 100.0, findingFirst, findingLast, actor, target, source, scenario.Text("explanation"), scenario.Text("explanation"), "Review the linked evidence and validate the security impact.", (int)evidence.Number("count"), evidence["max_event_id"] is null ? null : evidence.Number("max_event_id"), id, repeats);
        await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding13, ct, sid, id, job, fingerprint, (int)evidence.Number("count"));
        var publication = (await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding14, ct, sid)).Single()!;
        bool canonicalPublication = publication.Number("finding_id") == id && publication.Text("finding_fingerprint") == fingerprint;
        if (campaign is null && !canonicalPublication)
            throw new InvalidDataException("finding_publication_replay_conflict");
        if (created.Count > 0) await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding15, ct, id);
        bool legacyModule = rule is "semantic.qw.nps-denials" or "semantic.qw.file-decoy" or "semantic.qw.file-acl-broad-write";
        if (finding.Flag("transition_admission") && !legacyModule)
        {
            if (canonicalPublication && (p.Policy.Source == "qw_signal" || p.DcCatalogEvidence is not null) &&
                Notifications.ProblemNotification.IsTransition(created.Count > 0, false, finding.Text("status")!, finding.Text("severity")!, severity!))
                await session.QueryAsync("select public.enqueue_problem_notification423($1,$2) as enqueued", ct, sid, job);
        }
        else
        {
            if (p.Policy.Source == "qw_signal" && (!passwordThreshold || created.Count > 0)) await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding16, ct, sid);
            if (p.DcCatalogEvidence is not null)
                await session.QueryAsync("select public.enqueue_dc_catalog_notifications401($1) as enqueued", ct, sid);
        }
        await RecordFindingIdentitySupersessions(session, sid, id, ct);
        return created.Count > 0;
    }

    private static async Task<string?> CampaignFingerprint(ISemanticSession session, Guid job, CancellationToken ct)
    {
        var available = await session.QueryAsync("select to_regprocedure('public.problem_campaign_route444(uuid,bigint)') is not null as available", ct);
        return available.Single().Flag("available")
            ? (await session.QueryAsync("select public.problem_campaign_route444($1,null) as fingerprint", ct, job)).Single().Text("fingerprint")
            : null;
    }
    private static async Task RecordScenarioIdentitySupersessions(ISemanticSession session, Guid scenario, CancellationToken ct)
    {
        var available = await session.QueryAsync("select to_regclass('public.entity_identity_scenario_supersessions_v2') is not null as available", ct);
        if (!available[0].Flag("available")) return;
        await session.QueryAsync("""
            insert into public.entity_identity_scenario_supersessions_v2(merge_id,old_scenario_id,new_scenario_id)
            select distinct replay.merge_id,old_evidence.scenario_id,$1 from public.semantic_scenario_evidence new_evidence
            join public.entity_identity_semantic_replays_v2 replay on replay.new_normalized_event_id=new_evidence.normalized_event_id
            join public.semantic_scenario_evidence old_evidence on old_evidence.normalized_event_id=replay.old_normalized_event_id
            join public.semantic_security_scenarios old_scenario on old_scenario.scenario_id=old_evidence.scenario_id
            join public.semantic_security_scenarios new_scenario on new_scenario.scenario_id=$1
            where new_evidence.scenario_id=$1 and old_evidence.scenario_id<>$1
              and old_scenario.scenario_kind=new_scenario.scenario_kind and old_scenario.result_class=new_scenario.result_class
            on conflict do nothing
            """, ct, scenario);
    }
    private static async Task RecordFindingIdentitySupersessions(ISemanticSession session, Guid scenario, long finding, CancellationToken ct)
    {
        var available = await session.QueryAsync("select to_regclass('public.entity_identity_finding_supersessions_v2') is not null as available", ct);
        if (!available[0].Flag("available")) return;
        await session.QueryAsync("""
            insert into public.entity_identity_finding_supersessions_v2(merge_id,old_scenario_id,new_scenario_id,old_finding_id,new_finding_id)
            select supersession.merge_id,supersession.old_scenario_id,supersession.new_scenario_id,old_publication.finding_id,$2
            from public.entity_identity_scenario_supersessions_v2 supersession join public.semantic_finding_publications old_publication
              on old_publication.scenario_id=supersession.old_scenario_id
            where supersession.new_scenario_id=$1 and old_publication.finding_id<>$2
            on conflict do nothing
            """, ct, scenario, finding);
    }
    private static async Task<JsonArray> ScenarioNative(ISemanticSession session, Guid scenario, CancellationToken ct)
    {
        var documents = await session.QueryAsync("select s.source_kind,d.document_json as detection,q.document_json as qw from semantic_scenario_steps s left join semantic_detection_matches d on d.match_id=s.detection_match_id left join semantic_qw_signals q on q.signal_id=s.qw_signal_id where s.scenario_id=$1 and s.source_kind in('detection_match','qw_signal') order by s.occurred_at_utc,s.step_id", ct, scenario); var result = new JsonArray();
        foreach (var row in documents)
        {
            if (row.Text("source_kind") == "detection_match") result.Add(row!["detection"]!["evidence"].Copy());
            else { var doc = row!["qw"]!; await VerifyQWContext(session, doc.AsObject(), ct); var verified = await session.QueryAsync("select public.qw_signal_evidence_allowed($1,true) as verified", ct, doc); if (!verified[0].Flag("verified")) throw new InvalidDataException("qw_evidence_unavailable"); foreach (var reference in doc["evidence_refs"]!.AsArray()) result.Add(reference.Copy()); }
            if (result.Count > 32768) throw new InvalidDataException("scenario_native_evidence_limit_exceeded");
        }
        return result;
    }
}
