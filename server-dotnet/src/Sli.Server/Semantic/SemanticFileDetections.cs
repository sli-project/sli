using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticProduction
{
    private static string FileCheckpoint(JsonObject scope, string agent, string rule, string mode = "enabled", int revision = 1, string processing = "live", JsonObject? config = null)
    {
        var document = new JsonObject { ["scope"] = scope.Copy(), ["agent_id"] = agent, ["policy_revision"] = revision, ["evaluation_mode"] = mode };
        if (rule == "qw.file-ransom") { document["source_policy_revision"] = config?["policy_revision"].Copy() ?? JsonValue.Create("1"); document["threshold"] = config?["mass_operation_files"].Copy() ?? JsonValue.Create(100); document["window_seconds"] = config?["mass_operation_seconds"].Copy() ?? JsonValue.Create(300); }
        else if (processing != "live") document["processing_mode"] = processing; return Digest(document);
    }
    private static async Task<int> ProcessFileDecoy(ISemanticSession session, JsonNode source, CancellationToken ct) => (int)(await RunFileDecoy(session,source,ct)).Number("jobs");
    private static async Task<JsonObject> RunFileDecoy(ISemanticSession session, JsonNode source, CancellationToken ct, DetectorRule? rule = null, DateTimeOffset? now = null)
    {
        var scope = source["scope"]!.AsObject(); string agent = source.Text("agent_id")!; var definition = Definition("qw.file-decoy", scope, agent); if (rule is null && !await AdmitDefault(session, definition, ct)) return new() { ["state"] = "processed", ["observations"] = 0, ["jobs"] = 0 };
        string checkpoint = FileCheckpoint(scope, agent, "qw.file-decoy", rule?.Mode ?? "enabled", rule?.Revision ?? 1, rule?.Processing ?? "live"); await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, checkpoint);
        var rows = await session.QueryAsync("select * from public.read_file_decoy_observations($1::jsonb,$2,$3,null)", ct, scope, Guid.Parse(agent), checkpoint); if (rows.Count > 128) throw new InvalidDataException("file_decoy_batch_invalid"); int jobs = 0; var states = new JsonObject();
        foreach (var row in rows)
        {
            var (signals, state) = EvaluateFileDecoy(definition, agent, row!, now ?? DateTimeOffset.UtcNow);
            foreach (var signal in signals) { int count = await EnqueueQW(session, rule?.Apply(signal!.AsObject()) ?? signal!.AsObject(), ct); if (count == 0) throw new InvalidOperationException("file_decoy_policy_unavailable"); jobs += count; }
            await session.QueryAsync("insert into semantic_file_decoy_checks(checkpoint_key,observation_key,scope_json,result_code) values($1,$2,$3,$4) on conflict do nothing", ct, checkpoint, row!["observation"].Text("evidence_key"), scope, state); states[state] = (states[state]?.GetValue<int>() ?? 0) + 1;
        }
        return new() { ["state"] = "processed", ["observations"] = rows.Count, ["results"] = states, ["jobs"] = jobs };
    }
    internal static (JsonArray Signals, string State) EvaluateFileDecoy(JsonObject definition, string agent, JsonNode row, DateTimeOffset now)
    {
        var signals = new JsonArray(); var scope = definition["source_selector"]!["execution"]!["scope"]!; var obs = row["observation"]!; var facts = obs["facts"]!; var at = SigmaProjection.At(obs, "observed_at"); int id = (int)obs.Number("event_id");
        if (at > now || obs.Text("agent_id") != agent || obs.Text("source_instance_id") != scope.Text("source_instance_id") || obs.Text("generation") != scope.Text("source_generation") || id is not (4656 or 5145 or 4663 or 4660 or 4670) || facts.Text("outcome") is not ("success" or "failure") || !(facts.Text("object_type") ?? "File").Equals("file", StringComparison.OrdinalIgnoreCase)) return (signals, "not_applicable");
        var chosen = obs; var witnesses = new List<JsonNode> { obs };
        if (id == 4660)
        {
            string[] fields = ["subject_user_sid", "logon_id_numeric", "server_process_id", "handle_id"];
            if (facts.Text("outcome") != "success" || facts["handle_id"] is null || facts["handle_id"]!.ToString() is "0" or "" || fields.Any(k => facts[k] is null)) return (signals, "not_applicable");
            var contexts = row["contexts"]!.AsArray(); if (contexts.Count > 128) throw new InvalidDataException("file_decoy_context_limit");
            var available = contexts.Where(x => new[] { "agent_id", "source_instance_id", "generation", "policy_revision" }.All(k => JsonNode.DeepEquals(x![k], obs[k])) && x.Number("record_id") < obs.Number("record_id") && SigmaProjection.At(x!, "observed_at") <= at && SigmaProjection.At(x!, "observed_at") >= at.AddSeconds(-300)).ToArray();
            long boot = available.Where(x => x.Number("event_id") is 4608 or 1102).Select(x => x.Number("record_id")).DefaultIfEmpty(0).Max();
            var related = available.Where(x => x.Number("record_id") > boot && x.Number("event_id") is 4656 or 4659 or 4663 or 4658 or 4660 && fields.All(k => JsonNode.DeepEquals(x!["facts"]![k], facts[k]))).ToArray();
            long boundary = related.Where(x => x.Number("event_id") is 4658 or 4660).Select(x => x.Number("record_id")).DefaultIfEmpty(0).Max();
            if (related.Any(x => x.Number("record_id") > boundary && x.Number("event_id") != 4660 && string.IsNullOrEmpty(x.Text("path")))) return (signals, "not_applicable");
            var candidates = related.Where(x => x.Number("record_id") > boundary && !string.IsNullOrEmpty(x.Text("path")) && x!["facts"].Text("outcome") == "success").ToArray();
            if (candidates.Select(x => x.Text("path")!.ToLowerInvariant()).Distinct().Count() != 1) return (signals, "not_applicable"); chosen = candidates.MaxBy(x => x.Number("record_id"))!; witnesses.Add(chosen);
        }
        if (string.IsNullOrEmpty(chosen.Text("path")) || !chosen["scopes"]!.AsArray().Any(x => x.Text("collection_scope_id") == scope.Text("collection_scope_id")) || !(chosen["facts"].Text("object_type") ?? "File").Equals("file", StringComparison.OrdinalIgnoreCase)) return (signals, "not_applicable");
        string path; try { path = AgentFileAuditPolicy.NormalizePath(chosen.Text("path")!).Replace('/', '\\').ToLowerInvariant(); } catch (Exception e) when (e is ArgumentException or InvalidDataException) { return (signals, "not_applicable"); }
        if (facts.Text("outcome") == "failure" && id is not (4656 or 5145)) return (signals, "not_applicable");
        string meaning = facts.Text("outcome") == "failure" ? "access_denied" : id is 4656 or 5145 ? "access_check" : id == 4660 ? "deleted" : id == 4670 ? "permissions_changed" : (facts.Number("access_mask") & 1) != 0 && (facts.Text("object_type") ?? "").Equals("file", StringComparison.OrdinalIgnoreCase) ? "read" : "file_action";
        var identity = new JsonObject { ["agent_id"] = agent, ["source_instance_id"] = scope["source_instance_id"].Copy(), ["collection_scope_id"] = scope["collection_scope_id"].Copy(), ["path"] = path };
        var labels = row["labels"]!.AsArray(); if (labels.Count > 128) throw new InvalidDataException("file_decoy_label_limit");
        foreach (var label in labels)
        {
            if (label.Text("kind") != "file" || !JsonNode.DeepEquals(label!["identity"], identity) || !label.Flag("active") || SigmaProjection.At(label, "active_from") > at || label["active_to"] is not null && at >= SigmaProjection.At(label, "active_to")) continue;
            var context = new JsonObject { ["label_id"] = label["id"].Copy(), ["label_revision"] = label["revision"].Copy(), ["identity_sha256"] = Digest(identity), ["observation_key"] = obs["evidence_key"].Copy(), ["agent_id"] = agent, ["meaning"] = meaning, ["outcome"] = facts["outcome"].Copy() };
            var session = new JsonArray(new[] { "subject_user_sid", "logon_id_numeric", "server_process_id", "handle_id" }.Select(k => facts[k].Copy()).ToArray());
            JsonNode group = session.All(x => x is not null && x.ToString() is not ("" or "0")) ? new JsonArray(session, at.ToUnixTimeSeconds() / 300) : obs["evidence_key"].Copy()!;
            var refs = new JsonArray(witnesses.Select(x => (JsonNode)Reference(scope, "file_audit_observation", x.Text("evidence_key")!, x.Text("payload_sha256")!)).ToArray());
            signals.Add(Signal(definition, Digest(new JsonArray(scope.Copy(), identity.Copy())), Digest(new JsonArray(scope.Copy(), label["id"].Copy(), label["revision"].Copy(), group)), at, now, refs, reason: "decoy_file_touch", contextKey: "file_decoy_context", context: context));
        }
        return (signals, signals.Count > 0 ? "observed" : "no_match");
    }
    private static async Task<int> ProcessFileRansom(ISemanticSession session, JsonNode source, CancellationToken ct) => (int)(await RunFileRansom(session,source,ct)).Number("jobs");
    private static async Task<JsonObject> RunFileRansom(ISemanticSession session, JsonNode source, CancellationToken ct,
        DetectorRule? rule = null, DateTimeOffset? now = null, JsonObject? evaluation = null)
    {
        var scope = source["scope"]!.AsObject(); string agent = source.Text("agent_id")!; var config = source["config"]!.AsObject(); var definition = Definition("qw.file-ransom", scope, agent, config); if (rule is null && !await AdmitDefault(session, definition, ct)) return new() { ["state"] = "processed", ["members"] = 0, ["jobs"] = 0 };
        if (source["ransom_policy"] is not null && source["ransom_policy"].Text("state") != "ready") throw new InvalidOperationException("source_policy_waiting");
        int threshold = (int)definition.Number("expected_evidence_count"), window = (int)definition.Number("merge_window_seconds"); string revision = config["policy_revision"]?.ToString() ?? "1";
        string checkpoint = FileCheckpoint(scope, agent, "qw.file-ransom", rule?.Mode ?? "enabled", rule?.Revision ?? 1, config: config); await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, checkpoint);
        var rows = await session.QueryAsync("select * from public.read_file_ransom_results($1::jsonb,$2,$3,$4,$5,$6)", ct, scope, Guid.Parse(agent), revision, checkpoint, threshold, window); if (rows.Count > 32) throw new InvalidDataException("file_ransom_batch_invalid"); int jobs = 0, members = 0;
        if (evaluation is not null)
        {
            evaluation["result_count"] = rows.Count;
            if (rows.Count != 0) evaluation.Remove("reason");
        }
        foreach (var row in rows)
        {
            var result = row!["result"]!; var details = result["details"]!;
            long distinctFiles = details.Number("distinct_files");
            var decision = evaluation is null ? null : new JsonObject { ["distinct_files"] = distinctFiles, ["episode"] = "none" };
            if (decision is not null) evaluation!["results"]!.AsArray().Add(decision);
            string? invalid = null;
            if (result.Text("agent_id") != agent || result.Text("source_instance_id") != scope.Text("source_instance_id")
                || result.Text("collection_scope_id") != scope.Text("collection_scope_id")) invalid = "scope_mismatch";
            else if (distinctFiles < threshold) invalid = "below_threshold";
            else if (result.Text("rule_code") is not ("file-audit.mass-write" or "file-audit.mass-delete")
                || result.Text("conclusion_state") != "observed" || result.Number("rule_version") != 1
                || string.IsNullOrEmpty(result.Text("subject_sid")) || details.Number("threshold") != threshold
                || details.Number("window_seconds") != window || distinctFiles > result["action_ids"]!.AsArray().Count) invalid = "invalid_result";
            if (invalid is not null)
            {
                if (decision is not null) decision["reason"] = invalid;
                throw new InvalidDataException("file_ransom_result_invalid");
            }
            var start = SigmaProjection.At(details, "window_start"); var end = SigmaProjection.At(details, "window_end");
            if (end < start || end - start > TimeSpan.FromSeconds(window))
            {
                if (decision is not null) decision["reason"] = "outside_window";
                throw new InvalidDataException("file_ransom_window_invalid");
            }
            if ((await session.QueryAsync("select 1 from semantic_file_ransom_members where checkpoint_key=$1 and result_id=$2", ct, checkpoint, result.Text("result_id"))).Count > 0)
            {
                if (decision is not null) decision["reason"] = "already_evaluated";
                continue;
            }
            var exclusion = rule?.Exclusions.FirstOrDefault(e => e.Text("subject_sid") == result.Text("subject_sid") && SigmaProjection.At(e!,"active_from") <= start && end < SigmaProjection.At(e!,"active_to"));
            if (exclusion is not null)
            {
                if (decision is not null) decision["reason"] = "excluded";
                await session.QueryAsync("insert into semantic_file_ransom_members(checkpoint_key,result_id,episode_key,scope_json,exclusion_json,evaluation_mode) values($1,$2,null,$3,$4,$5)",ct,checkpoint,result.Text("result_id"),scope,exclusion,rule!.Mode); members++; continue;
            }
            string entity = Digest(new JsonArray(checkpoint, result["subject_sid"].Copy()));
            // The event-time deadline is exclusive. Late results can still
            // contribute to their original episode inside that deadline.
            var episode = (await session.QueryAsync("""
                select * from semantic_file_ransom_episodes
                where checkpoint_key=$1 and entity_key=$2 and not sealed
                  and first_seen<$3 and last_seen>$4
                order by (first_seen<=$6 and last_seen>=$5) desc,
                    greatest(first_seen-$6,$5-last_seen,interval '0 seconds'),first_seen,episode_key
                limit 1 for update
                """, ct, checkpoint, entity, end.AddSeconds(window), start.AddSeconds(-window), start, end)).FirstOrDefault();
            string key = episode.Text("episode_key") ?? Digest(new JsonArray(checkpoint, entity, result["result_id"].Copy()));
            bool complete = row.Flag("complete") && !episode.Flag("incomplete");
            if(complete && episode is not null)
            {
                var previousStart=SigmaProjection.At(episode,"first_seen");
                var previousEnd=SigmaProjection.At(episode,"last_seen");
                var coverage=await session.QueryAsync("""
                    select public.file_ransom_window_has_gap464($1::jsonb,$2,$3,$4) as gap
                    """,ct,scope,Guid.Parse(agent),previousStart<start ? previousStart : start,previousEnd>end ? previousEnd : end);
                complete=!coverage.Single().Flag("gap");
            }
            var refs = SemanticJson.Array(row["evidence"]!.AsArray().Select(x => Reference(scope, "file_audit_observation", x.Text("native_id")!, x.Text("sha256")!)).DistinctBy(x => x!.ToJsonString()).OrderBy(x => x.Text("native_id"), StringComparer.Ordinal)); if (refs.Count is < 1 or > 32768) throw new InvalidDataException("file_ransom_evidence_invalid");
            for (int offset = 0; offset < refs.Count; offset += 256) { var signal = Signal(definition, entity, key, end, now ?? DateTimeOffset.UtcNow, SemanticJson.Array(refs.Skip(offset).Take(256)), reason: "mass_file_changes", quality: complete ? "good" : "degraded", total: refs.Count); int count = await EnqueueQW(session, rule?.Apply(signal) ?? signal, ct); if (count == 0) throw new InvalidOperationException("file_ransom_policy_unavailable"); jobs += count; }
            await session.QueryAsync("insert into semantic_file_ransom_episodes(episode_key,checkpoint_key,scope_json,entity_key,first_seen,last_seen,incomplete) values($1,$2,$3,$4,$5,$6,$7) on conflict(episode_key) do update set first_seen=least(semantic_file_ransom_episodes.first_seen,excluded.first_seen),last_seen=greatest(semantic_file_ransom_episodes.last_seen,excluded.last_seen),incomplete=semantic_file_ransom_episodes.incomplete or excluded.incomplete", ct, key, checkpoint, scope, entity, start, end, !complete);
            await session.QueryAsync("insert into semantic_file_ransom_members(checkpoint_key,result_id,episode_key,scope_json,evaluation_mode) values($1,$2,$3,$4,$5)", ct, checkpoint, result.Text("result_id"), key, scope, rule?.Mode ?? "enabled"); members++;
            if (decision is not null)
            {
                decision["episode"] = episode is null ? "opened" : "extended";
                if (!complete) decision["reason"] = "incomplete_coverage";
            }
        }
        return new() { ["state"] = "processed", ["members"] = members, ["jobs"] = jobs };
    }
    private static async Task<DetectionOutcome> ProcessFileAcl(NpgsqlConnection db, CancellationToken ct, DetectionDiagnostics? diagnostics = null)
    {
        JsonArray resources;
        await using (var tx = await db.BeginTransactionAsync(ct)) { resources = (await new SemanticSession(db, tx, diagnostics:diagnostics).QueryAsync("select public.read_default_file_acl_resources(null,1) as page", ct))[0]!["page"]!["items"]!.AsArray(); await tx.CommitAsync(ct); }
        if (resources.Count > 1) throw new InvalidDataException("file_acl_discovery_invalid"); int jobs = 0, failed = 0;
        foreach (var resource in resources)
        {
            await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db,tx,diagnostics:diagnostics);
            await session.ExecuteAsync("set local statement_timeout=0;set local lock_timeout=1000",ct);
            var definition = DefaultDetectionDefinitions.Read()["qw.file-acl-broad-write"]!.DeepClone().AsObject(); definition["source_selector"]!["execution"]!["resource"] = resource.Copy();
            if (!await AdmitDefault(session,definition,ct)) { await tx.CommitAsync(ct); continue; }
            var result = await RunFileAclResource(session,resource!.AsObject(),ct); await tx.CommitAsync(ct); jobs += (int)result.Number("jobs");
            if (result["diagnostics"]!.AsObject().Any(p => p.Key != "verified_excluded")) { diagnostics?.FileAcl(result["diagnostics"]!.AsObject()); failed++; }
        }
        return new(jobs,failed,Sources:resources.Count);
    }
    internal static async Task<JsonObject> RunFileAclResource(ISemanticSession session, JsonObject resource, CancellationToken ct)
    {
        string key = FileAclResourceKey(resource); await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))",ct,key); var diagnostics = new JsonObject();
            var portions = (await session.QueryAsync("select public.read_pending_file_acl_portions_v265($1::jsonb) as portions", ct, resource))[0]!["portions"]!.AsArray();
            if (portions.Count == 0)
            {
                var page = (await session.QueryAsync("select public.read_file_acl_results($1::jsonb,null,32) as page", ct, resource))[0]!["page"]!;
                diagnostics = page["diagnostics"]?.DeepClone().AsObject() ?? throw new InvalidDataException("file_acl_diagnostics_invalid");
                foreach (var group in page["items"]!.AsArray().GroupBy(x => x!["provenance"].Text("command_id")).OrderBy(x => x.Key, StringComparer.Ordinal))
                {
                    var members = new JsonArray(group.Select(x => (JsonNode)new JsonObject { ["result_id"] = x!["result"]!["result_id"].Copy(), ["result_sha256"] = x["result_sha256"].Copy() }).ToArray());
                    portions.Add((await session.QueryAsync("select public.prepare_file_acl_portion_v265($1::jsonb,$2::jsonb) as portion", ct, resource, members))[0]!["portion"].Copy());
                }
            }
            int added = 0;
            foreach (var portion in portions)
            {
                var document = portion!["document"]!.AsObject(); var material = document.DeepClone().AsObject(); material.Remove("received_at_utc"); if (Digest(material) != portion.Text("signal_id")) throw new InvalidDataException("file_acl_portion_conflict");
                int count = await EnqueueQW(session, document, ct); if (count == 0) throw new InvalidOperationException("file_acl_required_jobs_missing");
                var checkpoint = (await session.QueryAsync("select public.advance_file_acl_checkpoint_v265($1::jsonb,$2,$3) as advanced", ct, resource, portion.Text("portion_id"), portion.Text("signal_id")))[0]!;
                if (!checkpoint.Flag("advanced")) throw new InvalidOperationException("file_acl_checkpoint_denied"); added += count;
            }
        return new() { ["jobs"] = added, ["portions"] = portions.Count, ["diagnostics"] = AclDiagnostics(diagnostics) };
    }
    internal static JsonObject AclDiagnostics(JsonObject diagnostics)
    {
        string[] allowed = ["source_unbound", "result_hash_mismatch", "snapshot_proof_mismatch", "producer_identity_mismatch", "blocked_result_detail_subset", "owner_denied", "unsupported_descriptor", "verified_excluded", "blocked_direct_ad_proof_unsupported", "blocked_broad_principal_unsupported"];
        var counts = new JsonObject(); foreach (var (code,value) in diagnostics)
        {
            if (value is not JsonValue v || !v.TryGetValue<int>(out int count) || count < 0 || count > 32) throw new InvalidDataException("file_acl_diagnostics_invalid");
            if (count == 0) continue; string safe = allowed.Contains(code) ? code : "unrecognized_status"; counts[safe] = (counts[safe]?.GetValue<int>() ?? 0) + count;
        }
        return counts;
    }
}
