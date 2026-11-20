using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Auth.Lifecycle.Security;

namespace Sli.Server.Semantic;

// Foundation operations own no transaction, worker admission or scenario creation.
// Callers commit rule, evidence and replay changes through their semantic session.
internal static class SemanticCorrelationRepository
{
    private static readonly HashSet<string> Kinds = ["action", "sequence", "all_of", "any_of", "count", "count_then", "distinct_count", "rate", "state_equals", "state_changed", "relationship_added", "relationship_removed", "graph_path_created", "graph_path_removed", "metric_threshold", "absence", "time_condition", "entity_classification"];
    private static readonly Dictionary<string, string[]> Transitions = new()
    {
        ["draft"] = ["validated", "disabled"], ["validated"] = ["draft", "test", "disabled"],
        ["test"] = ["draft", "shadow", "disabled"], ["shadow"] = ["enabled", "disabled", "deprecated"],
        ["enabled"] = ["disabled", "deprecated"], ["disabled"] = ["draft", "deprecated"], ["deprecated"] = []
    };

    internal static async Task Register(ISemanticSession session, string id, int version, string kind, JsonObject definition, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Length > 160 || version <= 0 || !Kinds.Contains(kind) || definition.Text("type") != kind)
            throw new InvalidDataException("correlation_rule_invalid");
        SemanticPolicy.ValidateDsl(definition);
        string hash = SemanticJson.Hash(definition);
        await session.QueryAsync("insert into semantic_correlation_rules(rule_id,rule_version,rule_kind,lifecycle_status,definition_json,definition_sha256) values($1,$2,$3,'draft',$4,$5) on conflict(rule_id,rule_version) do nothing returning rule_id", ct, id, version, kind, definition, Convert.FromHexString(hash));
        var stored = (await session.QueryAsync("select rule_kind,definition_json,encode(definition_sha256,'hex') as definition_sha256 from semantic_correlation_rules where rule_id=$1 and rule_version=$2", ct, id, version)).Single();
        if (stored.Text("rule_kind") != kind || stored.Text("definition_sha256") != hash || !JsonNode.DeepEquals(stored!["definition_json"], definition))
            throw new InvalidDataException("correlation_rule_version_replay_conflict");
    }

    internal static async Task<string> Transition(ISemanticSession session, string id, int version, string target, CancellationToken ct)
    {
        if (!Transitions.ContainsKey(target)) throw new InvalidDataException("correlation_rule_lifecycle_invalid");
        var stored = (await session.QueryAsync("select lifecycle_status from semantic_correlation_rules where rule_id=$1 and rule_version=$2 for update", ct, id, version)).SingleOrDefault();
        if (stored is null) throw new KeyNotFoundException("correlation_rule_not_found");
        string current = stored.Text("lifecycle_status")!;
        if (current == target) return current;
        if (!Transitions[current].Contains(target)) throw new InvalidDataException($"correlation_rule_transition_invalid: {current} -> {target}");
        var changed = await session.QueryAsync("update semantic_correlation_rules set lifecycle_status=$1,updated_at=now() where rule_id=$2 and rule_version=$3 and lifecycle_status=$4 returning lifecycle_status", ct, target, id, version, current);
        if (changed.Count != 1) throw new InvalidOperationException("correlation_rule_changed_concurrently");
        return target;
    }

    private static async Task EnsureExecutable(ISemanticSession session, string id, int version, CancellationToken ct)
    {
        var stored = (await session.QueryAsync("select lifecycle_status from semantic_correlation_rules where rule_id=$1 and rule_version=$2 for share", ct, id, version)).SingleOrDefault();
        if (stored is null) throw new KeyNotFoundException("correlation_rule_not_found");
        if (stored.Text("lifecycle_status") is not ("test" or "shadow" or "enabled")) throw new InvalidOperationException("correlation_rule_not_executable");
    }

    internal static async Task<Guid> PersistCandidate(ISemanticSession session, string id, int version, SemanticRelation relation, string normalizerVersion, CancellationToken ct)
    {
        if (relation.Evidence.Count == 0 || relation.Confidence is not ("low" or "medium" or "high")) throw new InvalidDataException("correlation_candidate_invalid");
        await EnsureExecutable(session, id, version, ct);
        long[] sources = relation.Evidence.Select(e => e.Source).Distinct().ToArray();
        var rows = await session.QueryAsync("select *,encode(semantic_sha256,'hex') as semantic_sha256 from normalized_events where source_event_id=any($1) and semantic_contract_version=1 and normalizer_id=$2 and normalizer_version=$3 order by occurred_at_utc,source_event_id", ct, sources, SemanticEvent.Normalizer, normalizerVersion);
        if (rows.Count != sources.Length) throw new InvalidDataException("correlation_evidence_not_normalized");
        var evidence = rows.Select(r => SemanticEvent.Read(r!)).ToArray();
        string partition = relation.Partition?.Trim() ?? "";
        if (partition.Length > 0)
        {
            var pieces = new Dictionary<string, string>();
            foreach (string component in partition.Split('|'))
            {
                var pair = component.Split(':', 2);
                if (pair.Length != 2 || !pieces.TryAdd(pair[0], pair[1])) throw new InvalidDataException("correlation_candidate_partition_invalid");
            }
            var keys = pieces.Keys.ToHashSet();
            if (partition.Length > 512 || !partition.StartsWith("domain:", StringComparison.Ordinal) ||
                !(keys.SetEquals(["domain", "account_sid"]) || keys.SetEquals(["domain", "member_sid", "group_sid"]) || keys.SetEquals(["domain", "account_member_sid"])) ||
                !Regex.IsMatch(pieces["domain"], @"\A[1-9][0-9]*\z") || pieces.Where(p => p.Key != "domain").Any(p => p.Value.Length > 184 || !Regex.IsMatch(p.Value, @"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z")))
                throw new InvalidDataException("correlation_candidate_partition_invalid");
        }
        else
        {
            var hosts = evidence.Select(e => e.Roles.Text("source_host")?.Trim()).Where(h => !string.IsNullOrEmpty(h)).Distinct().ToArray();
            if (hosts.Length != 1) throw new InvalidDataException("correlation_candidate_source_host_invalid");
            partition = hosts[0]!;
        }
        return await SemanticProduction.PersistRelation(session, id, version, relation with { Evidence = evidence, Partition = partition }, normalizerVersion, null, ct);
    }

    internal static async Task<Guid> ScheduleReplay(ISemanticSession session, string id, int version, DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        // These bounds are the persisted replay-range contract, not a process timeout.
        if (end <= start || end - start > TimeSpan.FromDays(7)) throw new InvalidDataException("correlation_replay_range_invalid");
        await EnsureExecutable(session, id, version, ct);
        string hash = SemanticJson.Hash(new JsonObject { ["rule_id"] = id, ["rule_version"] = version, ["range_start_utc"] = SemanticJson.Stamp(start), ["range_end_utc"] = SemanticJson.Stamp(end) });
        Guid replay = AuthAudit.Uuid5("adlog:correlation-replay:" + hash);
        await session.QueryAsync("insert into semantic_correlation_replays(replay_id,rule_id,rule_version,range_start_utc,range_end_utc,idempotency_key) values($1,$2,$3,$4,$5,$6) on conflict(idempotency_key) do nothing returning replay_id", ct, replay, id, version, start.ToUniversalTime(), end.ToUniversalTime(), Convert.FromHexString(hash));
        var stored = (await session.QueryAsync("select replay_id from semantic_correlation_replays where idempotency_key=$1", ct, Convert.FromHexString(hash))).Single();
        if (stored.Text("replay_id") != replay.ToString()) throw new InvalidDataException("correlation_replay_identity_conflict");
        return replay;
    }

    internal static Task<JsonArray> ClaimReplays(ISemanticSession session, int limit, CancellationToken ct) => session.QueryAsync("""
        with candidates as (
          select replay_id from semantic_correlation_replays
          where attempt_count<max_attempts and available_at<=now()
            and(replay_status in('queued','failed') or(replay_status='leased' and lease_until<now()))
          order by available_at,created_at,replay_id for update skip locked limit $1
        )
        update semantic_correlation_replays replay
        set replay_status='leased',attempt_count=attempt_count+1,lease_token=$2,lease_until=now()+interval '300 seconds',
            heartbeat_at=now(),updated_at=now(),last_error_code=null,last_error_detail=null
        from candidates where replay.replay_id=candidates.replay_id returning replay.*
        """, ct, Math.Max(1, limit), Guid.NewGuid());

    internal static async Task CompleteReplay(ISemanticSession session, Guid replay, Guid lease, DateTimeOffset checkpoint, long processed, long matched, CancellationToken ct)
    {
        if (processed < 0 || matched < 0) throw new InvalidDataException("correlation_replay_counters_invalid");
        var changed = await session.QueryAsync("""
            update semantic_correlation_replays set replay_status='completed',completed_at=now(),checkpoint_utc=$1,
              processed_events=$2,matched_candidates=$3,lease_token=null,lease_until=null,heartbeat_at=now(),updated_at=now()
            where replay_id=$4 and replay_status='leased' and lease_token=$5 and $1 between range_start_utc and range_end_utc returning replay_id
            """, ct, checkpoint.ToUniversalTime(), processed, matched, replay, lease);
        if (changed.Count != 1) throw new InvalidOperationException("correlation_replay_lease_or_checkpoint_invalid");
    }

    internal static void ValidateDefinition(string id, int version, string kind, JsonObject definition)
    {
        SemanticPolicy.ValidateDsl(definition);
        if (string.IsNullOrWhiteSpace(id) || id.Length > 160 || version <= 0)
            throw new InvalidDataException("correlation_rule_identity_invalid");
        if (!Kinds.Contains(kind))
            throw new InvalidDataException("correlation_kind_invalid");
        if (definition.Text("type") != kind) throw new InvalidDataException("correlation_definition_type_must_match_rule_kind");
        _ = SemanticJson.Hash(definition);
    }

    internal static string CandidatePartition(SemanticRelation relation, JsonArray evidence)
    {
        string explicitPartition = relation.Partition?.Trim() ?? "";
        if (explicitPartition.Length > 0 && !explicitPartition.StartsWith("domain:", StringComparison.Ordinal))
        {
            var explicitHosts = evidence.Select(x => x?["roles_json"].Text("source_host")).Distinct().ToArray();
            if (explicitPartition.Length > 512 || explicitHosts.Length != 1 || explicitHosts[0] != explicitPartition)
                throw new InvalidDataException("correlation candidate requires one exact source_host partition");
            return explicitPartition;
        }
        if (explicitPartition.Length > 0)
        {
            var parts = new Dictionary<string, string>();
            bool valid = explicitPartition.Length <= 512 && explicitPartition.StartsWith("domain:", StringComparison.Ordinal);
            foreach (string component in explicitPartition.Split('|'))
            {
                var pair = component.Split(':', 2);
                if (pair.Length != 2 || !parts.TryAdd(pair[0], pair[1])) { valid = false; break; }
            }
            string[] keys = parts.Keys.Order(StringComparer.Ordinal).ToArray();
            valid &= keys.SequenceEqual(new[] { "account_sid", "domain" }) || keys.SequenceEqual(new[] { "account_member_sid", "domain" }) || keys.SequenceEqual(new[] { "domain", "group_sid", "member_sid" });
            valid &= parts.TryGetValue("domain", out string? domain) && Regex.IsMatch(domain, @"\A[1-9][0-9]*\z");
            valid &= parts.Where(x => x.Key.EndsWith("_sid", StringComparison.Ordinal)).All(x => x.Value.Length <= 184 && Regex.IsMatch(x.Value, @"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z"));
            if (!valid) throw new InvalidDataException("correlation candidate partition is not an exact bounded SID key");
            return explicitPartition;
        }
        var hosts = evidence.Select(x => x?["roles_json"].Text("source_host")?.Trim()).Where(x => !string.IsNullOrEmpty(x)).Distinct().ToArray();
        if (hosts.Length != 1) throw new InvalidDataException("correlation candidate requires one exact source_host partition");
        return hosts[0]!;
    }

    internal static Task<JsonArray> ClaimReplaysAsync(ISemanticSession session, CancellationToken ct, int limit = 1, int leaseSeconds = 300) => session.QueryAsync("""
        with candidates as(select replay_id from semantic_correlation_replays
          where attempt_count<max_attempts and available_at<=now()
            and(replay_status in('queued','failed') or(replay_status='leased' and lease_until<now()))
          order by available_at,created_at,replay_id for update skip locked limit $1),
        leased as(update semantic_correlation_replays replay set replay_status='leased',attempt_count=attempt_count+1,
          lease_token=$2,lease_until=now()+($3 * interval '1 second'),heartbeat_at=now(),updated_at=now(),last_error_code=null,last_error_detail=null
          from candidates where replay.replay_id=candidates.replay_id returning replay.*) select * from leased
        """, ct, Math.Clamp(limit, 1, 16), Guid.NewGuid(), Math.Clamp(leaseSeconds, 60, 3600));

    internal static async Task<bool> HeartbeatReplayAsync(ISemanticSession session, Guid replay, Guid token, CancellationToken ct, int leaseSeconds = 300) =>
        (await SemanticProduction.Change(session, "update semantic_correlation_replays set heartbeat_at=now(),lease_until=now()+($1 * interval '1 second'),updated_at=now() where replay_id=$2 and replay_status='leased' and lease_token=$3 returning replay_id", ct, Math.Clamp(leaseSeconds, 60, 3600), replay, token)).Count == 1;

    internal static Task<string> TransitionAsync(ISemanticSession session, string id, int version, string target, CancellationToken ct) =>
        Transition(session, id, version, target, ct);

    internal static Task EnsureExecutableAsync(ISemanticSession session, string id, int version, CancellationToken ct) =>
        EnsureExecutable(session, id, version, ct);

    internal static Task<Guid> ScheduleReplayAsync(ISemanticSession session, string id, int version, DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        if (end <= start || end - start > TimeSpan.FromDays(7)) throw new InvalidDataException("correlation replay range must be within 7 days");
        return ScheduleReplay(session, id, version, start, end, ct);
    }

    internal static Task CompleteReplayAsync(ISemanticSession session, Guid replay, Guid token, DateTime checkpoint, long processed, long matched, CancellationToken ct)
    {
        if (checkpoint.Kind == DateTimeKind.Unspecified) throw new InvalidDataException("correlation replay checkpoint must be timezone-aware");
        if (processed < 0 || matched < 0) throw new InvalidDataException("correlation replay counters must be non-negative");
        return CompleteReplay(session, replay, token, new DateTimeOffset(checkpoint.ToUniversalTime()), processed, matched, ct);
    }
}
