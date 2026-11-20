using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class CorrelationRepository1Tests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTimeOffset Start = new(2026, 7, 19, 1, 0, 0, TimeSpan.Zero);
    private const string Partition = "domain:7|account_sid:S-1-5-21-100000001-200000002-300000003-1001";
    private static SemanticCorrelation Rule() => SemanticCorrelation.Compile(new JsonObject
    {
        ["rule_id"] = "session-special-privileges", ["rule_version"] = 1, ["rule_kind"] = "sequence",
        ["definition_json"] = new JsonObject { ["type"] = "sequence", ["inputs"] = new JsonArray("logon", "privileges"),
            ["join_roles"] = new JsonArray("source_host"), ["window_seconds"] = 60,
            ["output_relation_kind"] = "authentication.session.has_special_privileges", ["explanation"] = "Exact source host and LogonId" }
    });
    private static SemanticEvent Event(long id, int seconds = 0, string host = "1") => new(id, "logon", Start.AddSeconds(seconds),
        new JsonObject { ["source_host"] = host }, new(), new(), new string('a', 64));
    private static SemanticRelation Relation(string? partition = null) => new(Rule().Output, [Event(1), Event(2, 1)], "session-special-privileges:1:0x1:1:2", "high", "Exact source host and LogonId", partition);
    private static JsonObject Normalized(SemanticEvent ev) => new() { ["normalized_event_id"] = ev.Id().ToString(), ["source_event_id"] = ev.Source,
        ["occurred_at_utc"] = SemanticJson.Stamp(ev.At), ["roles_json"] = ev.Roles.DeepClone() };

    private sealed class Session : ISemanticSession
    {
        internal readonly List<(string Sql, object?[] Values)> Calls = [];
        internal Func<string, object?[], JsonArray> Reply = (_, _) => [];
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Calls.Add((sql, values)); return Task.FromResult(Reply(sql, values));
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    private static Session CandidateSession(SemanticRelation relation, int count = 2, int maximum = 1)
    {
        Guid candidate = default;
        return new Session { Reply = (sql, values) =>
        {
            if (sql.StartsWith("select lifecycle_status")) return [new JsonObject { ["lifecycle_status"] = "test" }];
            if (sql.Contains("from normalized_events where")) return new JsonArray(relation.Evidence.Select(x => (JsonNode)Normalized(x)).ToArray());
            if (sql.Contains("insert into semantic_correlation_candidates(")) candidate = (Guid)values[0]!;
            if (sql.StartsWith("select candidate_id")) return [new JsonObject { ["candidate_id"] = candidate.ToString(), ["relation_kind"] = relation.Kind, ["partition_key"] = relation.Partition ?? "1" }];
            if (sql.StartsWith("select count(*)")) return [new JsonObject { ["evidence_count"] = count, ["maximum_order"] = maximum }];
            return [];
        } };
    }

    [Fact]
    public void Definition_type_must_match_and_nested_executable_payloads_are_rejected()
    {
        var mismatch = Assert.Throws<InvalidDataException>(() => SemanticCorrelationRepository.ValidateDefinition("rule", 1, "count", new() { ["type"] = "rate" }));
        Assert.Contains("must_match", mismatch.Message);
        foreach (string key in new[] { "sql", " Shell ", "powershell", "python", "csharp", "command", "script", "network_call", "http", "url" })
        {
            var definition = new JsonObject { ["type"] = "count", ["nested"] = new JsonArray(new JsonObject { [key] = "untrusted" }) };
            Assert.Equal("forbidden_semantic_dsl_field", Assert.Throws<InvalidDataException>(() => SemanticCorrelationRepository.ValidateDefinition("rule", 1, "count", definition)).Message);
        }
        SemanticCorrelationRepository.ValidateDefinition("rule", 1, "count", new() { ["type"] = "count" });
    }

    [Fact]
    public async Task Enabled_rule_cannot_jump_back_to_test()
    {
        var session = new Session { Reply = (_, _) => [new JsonObject { ["lifecycle_status"] = "enabled" }] };
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => SemanticCorrelationRepository.TransitionAsync(session, "rule", 1, "test", Ct));
        Assert.Contains("enabled -> test", error.Message);
        Assert.Contains("for update", Assert.Single(session.Calls).Sql);
        Assert.Equal("enabled", await SemanticCorrelationRepository.TransitionAsync(session, "rule", 1, "enabled", Ct));
    }

    [Fact]
    public async Task Candidate_uses_exact_normalization_contract_and_appends_exact_evidence_under_lock()
    {
        var relation = Relation() with { Evidence = [Event(1), Event(2, 1), Event(1)] };
        var session = CandidateSession(relation);
        // Database rows are unique even when the requested evidence repeats a source.
        var original = session.Reply;
        session.Reply = (sql, values) => sql.Contains("from normalized_events where") ? [Normalized(Event(1)), Normalized(Event(2, 1))] : original(sql, values);
        Guid candidate = await SemanticProduction.PersistRelation(session, Rule(), relation, SemanticEvent.Version, null, Ct);
        var query = Assert.Single(session.Calls, x => x.Sql.Contains("from normalized_events where"));
        Assert.Equal(new long[] { 1, 2 }, Assert.IsType<long[]>(query.Values[0]));
        Assert.Equal(1, query.Values[1]); Assert.Equal(SemanticEvent.Normalizer, query.Values[2]); Assert.Equal(SemanticEvent.Version, query.Values[3]);
        Assert.Contains("semantic_contract_version=$2 and normalizer_id=$3 and normalizer_version=$4", query.Sql);
        int locked = session.Calls.FindIndex(x => x.Sql.Contains("pg_advisory_xact_lock"));
        int inserted = session.Calls.FindIndex(x => x.Sql.Contains("insert into semantic_correlation_candidates("));
        Assert.True(locked < inserted); Assert.Equal(candidate, session.Calls[inserted].Values[0]);
        var links = session.Calls.Where(x => x.Sql.Contains("insert into semantic_correlation_candidate_evidence(")).ToArray();
        Assert.Equal(new[] { Event(1).Id(), Event(2, 1).Id() }, links.Select(x => (Guid)x.Values[1]!));
        Assert.Contains(session.Calls, x => x.Sql.Contains("evidence_count=(select count(*)"));
        int shift = session.Calls.FindIndex(x => x.Sql.Contains("set evidence_order=evidence_order+16384"));
        int order = session.Calls.FindIndex(x => x.Sql.Contains("row_number() over(order by n.occurred_at_utc,n.source_event_id)"));
        Assert.True(shift > inserted && order > shift);
        Assert.DoesNotContain(session.Calls, x => x.Sql.Contains("shifted as"));
    }

    [Theory] [InlineData(16385, 1)] [InlineData(2, 16384)]
    public async Task Unsafe_evidence_renumbering_fails_before_any_order_shift(int count, int maximum)
    {
        var session = CandidateSession(Relation(), count, maximum);
        Assert.Equal("semantic_candidate_evidence_limit_exceeded", (await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistRelation(session, Rule(), Relation(), SemanticEvent.Version, null, Ct))).Message);
        Assert.DoesNotContain(session.Calls, x => x.Sql.Contains("set evidence_order=evidence_order+16384"));
    }

    [Fact]
    public async Task Explicit_domain_sid_partition_accepts_cross_dc_evidence()
    {
        var relation = Relation(Partition) with { Evidence = [Event(11, host: "dc-1"), Event(12, 1, "dc-2")] };
        var session = CandidateSession(relation);
        await SemanticProduction.PersistRelation(session, Rule(), relation, SemanticEvent.Version, null, Ct);
        Assert.Equal(Partition, Assert.Single(session.Calls, x => x.Sql.Contains("insert into semantic_correlation_candidates(")).Values[5]);
    }

    [Theory]
    [InlineData("domain:7|account_sid:S-1-5-21-not-numeric")]
    [InlineData("domain:0|account_sid:S-1-5-21-100000001-200000002-300000003-1001")]
    [InlineData("domain:7|account_sid:S-1-5-21-100000001-200000002-300000003-1001|domain:7")]
    public async Task Malformed_explicit_partition_is_rejected_before_candidate_write(string partition)
    {
        var relation = Relation(partition); var session = CandidateSession(relation);
        Assert.Contains("exact bounded SID key", (await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistRelation(session, Rule(), relation, SemanticEvent.Version, null, Ct))).Message);
        Assert.DoesNotContain(session.Calls, x => x.Sql.Contains("insert into semantic_correlation_candidates("));
    }

    [Theory]
    [InlineData("1", "1", true)]
    [InlineData("2", "1", false)]
    [InlineData("1", "2", false)]
    public async Task Explicit_host_partition_must_match_all_saved_evidence(string partition, string secondHost, bool valid)
    {
        var relation = Relation(partition) with { Evidence = [Event(1), Event(2, host: secondHost)] };
        var session = CandidateSession(relation);
        if (valid)
        {
            await SemanticProduction.PersistRelation(session, Rule(), relation, SemanticEvent.Version, null, Ct);
            Assert.Equal("1", Assert.Single(session.Calls, x => x.Sql.Contains("insert into semantic_correlation_candidates(")).Values[5]);
        }
        else
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistRelation(session, Rule(), relation, SemanticEvent.Version, null, Ct));
            Assert.DoesNotContain(session.Calls, x => x.Sql.Contains("insert into semantic_correlation_candidates("));
        }
    }

    [Fact]
    public async Task Missing_exact_normalization_and_implicit_cross_host_partition_fail_closed()
    {
        var session = CandidateSession(Relation()); var original = session.Reply;
        session.Reply = (sql, values) => sql.Contains("from normalized_events where") ? [Normalized(Event(1))] : original(sql, values);
        Assert.Equal("correlation_evidence_not_normalized", (await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistRelation(session, Rule(), Relation(), "other-version", null, Ct))).Message);
        var relation = Relation() with { Evidence = [Event(1, host: "dc-1"), Event(2, 1, "dc-2")] };
        session = CandidateSession(relation);
        Assert.Contains("one exact source_host", (await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistRelation(session, Rule(), relation, SemanticEvent.Version, null, Ct))).Message);
        Assert.DoesNotContain(session.Calls, x => x.Sql.Contains("insert into semantic_correlation_candidates("));
    }

    [Fact]
    public async Task Replay_window_claim_and_heartbeat_preserve_repository_contract()
    {
        var session = new Session();
        Assert.Contains("within 7 days", (await Assert.ThrowsAsync<InvalidDataException>(() => SemanticCorrelationRepository.ScheduleReplayAsync(session, "rule", 1, Start, Start.AddDays(8), Ct))).Message);
        Assert.Empty(session.Calls);
        Assert.Empty(await SemanticCorrelationRepository.ClaimReplaysAsync(session, Ct, limit: 999, leaseSeconds: 1));
        var claim = Assert.Single(session.Calls); Assert.Contains("for update skip locked", claim.Sql);
        Assert.Equal(16, claim.Values[0]); Assert.IsType<Guid>(claim.Values[1]); Assert.Equal(60, claim.Values[2]);
        var replay = Guid.NewGuid(); var token = Guid.NewGuid();
        session.Reply = (_, _) => [new JsonObject { ["replay_id"] = replay.ToString() }];
        Assert.True(await SemanticCorrelationRepository.HeartbeatReplayAsync(session, replay, token, Ct, leaseSeconds: 1));
        Assert.Equal(new object?[] { 60, replay, token }, session.Calls[^1].Values);
        Assert.Contains("replay_status='leased' and lease_token=$3", session.Calls[^1].Sql);
    }

    [Fact]
    public async Task Replay_completion_rejects_naive_checkpoint_and_negative_metrics_before_sql()
    {
        var session = new Session(); var replay = Guid.NewGuid(); var token = Guid.NewGuid();
        Assert.Contains("timezone-aware", (await Assert.ThrowsAsync<InvalidDataException>(() => SemanticCorrelationRepository.CompleteReplayAsync(session, replay, token, new DateTime(2026, 7, 19), 1, 1, Ct))).Message);
        foreach (var (processed, matched) in new[] { (-1, 0), (0, -1) })
            Assert.Contains("non-negative", (await Assert.ThrowsAsync<InvalidDataException>(() => SemanticCorrelationRepository.CompleteReplayAsync(session, replay, token, Start.UtcDateTime, processed, matched, Ct))).Message);
        Assert.Empty(session.Calls);
        await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticCorrelationRepository.CompleteReplayAsync(session, replay, token, Start.UtcDateTime, 1, 1, Ct));
    }

    [Fact]
    public async Task Postgres_replays_reorder_and_deduplicate_evidence_and_enforce_lease_ownership()
    {
        // Fresh local cluster, canonical correlation tables; no inherited DSN or stand data.
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create table normalized_events(normalized_event_id uuid primary key,source_event_id bigint not null,
              occurred_at_utc timestamptz not null,roles_json jsonb not null,semantic_contract_version int not null,
              normalizer_id text not null,normalizer_version text not null);
            """, Ct);
        string foundation = File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/026_semantic_correlation_foundation.sql"));
        foreach (string table in new[] { "semantic_correlation_rules", "semantic_correlation_candidates", "semantic_correlation_candidate_evidence", "semantic_correlation_replays" })
        {
            string sql = Regex.Match(foundation, @"create table if not exists " + table + @" \([\s\S]*?\r?\n\);").Value;
            Assert.NotEmpty(sql); await PostCollectionPostgres.Sql(db, sql, Ct);
        }
        await PostCollectionPostgres.Sql(db, """
            alter table semantic_correlation_candidates add column reopen_count int not null default 0,
              add column late_evidence_count int not null default 0,add column closed_at timestamptz,add column last_evidence_occurred_at timestamptz;
            alter table semantic_correlation_candidate_evidence add column is_late boolean not null default false;
            """, Ct);
        await using var tx = await db.BeginTransactionAsync(Ct); var session = new SemanticSession(db, tx);
        await SemanticProduction.Change(session, "insert into semantic_correlation_rules(rule_id,rule_version,rule_kind,definition_json,definition_sha256) values($1,1,'sequence','{}',decode(repeat('a',64),'hex')) returning rule_id", Ct, Rule().Id);
        foreach (string state in new[] { "validated", "test" }) Assert.Equal(state, await SemanticCorrelationRepository.TransitionAsync(session, Rule().Id, 1, state, Ct));
        foreach (var ev in new[] { Event(1), Event(3, 1800), Event(2, 600), Event(4, 600) })
            await SemanticProduction.Change(session, "insert into normalized_events values($1,$2,$3,$4,1,$5,$6) returning normalized_event_id", Ct, ev.Id(), ev.Source, ev.At, ev.Roles, SemanticEvent.Normalizer, SemanticEvent.Version);
        var relation = Relation(Partition) with { Evidence = [Event(1), Event(3, 1800)], Confidence = "medium" };
        Guid candidate = await SemanticProduction.PersistRelation(session, Rule(), relation, SemanticEvent.Version, null, Ct);
        // Replay adds earlier evidence and a same-time tie, deliberately supplied out of order.
        relation = relation with { Evidence = [Event(4, 600), Event(3, 1800), Event(2, 600), Event(1)], Confidence = "high" };
        Assert.Equal(candidate, await SemanticProduction.PersistRelation(session, Rule(), relation, SemanticEvent.Version, null, Ct));
        Assert.Equal(candidate, await SemanticProduction.PersistRelation(session, Rule(), relation with { Confidence = "low" }, SemanticEvent.Version, null, Ct));
        var ordered = await session.QueryAsync("select n.source_event_id,e.evidence_order from semantic_correlation_candidate_evidence e join normalized_events n using(normalized_event_id) where candidate_id=$1 order by evidence_order", Ct, candidate);
        Assert.Equal(new long[] { 1, 2, 4, 3 }, ordered.Select(x => x.Number("source_event_id")));
        Assert.Equal(new long[] { 0, 1, 2, 3 }, ordered.Select(x => x.Number("evidence_order")));
        var stored = Assert.Single(await session.QueryAsync("select evidence_count,confidence from semantic_correlation_candidates where candidate_id=$1", Ct, candidate));
        Assert.Equal(4, stored.Number("evidence_count")); Assert.Equal("high", stored.Text("confidence"));
        // Exactly seven days is accepted; equivalent UTC offsets preserve the replay identity.
        Guid replay = await SemanticCorrelationRepository.ScheduleReplayAsync(session, Rule().Id, 1, Start, Start.AddDays(7), Ct);
        Assert.Equal(replay, await SemanticCorrelationRepository.ScheduleReplayAsync(session, Rule().Id, 1, Start.ToOffset(TimeSpan.FromHours(3)), Start.AddDays(7), Ct));
        var job = Assert.Single(await SemanticCorrelationRepository.ClaimReplaysAsync(session, Ct));
        Guid token = Guid.Parse(job.Text("lease_token")!);
        Assert.True(await SemanticCorrelationRepository.HeartbeatReplayAsync(session, replay, token, Ct, 1));
        Assert.False(await SemanticCorrelationRepository.HeartbeatReplayAsync(session, replay, Guid.NewGuid(), Ct));
        await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticCorrelationRepository.CompleteReplayAsync(session, replay, token, Start.AddDays(8).UtcDateTime, 1, 1, Ct));
        await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticCorrelationRepository.CompleteReplayAsync(session, replay, Guid.NewGuid(), Start.UtcDateTime, 1, 1, Ct));
        await SemanticCorrelationRepository.CompleteReplayAsync(session, replay, token, Start.AddDays(7).UtcDateTime, 4, 1, Ct);
        Assert.False(await SemanticCorrelationRepository.HeartbeatReplayAsync(session, replay, token, Ct));
        var finished = Assert.Single(await session.QueryAsync("select replay_status,processed_events,matched_candidates,lease_token,lease_until from semantic_correlation_replays where replay_id=$1", Ct, replay));
        Assert.Equal("completed", finished.Text("replay_status")); Assert.Equal(4, finished.Number("processed_events")); Assert.Equal(1, finished.Number("matched_candidates"));
        Assert.Null(finished!["lease_token"]); Assert.Null(finished["lease_until"]);
        await tx.CommitAsync(Ct);
    }
}
