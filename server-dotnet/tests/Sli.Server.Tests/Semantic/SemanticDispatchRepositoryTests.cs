using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// SQL/session contracts mirror tests/semantic/test_semantic_dispatch_repository1.py.
public sealed class SemanticDispatchRepositoryTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    private static readonly DateTimeOffset Occurred = DateTimeOffset.Parse("2026-07-19T00:00:00Z");
    private static JsonObject RuleRow(bool crossDc = false) => new()
    {
        ["rule_id"] = crossDc ? "investigation.account.lockout.preceded-by-failures" : "dispatch-rule", ["rule_version"] = 1,
        ["rule_kind"] = crossDc ? "count_then" : "all_of",
        ["definition_json"] = new JsonObject
        {
            ["type"] = crossDc ? "count_then" : "all_of", ["inputs"] = new JsonArray("type.one", "type.two"),
            ["partition_kind"] = crossDc ? "domain_account_sid" : "source_host",
            ["join_roles"] = crossDc ? new JsonArray() : new JsonArray("source_host", "session_principal"),
            ["window_seconds"] = crossDc ? 900 : 300, ["minimum_count"] = 2,
            ["strict_time_order"] = crossDc, ["output_relation_kind"] = "relation.one-two",
            ["confidence"] = "medium", ["explanation"] = "same host and session"
        }
    };
    private static SemanticEvent Event(long source = 1) => new(source, "type.one", Occurred,
        new() { ["source_host"] = "dc-1", ["affected_entity"] = "sid:" + Sid }, new() { ["domain_id"] = 7 }, new(), new string('a', 64));
    private sealed class Session(Func<string, object?[], JsonArray>? query = null) : ISemanticSession
    {
        internal readonly List<(string Sql, object?[] Values)> Commands = [];
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            ct.ThrowIfCancellationRequested(); Commands.Add((sql, values));
            return Task.FromResult(query?.Invoke(sql, values) ?? new JsonArray());
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    [Fact] public async Task Subscription_replacement_locks_exact_draft_and_preserves_input_order()
    {
        var rule = SemanticCorrelation.Compile(RuleRow());
        var session = new Session((sql, _) => sql.StartsWith("select lifecycle_status")
            ? new(new JsonObject { ["lifecycle_status"] = "draft", ["definition_sha256"] = rule.Sha }) : []);
        await SemanticProduction.ReplaceRuleSubscriptions(session, rule, Ct);
        Assert.Contains("for update", session.Commands[0].Sql);
        Assert.Equal(new object?[] { rule.Id, rule.Version }, session.Commands[0].Values);
        Assert.Single(session.Commands, x => x.Sql.StartsWith("delete from semantic_correlation_subscriptions"));
        var inserts = session.Commands.Where(x => x.Sql.Contains("insert into semantic_correlation_subscriptions")).ToArray();
        Assert.Equal(2, inserts.Length);
        for (int i = 0; i < 2; i++)
            Assert.Equal(new object?[] { rule.Id, 1, rule.Inputs[i], (short)i, Convert.FromHexString(rule.Sha) }, inserts[i].Values);
    }

    [Theory] [InlineData("test")] [InlineData("shadow")] [InlineData("enabled")]
    public async Task Subscription_replacement_rejects_non_draft_without_mutation(string state)
    {
        var rule = SemanticCorrelation.Compile(RuleRow());
        var session = new Session((_, _) => new(new JsonObject { ["lifecycle_status"] = state, ["definition_sha256"] = rule.Sha }));
        Assert.Equal("semantic_correlation_subscriptions_require_draft", (await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.ReplaceRuleSubscriptions(session, rule, Ct))).Message);
        Assert.Single(session.Commands);
    }

    [Fact] public async Task Subscription_replacement_checks_parent_hash_and_is_a_noop_for_exact_subscriptions()
    {
        var rule = SemanticCorrelation.Compile(RuleRow());
        var missing = new Session();
        await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.ReplaceRuleSubscriptions(missing, rule, Ct));
        var mismatch = new Session((_, _) => new(new JsonObject { ["lifecycle_status"] = "draft", ["definition_sha256"] = new string('0', 64) }));
        await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.ReplaceRuleSubscriptions(mismatch, rule, Ct));
        Assert.Single(mismatch.Commands);
        var exact = new Session((sql, _) => sql.StartsWith("select lifecycle_status")
            ? new(new JsonObject { ["lifecycle_status"] = "draft", ["definition_sha256"] = rule.Sha })
            : new(rule.Inputs.Select((x, i) => (JsonNode)new JsonObject { ["semantic_type"] = x, ["subscription_order"] = i, ["definition_sha256"] = rule.Sha }).ToArray()));
        await SemanticProduction.ReplaceRuleSubscriptions(exact, rule, Ct);
        Assert.Equal(2, exact.Commands.Count);
    }

    private static Session EnqueueSession(double seconds, bool crossDc = false, bool conflict = false)
    {
        object?[]? inserted = null;
        return new((sql, values) =>
        {
            if (sql.Contains("from semantic_correlation_subscriptions")) return new(RuleRow(crossDc));
            if (sql.Contains("select source_ingested_at")) return new(new JsonObject { ["source_ingested_at"] = SemanticJson.Stamp(Occurred.AddSeconds(seconds)) });
            if (sql.Contains("insert into semantic_correlation_dispatch_jobs")) { inserted = values; return []; }
            if (sql.Contains("where idempotency_key")) return new(new JsonObject
            {
                ["job_id"] = ((Guid)inserted![0]!).ToString(), ["normalized_event_id"] = ((Guid)inserted[1]!).ToString(),
                ["partition_key"] = conflict ? "different" : (string)inserted[5]!, ["is_late"] = (bool)inserted[7]!
            });
            return [];
        });
    }

    [Theory] [InlineData(360, true)] [InlineData(300, false)] [InlineData(0, false)] [InlineData(-1, false)]
    public async Task Enqueue_replays_stable_identity_and_only_ingestion_delay_marks_late(double seconds, bool late)
    {
        var session = EnqueueSession(seconds); var ev = Event();
        await SemanticProduction.EnqueueDispatchForRules(session, ev, SemanticEvent.Version, Ct);
        await SemanticProduction.EnqueueDispatchForRules(session, ev, SemanticEvent.Version, Ct);
        var inserts = session.Commands.Where(x => x.Sql.Contains("insert into semantic_correlation_dispatch_jobs")).ToArray();
        Assert.Equal(2, inserts.Length); Assert.Equal(inserts[0].Values, inserts[1].Values);
        Assert.Equal(late, inserts[0].Values[7]); Assert.Equal("dc-1", inserts[0].Values[5]);
        Assert.Contains("on conflict(idempotency_key) do nothing", inserts[0].Sql);
        Assert.Contains("rule.lifecycle_status in('shadow','enabled')", session.Commands[0].Sql);
        Assert.Contains("rule.definition_sha256=s.definition_sha256", session.Commands[0].Sql);
    }

    [Fact] public async Task Enqueue_cross_dc_uses_exact_domain_sid_and_rejects_replay_conflicts()
    {
        var session = EnqueueSession(0, crossDc: true);
        await SemanticProduction.EnqueueDispatchForRules(session, Event(), SemanticEvent.Version, Ct);
        Assert.Equal("domain:7|account_sid:" + Sid, Assert.Single(session.Commands, x => x.Sql.Contains("insert into semantic_correlation_dispatch_jobs")).Values[5]);
        await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.EnqueueDispatchForRules(EnqueueSession(0, conflict: true), Event(), SemanticEvent.Version, Ct));
        var noIdentity = Event() with { Roles = new() { ["source_host"] = "dc-1" } };
        var skipped = EnqueueSession(0, crossDc: true);
        await SemanticProduction.EnqueueDispatchForRules(skipped, noIdentity, SemanticEvent.Version, Ct);
        Assert.Single(skipped.Commands);
    }

    [Fact] public async Task Enqueue_filters_exact_rule_ids_and_pinned_version_hash_in_sql()
    {
        var session = new Session();
        await SemanticProduction.EnqueueDispatchForRules(session, Event(), SemanticEvent.Version, Ct, allowedRuleIds: ["investigation.account.lockout.preceded-by-failures"]);
        var ids = Assert.Single(session.Commands); Assert.Contains("rule.rule_id=any($2)", ids.Sql);
        Assert.Equal(new[] { "investigation.account.lockout.preceded-by-failures" }, Assert.IsType<string[]>(ids.Values[1]));
        var exact = new Session(); string sha = new('1', 64);
        await SemanticProduction.EnqueueDispatchForRules(exact, Event(), SemanticEvent.Version, Ct, allowedRuleIdentities: [("investigation.rule", 3, sha)]);
        var identity = Assert.Single(exact.Commands);
        Assert.Contains("rule.rule_id=$2 and rule.rule_version=$3 and rule.definition_sha256=$4", identity.Sql);
        Assert.Equal(new object?[] { "type.one", "investigation.rule", 3, Convert.FromHexString(sha) }, identity.Values);
        var invalid = new Session();
        await Assert.ThrowsAsync<ArgumentException>(() => SemanticProduction.EnqueueDispatchForRules(invalid, Event(), SemanticEvent.Version, Ct, allowedRuleIds: []));
        await Assert.ThrowsAsync<ArgumentException>(() => SemanticProduction.EnqueueDispatchForRules(invalid, Event(), SemanticEvent.Version, Ct, allowedRuleIds: ["rule"], allowedRuleIdentities: [("rule", 1, sha)]));
        Assert.Empty(invalid.Commands);
    }

    [Theory] [InlineData("domain_account_sid", 2)] [InlineData("domain_member_group_sid", 2)] [InlineData("domain_account_member_sid", 3)]
    public void Cross_dc_predicates_are_exact_and_non_empty(string kind, int count)
    {
        string partition = kind switch { "domain_account_sid" => "domain:7|account_sid:" + Sid, "domain_member_group_sid" => $"domain:7|member_sid:{Sid}|group_sid:{Sid}", _ => "domain:7|account_member_sid:" + Sid };
        var (sql, parameters) = SemanticProduction.CrossDcContextPredicate(kind, partition);
        Assert.Equal(count, parameters.Length); Assert.Equal(count, sql.Split("@>").Length - 1);
        Assert.All(parameters, x => Assert.NotEmpty(x)); Assert.Equal(7L, parameters[0].Number("domain_id"));
        if (kind == "domain_account_sid") Assert.Equal("sid:" + Sid, parameters[1].Text("affected_entity"));
        else if (kind == "domain_member_group_sid") { Assert.Equal(Sid, parameters[1].Text("relation_member_sid")); Assert.Equal(Sid, parameters[1].Text("relation_group_sid")); }
        else { Assert.Contains(" or ", sql); Assert.Equal("sid:" + Sid, parameters[1].Text("affected_entity")); Assert.Equal(Sid, parameters[2].Text("relation_member_sid")); }
    }

    [Theory]
    [InlineData("domain:7|account_sid:not-a-sid")] [InlineData("domain:7|account_sid:")]
    [InlineData("domain:0|account_sid:{sid}")] [InlineData("domain:07|account_sid:{sid}")]
    [InlineData("domain:7|account_sid:{sid}|extra:value")] [InlineData("domain:7|domain:8|account_sid:{sid}")]
    [InlineData("domain:7|member_sid:{sid}|group_sid:{sid}")]
    public void Cross_dc_predicate_fails_closed_for_malformed_or_wrong_partition(string partition) =>
        Assert.Contains("exact SID key", Assert.Throws<InvalidDataException>(() => SemanticProduction.CrossDcContextPredicate("domain_account_sid", partition.Replace("{sid}", Sid))).Message);

    [Fact] public async Task Claim_is_skip_locked_leased_and_filters_exact_rules_and_jobs()
    {
        var plain = new Session(); Assert.Empty(await SemanticProduction.ClaimDispatchJobs(plain, Ct, limit: 3, leaseSeconds: 1));
        var command = Assert.Single(plain.Commands);
        Assert.Contains("for update of job skip locked limit $1", command.Sql);
        Assert.Equal(3, command.Values[0]); Assert.IsType<Guid>(command.Values[1]); Assert.Equal(60, command.Values[2]);
        Assert.Contains("heartbeat_at=now()", command.Sql); Assert.Contains("job.lease_until<now()", command.Sql);
        var filtered = new Session(); await SemanticProduction.ClaimDispatchJobs(filtered, Ct, limit: 3, allowedRuleIds: ["investigation.account.unlock.after-lock"]);
        var filter = Assert.Single(filtered.Commands); Assert.Contains("rule.rule_id=any($1)", filter.Sql);
        Assert.Equal(new[] { "investigation.account.unlock.after-lock" }, Assert.IsType<string[]>(filter.Values[0])); Assert.Equal(3, filter.Values[1]);
        var exact = new Session(); string sha = new('2', 64); Guid job = Guid.Parse("00000000-0000-0000-0000-000000000099");
        await SemanticProduction.ClaimDispatchJobs(exact, Ct, limit: 3, allowedRuleIdentities: [("investigation.rule", 4, sha)], allowedJobIds: [job]);
        var pinned = Assert.Single(exact.Commands);
        Assert.Contains("join semantic_correlation_rules rule", pinned.Sql);
        Assert.Contains("rule.rule_id=$1 and rule.rule_version=$2 and rule.definition_sha256=$3", pinned.Sql);
        Assert.Contains("job.job_id=any($4::uuid[])", pinned.Sql);
        Assert.Equal("investigation.rule", pinned.Values[0]); Assert.Equal(4, pinned.Values[1]);
        Assert.Equal(Convert.FromHexString(sha), Assert.IsType<byte[]>(pinned.Values[2])); Assert.Equal(new[] { job }, Assert.IsType<Guid[]>(pinned.Values[3]));
        var empty = new Session(); Assert.Empty(await SemanticProduction.ClaimDispatchJobs(empty, Ct, allowedJobIds: [])); Assert.Empty(empty.Commands);
    }

    [Fact] public async Task Expiry_requires_aware_boundary_and_locks_only_matched_candidates_before_it()
    {
        var session = new Session();
        Assert.Contains("timezone-aware", (await Assert.ThrowsAsync<ArgumentException>(() => SemanticProduction.ExpireCorrelationCandidates(session, new DateTime(2026, 7, 19), Ct))).Message);
        Assert.Empty(session.Commands);
        Assert.Empty(await SemanticProduction.ExpireCorrelationCandidates(session, Occurred.UtcDateTime, Ct, limit: 3));
        var command = Assert.Single(session.Commands);
        Assert.Contains("candidate_status='matched' and window_end_utc < $1", command.Sql);
        Assert.Contains("for update skip locked limit $2", command.Sql); Assert.Contains("candidate_status='expired',closed_at=now()", command.Sql);
        Assert.Equal(Occurred.UtcDateTime, command.Values[0]); Assert.Equal(3, command.Values[1]);
    }

    [Fact] public async Task Late_evidence_reopens_only_expired_candidates_once_and_rejects_unrelated_sources()
    {
        var rule = SemanticCorrelation.Compile(RuleRow()); var relation = new SemanticRelation(rule.Output, [Event(1), Event(2)], "dispatch:stable", "medium", rule.Explanation, "dc-1");
        object?[]? inserted = null;
        var session = new Session((sql, values) =>
        {
            if (sql.StartsWith("select lifecycle_status")) return new(new JsonObject { ["lifecycle_status"] = "shadow" });
            if (sql.StartsWith("select normalized_event_id,source_event_id")) return new JsonArray(new[] { Event(1), Event(2) }.Select(e => (JsonNode)new JsonObject { ["normalized_event_id"] = e.Id().ToString(), ["source_event_id"] = e.Source, ["occurred_at_utc"] = SemanticJson.Stamp(e.At), ["roles_json"] = e.Roles.DeepClone() }).ToArray());
            if (sql.Contains("insert into semantic_correlation_candidates(")) inserted = values;
            if (sql.StartsWith("select candidate_id,relation_kind,partition_key")) return new(new JsonObject { ["candidate_id"] = ((Guid)inserted![0]!).ToString(), ["relation_kind"] = rule.Output, ["partition_key"] = "dc-1" });
            if (sql.StartsWith("select count(*) as evidence_count")) return new(new JsonObject { ["evidence_count"] = 2, ["maximum_order"] = 1 });
            return [];
        });
        await SemanticProduction.PersistRelation(session, rule, relation, SemanticEvent.Version, 2, Ct);
        var command = session.Commands[^1];
        Assert.StartsWith("with prior as(", command.Sql);
        Assert.Contains("and not e.is_late", command.Sql);
        Assert.Contains("n.source_event_id=$2::bigint", command.Sql); Assert.Equal(2L, command.Values[1]);
        Assert.Contains("c.candidate_status='expired' and changed.changed_count>0 then 1 else 0", command.Sql);
        Assert.Contains("then 'matched' else c.candidate_status", command.Sql);
        Assert.Contains("then null else c.closed_at", command.Sql);
        Assert.Contains("prior.prior_late_count+changed.changed_count", command.Sql);
        var invalid = new Session();
        Assert.Contains("must belong", (await Assert.ThrowsAsync<ArgumentException>(() => SemanticProduction.PersistRelation(invalid, rule, relation, SemanticEvent.Version, 3, Ct))).Message);
        Assert.Empty(invalid.Commands);
    }
}
