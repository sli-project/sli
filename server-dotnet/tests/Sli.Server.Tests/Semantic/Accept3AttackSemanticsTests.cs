using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// tests/semantic/test_accept3_attack_semantics.py: synthetic cohorts, no source or DB access.
public sealed class Accept3AttackSemanticsTests
{
    private const string Sid = "S-1-5-21-100000001-200000002-300000003";
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static JsonObject[] Sources(string scenario)
    {
        var rows = new List<(int Id, JsonObject Data)>();
        switch (scenario)
        {
            case "brute":
                for (int i = 0; i < 20; i++) rows.Add((4625, new() { ["Status"] = "0xc000006d", ["SubStatus"] = "0xc000006a" }));
                rows.Add((4740, new())); rows.Add((4767, new()));
                rows.Add((4624, new() { ["TargetLogonId"] = "0x42" })); rows.Add((4634, new() { ["TargetLogonId"] = "0x42" }));
                break;
            case "spray":
                for (int i = 0; i < 30; i++) rows.Add((4625, new() { ["TargetUserSid"] = $"{Sid}-{1300 + i}", ["TargetUserName"] = $"fixture-{i}", ["Status"] = "0xc000006d", ["SubStatus"] = "0xc000006a" }));
                break;
            case "admin":
                rows.Add((4728, new() { ["TargetSid"] = Sid + "-512", ["MemberSid"] = Sid + "-1100" }));
                rows.Add((5136, new()));
                rows.Add((4729, new() { ["TargetSid"] = Sid + "-512", ["MemberSid"] = Sid + "-1100" }));
                rows.Add((5136, new()));
                break;
            case "kerberos":
                for (int i = 0; i < 10; i++) rows.Add((4769, new() { ["ServiceName"] = $"fixture-service-{i}", ["TicketEncryptionType"] = "0x17", ["Status"] = "0x0" }));
                break;
            case "disabled": rows.Add((4625, new() { ["Status"] = "0xc000006e", ["SubStatus"] = "0xc0000072" })); break;
            case "task":
                rows.Add((4698, new() { ["TaskName"] = "\\fixture-task" })); rows.Add((4699, new() { ["TaskName"] = "\\fixture-task" }));
                break;
            default: throw new ArgumentOutOfRangeException(nameof(scenario));
        }
        return rows.Select((row, i) => {
            var data = new JsonObject { ["TargetUserSid"] = Sid + "-1100", ["TargetUserName"] = "fixture-user", ["SubjectUserSid"] = Sid + "-1200", ["IpAddress"] = "192.0.2.20" };
            foreach (var pair in row.Data) data[pair.Key] = pair.Value?.DeepClone();
            return new JsonObject { ["id"] = i + 1, ["event_id"] = row.Id, ["channel"] = "Security", ["computer"] = "fixture-dc",
                ["source_host_id"] = 1, ["domain_id"] = 1, ["event_record_id"] = i + 1, ["provider_name"] = "Microsoft-Windows-Security-Auditing",
                ["time_created_utc"] = Start.AddSeconds(i).ToString("O"), ["event_data_json"] = data };
        }).ToArray();
    }

    [Theory]
    [InlineData("brute", 22, "authentication.session.failed")]
    [InlineData("spray", 30, "authentication.session.failed")]
    [InlineData("admin", 4, "group.member.added")]
    [InlineData("kerberos", 0, "authentication.kerberos.service_ticket.requested")]
    [InlineData("disabled", 1, "authentication.session.failed")]
    [InlineData("task", 2, "scheduled_task.created")]
    public async Task Attack_cohorts_reach_normalization_assembly_and_dispatch_without_database(string scenario, int ordinaryCount, string actionKind)
    {
        var cohort = Sources(scenario);
        var candidates = cohort.Select(row => new SemanticProducer.Source(row.Number("id"), row.Number("event_id").ToString(CultureInfo.InvariantCulture), row.Text("channel")!, row.Text("provider_name")!)).ToArray();
        Assert.Equal(ordinaryCount, SemanticProducer.Select(candidates).Jobs.Length);
        Assert.Equal(cohort.Select(x => x.Number("id")), SemanticProducer.Select(candidates, includeContext: true).Jobs.Select(x => x.Id));

        // Builds a data source only; opening a connection or reading credentials is forbidden here.
        await using var runtime = PasswordProducerRuntime.Create(name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? "Host=192.0.2.1;Username=synthetic;Database=synthetic" : null, _ => throw new InvalidOperationException("no_secret_access"));
        var production = new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticRuntimeSettings.InvestigationMode, cohort.Length);
        await using var session = new CohortSession();
        var normalized = new List<SemanticEvent>();
        int actions = 0;
        foreach (var source in cohort)
        {
            var ev = SemanticNormalization.Normalize(source); normalized.Add(ev);
            var identity = source.DeepClone().AsObject();
            identity["server_id"] = 1; identity["log_source_id"] = 1;
            identity["normalized_hash"] = new string('a', 64); identity["migrated_at"] = Start.ToString("O");
            var job = new JsonObject { ["job_id"] = ev.Id().ToString(), ["lease_token"] = "11111111-1111-1111-1111-111111111111", ["job_kind"] = "normalize_event" };
            actions += await production.PersistProcessedEvent(session, ev, identity, job, SemanticEvent.Version, TestContext.Current.CancellationToken);
        }
        Assert.Equal(cohort.Length, session.Normalized.Count);
        Assert.Equal(cohort.Select(x => x.Number("id")), session.Normalized.Select(x => x.Number("source_event_id")));
        Assert.Equal(normalized.Select(x => x.Type), session.DispatchTypes);
        Assert.Equal(normalized.Select(x => x.Id()), session.Completed);
        Assert.Equal(actions, session.ActionKinds.Count);
        Assert.Contains(actionKind, session.ActionKinds);
        Assert.Equal(actions, session.Evidence.Count);
        Assert.All(session.Evidence, id => Assert.Contains(id, normalized.Select(x => x.Id())));

        if (scenario is "brute" or "spray")
        {
            // The production count-rule engine expresses the reference's target/IP aggregate.
            var rule = SemanticCorrelation.Compile(new JsonObject { ["rule_id"] = "synthetic-accept3-brute", ["rule_version"] = 1, ["rule_kind"] = "count",
                ["definition_json"] = new JsonObject { ["type"] = "count", ["inputs"] = new JsonArray("authentication.session.failed"),
                    ["join_roles"] = new JsonArray("source_host", "affected_entity", "source_ip"), ["minimum_count"] = 5, ["window_seconds"] = 600,
                    ["output_relation_kind"] = "authentication.bruteforce.suspected", ["explanation"] = "Synthetic target/IP aggregate" } });
            var relations = rule.Match(normalized);
            if (scenario == "brute") Assert.Equal(Enumerable.Range(1, 20).Select(x => (long)x), Assert.Single(relations).Evidence.Select(x => x.Source));
            else Assert.Empty(relations);
        }
        if (scenario == "disabled") Assert.Equal("0xc0000072", Assert.Single(normalized).Facts.Text("failure_status")?.ToLowerInvariant());
        if (scenario == "kerberos") Assert.Equal(Enumerable.Range(0, 10).Select(i => $"fixture-service-{i}"), normalized.Select(x => x.Facts.Text("service_name")));
    }

    [Theory]
    [InlineData("group.member.added")]
    [InlineData("scheduled_task.created")]
    public async Task Shadow_attack_policy_cannot_publish_a_finding(string kind)
    {
        await using var session = new ShadowSession(kind);
        var scenario = new JsonObject { ["scenario_id"] = session.ScenarioId.ToString(), ["scenario_kind"] = kind };
        var policy = new SemanticPolicy("synthetic", 1, "canonical_action", new(), new string('a', 64), kind, kind, "security_incident", ["source_host"], 300,
            "Synthetic attack", "Synthetic attack", "medium", 25m, 25, false, "Synthetic rationale", 1, [], null);
        var proposal = new SemanticProposal(policy, Guid.NewGuid().ToString(), Start, "fixture-dc", new(), new(), [], [], []);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.PublishFinding(session, proposal, scenario, Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("finding_requires_enabled_observed_result", error.Message);
        Assert.Equal(SemanticRiskSql.publish_enabled_scenario_finding0, Assert.Single(session.Queries));
        Assert.DoesNotContain("insert into findings", session.Queries[0], StringComparison.OrdinalIgnoreCase);
    }

    private sealed class ShadowSession(string kind) : ISemanticSession
    {
        internal readonly Guid ScenarioId = Guid.NewGuid();
        internal readonly List<string> Queries = [];
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Queries.Add(sql);
            return Task.FromResult(new JsonArray(new JsonObject { ["evaluation_mode"] = "shadow", ["conclusion_state"] = "observed",
                ["scenario_id"] = ScenarioId.ToString(), ["scenario_kind"] = kind, ["policy_admitted"] = false }));
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("no_commit");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class CohortSession : ISemanticSession
    {
        internal readonly List<JsonObject> Normalized = [];
        internal readonly List<string> ActionKinds = [], DispatchTypes = [];
        internal readonly List<Guid> Completed = [], Evidence = [];
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            JsonArray rows = [];
            if (sql.StartsWith("with changed as(insert into normalized_events", StringComparison.Ordinal))
                Normalized.Add(new() { ["normalized_event_id"] = values[0]!.ToString(), ["source_event_id"] = (long)values[1]!,
                    ["semantic_sha256"] = Convert.ToHexStringLower((byte[])values[4]!), ["semantic_type"] = (string)values[5]!,
                    ["occurred_at_utc"] = ((DateTimeOffset)values[6]!).ToString("O"), ["roles_json"] = ((JsonObject)values[8]!).DeepClone(),
                    ["facts_json"] = ((JsonObject)values[9]!).DeepClone(), ["quality_json"] = ((JsonObject)values[10]!).DeepClone() });
            else if (sql.StartsWith("select normalized_event_id,semantic_type", StringComparison.Ordinal))
                rows.Add(Normalized.Single(x => x.Number("source_event_id") == (long)values[0]!).DeepClone());
            else if (sql.StartsWith("with changed as(insert into canonical_actions(", StringComparison.Ordinal)) ActionKinds.Add((string)values[1]!);
            else if (sql.StartsWith("with changed as(insert into canonical_action_evidence", StringComparison.Ordinal)) Evidence.Add((Guid)values[1]!);
            else if (sql.StartsWith("select s.rule_id", StringComparison.Ordinal)) DispatchTypes.Add((string)values[0]!);
            else if (sql.StartsWith("with changed as(update semantic_processing_outbox", StringComparison.Ordinal))
            {
                Assert.Equal(Guid.Parse("11111111-1111-1111-1111-111111111111"), values[1]);
                Completed.Add((Guid)values[0]!); rows.Add(new JsonObject { ["job_id"] = values[0]!.ToString() });
            }
            else if (!(sql.StartsWith("select pg_advisory_xact_lock(", StringComparison.Ordinal) ||
                sql.StartsWith("select *,encode(canonical_deduplication_key", StringComparison.Ordinal) ||
                sql.StartsWith("select normalized_event_id from canonical_action_evidence", StringComparison.Ordinal) ||
                sql.StartsWith("with changed as(update canonical_actions action", StringComparison.Ordinal)))
                throw new InvalidOperationException("Unexpected cohort query: " + sql);
            return Task.FromResult(rows);
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("transaction_owned_by_caller");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
