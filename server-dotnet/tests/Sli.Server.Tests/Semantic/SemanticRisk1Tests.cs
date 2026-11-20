using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Risk;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticRisk1Tests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 5, 0, 0, TimeSpan.Zero);
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static JsonObject Factors(bool weak = false) => new()
    {
        ["identity_resolution"] = weak ? "unresolved" : "exact", ["state_confirmed"] = false,
        ["multi_source_confirmed"] = !weak, ["sequence_completeness"] = weak ? 10 : 100,
        ["time_quality"] = weak ? "poor" : "good", ["parser_quality"] = weak ? "poor" : "good"
    };

    private static JsonObject Coverage(string status, int minute = 0, string control = "security-audit-logon") => new()
    {
        ["control_id"] = control, ["coverage_status"] = status, ["reason"] = "Synthetic control observation",
        ["observed_at_utc"] = SemanticJson.Stamp(Now.AddMinutes(minute))
    };

    private static SemanticProposal Proposal(int id = 1, int minute = 0, bool weak = false,
        string risk = "high", bool hard = false, string policyId = "privileged-session-policy", int points = 50)
    {
        var definition = new JsonObject
        {
            ["type"] = "scenario_policy", ["source_selector"] = new JsonObject { ["relation_kind"] = "privileged-session" },
            ["strict_roles"] = new JsonArray("session_principal"), ["scenario_kind"] = "authentication.privileged_session",
            ["result_class"] = "security_incident", ["merge_window_seconds"] = 1800,
            ["title"] = "Privileged session requires review", ["explanation"] = "Strict host and session identity matched",
            ["risk"] = new JsonObject { ["class"] = risk, ["raw_score"] = points.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["display_points"] = points, ["hard_critical"] = hard, ["rationale"] = "Exact privileged session correlation" }
        };
        var policy = SemanticPolicy.Compile(new JsonObject { ["policy_id"] = policyId, ["policy_version"] = 1,
            ["source_kind"] = "correlation_candidate", ["definition_json"] = definition });
        return new(policy, $"00000000-0000-0000-0000-{id:000000000000}", Now.AddMinutes(minute), "dc-1",
            new() { ["session_principal"] = "dc-1:0xabc" }, Factors(weak),
            [Guid.Parse($"10000000-0000-0000-0000-{id:000000000000}")], [], []);
    }

    [Fact]
    public void Coverage_is_explicit_and_latest_observation_wins()
    {
        Assert.Equal("unknown", SemanticProduction.CoverageStatus([]));
        Assert.Equal("unavailable", SemanticProduction.CoverageStatus(new(Coverage("unavailable"))));
        Assert.Equal("complete", SemanticProduction.CoverageStatus(new(Coverage("unavailable"), Coverage("complete", 1))));
        Assert.Equal("complete", SemanticProduction.CoverageStatus(new(Coverage("complete", 1), Coverage("unavailable"))));
        Assert.Equal("partial", SemanticProduction.CoverageStatus(new(Coverage("complete"), Coverage("unavailable", control: "directory-audit"))));
    }

    [Fact]
    public async Task Confidence_uses_evidence_quality_without_reducing_hard_critical_risk()
    {
        var p = Proposal(weak: true, risk: "critical", hard: true);
        p.Coverage.Add(Coverage("unavailable"));
        var result = await SemanticProduction.PersistProposal(new ScenarioSession(p), p, Ct);
        Assert.Equal("low", result.Text("confidence"));
        Assert.Equal(2, result.Number("confidence_score"));
        Assert.Equal("critical", result.Text("risk_class"));
        Assert.True(result.Flag("hard_critical"));
    }

    [Fact]
    public async Task Repeated_contribution_is_idempotent_and_conflicting_source_is_rejected()
    {
        var p = Proposal(); var session = new ScenarioSession(p);
        await SemanticProduction.PersistProposal(session, p, Ct);
        var result = await SemanticProduction.PersistProposal(session, p, Ct);
        Assert.Equal(50m, result["raw_score"]!.GetValue<decimal>());
        Assert.Equal(50, result.Number("display_score"));
        Assert.Equal(1, result.Number("step_count"));
        Assert.Equal(1, result.Number("contribution_count"));
        session.Contributions[p.Contribution]["correlation_candidate_id"] = Proposal(2).SourceId;
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistProposal(session, p, Ct));
        Assert.Equal("risk_contribution_replay_conflict", error.Message);
    }

    [Fact]
    public async Task Different_policies_do_not_double_count_the_same_evidence()
    {
        var p = Proposal(); var session = new ScenarioSession(p);
        await SemanticProduction.PersistProposal(session, p, Ct);
        var second = Proposal(risk: "critical", hard: true, policyId: "second-policy", points: 60);
        var result = await SemanticProduction.PersistProposal(session, second, Ct);
        Assert.Equal(60m, result["raw_score"]!.GetValue<decimal>());
        Assert.Equal(60, result.Number("display_score"));
        Assert.Equal("critical", result.Text("risk_class"));
        Assert.True(result.Flag("hard_critical"));
        Assert.Equal(2, result.Number("contribution_count"));
    }

    [Theory]
    [InlineData(10)]
    [InlineData(30)]
    public async Task Scenario_merge_preserves_times_and_accepts_the_window_boundary(int minute)
    {
        var p = Proposal(); var session = new ScenarioSession(p);
        await SemanticProduction.PersistProposal(session, p, Ct);
        session.Source = Proposal(2, minute);
        var result = await SemanticProduction.PersistProposal(session, session.Source, Ct);
        Assert.Equal(Now, SigmaProjection.At(result, "first_seen_utc"));
        Assert.Equal(Now.AddMinutes(minute), SigmaProjection.At(result, "last_seen_utc"));
        Assert.Equal(100, result.Number("display_score"));
        Assert.Equal("high", result.Text("confidence"));
        Assert.Equal(80, result.Number("confidence_score"));
    }

    [Theory]
    [InlineData("partition")]
    [InlineData("session")]
    [InlineData("window")]
    public async Task Scenario_merge_rejects_wrong_identity_and_exceeded_window_before_writing(string change)
    {
        var p = Proposal(); var session = new ScenarioSession(p);
        await SemanticProduction.PersistProposal(session, p, Ct);
        var second = Proposal(2, change == "window" ? 31 : 10);
        if (change == "partition") second = second with { Partition = "dc-2" };
        if (change == "session") second.Strict["session_principal"] = "dc-1:0xdef";
        session.Source = second;
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistProposal(session, second, Ct));
        Assert.Equal(change == "window" ? "scenario_merge_window_exceeded" : "scenario_identity_replay_conflict", error.Message);
        Assert.Single(session.Contributions);
    }

    [Fact]
    public async Task Scenario_confidence_is_limited_by_the_weakest_mandatory_step()
    {
        var p = Proposal(); var session = new ScenarioSession(p);
        await SemanticProduction.PersistProposal(session, p, Ct);
        session.Source = Proposal(2, 10, weak: true);
        var result = await SemanticProduction.PersistProposal(session, session.Source, Ct);
        Assert.Equal("low", result.Text("confidence"));
        Assert.Equal(2, result.Number("confidence_score"));
        Assert.Equal(100, result.Number("display_score"));
    }

    [Fact]
    public void Hard_critical_contract_rejects_inconsistent_class()
    {
        Assert.Equal("risk_policy_bounds_invalid", Assert.Throws<InvalidDataException>(() => Proposal(hard: true)).Message);
    }

    private static JsonObject Snapshot() => new()
    {
        ["captured_at_utc"] = SemanticJson.Stamp(Now.AddHours(1)),
        ["catalog_completeness"] = new JsonObject { ["entry_count"] = 10, ["fully_classified"] = 10, ["schema_v2_ready"] = 10 },
        ["collection_freshness"] = new JsonObject { ["max_age_seconds"] = 60, ["budget_seconds"] = 1800, ["complete"] = true },
        ["channel_availability"] = new JsonObject { ["required"] = new JsonArray("dc-1|Security"),
            ["available"] = new JsonArray("dc-1|Security"), ["required_count"] = 1, ["available_count"] = 1, ["complete"] = true },
        ["window_closure"] = new JsonObject { ["window_end_utc"] = SemanticJson.Stamp(Now),
            ["descriptor_close_timeout_seconds"] = 900, ["allowed_lateness_seconds"] = 60,
            ["close_deadline_utc"] = SemanticJson.Stamp(Now.AddSeconds(960)), ["closed"] = true }
    };

    [Fact]
    public void Negative_conclusion_requires_all_four_captured_values()
    {
        var complete = Snapshot();
        Assert.True(SemanticProduction.SupportsNegativeConclusion(complete));
        Assert.Equal("not_found", SemanticProduction.ResolveConclusionState("not_found", complete));
        var captured = PasswordRiskCompleteness.Capture(Now.AddHours(1), Now);
        foreach (string key in new[] { "catalog_completeness", "collection_freshness", "channel_availability", "window_closure" })
            Assert.IsType<JsonObject>(captured[key]);

        var incomplete = Snapshot();
        incomplete["catalog_completeness"]!["fully_classified"] = 9;
        incomplete["collection_freshness"]!["max_age_seconds"] = null;
        incomplete["collection_freshness"]!["complete"] = false;
        incomplete["channel_availability"]!["available"] = new JsonArray();
        incomplete["channel_availability"]!["complete"] = false;
        incomplete["window_closure"]!["descriptor_close_timeout_seconds"] = null;
        incomplete["window_closure"]!["close_deadline_utc"] = null;
        incomplete["window_closure"]!["closed"] = false;
        Assert.False(SemanticProduction.SupportsNegativeConclusion(incomplete));
        Assert.Equal("not_checked", SemanticProduction.ResolveConclusionState("not_found", incomplete));
        Assert.Equal("observed", SemanticProduction.ResolveConclusionState("observed", incomplete));
        Assert.Equal("not_checked", SemanticProduction.ResolveConclusionState("not_checked", complete));
    }

    [Theory]
    [InlineData("classification")]
    [InlineData("schema")]
    [InlineData("freshness_missing")]
    [InlineData("freshness_stale")]
    [InlineData("channels_missing")]
    [InlineData("channels_empty")]
    [InlineData("timeout")]
    [InlineData("lateness")]
    [InlineData("deadline")]
    [InlineData("window_open")]
    public void Each_incomplete_measurement_independently_prevents_a_negative_conclusion(string missing)
    {
        var snapshot = Snapshot();
        switch (missing)
        {
            case "classification": snapshot["catalog_completeness"]!["fully_classified"] = 9; break;
            case "schema": snapshot["catalog_completeness"]!["schema_v2_ready"] = 9; break;
            case "freshness_missing": snapshot["collection_freshness"]!["max_age_seconds"] = null; break;
            case "freshness_stale": snapshot["collection_freshness"]!["max_age_seconds"] = 1801; break;
            case "channels_missing": snapshot["channel_availability"]!["available"] = new JsonArray(); break;
            case "channels_empty":
                snapshot["channel_availability"]!["required"] = new JsonArray();
                snapshot["channel_availability"]!["available"] = new JsonArray(); break;
            case "timeout": snapshot["window_closure"]!["descriptor_close_timeout_seconds"] = null; break;
            case "lateness": snapshot["window_closure"]!["allowed_lateness_seconds"] = null; break;
            case "deadline": snapshot["window_closure"]!["close_deadline_utc"] = null; break;
            case "window_open": snapshot["window_closure"]!["closed"] = false; break;
            default: throw new InvalidOperationException("Unknown measurement");
        }
        Assert.False(SemanticProduction.SupportsNegativeConclusion(snapshot));
        Assert.Equal("not_checked", SemanticProduction.ResolveConclusionState("not_found", snapshot));
        Assert.Equal("observed", SemanticProduction.ResolveConclusionState("observed", snapshot));
    }

    // Only the SQL transport is replaced. Production persistence validates replay rows,
    // aggregates contributions/steps, and supplies the resulting scenario update values.
    private sealed class ScenarioSession : ISemanticSession
    {
        private static readonly Guid Id = Guid.Parse("20000000-0000-0000-0000-000000000001");
        private readonly JsonObject scenario;
        internal SemanticProposal Source;
        private readonly Dictionary<string, JsonObject> steps = [];
        private readonly List<JsonObject> coverage = [];
        internal readonly Dictionary<string, JsonObject> Contributions = [];
        internal ScenarioSession(SemanticProposal p)
        {
            Source = p;
            scenario = new() { ["scenario_id"] = Id.ToString(), ["identity_key"] = p.Identity,
                ["scenario_kind"] = p.Policy.Kind, ["result_class"] = p.Policy.Result, ["partition_key"] = p.Partition,
                ["strict_keys_json"] = p.Strict.DeepClone(), ["merge_window_seconds"] = p.Policy.Window,
                ["first_seen_utc"] = SemanticJson.Stamp(p.At), ["last_seen_utc"] = SemanticJson.Stamp(p.At) };
        }
        private static string Key(object? value) => Convert.ToHexStringLower((byte[])value!);
        private static JsonArray Rows(IEnumerable<JsonObject> rows) => new(rows.Select(x => (JsonNode)x.DeepClone()).ToArray());
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] v)
        {
            ct.ThrowIfCancellationRequested(); JsonArray result = [];
            if (sql.StartsWith("select candidate_status,partition_key", StringComparison.Ordinal))
                result = Rows([new() { ["candidate_status"] = "matched", ["partition_key"] = JsonValue.Create(Source.Partition),
                    ["window_start_utc"] = SemanticJson.Stamp(DateTimeOffset.Parse("2026-07-19T00:00:00Z")),
                    ["window_end_utc"] = SemanticJson.Stamp(DateTimeOffset.Parse("2026-07-20T00:00:00Z")) }]);
            else if (sql.StartsWith("select normalized_event_id from semantic_correlation_candidate_evidence", StringComparison.Ordinal))
                result = Rows([new() { ["normalized_event_id"] = Source.Evidence[0].ToString() }]);
            else if (sql.Contains("pg_advisory_xact_lock(")) { }
            else if (sql.StartsWith("select * from semantic_risk_contributions", StringComparison.Ordinal) || sql == SemanticRiskSql.persist_contribution1)
                result = Contributions.TryGetValue(Key(v[0]), out var contribution) ? Rows([contribution]) : [];
            // Return a selected row, including stale/invalid rows, to exercise the .NET validation.
            else if (sql.StartsWith("select * from semantic_security_scenarios", StringComparison.Ordinal)) result = Rows([scenario]);
            else if (sql == SemanticRiskSql.persist_step0)
                steps.TryAdd(Key(v[2]), new() { ["step_id"] = v[0]!.ToString(), ["scenario_id"] = v[1]!.ToString(),
                    ["source_kind"] = v[3]!.ToString(), ["occurred_at_utc"] = SemanticJson.Stamp((DateTimeOffset)v[7]!),
                    ["title"] = v[8]!.ToString(), ["explanation"] = v[9]!.ToString(), ["confidence_factors_json"] = ((JsonObject)v[12]!).DeepClone() });
            else if (sql == SemanticRiskSql.persist_step1) result = Rows([steps[Key(v[0])]]);
            else if (sql.StartsWith("insert into semantic_scenario_evidence", StringComparison.Ordinal)) { }
            else if (sql == SemanticRiskSql.persist_contribution0)
                Contributions.TryAdd(Key(v[2]), new() { ["contribution_id"] = v[0]!.ToString(), ["scenario_id"] = v[1]!.ToString(),
                    ["source_kind"] = v[3]!.ToString(), ["canonical_action_id"] = v[4]?.ToString(),
                    ["correlation_candidate_id"] = v[5]?.ToString(), ["control_reference"] = v[6]?.ToString(),
                    ["policy_id"] = v[7]!.ToString(), ["policy_version"] = (int)v[8]!, ["policy_sha256"] = Key(v[9]),
                    ["risk_class"] = v[10]!.ToString(), ["raw_score"] = (decimal)v[11]!, ["display_points"] = (int)v[12]!,
                    ["hard_critical"] = (bool)v[13]!, ["rationale"] = v[14]!.ToString() });
            else if (sql == SemanticRiskSql.persist_coverage0)
                coverage.Add(new() { ["control_id"] = v[3]!.ToString(), ["coverage_status"] = v[4]!.ToString(),
                    ["reason"] = v[5]!.ToString(), ["observed_at_utc"] = SemanticJson.Stamp((DateTimeOffset)v[6]!) });
            else if (sql == SemanticRiskSql.refresh_scenario0) result = Rows(Contributions.Values);
            else if (sql == SemanticRiskSql.refresh_scenario1) result = Rows(steps.Values);
            else if (sql == SemanticRiskSql.refresh_scenario2) result = Rows(coverage);
            else if (sql == SemanticRiskSql.refresh_scenario3)
                result = Rows([new() { ["first_seen_utc"] = SemanticJson.Stamp(steps.Values.Min(x => SigmaProjection.At(x, "occurred_at_utc"))),
                    ["last_seen_utc"] = SemanticJson.Stamp(steps.Values.Max(x => SigmaProjection.At(x, "occurred_at_utc"))),
                    ["step_count"] = steps.Count, ["evidence_count"] = steps.Count, ["expected_evidence_count"] = steps.Count,
                    ["contribution_count"] = Contributions.Count }]);
            else if (sql == SemanticRiskSql.refresh_scenario4)
            {
                scenario["first_seen_utc"] = SemanticJson.Stamp((DateTimeOffset)v[0]!); scenario["last_seen_utc"] = SemanticJson.Stamp((DateTimeOffset)v[1]!);
                scenario["risk_class"] = v[2]!.ToString(); scenario["raw_score"] = (decimal)v[3]!;
                scenario["display_score"] = (int)v[4]!; scenario["hard_critical"] = (bool)v[5]!;
                scenario["confidence"] = v[6]!.ToString(); scenario["confidence_score"] = (int)v[7]!;
                scenario["confidence_factors_json"] = ((JsonObject)v[8]!).DeepClone(); scenario["coverage_status"] = v[9]!.ToString();
                scenario["step_count"] = (int)v[10]!; scenario["contribution_count"] = (int)v[12]!;
            }
            else if (sql.Contains("to_regclass('public.entity_identity_scenario_supersessions_v2')")) result = Rows([new() { ["available"] = false }]);
            else throw new InvalidOperationException("Unexpected scenario SQL");
            return Task.FromResult(result);
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("caller_owns_transaction");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
