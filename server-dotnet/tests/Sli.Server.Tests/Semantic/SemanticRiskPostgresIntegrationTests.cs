using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Parity: tests/semantic/test_semantic_risk_postgres_integration.py.
public sealed class SemanticRiskPostgresIntegrationTests
{
    private static readonly DateTimeOffset Occurred = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()).AddMinutes(-3);

    [Fact]
    public async Task Scenario_risk_confidence_and_coverage_are_durable_and_independent()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        JsonObject first, second;
        long findingsBefore;
        await using (var db = new NpgsqlConnection(fixture.Pg.ConnectionString))
        {
            await db.OpenAsync(ct);
            var shortRows = await ShortEventAdmissionPostgresTests.SeedAsync(db, ct, eventKinds: [4624, 4672],
                nativeTimestamps: [SemanticJson.Stamp(Occurred), SemanticJson.Stamp(Occurred.AddSeconds(1))],
                nativeFields: new Dictionary<string, string>
                {
                    ["TargetLogonId"] = "0xabc",
                    ["SubjectUserSid"] = "S-1-5-21-100000001-200000002-300000003-1001",
                    ["SubjectLogonId"] = "0xabc",
                });
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, shortRows, ct);
            await using var tx = await db.BeginTransactionAsync(ct);
            var session = new SemanticSession(db, tx);
            Assert.Single(await session.QueryAsync("select 1 from schema_migrations where version=28 and name='semantic_risk_scenarios'", ct));
            findingsBefore = (await session.QueryAsync("select count(*) as value from findings", ct))[0].Number("value");
            var (candidates, evidence) = await Seed(session, shortRows.Select(row => row.EventId), ct);
            var low = Proposal(candidates[0], evidence, strong: false);
            first = await SemanticProduction.PersistProposal(session, low, ct);
            var replay = await SemanticProduction.PersistProposal(session, low, ct);
            AssertAssessment(first, raw: 80, display: 90, coverage: "unavailable", steps: 1, contributions: 1);
            Assert.True(JsonNode.DeepEquals(Assessment(first), Assessment(replay)));

            second = await SemanticProduction.PersistProposal(session, Proposal(candidates[1], evidence, strong: true), ct);
            Assert.Equal(first.Text("scenario_id"), second.Text("scenario_id"));
            AssertAssessment(second, raw: 110, display: 100, coverage: "complete", steps: 2, contributions: 2);
            Assert.Equal("unresolved", second["confidence_factors_json"].Text("identity_resolution"));
            await tx.CommitAsync(ct);
        }

        // Reconnect after commit: assertions must hold for durable rows, not just return values.
        await using (var db = new NpgsqlConnection(fixture.Pg.ConnectionString))
        {
            await db.OpenAsync(ct);
            await using var tx = await db.BeginTransactionAsync(ct);
            var session = new SemanticSession(db, tx);
            Assert.Equal(findingsBefore, (await session.QueryAsync("select count(*) as value from findings", ct))[0].Number("value"));
            var durable = Assert.Single(await session.QueryAsync("select * from semantic_security_scenarios where scenario_kind='authentication.privileged_session' and partition_key='1'", ct))!;
            Assert.True(JsonNode.DeepEquals(Assessment(second), Assessment(durable)));
            Guid scenario = Guid.Parse(second.Text("scenario_id")!);
            Assert.Equal(2, (await session.QueryAsync("select count(*) as value from semantic_scenario_coverage_history where scenario_id=$1", ct, scenario))[0].Number("value"));
            var steps = await session.QueryAsync("select confidence,confidence_factors_json from semantic_scenario_steps where scenario_id=$1 order by confidence_score", ct, scenario);
            Assert.Equal(new[] { "low", "high" }, steps.Select(x => x.Text("confidence")).ToArray());
            Assert.Equal("unresolved", steps[0]!["confidence_factors_json"].Text("identity_resolution"));
            Assert.Equal("exact", steps[1]!["confidence_factors_json"].Text("identity_resolution"));
            await tx.CommitAsync(ct);
        }
        // The canonical database trigger must reject mutation even by the fixture owner.
        await using (var db = new NpgsqlConnection(fixture.Pg.ConnectionString))
        {
            await db.OpenAsync(ct);
            await using var command = new NpgsqlCommand("update semantic_risk_contributions set display_points=1 where policy_id='privileged-session-risk'", db) { CommandTimeout = 0 };
            var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(ct));
            Assert.Equal("P0001", error.SqlState);
            Assert.Contains("immutable", error.MessageText);
        }
    }

    private static JsonObject Assessment(JsonNode row)
    {
        var result = new JsonObject();
        foreach (string key in new[] { "scenario_id", "scenario_status", "risk_class", "raw_score", "display_score", "hard_critical", "confidence", "confidence_score", "coverage_status", "step_count", "evidence_count", "contribution_count" })
            result[key] = row[key]!.DeepClone();
        return result;
    }

    private static void AssertAssessment(JsonObject result, decimal raw, int display, string coverage, int steps, int contributions)
    {
        Assert.Equal("critical", result.Text("risk_class"));
        Assert.True(result.Flag("hard_critical"));
        Assert.Equal(raw, result["raw_score"]!.GetValue<decimal>());
        Assert.Equal(display, result.Number("display_score"));
        Assert.Equal("low", result.Text("confidence"));
        Assert.Equal(coverage, result.Text("coverage_status"));
        Assert.Equal(steps, result.Number("step_count"));
        Assert.Equal(2, result.Number("evidence_count"));
        Assert.Equal(contributions, result.Number("contribution_count"));
    }

    private static SemanticProposal Proposal(Guid candidate, Guid[] evidence, bool strong)
    {
        var policy = new SemanticPolicy("privileged-session-risk", 1, "correlation_candidate", new(), new string('3', 64),
            "authentication.session.has_special_privileges", "authentication.privileged_session", "security_incident", ["session_principal"], 1800,
            "Privileged session requires review", "Strict session identity joined two correlation sources",
            strong ? "high" : "critical", strong ? 30 : 80, strong ? 20 : 90, !strong, strong ? "Risk contribution high" : "Risk contribution low", 2, [], null);
        var factors = new JsonObject
        {
            ["identity_resolution"] = strong ? "exact" : "unresolved", ["state_confirmed"] = strong, ["multi_source_confirmed"] = strong,
            ["sequence_completeness"] = strong ? 100 : 10, ["time_quality"] = strong ? "good" : "poor", ["parser_quality"] = strong ? "good" : "poor"
        };
        return new(policy, candidate.ToString(), Occurred.AddSeconds(1), "1", new() { ["session_principal"] = "1:0xabc" }, factors, evidence, [],
            new(new JsonObject { ["control_id"] = "security-audit-logon", ["coverage_status"] = strong ? "complete" : "unavailable",
                ["reason"] = strong ? "Audit coverage is confirmed" : "Audit coverage is not confirmed", ["observed_at_utc"] = SemanticJson.Stamp(strong ? Occurred.AddMinutes(1) : Occurred) }));
    }

    private static async Task<(Guid[] Candidates, Guid[] Evidence)> Seed(ISemanticSession session, IEnumerable<long> sourceIds, CancellationToken ct)
    {
        // Correlate attested short rows through the same source view, normalizer
        // and persisted evidence identity as the semantic worker.
        var events = new List<SemanticEvent>();
        foreach (long source in sourceIds)
        {
            var stored = Assert.Single(await session.QueryAsync(
                "select *,encode(normalized_hash,'hex') as normalized_hash from public.semantic_event_source355 where id=$1", ct, source))!.AsObject();
            var identity = SemanticProduction.SourceIdentity(stored);
            var ev = SemanticNormalization.Normalize(SemanticProduction.HydrateSource(source, identity, stored));
            events.Add(ev);
            await SemanticProduction.PersistNormalized(session, ev, identity, SemanticEvent.Version, ct);
        }
        var candidates = new List<Guid>();
        foreach (string ruleId in new[] { "risk-session-rule-low", "risk-session-rule-high" })
        {
            var definition = JsonNode.Parse("""
                {"type":"all_of","inputs":["authentication.session.created","authentication.privileged_session.created"],
                 "join_roles":["source_host","session_principal"],"window_seconds":900,"output_relation_kind":"authentication.session.has_special_privileges",
                 "confidence":"high","explanation":"Strict session identity joined two events"}
                """)!.AsObject();
            var rule = SemanticCorrelation.Compile(new JsonObject { ["rule_id"] = ruleId, ["rule_version"] = 1, ["rule_kind"] = "all_of", ["definition_json"] = definition });
            var relation = Assert.Single(rule.Match(events));
            Guid candidate = Guid.NewGuid(); candidates.Add(candidate);
            await session.QueryAsync("insert into semantic_correlation_rules(rule_id,rule_version,rule_kind,lifecycle_status,definition_json,definition_sha256) values($1,1,'all_of','test',$2,$3)", ct, ruleId, definition, Convert.FromHexString(rule.Sha));
            await session.QueryAsync("""
                insert into semantic_correlation_candidates(candidate_id,rule_id,rule_version,relation_kind,candidate_key,partition_key,window_start_utc,window_end_utc,confidence,explanation,evidence_count)
                values($1,$2,1,$3,$4,'1',$5,$6,$7,$8,2)
                """, ct, candidate, ruleId, relation.Kind, Convert.FromHexString(SemanticProposal.HashText(relation.Key)), Occurred, Occurred.AddSeconds(1), relation.Confidence, relation.Explanation);
            for (int i = 0; i < relation.Evidence.Count; i++)
                await session.QueryAsync("insert into semantic_correlation_candidate_evidence(candidate_id,normalized_event_id,evidence_order) values($1,$2,$3)", ct, candidate, relation.Evidence[i].Id(), i);
        }
        return (candidates.ToArray(), events.Select(x => x.Id()).ToArray());
    }
}
