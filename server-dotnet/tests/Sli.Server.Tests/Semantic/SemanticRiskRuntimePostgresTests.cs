using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Parity: tests/semantic/test_semantic_risk_runtime_postgres_integration.py.
public sealed class SemanticRiskRuntimePostgresTests
{
    private const string Candidate = "00000000-0000-4000-8000-000000950001";
    private static readonly DateTimeOffset Occurred = new(2026, 7, 19, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Test_and_shadow_risk_are_leased_idempotent_and_findings_free()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        // The clean install includes production policies. Only this disposable
        // cluster is put into the development worker's required test/shadow scope.
        await PostCollectionPostgres.Sql(owner, "update semantic_risk_policies set lifecycle_status='disabled' where lifecycle_status='enabled'", ct);
        long findingsBefore = await Count(owner, "findings", ct);
        await SeedCandidate(owner, ct);
        await SeedPolicy(owner, false, ct);
        await using var runtime = Sli.Server.Semantic.Password.PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        await using (var tx = await worker.BeginTransactionAsync(ct)) {
            var session = new SemanticSession(worker, tx);
            Assert.Equal(1, await SemanticProduction.EnqueueRiskSource(session, "correlation_candidate", Candidate, ct, development: true));
            Assert.Equal(1, await SemanticProduction.EnqueueRiskSource(session, "correlation_candidate", Candidate, ct, development: true));
            await tx.CommitAsync(ct);
        }
        Assert.Equal(1, await Count(owner, "semantic_risk_evaluation_jobs", ct));

        // Exercise the actual leasing SQL and its concurrent skip-locked path.
        await using (var lease = await worker.BeginTransactionAsync(ct)) {
            Guid token = Guid.NewGuid();
            var claimed = Assert.IsType<JsonObject>(Assert.Single(await new SemanticSession(worker, lease).QueryAsync(SemanticProductionSql.RiskClaim0, ct, 1, token, 300)));
            Assert.Equal("leased", claimed.Text("evaluation_status"));
            Assert.Equal(token.ToString(), claimed.Text("lease_token"));
            Assert.Equal(1L, claimed.Number("attempt_count"));
            Assert.NotNull(claimed["heartbeat_at"]); Assert.NotNull(claimed["lease_until"]);
            await using var other = await runtime.OpenAsync(ct);
            await using var otherTx = await other.BeginTransactionAsync(ct);
            Assert.Empty(await new SemanticSession(other, otherTx).QueryAsync(SemanticProductionSql.RiskClaim0, ct, 1, Guid.NewGuid(), 300));
            await lease.RollbackAsync(ct); // Leave the same job for the native worker.
        }

        var test = await RunWorker(fixture, 1, ct);
        Assert.Equal(1L, test["modes"].Number("test"));
        Assert.Equal(1L, test.Number("completed"));
        Assert.Equal(0, await Count(owner, "semantic_security_scenarios", ct));
        await using (var result = new NpgsqlCommand("select evaluation_mode,scenario_id from semantic_risk_evaluation_results", owner))
        await using (var rows = await result.ExecuteReaderAsync(ct)) {
            Assert.True(await rows.ReadAsync(ct)); Assert.Equal("test", rows.GetString(0)); Assert.True(rows.IsDBNull(1));
            Assert.False(await rows.ReadAsync(ct));
        }

        await PostCollectionPostgres.Sql(owner, "update semantic_risk_policies set lifecycle_status='shadow' where policy_id='runtime-privileged-risk'", ct);
        await RecordControl(owner, Occurred, "integration:audit-policy", ct);
        await SeedPolicy(owner, true, ct);
        var shadow = await RunWorker(fixture, 4, ct);
        Assert.Equal(2L, shadow["modes"].Number("shadow"));
        Assert.Equal(2L, shadow.Number("completed"));
        Assert.Equal(findingsBefore, await Count(owner, "findings", ct));
        Assert.Equal(3, await Count(owner, "semantic_risk_evaluation_results", ct));
        await AssertScenarios(owner, ct);

        // Same source and mode never creates another evaluation or contribution.
        var replay = await RunWorker(fixture, 4, ct);
        Assert.Equal(0L, replay.Number("completed"));
        Assert.Equal(3, await Count(owner, "semantic_risk_evaluation_jobs", ct));
        await RecordControl(owner, Occurred.AddMinutes(2), "integration:audit-policy:later", ct);
        var later = await RunWorker(fixture, 1, ct);
        Assert.Equal(1L, later.Number("completed"));
        Assert.Equal(4, await Count(owner, "semantic_risk_evaluation_results", ct));
        await AssertScenarios(owner, ct);
        Assert.Equal(3, await Count(owner, "semantic_risk_contributions", ct));
        Assert.Equal(findingsBefore, await Count(owner, "findings", ct));
        Assert.Equal(0, await Count(owner, "semantic_finding_publications", ct));
        await using (var jobs = new NpgsqlCommand("select count(*) from semantic_risk_evaluation_jobs where evaluation_status<>'completed' or lease_token is not null or lease_until is not null or last_error_code is not null", owner))
            Assert.Equal(0L, (long)(await jobs.ExecuteScalarAsync(ct))!);

        await using var mutation = new NpgsqlCommand("update semantic_risk_policies set definition_json='{}'::jsonb where policy_id='runtime-privileged-risk'", owner);
        var immutable = await Assert.ThrowsAsync<PostgresException>(() => mutation.ExecuteNonQueryAsync(ct));
        Assert.Contains("immutable", immutable.MessageText);
    }

    private static async Task AssertScenarios(NpgsqlConnection db, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select result_class,risk_class,hard_critical,coverage_status,evidence_count from semantic_security_scenarios order by result_class", db);
        await using var rows = await command.ExecuteReaderAsync(ct);
        foreach (var (kind, evidence) in new[] { ("control_gap", 0), ("security_incident", 2) }) {
            Assert.True(await rows.ReadAsync(ct)); Assert.Equal(kind, rows.GetString(0)); Assert.Equal("critical", rows.GetString(1));
            Assert.True(rows.GetBoolean(2)); Assert.Equal("unavailable", rows.GetString(3)); Assert.Equal(evidence, rows.GetInt32(4));
        }
        Assert.False(await rows.ReadAsync(ct));
    }

    private static async Task<long> Count(NpgsqlConnection db, string table, CancellationToken ct)
    {
        // Table names are constants supplied only by this test.
        await using var command = new NpgsqlCommand("select count(*) from " + table, db);
        return (long)(await command.ExecuteScalarAsync(ct))!;
    }

    private static async Task SeedPolicy(NpgsqlConnection db, bool gap, CancellationToken ct)
    {
        var definition = JsonNode.Parse("""
            {"type":"scenario_policy","source_selector":{"relation_kind":"authentication.session.has_special_privileges"},
             "scenario_kind":"authentication.privileged_session","result_class":"security_incident","strict_roles":["session_principal"],
             "merge_window_seconds":1800,"title":"Privileged session","explanation":"Exact host and session identity matched",
             "expected_evidence_count":2,"required_controls":["security-audit-logon"],
             "risk":{"class":"critical","raw_score":"80","display_points":90,"hard_critical":true,"rationale":"Privileged session"}}
            """)!.AsObject();
        if (gap) {
            definition["source_selector"] = new JsonObject { ["control_id"] = "security-audit-logon" };
            definition["scenario_kind"] = "control.audit.unavailable"; definition["result_class"] = "control_gap";
            definition["strict_roles"] = new JsonArray(); definition["title"] = "Audit control gap";
            definition["explanation"] = "Required audit coverage is unavailable"; definition["expected_evidence_count"] = 1;
            definition["risk"] = new JsonObject { ["class"] = "critical", ["raw_score"] = "70", ["display_points"] = 70, ["hard_critical"] = true, ["rationale"] = "Critical control gap" };
        }
        await using var tx = await db.BeginTransactionAsync(ct);
        var session = new SemanticSession(db, tx);
        string id = gap ? "runtime-audit-gap" : "runtime-privileged-risk", source = gap ? "control_health" : "correlation_candidate";
        await session.QueryAsync("insert into semantic_risk_policies(policy_id,policy_version,source_kind,definition_json,definition_sha256) values($1,1,$2,$3,$4)", ct, id, source, definition, Convert.FromHexString(SemanticJson.Hash(definition)));
        await session.QueryAsync("insert into semantic_risk_policy_subscriptions(policy_id,policy_version,source_kind,selector_value,definition_sha256) select policy_id,policy_version,source_kind,$2,definition_sha256 from semantic_risk_policies where policy_id=$1", ct, id, gap ? "security-audit-logon" : "authentication.session.has_special_privileges");
        foreach (string status in gap ? new[] { "validated", "test", "shadow" } : new[] { "validated", "test" })
            await session.QueryAsync("update semantic_risk_policies set lifecycle_status=$2 where policy_id=$1", ct, id, status);
        await tx.CommitAsync(ct);
    }

    private static async Task RecordControl(NpgsqlConnection db, DateTimeOffset at, string reference, CancellationToken ct)
    {
        await using var tx = await db.BeginTransactionAsync(ct);
        await new SemanticSession(db, tx).QueryAsync("""
            insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,coverage_status,reason,observed_at_utc,source_reference)
            values($1,sha256(convert_to($2,'UTF8')),'security-audit-logon','1','unavailable',$3,$4,$2)
            """, ct, Guid.NewGuid(), reference, "Audit policy confirmation is unavailable", at);
        await tx.CommitAsync(ct);
    }

    private static async Task SeedCandidate(NpgsqlConnection db, CancellationToken ct)
    {
        await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db, tx);
        var events = new List<SemanticEvent>();
        foreach (int eventId in new[] { 4624, 4672 }) {
            int ordinal = events.Count; long id = 950001 + ordinal;
            var source = new JsonObject {
                ["id"] = id, ["event_id"] = eventId, ["server_id"] = 1, ["domain_id"] = 1, ["log_source_id"] = 1,
                ["channel"] = "Security", ["computer"] = "dc.example.test", ["provider_name"] = "Microsoft-Windows-Security-Auditing",
                ["time_created_utc"] = SemanticJson.Stamp(Occurred.AddSeconds(ordinal)), ["migrated_at"] = SemanticJson.Stamp(Occurred),
                ["normalized_hash"] = new string('a', 64), ["event_data_json"] = new JsonObject {
                    [eventId == 4624 ? "TargetUserSid" : "SubjectUserSid"] = "S-1-5-21-100000001-200000002-300000003-400",
                    [eventId == 4624 ? "TargetLogonId" : "SubjectLogonId"] = "0xabc" }
            };
            var ev = SemanticNormalization.Normalize(source); events.Add(ev); source.Remove("event_data_json");
            await session.QueryAsync("""
                insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,processing_status,
                    source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,source_ingested_at,roles_json,facts_json,quality_json,source_identity_json)
                values($1,$2,1,'windows.named-eventdata',$3,'normalized',$4,$5,$6,$7,$8,$9,$10,$11,$12)
                """, ct, ev.Id(), (int)id, SemanticEvent.Version, Convert.FromHexString(new string('a', 64)), Convert.FromHexString(ev.Sha), ev.Type, ev.At, Occurred, ev.Roles, ev.Facts, ev.Quality, source);
        }
        var rule = new SemanticCorrelation("runtime-risk-source-rule", 1, "all_of",
            ["authentication.session.created", "authentication.privileged_session.created"], ["source_host", "session_principal"],
            "source_host", false, "first_admissible", 900, 2, "authentication.session.has_special_privileges", "high", "Exact host and session identity matched", new string('b', 64));
        var relation = Assert.Single(rule.Match(events));
        await session.QueryAsync("insert into semantic_correlation_rules(rule_id,rule_version,rule_kind,lifecycle_status,definition_json,definition_sha256) values($1,1,'all_of','test',$2,$3)", ct,
            rule.Id, JsonNode.Parse("""{"type":"all_of","inputs":["authentication.session.created","authentication.privileged_session.created"],"window_seconds":900} """), Convert.FromHexString(rule.Sha));
        await session.QueryAsync("""
            insert into semantic_correlation_candidates(candidate_id,rule_id,rule_version,relation_kind,candidate_status,candidate_key,partition_key,window_start_utc,window_end_utc,confidence,explanation,evidence_count)
            values($1,$2,1,$3,'matched',sha256('synthetic-candidate'::bytea),'1',$4,$5,$6,$7,2)
            """, ct, Guid.Parse(Candidate), rule.Id, relation.Kind, Occurred, Occurred.AddSeconds(1), relation.Confidence, relation.Explanation);
        for (int i = 0; i < events.Count; i++)
            await session.QueryAsync("insert into semantic_correlation_candidate_evidence(candidate_id,normalized_event_id,evidence_order) values($1,$2,$3)", ct, Guid.Parse(Candidate), events[i].Id(), i);
        await tx.CommitAsync(ct);
    }

    private static async Task<JsonObject> RunWorker(SqlPostgresFixture fixture, int limit, CancellationToken ct)
    {
        var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet") {
            UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = fixture.Pg.Root
        };
        foreach (string key in info.Environment.Keys.Where(k => k.StartsWith("ADLOG_", StringComparison.OrdinalIgnoreCase)
            || k.StartsWith("SLI", StringComparison.OrdinalIgnoreCase) || k.StartsWith("PG", StringComparison.OrdinalIgnoreCase)
            || k.StartsWith("ConnectionStrings", StringComparison.OrdinalIgnoreCase)).ToArray()) info.Environment.Remove(key);
        foreach (string arg in new[] { typeof(Program).Assembly.Location, "semantic-worker", "--once", "--limit", limit.ToString() }) info.ArgumentList.Add(arg);
        info.Environment["ADLOG_SEMANTIC_WORKER_DSN"] = fixture.Dsn("sli_semantic_login");
        info.Environment["ADLOG_DATA_DIR"] = fixture.Pg.Root;
        foreach (string stage in new[] { "NORMALIZATION", "ASSEMBLY", "CORRELATION", "RISK_ENGINE" }) info.Environment["ADLOG_SEMANTIC_" + stage + "_ENABLED"] = "true";
        using var process = Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync(ct); var stderr = process.StandardError.ReadToEndAsync(ct);
        try { await process.WaitForExitAsync(ct); }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
        string text = await stdout, errors = await stderr;
        Assert.True(process.ExitCode == 0, errors + text);
        Assert.Empty(errors);
        var result = JsonNode.Parse(text.Trim())!.AsObject();
        Assert.Equal(0L, result.Number("failed")); Assert.Equal(0L, result.Number("findings_created"));
        return result;
    }
}
