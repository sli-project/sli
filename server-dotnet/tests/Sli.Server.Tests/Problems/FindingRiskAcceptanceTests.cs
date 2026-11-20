using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Problems;

// Remaining vectors from tests/semantic/test_finding_risk_acceptance.py.
public sealed class FindingRiskAcceptanceTests
{
    static readonly DateTimeOffset Now = new(2026, 10, 7, 0, 0, 0, TimeSpan.Zero);
    const string Actor = "fixture-analyst";
    sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    static JsonObject Body(DateTimeOffset now) => new() { ["action"] = "create", ["reason"] = "Fixture decision",
        ["responsible_user_id"] = 12, ["expires_at"] = now.AddDays(1).ToString("O") };

    public static IEnumerable<object[]> InvalidInputs()
    {
        yield return ["reason", JsonValue.Create(new string('x', 2001))!.ToJsonString(), "reason_required"];
        yield return ["expires_at", "\"2026-10-06T00:00:00+00:00\"", "invalid_expiry"];
        yield return ["expires_at", "\"2027-01-06T00:00:00+00:00\"", "invalid_expiry"];
        yield return ["expires_at", "\"2026-10-08\"", "invalid_expiry"];
        yield return ["responsible_user_id", "1.5", "invalid_responsible"];
        yield return ["responsible_user_id", "0", "invalid_responsible"];
        foreach (string action in new[] { "null", "[]", "{}", "\"unknown\"" }) yield return ["action", action, "invalid_action"];
    }

    [Theory, MemberData(nameof(InvalidInputs))]
    public async Task InvalidInputIsRejectedBeforeStorage(string field, string json, string code)
    {
        var body = Body(Now); body[field] = JsonNode.Parse(json);
        Assert.Equal(code, Assert.Throws<ProblemException>(() => RiskInput.Parse(body, Actor, Now)).Code);
        // Exercise the HTTP boundary as well; the invalid field must not reach a writer.
        await using var f = await ProblemEndpointTests.Fixture.Start(clock: new Clock());
        var response = await f.Send("POST", "/api/findings/7/risk-acceptance", body.ToJsonString());
        Assert.Equal(400, response.Status); Assert.Equal(code, response.Json["error"]!.GetValue<string>());
        Assert.Equal(0, f.Repo.Calls);
    }

    [Theory]
    [InlineData("create")]
    [InlineData("revoke")]
    public async Task BothActionsUseAuthenticatedAuthorInsteadOfForgedBody(string action)
    {
        await using var f = await ProblemEndpointTests.Fixture.Start();
        var body = Body(DateTimeOffset.UtcNow); body["action"] = action; body["id"] = 31;
        body["created_by"] = "forged"; body["changed_by"] = "forged";
        var response = await f.Send("POST", "/api/findings/7/risk-acceptance", body.ToJsonString());
        Assert.Equal(200, response.Status); Assert.Equal("ok", response.Json["status"]!.GetValue<string>());
        Assert.Equal("alice", f.Repo.Risk!.Actor);
    }

    [Theory]
    [InlineData("reason_required", 400)]
    [InlineData("responsible_not_found", 400)]
    [InlineData("invalid_expiry", 400)]
    [InlineData("not_found", 404)]
    [InlineData("risk_already_accepted", 409)]
    public async Task ApiPreservesRiskErrorCodeAndStatus(string code, int status)
    {
        await using var f = await ProblemEndpointTests.Fixture.Start(); f.Repo.Error = code; f.Repo.ErrorStatus = status;
        var response = await f.Send("POST", "/api/findings/7/risk-acceptance", Body(DateTimeOffset.UtcNow).ToJsonString());
        Assert.Equal(status, response.Status); Assert.Equal(code, response.Json["error"]!.GetValue<string>());
    }

    [Fact]
    public async Task ExtraRouteSegmentNeverReachesWriter()
    {
        await using var f = await ProblemEndpointTests.Fixture.Start();
        var response = await f.Send("POST", "/api/findings/7/extra/risk-acceptance", Body(DateTimeOffset.UtcNow).ToJsonString());
        Assert.Equal(400, response.Status); Assert.Equal("invalid_finding_id", response.Json["error"]!.GetValue<string>());
        Assert.Equal(0, f.Repo.Calls);
    }

    [Fact]
    public async Task ApiForwardsFindingAuditCursorAndAcceptedFilter()
    {
        await using var f = await ProblemEndpointTests.Fixture.Start();
        Assert.Equal(200, (await f.Send("GET", "/api/findings/7/risk-audit?before=31", null)).Status);
        Assert.Equal((7L, (long?)31), f.Repo.AuditRequest);
        Assert.Equal(200, (await f.Send("GET", "/api/findings?source=semantic-production&risk=accepted", null)).Status);
        Assert.Equal("accepted", f.Repo.Query!.Risk);
    }

    [Theory]
    [InlineData("GET", "/api/findings/7/risk-audit?before=31", "investigations.view")]
    [InlineData("GET", "/api/findings/risk-responsibles", "investigations.manage")]
    [InlineData("POST", "/api/findings/7/risk-acceptance", "investigations.manage")]
    public async Task RiskRoutesRequireTheirExactCapability(string method, string path, string capability)
    {
        var grant = ProblemEndpointTests.J(new { capability_key = capability, effect = "allow", scope_json = new { kind = "all" } });
        // The reference's outer /api/findings GET gate also requires view.
        var prerequisite = path == "/api/findings/risk-responsibles"
            ? new[] { ProblemEndpointTests.J(new { capability_key = "investigations.view", effect = "allow", scope_json = new { kind = "all" } }) } : [];
        var facts = ProblemEndpointTests.Facts() with { DirectCapabilities = [.. prerequisite, grant], ReportAssignments = [] };
        await using var allowed = await ProblemEndpointTests.Fixture.Start(facts: facts);
        Assert.Equal(200, (await allowed.Send(method, path, method == "POST" ? "{\"action\":\"revoke\",\"id\":31}" : null)).Status);
        await using var denied = await ProblemEndpointTests.Fixture.Start(facts: facts with { DirectCapabilities = prerequisite });
        var response = await denied.Send(method, path, method == "POST" ? "invalid JSON" : null);
        Assert.Equal(403, response.Status); Assert.Equal(capability, response.Json["required_capability"]!.GetValue<string>());
        Assert.Equal(0, denied.Repo.Calls);
    }

    sealed class Connections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }
    static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, db); return await command.ExecuteScalarAsync(ct); }
    static long Id(JsonNode row) => row["id"]!.GetValue<long>();
    static void Timestamp(JsonNode? value, DateTimeOffset expected) => Assert.Equal(expected, DateTimeOffset.Parse(value!.GetValue<string>(), CultureInfo.InvariantCulture));
    static async Task Error(Func<Task<JsonObject>> call, string code, int status = 400)
    { var error = await Assert.ThrowsAsync<ProblemException>(call); Assert.Equal(code, error.Code); Assert.Equal(status, error.Status); }

    [Fact]
    public async Task RealStoragePreservesDecisionsAuditTransactionsExpiryAndPopulation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = await fixture.Pg.OpenAsync(ct);
        var events = await ShortEventAdmissionPostgresTests.SeedAsync(admin, ct, eventKinds: [4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, events, ct);
        Assert.Single(events);
        await Seed(admin, ct);
        var repository = new ProblemRepository(new Connections(fixture), TimeProvider.System);
        DateTimeOffset now = new(DateTimeOffset.UtcNow.Ticks / TimeSpan.TicksPerSecond * TimeSpan.TicksPerSecond, TimeSpan.Zero);
        var body = Body(now); body["created_by"] = "forged";
        RiskInput input = RiskInput.Parse(body, Actor, now);
        await Error(() => repository.RiskAsync(99, input, ct), "not_found", 404);
        foreach (long responsible in new[] { 13L, 999L })
            await Error(() => repository.RiskAsync(7, input with { Responsible = responsible }, ct), "responsible_not_found");
        Assert.Equal(0L, await Scalar(admin, "select count(*) from semantic_suppressions", ct));

        // The expiry can pass between input validation and the INSERT's DB-clock decision.
        var elapsed = Body(now.AddDays(-2));
        await Error(() => repository.RiskAsync(7, RiskInput.Parse(elapsed, Actor, now.AddDays(-2)), ct), "invalid_expiry");
        Assert.Equal(0L, await Scalar(admin, "select count(*) from semantic_suppressions", ct));

        var created = await repository.RiskAsync(7, input, ct); var acceptance = created["acceptance"]!; long id = Id(acceptance);
        Assert.Equal("ok", created["status"]!.GetValue<string>());
        Assert.Equal("risk_acceptance", acceptance["kind"]!.GetValue<string>());
        Assert.Equal("semantic.fixture", acceptance["semantic_type"]!.GetValue<string>());
        Assert.Equal("finding", acceptance["scope_kind"]!.GetValue<string>()); Assert.Equal("7", acceptance["scope_value"]!.GetValue<string>());
        Assert.Equal(7, acceptance["finding_id"]!.GetValue<int>()); Assert.Equal(12, acceptance["responsible_user_id"]!.GetValue<int>());
        Assert.Equal("Fixture decision", acceptance["reason"]!.GetValue<string>()); Assert.Equal(Actor, acceptance["created_by"]!.GetValue<string>());
        Timestamp(acceptance["expires_at"], input.Expires!.Value);
        var audit = Assert.Single(created["risk_audit"]!.AsArray())!;
        Assert.Equal("suppression_create", audit["action"]!.GetValue<string>()); Assert.Equal(Actor, audit["actor"]!.GetValue<string>());
        Assert.Equal(id, Id(audit["details"]!["rule"]!));
        await Error(() => repository.RiskAsync(7, input, ct), "risk_already_accepted", 409);

        var revoke = RiskInput.Parse(new() { ["action"] = "revoke", ["id"] = id, ["changed_by"] = "forged" }, Actor, now);
        await Error(() => repository.RiskAsync(8, revoke, ct), "risk_not_active", 409);
        await Error(() => repository.RiskAsync(7, revoke with { Id = id + 100 }, ct), "risk_not_active", 409);

        // The security-definer trigger can write, but the caller cannot read the audit.
        // Failure of that read must roll back the mutation and trigger's audit together.
        await PostCollectionPostgres.Sql(admin, "revoke select on semantic_control_audit from adlog_user", ct);
        try
        {
            var failure = await Assert.ThrowsAsync<PostgresException>(() => repository.RiskAsync(7, revoke, ct));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, failure.SqlState);
            Assert.Contains("semantic_control_audit", failure.MessageText);
        }
        finally { await PostCollectionPostgres.Sql(admin, "grant select on semantic_control_audit to adlog_user", ct); }
        Assert.Equal("active", await Scalar(admin, "select state from semantic_suppressions where finding_id=7", ct));
        Assert.Equal(1L, await Scalar(admin, "select count(*) from semantic_control_audit where details->'rule'->>'finding_id'='7'", ct));
        var revoked = await repository.RiskAsync(7, revoke, ct);
        Assert.Equal("revoked", revoked["acceptance"]!["state"]!.GetValue<string>()); Assert.Equal(Actor, revoked["acceptance"]!["changed_by"]!.GetValue<string>());
        Timestamp(revoked["acceptance"]!["expires_at"], input.Expires.Value);
        Assert.Equal(2, revoked["risk_audit"]!.AsArray().Count);
        Assert.Equal("suppression_revoked", revoked["risk_audit"]![0]!["action"]!.GetValue<string>());
        await Error(() => repository.RiskAsync(7, revoke, ct), "risk_not_active", 409);
        Assert.Equal(2L, await Scalar(admin, "select count(*) from semantic_control_audit where details->'rule'->>'finding_id'='7'", ct));

        var responsibles = (await repository.ResponsiblesAsync(ct))["items"]!.AsArray();
        Assert.Contains(responsibles, r => Id(r!) == 12 && r!["username"]!.GetValue<string>() == "fixture-owner");
        Assert.DoesNotContain(responsibles, r => Id(r!) == 13);
        Assert.All(responsibles, r => Assert.Equal(new[] { "id", "username" }, r!.AsObject().Select(p => p.Key).Order().ToArray()));

        await repository.RiskAsync(7, input, ct);
        await PostCollectionPostgres.Sql(admin, """
            insert into semantic_suppressions(semantic_type,scope_kind,scope_value,kind,finding_id,responsible_user_id,reason,created_at,expires_at,created_by)
            select 'semantic.fixture','finding',n::text,'risk_acceptance',n,12,'Fixture expired decision',now()-interval '2 days',now()-interval '1 day','fixture-analyst'
            from generate_series(8,9) n;
            """, ct);
        long expiredId = Convert.ToInt64(await Scalar(admin, "select id from semantic_suppressions where finding_id=8", ct));
        await Error(() => repository.RiskAsync(8, revoke with { Id = expiredId }, ct), "risk_not_active", 409);
        // An unrelated suppression must never be a revocable risk acceptance.
        await PostCollectionPostgres.Sql(admin, """
            insert into semantic_suppressions(semantic_type,domain_id,scope_kind,scope_value,reason,created_at,expires_at,created_by)
            select 'semantic.fixture',id,'bucket','unknown','Fixture suppression',now(),now()+interval '1 day','fixture-analyst' from domains where fqdn='example.test';
            """, ct);
        long suppressionId = Convert.ToInt64(await Scalar(admin, "select id from semantic_suppressions where kind='suppression'", ct));
        await Error(() => repository.RiskAsync(7, revoke with { Id = suppressionId }, ct), "risk_not_active", 409);

        foreach (var (risk, status, ids) in new (string?, string, long[])[] { (null, "new", [8]), ("accepted", "new", [7]), ("all", "new", [7, 8]), (null, "repeated", [9]) })
        {
            var query = new FindingQuery(status, null, null, null, null, risk, null, null, 200, false) { Compact = true };
            var result = await repository.FindingsAsync(query, ProblemLifecycleTests.Access("security.queue"), ct);
            Assert.Equal(ids, result["items"]!.AsArray().Select(r => Id(r!)).Order().ToArray());
            Assert.Equal(ids.Length, result["summary"]!.AsArray().Sum(r => r!["count"]!.GetValue<int>()));
            Assert.All(result["summary"]!.AsArray(), r => Assert.Equal(status, r!["status"]!.GetValue<string>()));
            if (risk == "accepted") Assert.True(result["summary"]![0]!["risk_accepted"]!.GetValue<bool>());
            foreach (var row in result["items"]!.AsArray().Where(r => Id(r!) != 7))
                Assert.Equal("expired", row!["risk_acceptance"]!["state"]!.GetValue<string>());
            Assert.All(result["items"]!.AsArray(), r => Assert.NotEmpty(r!["risk_audit"]!.AsArray()));
        }

        await PostCollectionPostgres.Sql(admin, """
            insert into semantic_control_audit(id,action,target,actor,occurred_at,details) overriding system value
            select n,'suppression_create','fixture','fixture-analyst','2026-10-07T00:00:00Z',jsonb_build_object('rule',jsonb_build_object('kind','risk_acceptance','finding_id',7)) from generate_series(100,150) n;
            insert into semantic_control_audit(id,action,target,actor,details) overriding system value values
            (200,'suppression_create','fixture','fixture-analyst','{"rule":{"kind":"risk_acceptance","finding_id":8}}'),
            (201,'suppression_create','fixture','fixture-analyst','{"rule":{"kind":"suppression","finding_id":7}}');
            """, ct);
        var page = await repository.RiskAuditAsync(7, 151, ct);
        Assert.True(page["has_more"]!.GetValue<bool>()); Assert.Equal(50, page["items"]!.AsArray().Count);
        Assert.Equal(Enumerable.Range(101, 50).Reverse().Select(n => (long)n), page["items"]!.AsArray().Select(r => Id(r!)));
        Timestamp(page["items"]![0]!["occurred_at"], Now);
        var older = await repository.RiskAuditAsync(7, 101, ct);
        Assert.False(older["has_more"]!.GetValue<bool>()); Assert.Equal(100, Id(older["items"]![0]!));
        var latest = await repository.RiskAuditAsync(7, null, ct);
        Assert.Equal(150, Id(latest["items"]![0]!));
    }

    static Task Seed(NpgsqlConnection db, CancellationToken ct) => PostCollectionPostgres.Sql(db, """
        insert into auth_users(id,username,password_hash,role,is_active) values
            (12,'fixture-owner','synthetic-unusable-hash','viewer',true),(13,'fixture-inactive','synthetic-unusable-hash','viewer',false);
        insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
            values('synthetic-risk',1,'control_health','disabled','{}',sha256('{}'::bytea));
        insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,coverage_status,reason,observed_at_utc,source_reference)
            select ('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,sha256(('fixture-risk-'||n)::bytea),'fixture','fixture','unknown','Fixture observation',now(),n::text from generate_series(7,9) n;
        insert into semantic_security_scenarios(scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,strict_keys_json,merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
            select ('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'fixture','control_gap',sha256(n::text::bytea),sha256(n::text::bytea),'fixture','{}',300,'Fixture scenario','Fixture decision',now(),now(),'high' from generate_series(7,9) n;
        insert into findings(id,fingerprint,rule_code,title,severity,source,status,repeat_count)
            select n,'semantic:'||encode(sha256(n::text::bytea),'hex'),'semantic.fixture','Fixture finding','high','semantic-production',case when n=7 then 'new' else 'closed' end,case when n=9 then 1 else 0 end from generate_series(7,9) n;
        insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,control_health_id,source_reference,evaluation_mode,idempotency_key,evaluation_status,completed_at)
            select observation_id,'synthetic-risk',1,'control_health',observation_id,observation_id::text,'enabled',sha256(observation_id::text::bytea),'completed',now() from semantic_control_health_observations where control_id='fixture';
        insert into semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,hard_critical,confidence,confidence_score,coverage_status,evaluation_ms)
            select scenario_id,scenario_id,'enabled','high',75,75,false,'high',90,'unknown',1 from semantic_security_scenarios where scenario_kind='fixture';
        insert into semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
            select s.scenario_id,f.id,s.scenario_id,f.fingerprint,1 from findings f join semantic_security_scenarios s on s.scenario_id=('00000000-0000-4000-8000-'||lpad(f.id::text,12,'0'))::uuid;
        insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,evidence_role)
            select n,event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,'semantic_scenario'
            from generate_series(7,9) n cross join event_hot where event_kind=4625;
        """, ct);
}
