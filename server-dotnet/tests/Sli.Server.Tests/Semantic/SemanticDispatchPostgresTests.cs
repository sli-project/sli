using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticDispatchPostgresTests
{
    // Parity: tests/semantic/test_semantic_dispatch_postgres_integration.py.
    [Fact]
    public async Task Late_evidence_reopens_expired_candidate_once_and_subscriptions_are_immutable()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await using var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        var production = new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticProduction.DevelopmentMode, 1, development: true);
        var occurred = new DateTimeOffset(2026, 7, 19, 3, 0, 0, TimeSpan.Zero);
        var ruleRow = JsonNode.Parse("""
            {"rule_id":"dispatch-session-special-privileges","rule_version":1,"rule_kind":"all_of","definition_json":{
              "type":"all_of","inputs":["authentication.session.created","authentication.privileged_session.created"],
              "join_roles":["source_host","session_principal"],"window_seconds":900,
              "output_relation_kind":"authentication.session.has_special_privileges","confidence":"high",
              "explanation":"same source host and session principal"}}
            """)!;
        var rule = SemanticCorrelation.Compile(ruleRow);
        await ShortEventAdmissionPostgresTests.RegisterDcAsync(db,ShortEventAdmissionPostgresTests.Agent,
            ShortEventAdmissionPostgresTests.Agent,920001,1,"dispatch-dc.example.test","Security",ct);
        var sources=await ShortEventAdmissionPostgresTests.SeedAsync(db,ct,eventKinds:[4624,4672],
            registered:(ShortEventAdmissionPostgresTests.Agent,ShortEventAdmissionPostgresTests.Agent,920001,1),
            nativeTimestamps:[SemanticJson.Stamp(occurred),SemanticJson.Stamp(occurred.AddSeconds(1))],
            allocatedAt:[occurred.AddSeconds(5),occurred.AddSeconds(601)],firstRecordId:20001,hostName:"dispatch-dc.example.test",
            nativeFields:new Dictionary<string,string> {
                ["SubjectUserSid"]="S-1-5-21-100000001-200000002-300000003-1001",["TargetLogonId"]="0xdef",["SubjectLogonId"]="0xdef"
            });
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,sources,ct);
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            var session = new SemanticSession(db, tx);
            for (int i = 0; i < 2; i++) {
                int code = i == 0 ? 4624 : 4672; long id = 920001 + i;
                var at = occurred.AddSeconds(i);
                var ev = SemanticNormalization.Normalize(new JsonObject {
                    ["id"] = id, ["event_id"] = code, ["channel"] = "Security", ["computer"] = "dispatch-dc.example.test",
                    ["source_host_id"] = 1, ["server_id"] = 920001, ["time_created_utc"] = SemanticJson.Stamp(at),
                    ["provider_name"] = "Microsoft-Windows-Security-Auditing", ["event_data_json"] = new JsonObject {
                        [i == 0 ? "TargetUserSid" : "SubjectUserSid"] = "S-1-5-21-100000001-200000002-300000003-1001",
                        [i == 0 ? "TargetLogonId" : "SubjectLogonId"] = "0xdef" }
                });
                var identity = (await session.QueryAsync("select to_jsonb(e)||jsonb_build_object('normalized_hash',encode(normalized_hash,'hex')) as identity from public.semantic_event_source355 e where id=$1", ct, id))[0]!["identity"]!.AsObject();
                await SemanticProduction.PersistNormalized(session, ev, identity, SemanticEvent.Version, ct);
            }
            await session.QueryAsync("insert into semantic_correlation_rules(rule_id,rule_version,rule_kind,definition_json,definition_sha256) values($1,$2,$3,$4,$5)", ct,
                rule.Id, rule.Version, rule.Kind, ruleRow["definition_json"], Convert.FromHexString(rule.Sha));
            await SemanticProduction.ReplaceRuleSubscriptions(session, rule, ct);
            await SemanticProduction.ReplaceRuleSubscriptions(session, rule, ct);
            var subscriptions = await session.QueryAsync("select semantic_type,subscription_order,encode(definition_sha256,'hex') as sha from semantic_correlation_subscriptions where rule_id=$1 order by subscription_order", ct, rule.Id);
            Assert.Equal(new[] { "authentication.session.created", "authentication.privileged_session.created" }, subscriptions.Select(x => x.Text("semantic_type")));
            Assert.Equal(new long[] { 0, 1 }, subscriptions.Select(x => x.Number("subscription_order")));
            Assert.All(subscriptions, row => Assert.Equal(rule.Sha, row.Text("sha")));
            await session.QueryAsync("update semantic_correlation_rules set lifecycle_status='validated' where rule_id=$1", ct, rule.Id);
            await session.QueryAsync("update semantic_correlation_rules set lifecycle_status='test' where rule_id=$1", ct, rule.Id);
            var immutable = await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.ReplaceRuleSubscriptions(session, rule, ct));
            Assert.Equal("semantic_correlation_subscriptions_require_draft", immutable.Message);
            var normalized = await session.QueryAsync("select *,encode(semantic_sha256,'hex') as semantic_sha256 from normalized_events where source_event_id in(920001,920002) order by source_event_id", ct);
            // TEST rules stay outside production admission, even if only one
            // of the two development opt-ins is supplied.
            foreach (var excluded in new[] {
                new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticRuntimeSettings.FindingsMode, 1),
                new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticRuntimeSettings.FindingsMode, 1, development: true),
                new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticProduction.DevelopmentMode, 1)
            }) {
                foreach (var row in normalized) await excluded.EnqueueDispatch(session, SemanticEvent.Read(row!), SemanticEvent.Version, ct);
                Assert.Empty(await session.QueryAsync("select * from semantic_correlation_dispatch_jobs where rule_id=$1", ct, rule.Id));
            }
            foreach (var row in normalized) await production.EnqueueDispatch(session, SemanticEvent.Read(row!), SemanticEvent.Version, ct);
            var jobs = await session.QueryAsync("select n.source_event_id,j.is_late from semantic_correlation_dispatch_jobs j join normalized_events n using(normalized_event_id) where rule_id=$1 order by n.source_event_id", ct, rule.Id);
            Assert.Equal(2, jobs.Count); Assert.False(jobs[0].Flag("is_late")); Assert.True(jobs[1].Flag("is_late"));
            await session.QueryAsync("update semantic_correlation_dispatch_jobs set available_at=now()+interval '1 day' where is_late", ct);
            await tx.CommitAsync(ct);
        }
        await AssertDispatch();
        Guid candidate;
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            var session = new SemanticSession(db, tx);
            var initial = Assert.Single(await session.QueryAsync("select * from semantic_correlation_candidates where rule_id=$1", ct, rule.Id))!;
            candidate = Guid.Parse(initial.Text("candidate_id")!);
            Assert.Equal("matched", initial.Text("candidate_status")); Assert.Equal(0, initial.Number("reopen_count")); Assert.Equal(0, initial.Number("late_evidence_count"));
            var evidence = await session.QueryAsync("select n.source_event_id from semantic_correlation_candidate_evidence e join normalized_events n using(normalized_event_id) where candidate_id=$1 order by evidence_order", ct, candidate);
            Assert.Equal(new long[] { 920001, 920002 }, evidence.Select(x => x.Number("source_event_id")));
            Assert.Equal(candidate, Assert.Single(await SemanticProduction.ExpireCorrelationCandidates(session, occurred.AddHours(1), ct)));
            var expired = Assert.Single(await session.QueryAsync("select * from semantic_correlation_candidates where candidate_id=$1", ct, candidate))!;
            Assert.Equal("expired", expired.Text("candidate_status")); Assert.NotNull(expired["closed_at"]);
            await session.QueryAsync("update semantic_correlation_dispatch_jobs set available_at=now() where is_late", ct);
            await tx.CommitAsync(ct);
        }
        await AssertDispatch(); await AssertCandidate();
        // Redelivering the same late job must not count its evidence twice.
        await PostCollectionPostgres.Sql(db, "update semantic_correlation_dispatch_jobs set dispatch_status='queued',completed_at=null,available_at=now() where is_late", ct);
        await AssertDispatch();
        await AssertCandidate();
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            var session = new SemanticSession(db, tx);
            Assert.Equal(2, (await session.QueryAsync("select * from semantic_correlation_dispatch_jobs where rule_id=$1 and dispatch_status='completed' and lease_token is null and lease_until is null and completed_at is not null", ct, rule.Id)).Count);
            Assert.Single(await session.QueryAsync("select * from semantic_correlation_candidate_evidence where candidate_id=$1 and is_late", ct, candidate));
            var error = await Assert.ThrowsAsync<PostgresException>(() => session.QueryAsync("update semantic_correlation_subscriptions set semantic_type='type.changed' where rule_id=$1 and subscription_order=0", ct, rule.Id));
            Assert.Equal("P0001", error.SqlState); Assert.Contains("immutable outside draft", error.MessageText);
            await tx.RollbackAsync(ct);
        }

        async Task AssertDispatch() {
            await using var worker = await runtime.OpenAsync(ct);
            var result = await production.ProcessDispatch(worker, ct);
            await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db, tx);
            var errors = await session.QueryAsync("select last_error_code,last_error_detail from semantic_correlation_dispatch_jobs where rule_id=$1 and last_error_code is not null", ct, rule.Id);
            Assert.True(result.Number("failed") == 0, errors.ToJsonString());
            Assert.Equal(1, result.Number("claimed")); Assert.Equal(1, result.Number("completed")); Assert.Equal(0, result.Number("failed")); Assert.Equal(1, result.Number("relations"));
        }
        async Task AssertCandidate() {
            // Observe committed state through a separate connection, as the Python test does.
            await using var observer = new NpgsqlConnection(fixture.Pg.ConnectionString); await observer.OpenAsync(ct);
            await using var tx = await observer.BeginTransactionAsync(ct); var session = new SemanticSession(observer, tx);
            var row = Assert.Single(await session.QueryAsync("select * from semantic_correlation_candidates where rule_id=$1", ct, rule.Id))!;
            Assert.Equal(candidate.ToString(), row.Text("candidate_id")); Assert.Equal("matched", row.Text("candidate_status"));
            Assert.Equal(1, row.Number("reopen_count")); Assert.Equal(1, row.Number("late_evidence_count"));
            Assert.Null(row["closed_at"]); Assert.Equal(occurred.AddSeconds(1), SigmaProjection.At(row, "last_evidence_occurred_at"));
        }
    }
}
