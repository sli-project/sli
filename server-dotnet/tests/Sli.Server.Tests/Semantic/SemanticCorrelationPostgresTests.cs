using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticCorrelationPostgresTests
{
    private const string Rule = "session-special-privileges";
    private static readonly DateTimeOffset Occurred = new(2026, 7, 19, 2, 0, 0, TimeSpan.Zero);
    private static JsonObject Definition() => new()
    {
        ["type"] = "all_of", ["inputs"] = new JsonArray("authentication.session.created", "authentication.privileged_session.created"), ["window_seconds"] = 900
    };
    private static SemanticEvent Event(long source, int kind, DateTimeOffset at) => SemanticNormalization.Normalize(new JsonObject
    {
        ["id"] = source, ["event_id"] = kind, ["channel"] = "Security", ["computer"] = "dc.example.test", ["source_host_id"] = 1,
        ["time_created_utc"] = SemanticJson.Stamp(at), ["provider_name"] = "Microsoft-Windows-Security-Auditing",
        ["event_data_json"] = new JsonObject
        {
            [kind == 4624 ? "TargetUserSid" : "SubjectUserSid"] = "S-1-5-21-100000001-200000002-300000003-1001",
            [kind == 4624 ? "TargetLogonId" : "SubjectLogonId"] = "0xabc"
        }
    });

    // Port of test_rule_candidate_and_bounded_replay_are_durable_and_idempotent.
    // Separate connections/commits prove durability; fixture owns a fresh local cluster.
    [Fact]
    public async Task Rule_candidate_and_bounded_replay_are_durable_and_idempotent()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        await ShortEventAdmissionPostgresTests.RegisterDcAsync(admin,ShortEventAdmissionPostgresTests.Agent,
            ShortEventAdmissionPostgresTests.Agent,1,1,"dc.example.test","Security",ct);
        var sources=await ShortEventAdmissionPostgresTests.SeedAsync(admin,ct,eventKinds:[4624,4672],
            registered:(ShortEventAdmissionPostgresTests.Agent,ShortEventAdmissionPostgresTests.Agent,1,1),
            nativeTimestamps:[SemanticJson.Stamp(Occurred),SemanticJson.Stamp(Occurred.AddSeconds(1))],firstRecordId:10001,
            nativeFields:new Dictionary<string,string> {
                ["SubjectUserSid"]="S-1-5-21-100000001-200000002-300000003-1001",["TargetLogonId"]="0xabc",["SubjectLogonId"]="0xabc"
            });
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,sources,ct);
        SemanticEvent[] events = [Event(910001, 4624, Occurred), Event(910002, 4672, Occurred.AddSeconds(1))];
        var relation = Assert.Single(SemanticCorrelation.SessionPrivilegeObservations(events));
        Assert.Equal("authentication.session.has_special_privileges", relation.Kind);
        Assert.Equal(new long[] { 910001, 910002 }, relation.Evidence.Select(e => e.Source));
        Assert.Equal("session-special-privileges:1:0xabc:910001:910002", relation.Key);
        Assert.Equal("high", relation.Confidence);
        // Rule management retains the foundation's storage-worker permissions;
        // semantic workers only read/lock definitions and write processing results.
        await using (var db = new NpgsqlConnection(fixture.Dsn("sli_storage_login")))
        {
            await db.OpenAsync(ct); await PostCollectionPostgres.Sql(db, "set role adlog_storage_worker", ct);
            await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db, tx);
            await SemanticCorrelationRepository.Register(session, Rule, 1, "all_of", Definition(), ct);
            await SemanticCorrelationRepository.Register(session, Rule, 1, "all_of", Definition(), ct);
            var conflict = Definition(); conflict["window_seconds"] = 901;
            await Assert.ThrowsAsync<InvalidDataException>(() => SemanticCorrelationRepository.Register(session, Rule, 1, "all_of", conflict, ct));
            await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticCorrelationRepository.PersistCandidate(session, Rule, 1, relation, SemanticEvent.Version, ct));
            await Assert.ThrowsAsync<InvalidDataException>(() => SemanticCorrelationRepository.Transition(session, Rule, 1, "enabled", ct));
            Assert.Equal("validated", await SemanticCorrelationRepository.Transition(session, Rule, 1, "validated", ct));
            Assert.Equal("test", await SemanticCorrelationRepository.Transition(session, Rule, 1, "test", ct));
            await tx.CommitAsync(ct);
        }
        Guid candidate, replay;
        await using (var db = new NpgsqlConnection(fixture.Dsn("sli_semantic_login")))
        {
            await db.OpenAsync(ct); await PostCollectionPostgres.Sql(db, "set role adlog_semantic_worker", ct);
            await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db, tx);
            foreach (var ev in events)
            {
                var identity = Assert.Single(await session.QueryAsync("select id,server_id,domain_id,log_source_id,event_id,time_created_utc,encode(normalized_hash,'hex') as normalized_hash,migrated_at,channel from public.semantic_event_source355 where id=$1", ct, ev.Source))!.AsObject();
                await SemanticProduction.PersistNormalized(session, ev, identity, SemanticEvent.Version, ct);
            }
            candidate = await SemanticCorrelationRepository.PersistCandidate(session, Rule, 1, relation, SemanticEvent.Version, ct);
            // Golden UUIDs computed using the Python repository's canonical JSON + uuid5.
            Assert.Equal(Guid.Parse("882220b2-7c9f-57ad-a81f-26124ba8c22e"), candidate);
            Assert.Equal(candidate, await SemanticCorrelationRepository.PersistCandidate(session, Rule, 1, relation, SemanticEvent.Version, ct));
            replay = await SemanticCorrelationRepository.ScheduleReplay(session, Rule, 1, Occurred.AddMinutes(-1), Occurred.AddMinutes(1), ct);
            Assert.Equal(Guid.Parse("5ab75a79-b2cd-52a3-bc19-a5aed1127c97"), replay);
            Assert.Equal(replay, await SemanticCorrelationRepository.ScheduleReplay(session, Rule, 1, Occurred.AddMinutes(-1), Occurred.AddMinutes(1), ct));
            Assert.Equal(replay, await SemanticCorrelationRepository.ScheduleReplay(session, Rule, 1, Occurred.AddMinutes(-1).ToOffset(TimeSpan.FromHours(7)), Occurred.AddMinutes(1).ToOffset(TimeSpan.FromHours(7)), ct));
            await Assert.ThrowsAsync<InvalidDataException>(() => SemanticCorrelationRepository.ScheduleReplay(session, Rule, 1, Occurred, Occurred, ct));
            await Assert.ThrowsAsync<InvalidDataException>(() => SemanticCorrelationRepository.ScheduleReplay(session, Rule, 1, Occurred, Occurred.AddDays(7).AddTicks(10), ct));
            await tx.CommitAsync(ct);
        }
        await using (var db = new NpgsqlConnection(fixture.Dsn("sli_semantic_login")))
        {
            await db.OpenAsync(ct); await PostCollectionPostgres.Sql(db, "set role adlog_semantic_worker", ct);
            await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db, tx);
            var claimed = Assert.Single(await SemanticCorrelationRepository.ClaimReplays(session, 1, ct))!;
            Assert.Equal(replay.ToString(), claimed.Text("replay_id"));
            Assert.Equal("leased", claimed.Text("replay_status")); Assert.Equal(1, claimed.Number("attempt_count"));
            Assert.NotNull(claimed["heartbeat_at"]);
            Guid lease = Guid.Parse(claimed.Text("lease_token")!);
            await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticCorrelationRepository.CompleteReplay(session, replay, Guid.NewGuid(), Occurred.AddSeconds(1), 2, 1, ct));
            await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticCorrelationRepository.CompleteReplay(session, replay, lease, Occurred.AddMinutes(2), 2, 1, ct));
            await Assert.ThrowsAsync<InvalidDataException>(() => SemanticCorrelationRepository.CompleteReplay(session, replay, lease, Occurred.AddSeconds(1), -1, 1, ct));
            await SemanticCorrelationRepository.CompleteReplay(session, replay, lease, Occurred.AddSeconds(1), 2, 1, ct);
            await tx.CommitAsync(ct);
        }
        await using (var db = new NpgsqlConnection(fixture.Dsn("sli_semantic_login")))
        {
            await db.OpenAsync(ct); await PostCollectionPostgres.Sql(db, "set role adlog_semantic_worker", ct);
            await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db, tx);
            var stored = Assert.Single(await session.QueryAsync("select candidate_id,evidence_count,candidate_status from semantic_correlation_candidates where rule_id=$1", ct, Rule))!;
            Assert.Equal(candidate.ToString(), stored.Text("candidate_id"));
            Assert.Equal(2, stored.Number("evidence_count")); Assert.Equal("matched", stored.Text("candidate_status"));
            var evidence = await session.QueryAsync("select n.source_event_id,e.evidence_order from semantic_correlation_candidate_evidence e join normalized_events n using(normalized_event_id) where candidate_id=$1 order by evidence_order", ct, candidate);
            Assert.Equal(new long[] { 910001, 910002 }, evidence.Select(e => e.Number("source_event_id")));
            Assert.Equal(new long[] { 0, 1 }, evidence.Select(e => e.Number("evidence_order")));
            var completed = Assert.Single(await session.QueryAsync("select * from semantic_correlation_replays where rule_id=$1", ct, Rule))!;
            Assert.Equal("completed", completed.Text("replay_status"));
            Assert.Equal(2, completed.Number("processed_events")); Assert.Equal(1, completed.Number("matched_candidates"));
            Assert.Equal(SemanticJson.Stamp(Occurred.AddSeconds(1)), completed.Text("checkpoint_utc"));
            Assert.Null(completed["lease_token"]); Assert.Null(completed["lease_until"]); Assert.NotNull(completed["completed_at"]);
            Assert.Empty(await SemanticCorrelationRepository.ClaimReplays(session, 1, ct));
            await tx.CommitAsync(ct);
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
        // The reference deliberately uses direct SQL to prove the database invariant.
        await using var mutation = new NpgsqlCommand("update semantic_correlation_rules set definition_json='{\"type\":\"count\"}'::jsonb where rule_id=@rule and rule_version=1", admin);
        mutation.Parameters.AddWithValue("rule", Rule);
        var error = await Assert.ThrowsAsync<PostgresException>(() => mutation.ExecuteNonQueryAsync(ct));
        Assert.Contains("immutable", error.MessageText);
    }
}
