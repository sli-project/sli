using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Archive;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Parity: tests/semantic/test_semantic_persistence_postgres_integration.py.
// Each test owns a disposable cluster with the canonical schema and worker grants.
[Collection("Semantic producer environment")]
public sealed class SemanticPersistencePostgresTests
{
    private static readonly DateTimeOffset Occurred = new(2026, 7, 19, 1, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task V2_archive_to_normalized_action_is_durable_and_idempotent()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        var sources = await Seed(fixture, admin, 900001, [4697, 7045], ct);
        string root = Path.Combine(fixture.Pg.Root, "semantic-archive");
        await using (var archiveDb = NpgsqlDataSource.Create(fixture.Dsn("sli_storage_login")))
            await new ArchivePublisher(root, new PostgresArchiveManifestStore(archiveDb))
                .PublishDirectAsync("semantic-test-service-install", sources, [], ct);

        await SemanticArchiveFixture.Seed(admin, root, ct);
        using var admission = new SemanticProducerPostgresTests.Admission(SemanticRuntimeSettings.FactsMode);
        admission.Set("ADLOG_STORAGE_V2_ARCHIVE_ROOT", root);
        admission.Set("SLI_PLUGIN_LOCK_DIR", Path.Combine(SemanticProduction.SourceBundleRoot(null, AppContext.BaseDirectory), "config/plugin_packages/v3"));
        await using var runtime = Runtime(fixture);
        await using (var worker = await runtime.OpenAsync(ct))
        await using (var tx = await worker.BeginTransactionAsync(ct))
        {
            var session = new SemanticSession(worker, tx);
            foreach (var source in sources)
            {
                await SemanticProduction.EnqueueSource(session, source.Number("id"), "parity", ct);
                await SemanticProduction.EnqueueSource(session, source.Number("id"), "parity", ct);
            }
            await tx.CommitAsync(ct);
        }
        // The outbox already owns the source identities. Retire both short copies
        // so replay has to open the authorized, published archive.
        await PostCollectionPostgres.Sql(admin, """
            delete from event_hot where event_id in(900001,900002);
            delete from event_cold_facts where event_id in(900001,900002);
            """, ct);
        var production = new SemanticProduction(runtime, new(true, true, false, false, false, false), SemanticRuntimeSettings.FactsMode, 2);
        await using (var sourceReader = await runtime.OpenAsync(ct))
        await using (var sourceTx = await sourceReader.BeginTransactionAsync(ct))
        {
            var sourceSession = new SemanticSession(sourceReader, sourceTx);
            Assert.Empty(await sourceSession.QueryAsync("select id from public.semantic_event_source355", ct));
            foreach (var source in sources)
                Assert.Equal("semantic-test-service", (await production.LoadSource(sourceSession, source.Number("id"), source, ct))["event_data_json"].Text("ServiceName"));
            await sourceTx.CommitAsync(ct);
        }
        // Replay after commit on a new connection, as after a worker restart.
        for (int delivery = 0; delivery < 2; delivery++)
        {
            await using var worker = await runtime.OpenAsync(ct);
            var result = await production.ProcessOutbox(worker, ct);
            await using (var tx = await admin.BeginTransactionAsync(ct))
            {
                var failures = await new SemanticSession(admin, tx).QueryAsync(
                    "select source_event_id,last_error_code,last_error_detail from semantic_processing_outbox where last_error_code is not null", ct);
                Assert.True(result.Number("completed") == 2, result.ToJsonString() + failures.ToJsonString());
                await tx.CommitAsync(ct);
            }
            Assert.Equal(2, result.Number("claimed")); Assert.Equal(2, result.Number("completed"));
            Assert.Equal(2, result.Number("normalized")); Assert.Equal(2, result.Number("actions"));
            Assert.Equal(0, result.Number("failed"));
            if (delivery == 0)
                await PostCollectionPostgres.Sql(admin, "update semantic_processing_outbox set status='queued',completed_at=null", ct);
        }
        // Read committed state from another session; no native packet fallback was seeded.
        await using (var tx = await admin.BeginTransactionAsync(ct))
        {
            var session = new SemanticSession(admin, tx);
            var normalized = await session.QueryAsync("select source_event_id,semantic_type,roles_json from normalized_events order by source_event_id", ct);
            Assert.Equal(new long[] { 900001, 900002 }, normalized.Select(x => x.Number("source_event_id")));
            Assert.All(normalized, row => {
                Assert.Equal("service.installed.fragment", row.Text("semantic_type"));
                Assert.Equal("1", row?["roles_json"].Text("source_host"));
            });
            var actions = await session.QueryAsync("select action_kind,action_status from canonical_actions", ct);
            Assert.Equal(2, actions.Count);
            Assert.All(actions, row => {
                Assert.Equal("service.installed", row.Text("action_kind"));
                Assert.Equal("observed", row.Text("action_status"));
            });
            Assert.Equal(2, (await session.QueryAsync("select count(*) as count from canonical_action_evidence", ct))[0].Number("count"));
            var jobs = await session.QueryAsync("select status,partition_key,occurred_at_utc,attempt_count from semantic_processing_outbox", ct);
            Assert.Equal(2, jobs.Count);
            Assert.All(jobs, job => {
                Assert.Equal("completed", job.Text("status")); Assert.NotNull(job.Text("partition_key"));
                Assert.Equal(Occurred, SigmaProjection.At(job!, "occurred_at_utc")); Assert.Equal(2, job.Number("attempt_count"));
            });
            await tx.CommitAsync(ct);
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Assembler_version_replay_preserves_identity_and_prior_evidence()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        var identity = Assert.Single(await Seed(fixture, admin, 900010, [4624], ct));
        var oldEvent = new SemanticEvent(900010, "authentication.succeeded", Occurred,
            new() { ["source_host"] = "DC1" }, new() { ["logon_type"] = "network" },
            new() { ["interpretation"] = "old" }, new string('1', 64));
        var nextEvent = oldEvent with { Facts = new() { ["logon_type"] = "network", ["authentication_package"] = "Kerberos" },
            Quality = new() { ["interpretation"] = "new" }, Sha = new string('2', 64) };
        string key = string.Concat(Enumerable.Repeat("5a", 32));
        var oldAction = Action(oldEvent, key); var nextAction = Action(nextEvent, key);
        // Fixed UUID from Python uuid.uuid5(NAMESPACE_URL, "adlog:canonical:" + key).
        Assert.Equal(Guid.Parse("605e679d-b4ee-514b-9651-4067f4d77019"), oldAction.Id);
        Assert.Equal(oldAction.Id, nextAction.Id);
        await using var runtime = Runtime(fixture);
        await using (var worker = await runtime.OpenAsync(ct))
        await using (var tx = await worker.BeginTransactionAsync(ct))
        {
            var session = new SemanticSession(worker, tx);
            await SemanticProduction.PersistNormalized(session, oldEvent, identity, "1.0", ct);
            // Seed the durable output of assembler 1.0; the runtime writes 1.1.
            await session.QueryAsync("""
                insert into canonical_actions(canonical_action_id,action_kind,action_status,semantic_contract_version,assembler_id,assembler_version,
                  occurred_at_utc,contribution_key,canonical_deduplication_key,action_sha256,attributes_json)
                values($1,$2,'observed',1,'semantic-action-assembler','1.0',$3,$4,$4,$5,$6);
                """, ct, oldAction.Id, oldAction.Kind, oldAction.At, Convert.FromHexString(key), Convert.FromHexString(oldAction.Sha), oldAction.Attributes);
            await session.QueryAsync("""
                insert into canonical_action_evidence(canonical_action_id,normalized_event_id,evidence_role,entity_role,evidence_order,relation_confidence)
                values($1,$2,'primary',null,0,1.000)
                """, ct, oldAction.Id, oldEvent.Id("1.0"));
            await tx.CommitAsync(ct);
        }
        await using (var worker = await runtime.OpenAsync(ct))
        await using (var tx = await worker.BeginTransactionAsync(ct))
        {
            var session = new SemanticSession(worker, tx);
            await SemanticProduction.PersistNormalized(session, nextEvent, identity, "1.1", ct);
            await SemanticProduction.PersistAction(session, nextAction, "1.1", ct);
            await SemanticProduction.PersistNormalized(session, nextEvent, identity, "1.1", ct);
            await SemanticProduction.PersistAction(session, nextAction, "1.1", ct);
            var error = await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistAction(session,
                nextAction with { Kind = "authentication.failed" }, "1.1", ct));
            Assert.Equal("canonical_action_replay_conflict", error.Message);
            await tx.CommitAsync(ct);
        }
        await using (var tx = await admin.BeginTransactionAsync(ct))
        {
            var session = new SemanticSession(admin, tx);
            var stored = Assert.Single(await session.QueryAsync("select * from canonical_actions", ct))!;
            Assert.Equal(oldAction.Id.ToString(), stored.Text("canonical_action_id"));
            Assert.Equal("1.1", stored.Text("assembler_version")); Assert.Equal("observed", stored.Text("action_status"));
            var expected = nextAction.Attributes.DeepClone().AsObject();
            expected["prior_interpretations"] = new JsonArray(new JsonObject {
                ["assembler_id"] = "semantic-action-assembler", ["assembler_version"] = "1.0", ["action_sha256"] = oldAction.Sha,
                ["evidence"] = new JsonArray(new JsonObject {
                    ["source_event_id"] = 900010, ["normalized_event_id"] = oldEvent.Id("1.0").ToString(),
                    ["evidence_role"] = "primary", ["entity_role"] = null, ["evidence_order"] = 0, ["relation_confidence"] = "1.000"
                }), ["attributes"] = oldAction.Attributes.DeepClone()
            });
            Assert.True(JsonNode.DeepEquals(expected, stored["attributes_json"]), stored["attributes_json"]!.ToJsonString());
            Assert.Equal(SemanticJson.Hash(new JsonObject { ["action_kind"] = nextAction.Kind, ["deduplication_key"] = key, ["attributes"] = expected }), stored.Text("action_sha256"));
            var link = Assert.Single(await session.QueryAsync("select normalized_event_id from canonical_action_evidence", ct));
            Assert.Equal(nextEvent.Id("1.1").ToString(), link.Text("normalized_event_id"));
            Assert.Equal(2, (await session.QueryAsync("select count(*) as count from normalized_events", ct))[0].Number("count"));
            await tx.CommitAsync(ct);
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static SemanticAction Action(SemanticEvent ev, string key) => new(ev.Type, ev.At, key, new() {
        ["material_identity"] = new JsonObject { ["source_host"] = "DC1", ["source_event_id"] = ev.Source },
        ["source_evidence"] = new JsonArray(new JsonObject { ["source_event_id"] = ev.Source, ["semantic_sha256"] = ev.Sha }),
        ["observed_facts"] = new JsonArray(ev.Facts.DeepClone()), ["observed_roles"] = new JsonArray(ev.Roles.DeepClone())
    }, [ev]);

    private static PasswordProducerRuntime Runtime(SqlPostgresFixture fixture) => PasswordProducerRuntime.Create(
        name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());

    private static async Task<JsonObject[]> Seed(SqlPostgresFixture fixture, NpgsqlConnection admin,
        long first, int[] codes, CancellationToken ct)
    {
        Guid agent = ShortEventAdmissionPostgresTests.Agent;
        await ShortEventAdmissionPostgresTests.RegisterDcAsync(admin, agent, agent, 1, 1, "dc.example.test", "Security", ct);
        var ids = new List<long>();
        for (int i = 0; i < codes.Length; i++)
        {
            int kind = codes[i];
            var service = kind switch {
                4697 => new Dictionary<string, string> { ["ServiceName"] = "semantic-test-service", ["ServiceFileName"] = "C:/semantic-test.exe" },
                7045 => new Dictionary<string, string> { ["ServiceName"] = "semantic-test-service", ["ImagePath"] = "C:/semantic-test.exe" },
                _ => null
            };
            var events = await ShortEventAdmissionPostgresTests.SeedAsync(admin, ct, occurredAt: Occurred, eventKinds: [kind],
                registered: (agent, agent, 1, 1), packetId: Guid.NewGuid(), sequence: i + 1,
                firstRecordId: checked((int)(first + i - 900000)), nativeFields: service,
                eventChannel: kind == 7045 ? "System" : "Security");
            ids.Add(Assert.Single(events).EventId);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, events, ct);
        }
        await using var tx = await admin.BeginTransactionAsync(ct);
        var rows = await new SemanticSession(admin, tx).QueryAsync("""
            select to_jsonb(e)||jsonb_build_object('normalized_hash',encode(e.normalized_hash,'hex')) as source
            from public.semantic_event_source355 e where id=any($1) order by id
            """, ct, ids.ToArray());
        await tx.CommitAsync(ct);
        Assert.Equal(ids, rows.Select(row => row!["source"].Number("id")));
        return rows.Select(row => row!["source"]!.AsObject()).ToArray();
    }
}
