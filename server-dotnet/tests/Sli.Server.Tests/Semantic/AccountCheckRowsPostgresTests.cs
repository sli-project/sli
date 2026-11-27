using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class AccountCheckRowsPostgresTests
{
    private const string DecoySid = "S-1-5-21-100000001-200000002-300000003-1001";
    private const string WatchSid = "S-1-5-21-100000001-200000002-300000003-1002";
    private const string OtherSid = "S-1-5-21-100000001-200000002-300000003-1003";
    private const int MigrationVersion = 460;
    private static int Predecessor => MigrationDirectory.Read().Where(m => m.Version < MigrationVersion).Max(m => m.Version);
    private static string Migration => MigrationDirectory.Read(MigrationVersion).Single(m => m.Version == MigrationVersion).Path;

    [Fact]
    public async Task Upgrade_keeps_five_hits_and_the_same_problems_for_one_hundred_thousand_events()
    {
        var ct = TestContext.Current.CancellationToken;
        var at = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1).AddHours(12));
        Assert.Equal(await Produce(upgrade: false), await Produce(upgrade: true));

        async Task<string[]> Produce(bool upgrade)
        {
            await using var fixture = new SqlPostgresFixture();
            await fixture.StartAsync(ct, throughVersion: Predecessor);
            await using var owner = await fixture.Pg.OpenAsync(ct);
            var initial = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4624],
                nativeTargetSids: [OtherSid], occurredAt: at);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, initial, ct);
            await SeedRegistry(owner, ct);
            await using var runtime = PasswordProducerRuntime.Create(
                name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
                _ => throw new InvalidOperationException());
            await using var worker = await runtime.OpenAsync(ct);
            var production = new SemanticProduction(runtime, SemanticRuntimeSettings.Read(_ => null),
                SemanticRuntimeSettings.FindingsMode, 32);
            var (first, _) = await production.ProcessDefaultDetections(worker, ct);
            Assert.Equal(0, first.Number("failed"));
            Assert.Equal(1L, await Count("semantic_account_decoy_checks"));
            Assert.Equal(1L, await Count("semantic_account_watch_checks"));

            if (upgrade)
            {
                await fixture.Pg.ApplyFileAsync(Migration, null, ct);
                await using var lifecycle = new LifecycleRuntime(name => name switch
                {
                    "ADLOG_PG_DSN" => fixture.Dsn("sli_storage_lifecycle_login"),
                    "ADLOG_STORAGE_LIFECYCLE_DELETE_DSN" => fixture.Dsn("sli_storage_lifecycle_delete_login"),
                    _ => null
                }, new LifecycleFiles(fixture.Pg.Root));
                Assert.True(await lifecycle.TryLockAsync(StorageLifecycleWorker.LockName, ct));
                var cleanup = await lifecycle.ExpirePartitionsAsync(DateTime.UtcNow, 1, ct);
                Assert.Equal(2L, LifecycleJson.Number(cleanup, "account_check_rows_deleted"));
                Assert.Equal(0L, await Count("semantic_account_decoy_checks"));
                Assert.Equal(0L, await Count("semantic_account_watch_checks"));
            }

            // The bulk rows are negative. All five hits use the normal writer
            // and arrive with occurrence times earlier than the first pass.
            string partition = $"event_hot_d{at:yyyyMMdd}";
            await using (var seed = new NpgsqlCommand($"""
                alter table {partition} disable trigger attest_short_event337;
                insert into event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields,source_sha256)
                select 2000000+g,h.time_created_utc+g*interval '1 millisecond',h.event_kind,
                    h.domain_id,h.computer,h.method,h.outcome,h.fields,sha256(int8send(g))
                from event_hot h cross join generate_series(1::bigint,99994) g where h.event_id=900001;
                alter table {partition} enable trigger attest_short_event337;
                analyze event_hot;
                """, owner) { CommandTimeout = 0 })
                await seed.ExecuteNonQueryAsync(ct);
            var agent = ShortEventAdmissionPostgresTests.Agent;
            var hitTime = at.AddHours(-1);
            string[] timestamps = Enumerable.Range(0, 5).Select(i => hitTime.AddMinutes(i * 6)
                .ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", System.Globalization.CultureInfo.InvariantCulture)).ToArray();
            var hits = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4625, 4625, 4625, 4625, 4625],
                nativeTargetSids: [DecoySid, DecoySid, DecoySid, WatchSid, WatchSid], nativeTimestamps: timestamps,
                occurredAt: hitTime, registered: (agent, agent, 900001, 1),
                packetId: Guid.Parse("00000000-0000-4000-8000-000000000460"), sequence: 2, firstRecordId: 2);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, hits, ct);
            var (batch, _) = await production.ProcessDefaultDetections(worker, ct);
            Assert.Equal(0, batch.Number("failed"));
            var risk = await production.ProcessRisk(worker, ct);
            Assert.Equal(0, risk.Number("failed"));
            Assert.Equal(upgrade ? 3L : 100000L, await Count("semantic_account_decoy_checks"));
            Assert.Equal(upgrade ? 2L : 100000L, await Count("semantic_account_watch_checks"));
            Assert.Equal(2L, await Count("account_detection_checkpoints451"));
            Assert.Equal(0L, await Count("account_detection_pending451"));

            await using var query = new NpgsqlCommand("""
                select to_jsonb(f)::text from (
                    select rule_code,title,severity,first_seen_utc,last_seen_utc,evidence_count,
                        (select array_agg(c.event_id order by c.event_id) from finding_event_copies337 c where c.finding_id=f.id) as events
                    from findings f where rule_code in ('semantic.qw.account-decoy','semantic.qw.account-watch')
                    order by rule_code,first_seen_utc
                ) f
                """, owner);
            var problems = new List<string>();
            await using var reader = await query.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) problems.Add(reader.GetString(0));
            Assert.Equal(5, problems.Count);
            await fixture.AssertNoSqlErrorsAsync(ct);
            return problems.ToArray();

            async Task<long> Count(string table)
            {
                await using var command = new NpgsqlCommand($"select count(*) from public.{table}", owner);
                return (long)(await command.ExecuteScalarAsync(ct))!;
            }
        }
    }

    [Fact]
    public async Task Cleanup_preserves_manual_progress_and_aborted_batches_retry_late_events()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: Predecessor);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var at = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1).AddHours(12));
        var first = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4625], occurredAt: at);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, first, ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        JsonObject scope;
        await using (var tx = await worker.BeginTransactionAsync(ct))
        {
            var source = (await new SemanticSession(worker, tx).QueryAsync(
                "select source from public.default_detection_sources()", ct)).Single()!["source"]!;
            scope = source["scope"]!.DeepClone().AsObject();
            await tx.CommitAsync(ct);
        }
        var rule = DetectorRule.Read("account-decoy", new JsonObject { ["scope"] = scope, ["evaluation_mode"] = "test" });
        Assert.Equal(1, (await RunManual(commit: true)).Number("events"));
        Assert.Equal(0L, await Scalar("select count(*) from account_detection_checkpoints451"));

        await fixture.Pg.ApplyFileAsync(Migration, null, ct);
        await using (var db = new NpgsqlConnection(fixture.Dsn("sli_storage_lifecycle_delete_login")))
        {
            await db.OpenAsync(ct);
            await PostCollectionPostgres.Sql(db, "set role adlog_storage_lifecycle_delete", ct);
            await using var cleanup = new NpgsqlCommand("select deleted from public.prune_account_check_rows460('decoy',1)", db);
            Assert.Equal(1L, await cleanup.ExecuteScalarAsync(ct));
        }
        Assert.Equal(0, (await RunManual(commit: true)).Number("events"));

        var agent = ShortEventAdmissionPostgresTests.Agent;
        var late = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4625, 1102],
            occurredAt: at.AddHours(-1), registered: (agent, agent, 900001, 1),
            packetId: Guid.Parse("00000000-0000-4000-8000-000000000461"), sequence: 2, firstRecordId: 2);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, late, ct);
        var aborted = await RunManual(commit: false);
        Assert.Equal(2, aborted.Number("events"));
        Assert.Equal(1, aborted["results"].Number("not_applicable"));
        Assert.Equal(DBNull.Value, await Scalar("select last_evaluated_event_id from account_detection_checkpoints451"));
        Assert.Equal(2L, await Scalar("select count(*) from account_detection_pending451"));
        Assert.True(JsonNode.DeepEquals(aborted, await RunManual(commit: true)));
        Assert.Contains((long)(await Scalar("select last_evaluated_event_id from account_detection_checkpoints451"))!,
            late.Select(row => row.EventId));
        Assert.Equal(0L, await Scalar("select count(*) from account_detection_pending451"));
        Assert.Equal(0L, await Scalar("select count(*) from semantic_account_decoy_checks"));
        Assert.Equal(0, (await RunManual(commit: true)).Number("events"));

        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(Migration, ".rollback.sql"), null, ct);
        Assert.Equal(3, (await RunManual(commit: true)).Number("events"));
        Assert.Equal(3L, await Scalar("select count(*) from semantic_account_decoy_checks"));
        await fixture.Pg.ApplyFileAsync(Migration, null, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);

        async Task<JsonObject> RunManual(bool commit)
        {
            await using var tx = await worker.BeginTransactionAsync(ct);
            var result = await SemanticProduction.RunDetector(new SemanticSession(worker, tx), rule, DateTimeOffset.UtcNow, ct);
            if (commit) await tx.CommitAsync(ct);
            else await tx.RollbackAsync(ct);
            return result;
        }

        async Task<object?> Scalar(string sql)
        {
            await using var command = new NpgsqlCommand(sql, owner);
            return await command.ExecuteScalarAsync(ct);
        }
    }

    private static async Task SeedRegistry(NpgsqlConnection owner, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
            insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select t.id,k,k,1,sha256(k::bytea) from storage_v2_entity_type t
                cross join unnest(array['synthetic-decoy','synthetic-watch']) k where t.value='ad_user';
            insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status)
                values(md5('check-rows-run')::uuid,'synthetic','1',1,'full',now()-interval '3 days',sha256('run'::bytea),'completed');
            insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
                select id,'directory_accounts',now()-interval '3 days',now()-interval '3 days',sha256(natural_key::bytea),
                    jsonb_build_object('identity',jsonb_build_object('kind','ad_user','object_sid',s.sid,'object_guid',md5(natural_key)::uuid)),
                    md5('check-rows-run')::uuid
                from entities_v2 join (values ('synthetic-decoy',@decoy),('synthetic-watch',@watch)) s(k,sid) on k=natural_key;
            insert into decoy_label_versions(id,revision,kind,identity,owner,reason,active,active_from,actor_type,actor_id,readiness,plugin_id,entity_id,collection_scope_id)
                select md5('check-rows-decoy')::uuid,1,'account',jsonb_build_object('domain_id',1,'entity_id',id,
                    'sid',@decoy,'guid',md5(natural_key)::uuid),'synthetic','synthetic',true,
                    now()-interval '3 days','session',1,'{"state":"ready"}','sli.ad',id,'ad-domain:1'
                from entities_v2 where natural_key='synthetic-decoy';
            insert into watch_entry_versions(id,revision,identity,entity_id,collection_scope_id,owner,reason,active,active_from,expires_at,valid_from,actor_type,actor_id)
                select md5('check-rows-watch')::uuid,1,jsonb_build_object('domain_id',1,'entity_id',id,
                    'sid',@watch,'guid',md5(natural_key)::uuid),id,'ad-domain:1','synthetic','synthetic',
                    true,now()-interval '3 days',now()+interval '1 day',now()-interval '3 days','session',1
                from entities_v2 where natural_key='synthetic-watch';
            """, owner);
        command.Parameters.AddWithValue("decoy", DecoySid);
        command.Parameters.AddWithValue("watch", WatchSid);
        await command.ExecuteNonQueryAsync(ct);
    }
}
