using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class SemanticQuarantineReplayPostgresTests
{
    private static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, db); return await command.ExecuteScalarAsync(ct); }

    [Fact]
    public async Task Previous_maximum_accepts_migration_and_installed_login_has_only_replay_audit_rights()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 366);
        string migration = Path.Combine(SemanticProduction.SourceBundleRoot(null, AppContext.BaseDirectory), "config/postgres_migrations/368_semantic_quarantine_replay.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        Assert.Equal(true, await Scalar(owner, """
            select not (rolcanlogin or rolsuper or rolcreatedb or rolcreaterole or rolreplication or rolbypassrls)
              and has_column_privilege(rolname,'semantic_control_audit','action','SELECT')
              and has_column_privilege(rolname,'semantic_control_audit','target','SELECT')
              and has_column_privilege(rolname,'semantic_control_audit','details','SELECT')
              and not has_table_privilege(rolname,'semantic_control_audit','INSERT,UPDATE,DELETE,TRUNCATE')
              and not has_column_privilege(rolname,'semantic_control_audit','actor','SELECT')
              and has_function_privilege(rolname,'record_semantic_quarantine_resolution368(text,jsonb)','EXECUTE')
              and not has_schema_privilege(rolname,'public','CREATE')
              and not pg_has_role(rolname,'adlog_storage_owner','MEMBER')
            from pg_roles where rolname='adlog_semantic_worker'
            """, ct));
        Assert.Equal(false, await Scalar(owner, "select has_function_privilege('adlog_user','record_semantic_quarantine_resolution368(text,jsonb)','EXECUTE')", ct));
        await using (var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException()))
        await using (var worker = await runtime.OpenAsync(ct)) {
            await Scalar(worker, "select record_semantic_quarantine_resolution368('synthetic-job','{\"job_id\":\"synthetic-job\",\"outcome\":\"replayed\"}')", ct);
            Assert.Equal("synthetic-job", await Scalar(worker, "select target from semantic_control_audit where action='semantic_quarantine_resolution'", ct));
        }
        Assert.Equal(true, await Scalar(owner, "select actor='sli_semantic_login' from semantic_control_audit where target='synthetic-job'", ct));
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        Assert.Equal(1L, await Scalar(owner, "select count(*) from semantic_control_audit where target='synthetic-job'", ct));
        Assert.Equal(false, await Scalar(owner, "select has_column_privilege('adlog_semantic_worker','semantic_control_audit','details','SELECT')", ct));
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory] [InlineData(false, false)] [InlineData(true, false)] [InlineData(false, true)] [InlineData(true, true)]
    public async Task Installed_service_replays_admitted_source_once_and_preserves_integrity_rejections(bool conflictingHash, bool deleted)
    {
        var ct = TestContext.Current.CancellationToken;
        bool alteredShort = conflictingHash && deleted;
        if (alteredShort) deleted = false;
        using var environment = new SemanticProducerPostgresTests.Admission();
        environment.Set("SLI_PLUGIN_LOCK_DIR", Path.Combine(SemanticProduction.SourceBundleRoot(null, AppContext.BaseDirectory), "config/plugin_packages/v3"));
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 373);
        string migration = Path.Combine(SemanticProduction.SourceBundleRoot(null, AppContext.BaseDirectory), "config/postgres_migrations/374_semantic_source_deleted.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        Assert.Equal(false, await Scalar(owner, "select has_function_privilege('adlog_user','semantic_source_exists374(bigint)','EXECUTE')", ct));
        Assert.Equal(true, await Scalar(owner, "select has_function_privilege('adlog_semantic_worker','semantic_source_exists374(bigint)','EXECUTE')", ct));
        var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, [rows[0]], ct);
        await using var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        if (conflictingHash) {
            // A synthetic job with a conflicting original proof, not an UPDATE
            // that would bypass the installed source-identity immutability trigger.
            await PostCollectionPostgres.Sql(owner, """
                insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,
                    processor_id,processor_version,idempotency_key,source_id,domain_id,partition_key,occurred_at_utc,source_identity_json)
                select '00000000-0000-0000-0000-000000000001',e.id,'normalize_event',1,'semantic-shadow','synthetic-previous',
                    decode(repeat('b',64),'hex'),e.log_source_id,e.domain_id,e.server_id::text||':'||e.channel_id::text,e.time_created_utc,
                    jsonb_build_object('id',e.id,'server_id',e.server_id,'domain_id',e.domain_id,'log_source_id',e.log_source_id,
                        'event_id',e.event_id,'time_created_utc',e.time_created_utc,'normalized_hash',repeat('0',64),
                        'migrated_at',e.migrated_at,'provider_name',e.provider_name,'channel',e.channel,'computer',e.computer)
                from semantic_event_source355 e where e.id=900001;
                """, ct);
        }
        else {
            await using var worker = await runtime.OpenAsync(ct);
            Assert.Equal(1, (await SemanticProducerBackfill.RunAsync(worker, SemanticRuntimeSettings.FindingsMode, 10, ct)).Number("queued"));
        }
        await PostCollectionPostgres.Sql(owner, """
            update semantic_processing_outbox set status='quarantined',attempt_count=max_attempts,
                last_error_code='semantic_processing_failed',last_error_detail='{"code":"semantic_processing_failed","step":"source_read","sql_state":null}';
            delete from event_hot;
            """, ct);
        if (deleted) await PostCollectionPostgres.Sql(owner, "delete from event_cold_facts", ct);
        if (alteredShort) await PostCollectionPostgres.Sql(owner, "update event_cold_facts set source_sha256=decode(repeat('0',64),'hex')", ct);
        var settings = new SemanticRuntimeSettings(true, true, false, true, true, true);
        var production = new SemanticProduction(runtime, settings, SemanticRuntimeSettings.FindingsMode, 1);
        var result = await production.ReplayFixedQuarantineAsync(ct);
        Assert.Equal(conflictingHash || deleted ? 0 : 1, result.Number("replayed")); Assert.Equal(conflictingHash ? 1 : 0, result.Number("failed"));
        Assert.Equal(deleted ? 1 : 0, result.Number("closed"));
        Assert.Equal(deleted ? 0L : 1L, await Scalar(owner, "select count(*) from semantic_processing_outbox where status='quarantined'", ct));
        Assert.Equal(1L, await Scalar(owner, "select count(*) from semantic_processing_outbox", ct));
        Assert.Equal(deleted ? "source_deleted" : conflictingHash ? "source_integrity_failed" : "retry_normalization_source",
            await Scalar(owner, "select details->>'reason' from semantic_control_audit where action='semantic_quarantine_resolution'", ct));
        Assert.Equal(conflictingHash || deleted ? 0L : 1L, await Scalar(owner, "select count(*) from normalized_events", ct));
        Assert.Equal(conflictingHash || deleted ? 0L : 1L, await Scalar(owner, "select count(*) from canonical_actions", ct));
        if (deleted) {
            Assert.Equal("closed", await Scalar(owner, "select status from semantic_processing_outbox", ct));
            Assert.Equal("closed", await Scalar(owner, "select details->>'outcome' from semantic_control_audit where action='semantic_quarantine_resolution'", ct));
            string queues = Sli.Server.Operations.OperationsSql.Queues;
            Assert.Equal(0L, await Scalar(owner, $"select count(*) from ({queues}) q where queue_name='processing' and queue_status='quarantined'", ct));
            Assert.Equal(1L, await Scalar(owner, $"select depth from ({queues}) q where queue_name='processing' and queue_status='closed'", ct));
        }
        Assert.Equal(0, (await production.ReplayFixedQuarantineAsync(ct)).Number("replayed"));
        if (!conflictingHash) {
            var restarted = new SemanticProduction(runtime, settings, SemanticRuntimeSettings.FindingsMode, 1);
            Assert.Equal(1, (await restarted.ReplayFixedQuarantineAsync(ct)).Number("already_resolved"));
            Assert.Equal(1L, await Scalar(owner, "select count(*) from semantic_control_audit where action='semantic_quarantine_resolution'", ct));
            Assert.Equal(deleted ? 0L : 1L, await Scalar(owner, "select count(*) from canonical_actions", ct));
        }
        if (deleted) {
            await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
            Assert.Equal(1L, await Scalar(owner, "select count(*) from semantic_processing_outbox where status='quarantined'", ct));
            var rolledBack = new SemanticProduction(runtime, settings, SemanticRuntimeSettings.FindingsMode, 1);
            Assert.Equal(1, (await rolledBack.ReplayFixedQuarantineAsync(ct)).Number("already_resolved"));
            Assert.Equal(1L, await Scalar(owner, "select count(*) from semantic_control_audit where action='semantic_quarantine_resolution'", ct));
            await fixture.Pg.ApplyFileAsync(migration, null, ct);
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
