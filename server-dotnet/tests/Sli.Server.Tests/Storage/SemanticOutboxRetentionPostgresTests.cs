using Npgsql;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class SemanticOutboxRetentionPostgresTests
{
    [Fact]
    public async Task Old_terminal_jobs_are_removed_only_after_decision_coverage_and_never_hide_pending_work()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 376);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Seed(db, ct);
        using var state = new StorageLifecycleTests.State();
        await using var deletion = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
            Options = "-c role=adlog_storage_lifecycle_delete", CommandTimeout = 0 }.ConnectionString);
        var retention = new SemanticOutboxRetention(deletion, state.Files, "facts-v1");
        DateTime cutoff = new(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc);
        var unready = await retention.RunAsync(cutoff, Guid.Empty, 1000, ct);
        Assert.Equal("outbox_retention_schema_not_ready", unready["reason"]?.ToString());
        Assert.Equal(12L, await Scalar(db, "select count(*) from semantic_processing_outbox", ct));
        await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/377_db_load_indexes.sql"), null, ct);
        Guid after = Guid.Empty; long deleted = 0, scanned = 0;
        while (true) {
            var page = await retention.RunAsync(cutoff, after, 2, ct);
            deleted += LifecycleJson.Number(page, "deleted_count"); scanned += LifecycleJson.Number(page, "selected_count");
            after = Guid.Parse(page["last_scanned_job_id"]!.ToString());
            if (page["status"]?.ToString() == "complete") break;
            Assert.Equal("partial", page["status"]?.ToString());
        }
        Assert.Equal(12, scanned); Assert.Equal(3, deleted); // 1, 8, 11; both quarantined jobs stay held.
        Assert.Equal("2,3,4,5,6,7,9,9,12", await Scalar(db, "select string_agg(source_event_id::text,',' order by source_event_id) from semantic_processing_outbox", ct));
        Assert.Equal(true, await Scalar(db, "select decided_ids @> 1::bigint and decided_ids @> 8::bigint and decided_ids @> 11::bigint and not decided_ids @> 3::bigint from semantic_producer_coverage where runtime_mode='facts-v1' and processor_version='synthetic-v1'", ct));
        Assert.Equal(true, await Scalar(db, "select decided_ids @> 1::bigint from semantic_producer_coverage where runtime_mode='investigation-v1' and processor_version='existing-version'", ct));
        Assert.Equal(0, LifecycleJson.Number(await retention.RunAsync(cutoff, Guid.Empty, 1000, ct), "deleted_count"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Incomplete_coverage_for_one_version_blocks_the_whole_batch()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 377);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Seed(db, ct);
        await PostCollectionPostgres.Sql(db, """
            update semantic_processing_outbox set processor_version='synthetic-v2' where source_event_id=11;
            insert into semantic_producer_coverage(runtime_mode,processor_version,decided_ids)
              values('investigation-v1','synthetic-v1','{[1,100)}');
            create function public.synthetic_incomplete_coverage() returns trigger language plpgsql as $$
            begin
              if new.runtime_mode='facts-v1' and new.processor_version='synthetic-v1' then
                new.decided_ids = '{[1,2)}'::int8multirange;
              end if;
              return new;
            end $$;
            create trigger synthetic_incomplete_coverage before insert on semantic_producer_coverage
              for each row execute function public.synthetic_incomplete_coverage();
            """, ct);
        using var state = new StorageLifecycleTests.State();
        await using var deletion = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
            Options = "-c role=adlog_storage_lifecycle_delete", CommandTimeout = 0 }.ConnectionString);
        var error = await Assert.ThrowsAsync<LifecycleBlocked>(() => new SemanticOutboxRetention(deletion, state.Files, "facts-v1")
            .RunAsync(new(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc), Guid.Empty, 1000, ct));
        Assert.Equal("outbox_retention_coverage_unconfirmed", error.Message);
        Assert.Equal(12L, await Scalar(db, "select count(*) from semantic_processing_outbox", ct));
        Assert.Equal(0L, await Scalar(db, "select count(*) from semantic_producer_coverage where runtime_mode='facts-v1'", ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Coverage_and_deletion_roll_back_together_on_delete_failure()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 376);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Seed(db, ct);
        await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/377_db_load_indexes.sql"), null, ct);
        await PostCollectionPostgres.Sql(db, """
            create function public.synthetic_outbox_failure() returns trigger language plpgsql as $$
            begin raise exception 'synthetic_delete_failure'; end $$;
            create trigger synthetic_outbox_failure before delete on semantic_processing_outbox
              for each row execute function public.synthetic_outbox_failure();
            """, ct);
        using var state = new StorageLifecycleTests.State();
        await using var deletion = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
            Options = "-c role=adlog_storage_lifecycle_delete", CommandTimeout = 0 }.ConnectionString);
        var retention = new SemanticOutboxRetention(deletion, state.Files, "facts-v1");
        await Assert.ThrowsAsync<PostgresException>(() => retention.RunAsync(new(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc), Guid.Empty, 1000, ct));
        Assert.Equal(12L, await Scalar(db, "select count(*) from semantic_processing_outbox", ct));
        Assert.Equal(0L, await Scalar(db, "select count(*) from semantic_producer_coverage where runtime_mode='facts-v1'", ct));
    }

    [Fact]
    public async Task Unknown_cascading_dependency_blocks_cleanup_without_deleting_anything()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 376);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Seed(db, ct);
        await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/377_db_load_indexes.sql"), null, ct);
        await PostCollectionPostgres.Sql(db, """
            create table public.synthetic_outbox_dependency(job_id uuid references public.semantic_processing_outbox(job_id) on delete cascade);
            insert into public.synthetic_outbox_dependency select job_id from semantic_processing_outbox where source_event_id=11;
            """, ct);
        using var state = new StorageLifecycleTests.State();
        await using var deletion = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
            Options = "-c role=adlog_storage_lifecycle_delete", CommandTimeout = 0 }.ConnectionString);
        var error = await Assert.ThrowsAsync<LifecycleBlocked>(() => new SemanticOutboxRetention(deletion, state.Files, "facts-v1")
            .RunAsync(new(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc), Guid.Empty, 1000, ct));
        Assert.Equal("unknown_outbox_dependency", error.Message);
        Assert.Equal(12L, await Scalar(db, "select count(*) from semantic_processing_outbox", ct));
        Assert.Equal(1L, await Scalar(db, "select count(*) from synthetic_outbox_dependency", ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Quarantine_stays_held_without_any_event_source_lock()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 376);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Seed(db, ct);
        await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/377_db_load_indexes.sql"), null, ct);
        await using var writer = new NpgsqlConnection(fixture.Pg.ConnectionString); await writer.OpenAsync(ct);
        await using var tx = await writer.BeginTransactionAsync(ct);
        await PostCollectionPostgres.Sql(writer, "lock table event_hot,event_cold_facts,storage_v2_event_identity_allocations in access exclusive mode", ct);
        using var state = new StorageLifecycleTests.State();
        await using var deletion = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
            Options = "-c role=adlog_storage_lifecycle_delete", CommandTimeout = 0 }.ConnectionString);
        var result = await new SemanticOutboxRetention(deletion,state.Files,"facts-v1").RunAsync(new(2026,11,1,0,0,0,DateTimeKind.Utc),Guid.Empty,1000,ct);
        Assert.Equal(3,LifecycleJson.Number(result,"deleted_count"));
        Assert.Equal(2,LifecycleJson.Number(result["held_reasons"]!.AsObject(),"semantic_unresolved"));
        Assert.Equal(2L,await Scalar(db,"select count(*) from semantic_processing_outbox where status='quarantined'",ct));
    }

    static Task Seed(NpgsqlConnection db, CancellationToken ct) => PostCollectionPostgres.Sql(db, """
        insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,
          idempotency_key,status,completed_at,last_error_code,lease_token,lease_until,updated_at,created_at,
          source_id,domain_id,partition_key,occurred_at_utc,source_identity_json,payload_json)
        select ('00000000-0000-4000-8000-'||lpad(e.id::text,12,'0'))::uuid,case when e.id=10 then 9 else e.id end,
          case when e.id=10 then 'semantic_replay' else 'normalize_event' end,1,'synthetic','synthetic-v1',
          sha256(convert_to(e.id::text,'UTF8')),
          case when e.id in (2,3) then 'quarantined' when e.id=5 then 'queued' when e.id=6 then 'leased' when e.id=7 then 'failed' else 'completed' end,
          case when e.id in (1,4,8,9,10,11,12) then case when e.id=4 then '2026-11-01Z'::timestamptz else '2026-10-01Z'::timestamptz end end,
          case when e.id in (2,3,7) then 'synthetic' end,
          case when e.id=6 then gen_random_uuid() end,case when e.id=6 then now()+interval '1 day' end,
          case when e.id=12 then '2026-11-01Z'::timestamptz else '2026-10-01Z'::timestamptz end,'2026-09-01Z',
          1,1,'synthetic','2026-09-01Z'::timestamptz,
          jsonb_build_object('id',case when e.id=10 then 9 else e.id end,'server_id',900001,'domain_id',1,'log_source_id',1,
            'event_id',4625,'time_created_utc','2026-09-01Z','normalized_hash',encode(sha256(e.id::text::bytea),'hex'),'migrated_at','2026-09-01Z','channel','Security'),
          case when e.id=10 then '{"original_job_id":"00000000-0000-4000-8000-000000000009"}'::jsonb else '{}'::jsonb end
        from generate_series(1,12) e(id);
        update semantic_processing_outbox set status='queued',completed_at=null where job_kind='semantic_replay';
        insert into semantic_producer_coverage(runtime_mode,processor_version,decided_ids) values('investigation-v1','existing-version','{[1,3)}');
        """, ct);

    static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, db); return await command.ExecuteScalarAsync(ct);
    }
}
