using Npgsql;
using Sli.Server.Semantic.Detections;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class DropLegacyEventsPostgresTests
{
    private static string Migration => Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/372_drop_legacy_events.sql");
    private static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    { await using var cmd = new NpgsqlCommand(sql, db); return await cmd.ExecuteScalarAsync(ct); }

    [Fact]
    public async Task Database_at_371_accepts_372_keeps_admission_and_detection_and_rolls_back_empty_tables()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 371);
        await using var db = await fixture.Pg.OpenAsync(ct);
        Assert.Equal(18, await Scalar(db, "select current_setting('server_version_num')::int/10000", ct));
        Assert.Equal(371, await Scalar(db, "select max(version) from schema_migrations", ct));
        var native = await ShortEventAdmissionPostgresTests.SeedAsync(db, ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, native, ct);
        await PostCollectionPostgres.Sql(db, """
            insert into event_catalog_revisions(version) values('synthetic-372');
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select 800001,900001,id,'synthetic-retired','evtx',repeat('a',64) from log_sources where name='Security';
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,channel_id,
                time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
                select 800001,800001,900001,1,l.id,1102,c.id,now(),now(),decode(repeat('a',64),'hex'),decode(repeat('b',64),'hex'),'synthetic-372'
                from log_sources l cross join storage_v2_channel c where l.name='Security' and c.value='Security';
            insert into event_facts_v2(event_id,source_facts_sha256) values(800001,decode(repeat('c',64),'hex'));
            insert into findings(fingerprint,rule_code,title,severity,status,evidence_count)
                values('synthetic-retired','semantic.qw.log-cleared','synthetic','high','new',1);
            insert into finding_evidence(finding_id,event_id,evidence_role)
                select id,800001,'semantic_scenario' from findings where fingerprint='synthetic-retired';
            select setval('raw_log_files_id_seq',900000,true);
            """, ct);
        const string definitions = """
            select jsonb_agg(jsonb_build_array(p.oid::regprocedure::text,pg_get_functiondef(p.oid),
                pg_get_userbyid(p.proowner),p.proacl::text) order by p.oid::regprocedure::text)::text
            from pg_proc p where p.pronamespace='public'::regnamespace and p.prokind='f'
            """;
        string before = (string)(await Scalar(db, definitions, ct))!;
        const string tableGrants = """
            select jsonb_agg(jsonb_build_array(c.relname,pg_get_userbyid(c.relowner),c.relacl::text,
                (select jsonb_agg(jsonb_build_array(a.attname,a.attacl::text) order by a.attname)
                 from pg_attribute a where a.attrelid=c.oid and a.attnum>0 and not a.attisdropped)) order by c.relname)::text
            from pg_class c where c.relnamespace='public'::regnamespace and c.relname in
                ('events_v2_core','event_facts_v2','event_entity_link_blocks_v2','raw_log_files','event_entity_links_v2','raw_log_files_id_seq')
            """;
        string grantsBefore = (string)(await Scalar(db, tableGrants, ct))!;
        await fixture.Pg.ApplyFileAsync(Migration, null, ct);
        await AssertRetired(db, ct);
        Assert.Equal(1L, await Scalar(db, "select count(*) from finding_evidence where event_id=800001", ct));
        Assert.Equal((long)native.Length, await Scalar(db, "select count(*) from event_source_representations_v2", ct));
        await using (var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login"))) {
            await worker.OpenAsync(ct); await PostCollectionPostgres.Sql(worker, "set role adlog_semantic_worker", ct);
            Assert.Empty(await DetectionProducer.RefreshImportSummary(worker, ct));
            Assert.Equal(1L, await Scalar(worker, "select count(*) from default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", ct));
            Assert.Equal(1L, await Scalar(worker, "select count(*) from t109_detection_sources() d cross join lateral read_t109_native(d.source->'scope') e where e.event_id=1102", ct));
            Assert.True((long)(await Scalar(worker, "select count(*) from default_detection_sources() d cross join lateral read_default_password_events(d.source->'scope') e where d.source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", ct))! > 0);
            Assert.Equal(false, await Scalar(worker, "select has_table_privilege(current_user,'public.event_hot','select')", ct));
            long finding = (long)(await Scalar(db, "insert into findings(fingerprint,rule_code,title,severity,status,evidence_count) values('synthetic-short-owned','semantic.qw.log-cleared','synthetic','high','new',1) returning id", ct))!;
            await using var link = new NpgsqlCommand("""
                select link_finding_evidence_ref(@finding,(d.source#>>'{scope,installation_id}')::uuid,'sli.windows.ad-dc',
                    d.source#>>'{scope,source_instance_id}',d.source#>>'{scope,source_generation}','','core_event',e.native_id,e.sha256)
                from t109_detection_sources() d cross join lateral read_t109_native(d.source->'scope') e
                where e.event_id=1102
                """, worker);
            link.Parameters.AddWithValue("finding", finding);
            Assert.Equal(true, await link.ExecuteScalarAsync(ct));
        }
        Assert.Equal(true, await Scalar(db, """
            select (semantic_finding_review_v160(id)->>'sample_count')::int=1
                and (semantic_finding_review_v160(id)->>'domain_id')::int=1
                and not semantic_finding_suppressed_v160(id,rule_code)
            from findings where fingerprint='synthetic-short-owned'
            """, ct));
        // Surviving ingress tables no longer invoke the old summary trigger.
        await PostCollectionPostgres.Sql(db, """
            update sli_agent_packet_inbox set imported_at=imported_at;
            update sli_agent_receipts set receipt=receipt;
            update normalized_events set source_event_id=source_event_id where false;
            delete from event_hot; delete from event_cold_facts; delete from event_cold_daily;
            """, ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, native, ct);
        Assert.Equal((long)native.Length, await Scalar(db, "select count(*) from event_hot where source_sha256 is not null", ct));
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(Migration, ".rollback.sql"), null, ct);
        Assert.Equal(371, await Scalar(db, "select max(version) from schema_migrations", ct));
        Assert.Equal(0L, await Scalar(db, "select (select count(*) from events_v2_core)+(select count(*) from event_facts_v2)+(select count(*) from raw_log_files)+(select count(*) from event_entity_link_blocks_v2)", ct));
        Assert.Equal(before, await Scalar(db, definitions, ct));
        Assert.Equal(grantsBefore, await Scalar(db, tableGrants, ct));
        Assert.Equal(900000L, await Scalar(db, "select last_value from raw_log_files_id_seq", ct));
        Assert.Equal(1L, await Scalar(db, "select count(*) from finding_evidence where event_id=800001", ct));
        Assert.Equal(false, await Scalar(db, "select convalidated from pg_constraint where conname='finding_evidence_event_id_v2_fkey'", ct));
        await fixture.Pg.ApplyFileAsync(Migration, null, ct);
        await AssertRetired(db, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Installed_partitions_and_indexes_are_removed_and_rollback_recreates_them_empty()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 371);
        await using var db = await fixture.Pg.OpenAsync(ct);
        // An upgraded installation can have a partitioned former raw store.
        // Rebuild only this disposable fixture's old table, before testing 372.
        await PostCollectionPostgres.Sql(db, """
            alter table raw_log_files rename to synthetic_unpartitioned372;
            create table raw_log_files (like synthetic_unpartitioned372 including defaults including constraints,
                constraint synthetic_raw_path372 check(length(file_path)>0)) partition by range(id);
            create table synthetic_raw_partition372 partition of raw_log_files for values from (minvalue) to (maxvalue);
            alter table raw_log_files owner to adlog_user;
            alter sequence raw_log_files_id_seq owned by raw_log_files.id;
            drop table synthetic_unpartitioned372 cascade;
            alter table raw_log_files add primary key(id);
            create index synthetic_raw_lookup372 on raw_log_files(file_path);
            alter table source_capture_continuity_declarations add constraint source_capture_continuity_declarations_raw_log_file_id_fkey
                foreign key(raw_log_file_id) references raw_log_files(id);
            alter table synthetic_raw_partition372 owner to adlog_user;
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                values(800001,900001,1,'synthetic-partition','evtx',repeat('a',64));
            """, ct);
        await fixture.Pg.ApplyFileAsync(Migration, null, ct);
        Assert.Equal(true, await Scalar(db, "select to_regclass('synthetic_raw_partition372') is null and to_regclass('synthetic_raw_lookup372') is null", ct));
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(Migration, ".rollback.sql"), null, ct);
        Assert.Equal(0L, await Scalar(db, "select count(*) from raw_log_files", ct));
        Assert.Equal(true, await Scalar(db, """
            select exists(select 1 from pg_inherits where inhparent='raw_log_files'::regclass and inhrelid='synthetic_raw_partition372'::regclass)
                and (select bool_and(indisvalid and indisready) from pg_index where indrelid in ('raw_log_files'::regclass,'synthetic_raw_partition372'::regclass))
            """, ct));
        await fixture.Pg.ApplyFileAsync(Migration, null, ct);
        await AssertRetired(db, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Raw_files_owned_by_migration_login_are_dropped_when_runner_enters_as_storage_owner()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 371);
        await using var db = await fixture.Pg.OpenAsync(ct);
        // Installed systems: raw_log_files and its sequence belong to sli_migration, the other three tables to adlog_storage_owner.
        await PostCollectionPostgres.Sql(db, """
            create role sli_migration;
            alter table raw_log_files owner to sli_migration;
            alter sequence raw_log_files_id_seq owner to sli_migration;
            """, ct);
        Assert.Equal("adlog_storage_owner", await Scalar(db, "select pg_get_userbyid(relowner) from pg_class where oid='events_v2_core'::regclass", ct));
        // The package runner wraps every migration in SET ROLE adlog_storage_owner ... RESET ROLE.
        string wrapped = Path.Combine(Path.GetTempPath(), "sli372-" + Guid.NewGuid().ToString("N") + ".sql");
        await File.WriteAllTextAsync(wrapped, "set role adlog_storage_owner;\n" + (await File.ReadAllTextAsync(Migration, ct)).Replace("\r\n", "\n") + "\nreset role;\n", ct);
        try { await fixture.Pg.ApplyFileAsync(wrapped, null, ct); } finally { File.Delete(wrapped); }
        await AssertRetired(db, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory]
    [InlineData("create function public.synthetic_dependency372() returns bigint language plpgsql as $$begin return (select count(*) from public.events_v2_core); end$$")]
    [InlineData("create view public.synthetic_dependency372 as select id from public.events_v2_core")]
    [InlineData("create function public.synthetic_dependency372() returns trigger language plpgsql as $$begin perform count(*) from public.raw_log_files; return new; end$$; create trigger synthetic_dependency372 before update on sli_agents for each row execute function public.synthetic_dependency372()")]
    public async Task Unreviewed_dependencies_abort_before_removing_any_data(string dependency)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 371);
        await using var db = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            insert into servers(id,domain_id,hostname,role,is_active) values(900001,1,'dc.example.test','domain_controller',true);
            insert into log_sources(name) values('Security') on conflict do nothing;
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select 800001,900001,id,'synthetic-retired','evtx',repeat('a',64) from log_sources limit 1;
            """, ct);
        await PostCollectionPostgres.Sql(db, dependency, ct);
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Pg.ApplyFileAsync(Migration, null, ct));
        Assert.Contains("drop_legacy_events372_unreviewed_", failure.Message);
        Assert.Equal(371, await Scalar(db, "select max(version) from schema_migrations", ct));
        Assert.Equal(1L, await Scalar(db, "select count(*) from raw_log_files where id=800001", ct));
        Assert.Equal(true, await Scalar(db, "select to_regclass('public.events_v2_core') is not null and to_regclass('public.raw_log_files') is not null and to_regclass('public.legacy_event_rollback372') is null", ct));
    }

    private static async Task AssertRetired(NpgsqlConnection db, CancellationToken ct)
    {
        Assert.Equal(372, await Scalar(db, "select max(version) from schema_migrations", ct));
        Assert.Equal(false, await Scalar(db, """
            select exists(select 1 from pg_class where relname in
                ('events_v2_core','event_facts_v2','event_entity_link_blocks_v2','raw_log_files','event_entity_links_v2','raw_log_files_id_seq'))
              or exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public'
                and (p.proname in ('detections_use_short337','event_source_packet_v284','read_agent_semantic_source_v190','write_process_episode_revision_v89','lock_storage_lifecycle_events_v319','lock_storage_lifecycle_facts_v319','storage_lifecycle_evidence_v321','semantic_backfill_window_v332','read_nps_threshold_events','nps_threshold_window_quality','read_admitted_sigma_events','semantic_default_full320','semantic_default_refresh320','semantic_t109_full320','semantic_source_candidates320','semantic_import_notify320','semantic_import_refresh320','semantic_import_progress320')
                  or p.prosrc ~* '\m(events_v2_core|event_facts_v2|event_entity_link_blocks_v2|raw_log_files|detections_use_short337|event_source_packet_v284|read_agent_semantic_source_v190|write_process_episode_revision_v89|lock_storage_lifecycle_events_v319|lock_storage_lifecycle_facts_v319|storage_lifecycle_evidence_v321|semantic_backfill_window_v332|read_nps_threshold_events|nps_threshold_window_quality|read_admitted_sigma_events|semantic_default_full320|semantic_default_refresh320|semantic_t109_full320|semantic_source_candidates320|semantic_import_notify320|semantic_import_refresh320|semantic_import_progress320)\M'))
            """, ct));
        Assert.Equal(false, await Scalar(db, """
            select has_table_privilege('adlog_user','public.legacy_event_rollback372','select')
              or has_table_privilege('adlog_semantic_worker','public.legacy_event_rollback372','select')
              or exists(select 1 from pg_trigger t join pg_proc p on p.oid=t.tgfoid where p.proname='semantic_import_notify320')
            """, ct));
    }
}
