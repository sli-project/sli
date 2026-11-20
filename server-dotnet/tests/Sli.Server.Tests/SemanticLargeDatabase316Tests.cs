using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests
{
    [Fact]
    public async Task Schema315_accepts316_and_native_proofs_skip_other_hosts_sharing_the_log_source()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct, throughVersion: 315);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(db,ct);
        await SemanticRuntimePostgresTests.SeedNative(db,ct,1);
        await PostCollectionPostgres.Sql(db,"""
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,
                channel_id,provider_id,time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
            select n,900011,900011,(select domain_id from servers where id=900011),(select id from log_sources where name='Security'),
                1102,n+1000000,(select id from storage_v2_channel where value='Security'),
                (select id from storage_v2_provider where value='Microsoft-Windows-Eventlog'),
                '2026-11-01',now(),sha256(n::text::bytea),sha256(n::text::bytea),
                (select version from event_catalog_revisions order by id limit 1) from generate_series(1,2000) n;
            analyze events_v2_core;analyze raw_log_files;analyze sli_agent_packet_inbox;
            set track_functions='all';
            """,ct);
        async Task<string> Scalar(string sql) {await using var q=new NpgsqlCommand(sql,db);return (string)(await q.ExecuteScalarAsync(ct))!;}
        const string catalog="select jsonb_agg(jsonb_build_object('oid',oid,'owner',proowner,'acl',proacl::text,'definer',prosecdef,'config',proconfig) order by oid)::text from pg_proc where oid in ('public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure,'public.read_identity_attack_events_v301(jsonb,bigint[])'::regprocedure,'public.read_default_password_window_v2(jsonb)'::regprocedure,'public.read_default_password_events(jsonb)'::regprocedure)";
        string authority=await Scalar(catalog),original=await Scalar("select pg_get_functiondef('public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure)");
        await PostCollectionPostgres.Sql(db,"set session authorization sli_semantic_login;set role adlog_semantic_worker;set statement_timeout='20s'",ct);
        // Both actual discovery functions bind sources for the real login.
        Assert.Equal("2",await Scalar("select count(*)::text from default_detection_sources()"));
        Assert.Equal("2",await Scalar("select count(*)::text from t109_detection_sources()"));
        string scope=await Scalar("select (source->'scope')::text from t109_detection_sources() where source#>>'{scope,source_instance_id}'=md5('semantic-host')::uuid::text");
        await PostCollectionPostgres.Sql(db,"reset role;reset session authorization",ct);
        async Task<(JsonArray Rows,long Calls)> Read(bool window=false) {
            await PostCollectionPostgres.Sql(db,"select pg_stat_force_next_flush();select pg_stat_reset();set session authorization sli_semantic_login;set role adlog_semantic_worker",ct);
            var timer=Stopwatch.StartNew();
            await using var q=new NpgsqlCommand("select coalesce(jsonb_agg(to_jsonb(r) order by native_id),'[]')::text from read_t109_native(@scope::jsonb"+(window?",'2026-11-01'::timestamptz,'2026-11-02'::timestamptz":"")+") r",db);
            q.Parameters.AddWithValue("scope",scope);
            var rows=JsonNode.Parse((string)(await q.ExecuteScalarAsync(ct))!)!.AsArray();
            await PostCollectionPostgres.Sql(db,"reset role;reset session authorization;select pg_stat_force_next_flush();select pg_stat_clear_snapshot()",ct);
            long calls=long.Parse(await Scalar("select coalesce(sum(calls),0)::text from pg_stat_user_functions where funcid='public.read_agent_semantic_source_v190(bigint)'::regprocedure"));
            output.WriteLine($"T109 window={window}: rows={rows.Count}, native calls={calls}, ms={timer.Elapsed.TotalMilliseconds:F1}");
            return(rows,calls);
        }
        var before=await Read();Assert.Single(before.Rows);Assert.True(before.Calls>1000);
        string directory=Path.Combine(SqlPostgresFixture.Repository(),"config/postgres_migrations");
        string forward=Path.Combine(directory,"316_semantic_t109_source_candidates.sql"),rollback=Path.Combine(directory,"316_semantic_t109_source_candidates.rollback.sql");
        await fixture.Pg.ApplyFileAsync(forward,null,ct);Assert.Equal(authority,await Scalar(catalog));
        foreach(bool window in new[]{false,true}) {
            var after=await Read(window);Assert.True(JsonNode.DeepEquals(before.Rows,after.Rows));Assert.InRange(after.Calls,1,10);
        }
        // Failed native receipt/hash proof remains excluded; an empty batch is
        // never marked seen. Scoped worker still advances its actual checkpoint.
        await PostCollectionPostgres.Sql(db,"update sli_agent_packet_inbox set envelope=envelope||'{\"tampered\":true}'::jsonb where packet_id=md5('semantic-packet')::uuid",ct);
        Assert.Empty((await Read()).Rows);
        await PostCollectionPostgres.Sql(db,"update sli_agent_packet_inbox set envelope=envelope-'tampered' where packet_id=md5('semantic-packet')::uuid;set session authorization sli_semantic_login;set role adlog_semantic_worker",ct);
        await using(var seen=new NpgsqlCommand("insert into semantic_t109_seen(source_key,native_id,scope_json,storage_kind) values(encode(sha256(convert_to(@scope,'UTF8')),'hex'),'900001',@scope::jsonb,'core_event')",db)) {
            seen.Parameters.AddWithValue("scope",scope);Assert.Equal(1,await seen.ExecuteNonQueryAsync(ct));
        }
        await PostCollectionPostgres.Sql(db,"reset role;reset session authorization",ct);
        Assert.Empty((await Read()).Rows);Assert.Single((await Read(true)).Rows);
        await fixture.Pg.ApplyFileAsync(rollback,null,ct);Assert.Equal(original,await Scalar("select pg_get_functiondef('public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure)"));Assert.Equal(authority,await Scalar(catalog));
        await fixture.Pg.ApplyFileAsync(forward,null,ct);Assert.Empty((await Read()).Rows);
        await Check317(fixture,db,ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
