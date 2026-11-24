using System.Diagnostics;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordSourceDiscoveryPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Discovery_deduplicates_exact_origin_channels_and_preserves_existing_binding_authority()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 404);
        await using var owner = await fixture.Pg.OpenAsync(ct);

        var first = new Guid("00000000-0000-4000-8000-000000000407");
        var second = new Guid("00000000-0000-4000-8000-000000001407");
        var inactive = new Guid("00000000-0000-4000-8000-000000002407");
        await using (var settings = new NpgsqlCommand("""
            insert into public.sli_agents(id,host_id,key_fingerprint,registration_host_name,status,assigned_modules)
            select agent,agent,repeat('c',64),name,status,
                jsonb_build_array(jsonb_build_object('module_id','sli.windows.ad-dc','enabled',true,
                    'config',jsonb_build_object('channels',jsonb_build_object('Security',true,'System',system_enabled))))
            from (values (@first,'first.example.test','active',false),(@second,'second.example.test','active',true),
                (@inactive,'inactive.example.test','disabled',true)) a(agent,name,status,system_enabled)
            """, owner)) {
            settings.Parameters.AddWithValue("first", first);
            settings.Parameters.AddWithValue("second", second);
            settings.Parameters.AddWithValue("inactive", inactive);
            await settings.ExecuteNonQueryAsync(ct);
        }
        await using (var prepare = new NpgsqlCommand("""
            create temporary table fixture_origins (
                name text, agent uuid, channel text, log_source bigint, n integer, cold boolean,
                attested boolean, plugin text
            );
            insert into fixture_origins values
                ('primary',@first,'Security',11,48000,false,true,'sli.windows.ad-dc'),
                ('primary',@first,'Security',11,16000,true,true,'sli.windows.ad-dc'),
                ('primary',@first,'System',11,600,false,true,'sli.windows.ad-dc'),
                ('disabled-only',@first,'System',12,600,true,true,'sli.windows.ad-dc'),
                ('cold-only',@second,'System',13,600,true,true,'sli.windows.ad-dc'),
                ('already-bound',@second,'Security',14,600,false,true,'sli.windows.ad-dc'),
                ('already-bound',@second,'Security',15,600,false,true,'sli.windows.ad-dc'),
                ('inactive',@inactive,'Security',16,600,false,true,'sli.windows.ad-dc'),
                ('unattested',@first,'Security',17,60,false,false,'sli.windows.ad-dc'),
                ('generic',@first,'Security',18,60,false,true,'sli.windows-eventlog');
            select public.create_event_storage_partitions(current_date-10,current_date);
            """, owner)) {
            prepare.Parameters.AddWithValue("first", first);
            prepare.Parameters.AddWithValue("second", second);
            prepare.Parameters.AddWithValue("inactive", inactive);
            await prepare.ExecuteNonQueryAsync(ct);
        }

        async Task StoreFixtureRows(long idOffset = 0)
        {
            // Synthetic persisted short rows exercise the actual discovery inputs.
            // Receipt-to-origin attestation is covered by the short-event writer tests.
            await using var transaction = await owner.BeginTransactionAsync(ct);
            await PostCollectionPostgres.Sql(owner, "set local session_replication_role='replica'", ct);
            await using var persist = new NpgsqlCommand("""
                with rows as (
                    select o.*,@id_offset + row_number() over(order by name,agent,channel,log_source,i) as row_id,
                        jsonb_build_object('$channel',channel,'$origin',jsonb_build_object(
                            'installation_id',installation_id::text,'plugin_id',plugin,
                            'source_instance_id',name,'source_generation','fixture-generation',
                            'collection_scope_id','','log_source_id',log_source,'agent_id',agent::text)) method
                    from fixture_origins o cross join lateral generate_series(1,o.n) n(i)
                    cross join public.semantic_default_installation
                ), hot as (
                    insert into public.event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields,source_sha256)
                    select row_id,current_date::timestamptz,4625,1,'fixture',method,'{}','{}',
                        case when attested then sha256(convert_to(row_id::text,'UTF8')) end
                    from rows where not cold order by row_id returning 1
                )
                insert into public.event_cold_daily(day,grouping_key,event_kind,domain_id,computer,method,outcome,event_count,
                        first_seen_utc,last_seen_utc)
                    select current_date-10,sha256(convert_to(row_id::text,'UTF8')),4625,1,'fixture',method,'{}',1,
                        (current_date-10)::timestamptz,(current_date-10)::timestamptz
                    from rows where cold order by row_id;
                """, owner, transaction);
            persist.Parameters.AddWithValue("id_offset", idOffset);
            await persist.ExecuteNonQueryAsync(ct);
            await transaction.CommitAsync(ct);
        }
        await StoreFixtureRows();

        await using (var bind = new NpgsqlCommand("""
            insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,
                plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select r.oid,r.rolname,i.installation_id,'sli.windows.ad-dc','already-bound','fixture-generation','','core_event',15,@agent
            from pg_roles r cross join public.semantic_default_installation i where r.rolname='sli_semantic_login'
            """, owner)) {
            bind.Parameters.AddWithValue("agent", second);
            await bind.ExecuteNonQueryAsync(ct);
        }

        async Task ResetBindings() => await PostCollectionPostgres.Sql(owner, """
            delete from public.finding_evidence_source_bindings
            where principal_name='sli_semantic_login' and source_instance_id<>'already-bound'
            """, ct);

        async Task<long> AuthorizationCalls()
        {
            await PostCollectionPostgres.Sql(owner, "select pg_stat_clear_snapshot()", ct);
            await using var command = new NpgsqlCommand("""
                select coalesce((select calls from pg_stat_user_functions
                    where funcid='public.semantic_source_active320(uuid,text,text)'::regprocedure),0)
                """, owner);
            return (long)(await command.ExecuteScalarAsync(ct))!;
        }
        async Task<(string Sources, string Bindings, long Calls, TimeSpan Elapsed)> Discover(bool defaults = false, bool plan = false)
        {
            long before = await AuthorizationCalls();
            string sources;
            var elapsed = Stopwatch.StartNew();
            await using (var worker = await fixture.Pg.OpenAsync(ct)) {
                if (plan) await PostCollectionPostgres.Sql(worker, """
                    load 'auto_explain';
                    set auto_explain.log_min_duration='10ms';
                    set auto_explain.log_nested_statements=on;
                    set auto_explain.log_analyze=on;
                    set auto_explain.log_buffers=on;
                    set auto_explain.log_timing=off;
                    set auto_explain.log_format=json;
                    """, ct);
                await PostCollectionPostgres.Sql(worker, """
                    set track_functions='all';
                    set session authorization sli_semantic_login;
                    set role adlog_semantic_worker;
                    """, ct);
                await using var command = new NpgsqlCommand(defaults ? """
                    select coalesce(jsonb_agg(source order by source),'[]'::jsonb)::text from public.default_detection_sources()
                    """ : """
                    select coalesce(jsonb_agg(source order by source),'[]'::jsonb)::text from public.t109_detection_sources()
                    """, worker);
                sources = (string)(await command.ExecuteScalarAsync(ct))!;
            }
            elapsed.Stop();
            await using var bindings = new NpgsqlCommand("""
                select jsonb_agg(to_jsonb(b) order by to_jsonb(b))::text
                from public.finding_evidence_source_bindings b where b.principal_name='sli_semantic_login'
                """, owner);
            return (sources, (string)(await bindings.ExecuteScalarAsync(ct))!, await AuthorizationCalls() - before, elapsed.Elapsed);
        }
        async Task<string> FunctionContract(bool definition)
        {
            await using var command = new NpgsqlCommand("""
                select jsonb_build_array(oid,proowner,proacl,prosecdef,provolatile,proconfig,
                    case when @definition then pg_get_functiondef(oid) end)::text
                from pg_proc where oid='public.short_detection_sources337()'::regprocedure
                """, owner);
            command.Parameters.AddWithValue("definition", definition);
            return (string)(await command.ExecuteScalarAsync(ct))!;
        }

        string original = await FunctionContract(definition: true);
        string acl = await FunctionContract(definition: false);
        var legacyT109 = await Discover(plan: true);
        await ResetBindings();
        var legacyDefaults = await Discover(defaults: true);
        Assert.Equal(legacyT109.Bindings, legacyDefaults.Bindings);
        Assert.Contains("primary", legacyT109.Sources);
        Assert.Contains("cold-only", legacyT109.Sources);
        Assert.Contains("already-bound", legacyT109.Sources);
        Assert.DoesNotContain("disabled-only", legacyT109.Sources);
        Assert.DoesNotContain("inactive", legacyT109.Sources);
        Assert.DoesNotContain("unattested", legacyT109.Sources);
        Assert.DoesNotContain("generic", legacyT109.Sources);
        Assert.True(legacyT109.Calls > 64000, $"legacy calls: {legacyT109.Calls}");
        Assert.Equal(legacyT109.Calls, legacyDefaults.Calls);

        string migration = Path.Combine(PostCollectionPostgres.Repository(),
            "config/postgres_migrations/407_bound_source_discovery.sql");
        string rollback = Path.ChangeExtension(migration, ".rollback.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        Assert.Equal(acl, await FunctionContract(definition: false));
        await ResetBindings();
        var boundedT109 = await Discover(plan: true);
        await ResetBindings();
        var boundedDefaults = await Discover(defaults: true);
        Assert.Equal((legacyT109.Sources, legacyT109.Bindings), (boundedT109.Sources, boundedT109.Bindings));
        Assert.Equal((legacyDefaults.Sources, legacyDefaults.Bindings), (boundedDefaults.Sources, boundedDefaults.Bindings));
        output.WriteLine($"T109 discovery: {legacyT109.Calls} calls / {legacyT109.Elapsed.TotalMilliseconds:F0} ms before, {boundedT109.Calls} calls / {boundedT109.Elapsed.TotalMilliseconds:F0} ms after");
        output.WriteLine($"Default discovery: {legacyDefaults.Calls} calls / {legacyDefaults.Elapsed.TotalMilliseconds:F0} ms before, {boundedDefaults.Calls} calls / {boundedDefaults.Elapsed.TotalMilliseconds:F0} ms after");
        var plans = (await fixture.Pg.DiagnosticsAsync(ct)).Split((char)10);
        output.WriteLine(string.Join(Environment.NewLine, plans.Where(line =>
            line.Contains("duration:", StringComparison.Ordinal) ||
            line.StartsWith("\t    \"Temp Written Blocks\":", StringComparison.Ordinal) ||
            line.Contains("\"Sort Space Type\":", StringComparison.Ordinal) ||
            line.Contains("\"HashAgg Batches\":", StringComparison.Ordinal)).TakeLast(32)));
        Assert.Equal(7, boundedT109.Calls);
        Assert.Equal(7, boundedDefaults.Calls);

        // Two newly eligible projections share one binding PK, including different agents.
        await using (var competing = new NpgsqlCommand("""
            truncate fixture_origins;
            insert into fixture_origins values
                ('competing',@first,'Security',29,1,false,true,'sli.windows.ad-dc'),
                ('competing',@second,'Security',28,1,true,true,'sli.windows.ad-dc');
            """, owner)) {
            competing.Parameters.AddWithValue("first", first);
            competing.Parameters.AddWithValue("second", second);
            await competing.ExecuteNonQueryAsync(ct);
        }
        await StoreFixtureRows(idOffset: 100000);

        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        Assert.Equal(original, await FunctionContract(definition: true));
        await ResetBindings();
        var legacyCompeting = await Discover();
        Assert.Contains("competing", legacyCompeting.Sources);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await ResetBindings();
        var boundedCompeting = await Discover();
        Assert.Equal((legacyCompeting.Sources, legacyCompeting.Bindings), (boundedCompeting.Sources, boundedCompeting.Bindings));
        output.WriteLine($"Competing projections: legacy fallback calls {boundedCompeting.Calls - 9}, distinct preflight calls 9");
        Assert.Equal(legacyCompeting.Calls + 9, boundedCompeting.Calls);

        // A later poll can skip arbitration because the earlier binding is retained.
        var alreadyAdmitted = await Discover();
        Assert.Equal(boundedCompeting.Bindings, alreadyAdmitted.Bindings);
        Assert.Equal(9, alreadyAdmitted.Calls);
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        Assert.Equal(original, await FunctionContract(definition: true));
        Assert.Equal(boundedCompeting.Bindings, (await Discover()).Bindings);
    }
}
