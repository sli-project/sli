using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class DetectionReadPerformancePostgresTests(ITestOutputHelper output)
{
    private static string Migration => Path.Combine(PostCollectionPostgres.Repository(),
        "config/postgres_migrations/428_detection_read_checkpoints.sql");

    [Fact]
    public async Task Detection_discovery_and_incremental_account_reads_at_stand_size()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 421);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var events = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4625],
            occurredAt: DateTime.UtcNow.Date.AddDays(-1).AddHours(12));
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, events, ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        await using var discover = new NpgsqlCommand(
            "select (source->'scope')::text from public.default_detection_sources()", worker);
        string scope = (string)(await discover.ExecuteScalarAsync(ct))!;
        var day = events[0].Time.Date;
        string partition = $"event_hot_d{day:yyyyMMdd}";

        // Copy the already attested shape in this private fixture. Admission of
        // actual receipts, including new arrivals below, uses the normal writer.
        await using (var seed = new NpgsqlCommand($"""
            alter table {partition} disable trigger attest_short_event337;
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields,source_sha256)
            select 2000000+g,date_trunc('day',h.time_created_utc)+g*interval '1 millisecond',h.event_kind,
                h.domain_id,h.computer,h.method,h.outcome,h.fields,sha256(int8send(g))
            from event_hot h cross join generate_series(1::bigint,500000) g where h.event_id=900001;
            alter table {partition} enable trigger attest_short_event337;
            insert into event_source_representations_v2
            select 2000000+g,r.normalized_hash,2,r.canonical_hash,r.representation,r.representation_sha256
            from event_source_representations_v2 r cross join generate_series(1,1000000) g where r.event_id=900001;
            insert into semantic_account_decoy_checks(checkpoint_key,normalized_event_id,scope_json,result_code)
            select repeat('a',64),md5('sli.short-event.1:'||event_id||':'||encode(source_sha256,'hex'))::uuid,
                @scope::jsonb,'no_match' from event_hot where event_id between 2000001 and 2499800;
            insert into semantic_account_watch_checks(checkpoint_key,normalized_event_id,scope_json,result_code)
            select repeat('b',64),normalized_event_id,scope_json,result_code from semantic_account_decoy_checks;
            analyze event_hot;
            analyze event_source_representations_v2;
            analyze semantic_account_decoy_checks;
            analyze semantic_account_watch_checks;
            """, owner) { CommandTimeout = 0 })
        {
            seed.Parameters.AddWithValue("scope", scope);
            await seed.ExecuteNonQueryAsync(ct);
        }

        // Expose the four private entry points only inside this private
        // benchmark so each can be measured under the actual semantic login.
        await PostCollectionPostgres.Sql(owner, """
            grant execute on function public.default_detection_sources_before_v301(),public.short_detection_sources337(),
                public.read_account_decoy_events_short337(uuid,text,text,text,text,uuid),
                public.read_account_watch_events_short337(uuid,text,text,text,text,uuid) to adlog_semantic_worker
            """, ct);
        string[] discovery = ["default_detection_sources", "default_detection_sources_before_v301",
            "t109_detection_sources", "short_detection_sources337"];
        string[] readers = ["read_account_decoy_events", "read_account_decoy_events_short337",
            "read_account_watch_events", "read_account_watch_events_short337"];
        List<(string Function, double Milliseconds, long Blocks)> after = [];
        Dictionary<string, string[]> beforeRows = new();
        foreach (string phase in new[] { "before", "after" })
        {
            if (phase == "after") await fixture.Pg.ApplyFileAsync(Migration, null, ct);
            foreach (string function in discovery.Concat(readers))
            {
                bool watch = function.Contains("watch", StringComparison.Ordinal);
                string arguments = discovery.Contains(function) ? "" :
                    $"(@scope::jsonb->>'installation_id')::uuid,'sli.windows.ad-dc'," +
                    $"@scope::jsonb->>'source_instance_id',@scope::jsonb->>'source_generation',repeat('{(watch ? 'b' : 'a')}',64),null::uuid";
                string query = $"select * from public.{function}({arguments})";
                await using var explain = new NpgsqlCommand("explain (analyze,buffers,format json) " + query, worker) { CommandTimeout = 0 };
                explain.Parameters.AddWithValue("scope", scope);
                var plan = JsonNode.Parse((string)(await explain.ExecuteScalarAsync(ct))!)![0]!;
                var root = plan["Plan"]!;
                double time = plan["Execution Time"]!.GetValue<double>();
                long blocks = new[] { "Shared Hit Blocks", "Shared Read Blocks", "Local Hit Blocks", "Local Read Blocks",
                    "Temp Read Blocks", "Temp Written Blocks" }.Sum(key => root[key]?.GetValue<long>() ?? 0);
                output.WriteLine(FormattableString.Invariant($"{phase} {function} {time:F3} ms {blocks} blocks"));
                if (phase == "after") after.Add((function, time, blocks));
                if (function is not ("default_detection_sources" or "t109_detection_sources"
                    or "read_account_decoy_events" or "read_account_watch_events")) continue;
                await using var rows = new NpgsqlCommand($"select to_jsonb(r)::text from ({query}) r", worker) { CommandTimeout = 0 };
                rows.Parameters.AddWithValue("scope", scope);
                await using var reader = await rows.ExecuteReaderAsync(ct);
                var values = new List<string>();
                while (await reader.ReadAsync(ct)) values.Add(reader.GetString(0));
                if (!discovery.Contains(function)) Assert.Equal(128, values.Count);
                if (phase == "before") beforeRows.Add(function, values.ToArray());
                else Assert.Equal(beforeRows[function], values);
            }
        }
        Assert.All(after, item =>
        {
            bool source = discovery.Contains(item.Function);
            Assert.True(item.Milliseconds <= (source ? 50 : 1000), $"{item.Function}: {item.Milliseconds} ms");
            if (!source) Assert.True(item.Blocks <= 5000, $"{item.Function}: {item.Blocks} blocks");
        });
    }

    [Fact]
    public async Task Account_problems_match_predecessor_when_an_older_event_arrives_after_the_first_pass()
    {
        var ct = TestContext.Current.CancellationToken;
        var at = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1).AddHours(12));
        var before = await Produce(false);
        var after = await Produce(true);
        Assert.Equal(before, after);

        async Task<string[]> Produce(bool upgraded)
        {
            await using var fixture = new SqlPostgresFixture();
            await fixture.StartAsync(ct, throughVersion: 421);
            if (upgraded) await fixture.Pg.ApplyFileAsync(Migration, null, ct);
            await using var owner = await fixture.Pg.OpenAsync(ct);
            var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4625], occurredAt: at);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
            await PostCollectionPostgres.Sql(owner, """
                insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
                insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                    select id,'synthetic-read-checkpoint','Synthetic account',1,sha256('synthetic'::bytea)
                    from storage_v2_entity_type where value='ad_user';
                insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status)
                    values(md5('checkpoint-run')::uuid,'synthetic','1',1,'full',now()-interval '3 days',sha256('run'::bytea),'completed');
                insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
                    select id,'directory_accounts',now()-interval '3 days',now()-interval '3 days',sha256('account'::bytea),
                        '{"identity":{"kind":"ad_user","object_sid":"S-1-5-21-100000001-200000002-300000003-1001",
                          "object_guid":"00000000-0000-4000-8000-000000000001"}}',md5('checkpoint-run')::uuid
                    from entities_v2 where natural_key='synthetic-read-checkpoint';
                insert into decoy_label_versions(id,revision,kind,identity,owner,reason,active,active_from,actor_type,actor_id,readiness,plugin_id,entity_id,collection_scope_id)
                    select md5('checkpoint-decoy')::uuid,1,'account',jsonb_build_object('domain_id',1,'entity_id',id,
                        'sid','S-1-5-21-100000001-200000002-300000003-1001','guid','00000000-0000-4000-8000-000000000001'),
                        'synthetic','synthetic',true,now()-interval '3 days','session',1,'{"state":"ready"}','sli.ad',id,'ad-domain:1'
                    from entities_v2 where natural_key='synthetic-read-checkpoint';
                insert into watch_entry_versions(id,revision,identity,entity_id,collection_scope_id,owner,reason,active,active_from,expires_at,valid_from,actor_type,actor_id)
                    select md5('checkpoint-watch')::uuid,1,identity,entity_id,collection_scope_id,'synthetic','synthetic',
                        true,active_from,now()+interval '1 day',active_from,'session',1 from decoy_label_versions;
                """, ct);

            await using var runtime = PasswordProducerRuntime.Create(
                name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
                _ => throw new InvalidOperationException());
            await using var worker = await runtime.OpenAsync(ct);
            var production = new SemanticProduction(runtime, SemanticRuntimeSettings.Read(_ => null),
                SemanticRuntimeSettings.FindingsMode, 32);
            await Pass();
            var agent = ShortEventAdmissionPostgresTests.Agent;
            var late = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4625], occurredAt: at.AddHours(-1),
                registered: (agent, agent, 900001, 1), packetId: Guid.Parse("00000000-0000-4000-8000-000000000428"),
                sequence: 2, firstRecordId: 2);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, late, ct);
            await Pass();
            if (upgraded)
            {
                var detector = new DetectionProducer(new(), new());
                await using (var discover = new NpgsqlCommand(
                    "select (source->'scope')::text from public.t109_detection_sources()", worker))
                {
                    var scope = JsonNode.Parse((string)(await discover.ExecuteScalarAsync(ct))!)!;
                    await using var running = await owner.BeginTransactionAsync(ct);
                    await using var hold = new NpgsqlCommand("""
                        select pg_advisory_xact_lock(hashtextextended(@key,0));
                        lock table public.semantic_t109_seen in access exclusive mode
                        """, owner, running);
                    hold.Parameters.AddWithValue("key", "sli.attack-source:" + PasswordJson.Hash(scope) + ":False");
                    await hold.ExecuteNonQueryAsync(ct);
                    var duplicate = await detector.RunOnceAsync(worker, ct, discovered: []);
                    Assert.Equal(1, duplicate.Sources);
                    Assert.Equal(0, duplicate.Failed);
                    await running.RollbackAsync(ct);
                }

                // Block real discovery inside PostgreSQL and cancel the
                // producer while it owns the waiting command.
                await using (var block = await owner.BeginTransactionAsync(ct))
                {
                    await using var hold = new NpgsqlCommand("lock table public.detection_source_catalog428 in access exclusive mode", owner, block);
                    await hold.ExecuteNonQueryAsync(ct);
                    using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    var waiting = detector.RunOnceAsync(worker, stop.Token, discovered: []);
                    try
                    {
                        await using var blocked = new NpgsqlCommand("select cardinality(pg_blocking_pids(@pid))>0", owner, block);
                        blocked.Parameters.AddWithValue("pid", worker.ProcessID);
                        while (!waiting.IsCompleted && await blocked.ExecuteScalarAsync(ct) is false)
                            await Task.Yield();
                        Assert.False(waiting.IsCompleted);
                    }
                    finally
                    {
                        stop.Cancel();
                        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
                        await block.RollbackAsync(ct);
                    }
                }
                await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(Migration, ".rollback.sql"), null, ct);
                await fixture.Pg.ApplyFileAsync(Migration, null, ct);
                await Pass();
            }

            await using var query = new NpgsqlCommand("""
                select to_jsonb(f)::text from (
                    select rule_code,title,severity,first_seen_utc,last_seen_utc,evidence_count,
                        (select array_agg(c.event_id order by c.event_id) from finding_event_copies337 c where c.finding_id=f.id) as events
                    from findings f where rule_code in ('semantic.qw.account-decoy','semantic.qw.account-watch')
                    order by rule_code,first_seen_utc
                ) f
                """, owner);
            await using var reader = await query.ExecuteReaderAsync(ct);
            var problems = new List<string>();
            while (await reader.ReadAsync(ct)) problems.Add(reader.GetString(0));
            Assert.Equal(4, problems.Count);
            Assert.Equal(2, problems.Count(value => value.Contains("900002", StringComparison.Ordinal)));
            return problems.ToArray();

            async Task Pass()
            {
                var (batch, _) = await production.ProcessDefaultDetections(worker, ct);
                Assert.Equal(0, batch.Number("failed"));
                var risk = await production.ProcessRisk(worker, ct);
                Assert.Equal(0, risk.Number("failed"));
            }
        }
    }
}
