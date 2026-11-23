using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class PasswordQueueProjectionTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData("truncate public.ad_context_entity_aliases")]
    [InlineData("truncate public.finding_event_copies337")]
    [InlineData("update public.finding_event_copies337 set method=method || '{\"updated\":true}' where finding_id=1")]
    public async Task Source_changes_commit_while_the_projection_is_locked(string change)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var source = await fixture.Pg.OpenAsync(ct);
        await using var projection = await fixture.Pg.OpenAsync(ct);
        await ProblemQueuePagingTests.SeedPopulation(source, ct);
        await PostCollectionPostgres.Sql(source, """
            update public.findings set rule_code='semantic.qw.password-spray' where id=1;
            update public.finding_event_copies337 set method=jsonb_set(method,'{$principals}',
                '{"TargetUserName":"first-account","IpAddress":"192.0.2.1"}') where finding_id=1;
            select public.refresh_password_queue_presentation399(1);
            """, ct);
        Assert.True(await AliasesWereCached());

        await using (var cacheLock = await projection.BeginTransactionAsync(ct))
        {
            await PostCollectionPostgres.Sql(projection, "lock table public.password_queue_projection399 in access exclusive mode", ct);
            await using var changeTransaction = await source.BeginTransactionAsync(ct);
            await PostCollectionPostgres.Sql(source, "set local lock_timeout='1s'", ct);
            await PostCollectionPostgres.Sql(source, change, ct);
            await changeTransaction.CommitAsync(ct);
            await cacheLock.RollbackAsync(ct);
        }

        Assert.False(await AliasesWereCached());

        async Task<bool> AliasesWereCached()
        {
            await using var query = new NpgsqlCommand("""
                select aliases is not null from public.password_queue_presentation399(1,'semantic.qw.password-spray')
                """, source);
            return (bool)(await query.ExecuteScalarAsync(ct))!;
        }
    }

    [Fact]
    public async Task Projection_preserves_facts_and_falls_back_after_evidence_and_AD_changes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 398);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await using var reader = await fixture.Pg.OpenAsync(ct, "adlog_user");
        await ProblemQueuePagingTests.SeedPopulation(owner, ct);
        await PostCollectionPostgres.Sql(owner, """
            update findings set rule_code='semantic.qw.password-spray' where id=1;
            update finding_event_copies337 set method=jsonb_set(method,'{$principals}',
                '{"TargetUserName":"first-account","TargetDomainName":"example.test","IpAddress":"192.0.2.1"}') where finding_id=1;
            """, ct);
        await SeedScopeCases(owner, ct);
        await VerifyScopeCases(reader, ct);
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/399_password_queue_projection.sql");
        var timer = System.Diagnostics.Stopwatch.StartNew();
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        output.WriteLine($"Projection migration with preexisting published evidence: {timer.Elapsed.TotalMilliseconds:F1} ms");
        await VerifyScopeCases(reader, ct);
        var first = await ReadAsync();
        Assert.Equal(1, first["facts"]!["account_count"]!.GetValue<int>());
        Assert.Equal("first-account", Assert.Single(first["aliases"]!["accounts"]!.AsArray())!.ToString());

        await PostCollectionPostgres.Sql(owner, """
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields,source_sha256,evidence_role)
            select finding_id,2,time_created_utc+interval '1 second',event_kind,domain_id,computer,
                jsonb_set(method,'{$principals,TargetUserName}','"second-account"'),outcome,fields,sha256('second-attempt'::bytea),evidence_role
            from finding_event_copies337 where finding_id=1 and event_id=1;
            """, ct);
        var changed = await ReadAsync();
        Assert.Equal(2, changed["facts"]!["account_count"]!.GetValue<int>());
        Assert.Null(changed["aliases"]);

        await using var writer = new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));
        await writer.OpenAsync(ct);
        await PostCollectionPostgres.Sql(writer, "set role adlog_semantic_worker", ct);
        timer.Restart();
        await PostCollectionPostgres.Sql(writer, "select public.refresh_password_queue_presentation399(1)", ct);
        output.WriteLine($"Atomic projection refresh for two retained observations: {timer.Elapsed.TotalMilliseconds:F1} ms");
        var refreshed = await ReadAsync();
        Assert.Equal(2, refreshed["aliases"]!["accounts"]!.AsArray().Count);
        await PostCollectionPostgres.Sql(owner, """
            update finding_event_copies337 set method=jsonb_set(method,'{$principals}',
                '{"TargetUserName":"first-account","TargetDomainName":"","IpAddress":"192.0.2.1"}')
            where finding_id=1 and event_id=2;
            update findings set last_seen_utc=now()::text where id=1;
            """, ct);
        await PostCollectionPostgres.Sql(writer, "select public.refresh_password_queue_presentation399(1)", ct);
        Assert.Equal(1, (await ReadAsync())["facts"]!["account_count"]!.GetValue<int>());

        await using (var contextUpdate = await owner.BeginTransactionAsync(ct))
        {
            await PostCollectionPostgres.Sql(owner, "update domains set netbios_name='SYNTHETIC' where id=1", ct);
            await PostCollectionPostgres.Sql(owner, "select public.refresh_password_queue_presentation399(1)", ct);
            await PostCollectionPostgres.Sql(owner, "update domains set fqdn='renamed.example.test' where id=1", ct);
            await contextUpdate.CommitAsync(ct);
        }
        var renamed = await ReadAsync();
        Assert.Equal(2, renamed["facts"]!["account_count"]!.GetValue<int>());
        Assert.Null(renamed["aliases"]);

        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        Assert.Equal(0, (await new PasswordRiskConsumer(runtime, new()).RunOnceAsync(ct)).Claimed);
        Assert.Equal("first-account", Assert.Single((await ReadAsync())["aliases"]!["accounts"]!.AsArray())!.ToString());

        await PostCollectionPostgres.Sql(owner, "update domains set fqdn='example.test' where id=1", ct);
        await PostCollectionPostgres.Sql(writer, "select public.refresh_password_queue_presentation399(1)", ct);
        Assert.Equal("first-account", (await ReadAsync())["facts"]!["account"]!.ToString());
        await PostCollectionPostgres.Sql(owner, """
            insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select 500,id,'first-account','Synthetic account',1,sha256('identity'::bytea)
                from storage_v2_entity_type where value='ad_user';
            insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status)
                values(md5('account-snapshot')::uuid,'synthetic','1',1,'full',now()-interval '1 day',sha256('account-snapshot'::bytea),'importing');
            insert into ad_context_sections(run_id,section_name,status,record_count)
                values(md5('account-snapshot')::uuid,'directory_accounts','complete',1);
            insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
                values(500,'directory_accounts',now()-interval '1 day',now()-interval '1 day',sha256('account'::bytea),
                    '{"identity":{"kind":"ad_user","object_sid":"S-1-5-21-100000001-200000002-300000003-500"},"attributes":{"sam_account_name":"First-Account"}}',
                    md5('account-snapshot')::uuid);
            insert into ad_context_entity_aliases(entity_id,domain_id,alias_type,alias_value,normalized_value,first_seen_utc,last_seen_utc,source_run_id)
                values(500,1,'sam_account_name','First-Account','first-account',now()-interval '1 day',now()-interval '1 day',md5('account-snapshot')::uuid);
            """, ct);
        // A partially imported context cannot affect the historical match.
        Assert.Equal("first-account", (await ReadAsync())["facts"]!["account"]!.ToString());
        await PostCollectionPostgres.Sql(writer, "select public.refresh_password_queue_presentation399(1)", ct);
        await PostCollectionPostgres.Sql(owner, "update ad_context_runs set status='completed' where run_id=md5('account-snapshot')::uuid", ct);
        var imported = await ReadAsync();
        Assert.Null(imported["aliases"]);
        Assert.Equal("First-Account", imported["facts"]!["account"]!.ToString());

        await PostCollectionPostgres.Sql(owner, """
            update finding_event_copies337 set domain_id=2 where finding_id=1 and event_id=2;
            """, ct);
        await using (var scoped = new NpgsqlCommand("select public.semantic_finding_in_domains_v265(1,array[1]::bigint[])", reader))
            Assert.False((bool)(await scoped.ExecuteScalarAsync(ct))!);

        string rollback = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/399_password_queue_projection.rollback.sql");
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        await using var restored = new NpgsqlCommand("select public.semantic_finding_in_domains_v265(1,array[1,2]::bigint[])", reader);
        Assert.True((bool)(await restored.ExecuteScalarAsync(ct))!);

        async Task<JsonObject> ReadAsync()
        {
            await using var command = new NpgsqlCommand("""
                select to_jsonb(row)::text from (
                    select p.facts,p.aliases,public.password_problem_facts395(1,'semantic.qw.password-spray') as live
                    from public.password_queue_presentation399(1,'semantic.qw.password-spray') p
                ) row
                """, reader);
            var result = JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)!.AsObject();
            Assert.True(JsonNode.DeepEquals(result["facts"], result["live"]));
            return result;
        }
    }

    private static Task SeedScopeCases(NpgsqlConnection owner, CancellationToken ct) =>
        PostCollectionPostgres.Sql(owner, """
            insert into domains(id,forest_id,fqdn)
                select 2,forest_id,'other.example.test' from domains where id=1;
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,computer,
                method,outcome,fields,source_sha256,evidence_role)
            select finding_id,1000000+finding_id,time_created_utc,event_kind,case when finding_id=90 then 2 else 1 end,
                'dc02.example.test',jsonb_set(method,'{$server_id}','2'),outcome,fields,
                sha256(finding_id::text::bytea),'semantic_scenario'
            from finding_event_copies337 where finding_id in (90,92);
            update finding_event_copies337 set domain_id=2 where finding_id=91;
            insert into finding_evidence_refs(finding_id,installation_id,plugin_id,source_instance_id,source_generation,
                collection_scope_id,storage_kind,native_id,sha256)
            values
                (93,'10000000-0000-0000-0000-000000000001','sli.file-audit','missing-observation',
                 'synthetic-generation','synthetic-root','file_audit_observation',repeat('a',64),repeat('b',64)),
                (95,'10000000-0000-0000-0000-000000000001','sli.windows.ad-dc','missing-native',
                 'synthetic-generation','','core_event','90000001',repeat('c',64)),
                (211,'10000000-0000-0000-0000-000000000001','sli.windows.ad-dc','missing-native',
                 'synthetic-generation','','core_event','90000002',repeat('d',64));
            insert into finding_evidence(finding_id,event_id,evidence_role,note)
            values(94,90000003,'semantic_scenario','Authorized retained copy and legacy reference'),
                  (211,90000004,'semantic_scenario','Legacy reference without a retained copy');
            """, ct);

    private static async Task VerifyScopeCases(NpgsqlConnection reader, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select label from (values
                ('retained copy inside scope',1::bigint,array[1]::bigint[],true),
                ('retained copy outside scope',1,array[2]::bigint[],false),
                ('all domains',1,null::bigint[],true),
                ('empty scope',1,array[]::bigint[],false),
                ('null element',1,array[null::bigint],false),
                ('authorized domain and null',1,array[1,null]::bigint[],true),
                ('custom array bound',1,'[0:0]={1}'::bigint[],true),
                ('mixed domains, first requested',90,array[1]::bigint[],false),
                ('mixed domains, second requested',90,array[2]::bigint[],false),
                ('mixed domains, both requested',90,array[1,2]::bigint[],true),
                ('mixed domains, all authorized',90,null::bigint[],true),
                ('second domain inside scope',91,array[2]::bigint[],true),
                ('second domain outside scope',91,array[1]::bigint[],false),
                ('several sources in one domain',92,array[1]::bigint[],true),
                ('unresolved non-native reference',93,array[1]::bigint[],false),
                ('unresolved non-native reference, all domains',93,null::bigint[],false),
                ('retained copy with legacy reference',94,array[1]::bigint[],true),
                ('retained copy and orphan core reference',95,array[1]::bigint[],true),
                ('orphan references without retained copies',211,array[1]::bigint[],false),
                ('no retained evidence, all domains',211,null::bigint[],false)
            ) checks(label,finding,domains,expected)
            where public.semantic_finding_in_domains_v265(finding,domains) is distinct from expected
            """, reader);
        var failures = new List<string>();
        await using var result = await command.ExecuteReaderAsync(ct);
        while (await result.ReadAsync(ct)) failures.Add(result.GetString(0));
        Assert.Empty(failures);
    }
}
