using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordFirstBatchPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Database_at_previous_maximum_accepts_batch_migration_and_restores_exact_guards()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:374);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        async Task<string> Definitions() {
            await using var read=new NpgsqlCommand("""
                select jsonb_build_object('functions',(select jsonb_object_agg(oid::regprocedure::text,
                    jsonb_build_object('body',pg_get_functiondef(oid),'owner',proowner,'acl',proacl)) from pg_proc
                    where oid=any(array['public.password_event_clock362(jsonb,jsonb)'::regprocedure,
                        'public.password_v2_state_ledger_complete()'::regprocedure,
                        'public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure])),
                    'triggers',(select jsonb_object_agg(tgname,pg_get_triggerdef(oid)) from pg_trigger
                        where tgname in ('password_v2_state_ledger_complete','password_v2_members_complete')))::text
                """,owner);
            return (string)(await read.ExecuteScalarAsync(ct))!;
        }
        string before=await Definitions();
        string path=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/375_password_first_batch.sql");
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path,".rollback.sql"),null,ct);
        Assert.Equal(before,await Definitions());
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Large_backlog_commits_jobs_then_resumes_after_an_abandoned_attempt()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var start=DateTimeOffset.UtcNow.AddDays(-1).AddTicks(-DateTimeOffset.UtcNow.Ticks%TimeSpan.TicksPerSecond);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,occurredAt:start,eventKinds:[4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await SeedBacklog(owner,ct);
        await PostCollectionPostgres.Sql(owner,"alter role sli_semantic_login set log_min_duration_statement=0",ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var source=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')::text",app);
            bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);
            Assert.Equal("configured",JsonNode.Parse((string)(await bind.ExecuteScalarAsync(ct))!)!["status"]!.GetValue<string>());
        }
        var rule=new PasswordRule(scope); var producer=new PasswordProducer();
        var watch=Stopwatch.StartNew(); var first=await producer.RunAsync(worker,rule,ct); watch.Stop();
        string log=await fixture.Pg.DiagnosticsAsync(ct);
        var commits=Regex.Matches(log,@"duration:\s*([0-9.]+) ms\s+statement:\s*COMMIT",RegexOptions.IgnoreCase)
            .Select(m=>double.Parse(m.Groups[1].Value,CultureInfo.InvariantCulture)).ToArray();
        output.WriteLine($"first batch: total={watch.Elapsed.TotalMilliseconds:F1} ms; COMMIT max={(commits.Length==0?0:commits.Max()):F1} ms");
        Assert.False(first.Failed,first.Diagnostic?.ToJsonString()); Assert.True(first.Jobs>0,first.Status);
        output.WriteLine($"first batch: jobs={first.Jobs}; native items={first.Work!["native_items"]}; reserved occurrences={first.Work["reservation_occurrences"]}");
        var before=await Checkpoint(owner,ct);
        output.WriteLine($"first batch: watermark seconds={(before.Watermark-start).TotalSeconds:F1}; revision={before.Revision}");
        await using(var explain=new NpgsqlCommand("explain (analyze,buffers) select public.password_v2_assert_checkpoint(c) from semantic_password_checkpoints c",owner){CommandTimeout=0}) {
            await using var plan=await explain.ExecuteReaderAsync(ct);
            while(await plan.ReadAsync(ct)) output.WriteLine(plan.GetString(0));
        }
        // The larger slice still retains each inclusive 600-second rule window.
        Assert.InRange((before.Watermark-start).TotalSeconds,1,1800);
        await using(var abandoned=new NpgsqlCommand("select public.begin_password_attempt(@s::jsonb,@e::jsonb)::text",worker)) {
            abandoned.Parameters.AddWithValue("s",scope.Document.ToJsonString()); abandoned.Parameters.AddWithValue("e",rule.Execution.ToJsonString());
            var attempt=JsonNode.Parse((string)(await abandoned.ExecuteScalarAsync(ct))!)!;
            long token=attempt["token"]!.GetValue<long>();
            await using var tx=await worker.BeginTransactionAsync(ct);
            await using var read=new NpgsqlCommand("select public.read_password_checkpoint_v2(@s::jsonb,@e::jsonb)",worker,tx);
            read.Parameters.AddWithValue("s",scope.Document.ToJsonString()); read.Parameters.AddWithValue("e",rule.Execution.ToJsonString());
            await read.ExecuteNonQueryAsync(ct); await tx.RollbackAsync(ct);
            var stranded=await Checkpoint(owner,ct); Assert.Equal(token,stranded.Active); Assert.True(stranded.Active>stranded.Observed);
        }
        watch.Restart(); var second=await producer.RunAsync(worker,rule,ct); watch.Stop();
        output.WriteLine($"resumed batch: total={watch.Elapsed.TotalMilliseconds:F1} ms; jobs={second.Jobs}");
        Assert.False(second.Failed,second.Diagnostic?.ToJsonString()); Assert.Equal("committed",second.Status);
        var after=await Checkpoint(owner,ct);
        Assert.True(after.Watermark>before.Watermark); Assert.Equal(before.Revision+1,after.Revision);
        Assert.Equal(after.Active,after.Observed);
        await using var jobs=new NpgsqlCommand("select count(*) from semantic_risk_evaluation_jobs where source_kind='qw_signal'",owner);
        Assert.True((long)(await jobs.ExecuteScalarAsync(ct))!>=first.Jobs);
        // Deferred constraints must reject a changed projection, including a
        // second mutation after SET CONSTRAINTS drained the first check.
        await using(var tx=await owner.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(owner,"update semantic_password_window_members set member_document=member_document; set constraints all immediate; set constraints all deferred",ct);
            await PostCollectionPostgres.Sql(owner,"delete from semantic_password_window_members where native_id=(select min(native_id) from semantic_password_window_members)",ct);
            var error=await Assert.ThrowsAsync<PostgresException>(()=>tx.CommitAsync(ct));
            Assert.Equal("55000",error.SqlState); Assert.Equal("password_v2_checkpoint_corrupt",error.MessageText);
        }
        Assert.Equal(after,await Checkpoint(owner,ct));
        await using(var tx=await owner.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(owner,"update semantic_password_checkpoints set state_document=jsonb_set(state_document,'{episodes,0,budget,ref_occurrences}','1')",ct);
            var error=await Assert.ThrowsAsync<PostgresException>(()=>tx.CommitAsync(ct));
            Assert.Equal("55000",error.SqlState); Assert.Equal("password_v2_state_ledger_conflict",error.MessageText);
        }
        Assert.Equal(after,await Checkpoint(owner,ct));
        await using(var pending=new NpgsqlCommand("select count(*) from password_state_checks375",owner))
            Assert.Equal(0L,await pending.ExecuteScalarAsync(ct));
        await using(var access=new NpgsqlCommand("select has_table_privilege('adlog_semantic_worker','password_state_checks375','INSERT,UPDATE,DELETE,SELECT')",owner))
            Assert.Equal(false,await access.ExecuteScalarAsync(ct));
    }

    private static async Task<(DateTimeOffset Watermark,long Revision,long Active,long Observed)> Checkpoint(NpgsqlConnection db,CancellationToken ct)
    {
        await using var query=new NpgsqlCommand("select watermark,state_revision,active_token,last_observed_token from semantic_password_checkpoints",db);
        await using var r=await query.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
        return (r.GetFieldValue<DateTimeOffset>(0),r.GetInt64(1),r.GetInt64(2),r.GetInt64(3));
    }

    internal static async Task SeedBacklog(NpgsqlConnection db,CancellationToken ct,int total=70000,double spacing=0.7,bool noise=false,int clients=40,bool standNoise=false,bool missingTargets=false,int? accountCount=null)
    {
        // Generate native receipt/inbox/representation/allocation rows, then use
        // the real provenance trigger. Small packets avoid quadratic TOAST reads.
        await using var seed=new NpgsqlCommand("""
            create temporary table password_test_events as
            with template as (select i.event_rows->0 as doc from sli_agent_packet_inbox i limit 1),
            events as (select n,doc,(doc->>'time_created')::timestamptz+n*@spacing*(case when @stand and n<392 then 0.9 else 1 end)*interval '1 second' as at,
                md5('password-test-packet:'||(n/100)::text)::uuid as packet_id,
                case when @missing then '-' when n%nullif(@accounts,0)>0 then 'noise'||(n%@accounts)::text
                    when @accounts>0 then 'synthetic-user'
                    when @noise then case when n>=@total-10 then 'fresh' else 'noise'||n::text end else 'synthetic-user' end as account,
                case when @stand then case when n<392 or n>=@total-10 then '192.0.2.1' else '192.0.2.'||(n%(@clients-1)+2)::text end
                    when @noise and n<@total-10 then '192.0.2.'||(n%@clients+1)::text else '192.0.2.1' end as ip
                from template,generate_series(1,@total-1) n),
            native as (select *,jsonb_set(jsonb_set(doc,'{properties,1}',to_jsonb(account)),
                '{properties,4}',to_jsonb(ip))||jsonb_build_object('record_id',n+1,'time_created',to_char(at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                'xml',replace(replace(replace(replace(doc->>'xml','<EventRecordID>1</EventRecordID>','<EventRecordID>'||(n+1)::text||'</EventRecordID>'),
                    doc->>'time_created',to_char(at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),'synthetic-user',account),'192.0.2.1',ip)) as representation from events)
            select n,900001+n as id,at,packet_id,representation,account,ip,sha256(convert_to(representation::text,'UTF8')) as hash,
                (row_number() over(partition by packet_id order by n)-1)::integer as ordinal from native;
            select public.create_event_storage_partitions((select min(at)::date from password_test_events),(select max(at)::date from password_test_events));
            insert into storage_v2_event_identity_allocations(id,server_id,channel_id,event_record_id,time_created_utc,normalized_hash)
                select e.id,900001,c.id,n+1,at,hash from password_test_events e cross join storage_v2_channel c where c.value='Security';
            insert into event_source_representations_v2(event_id,normalized_hash,identity_version,canonical_hash,representation,representation_sha256)
                select id,hash,2,hash,representation,hash from password_test_events;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                select r.agent_id,r.module_id,p.sequence+1,p.packet_id,r.envelope_sha256,r.envelope,r.receipt
                from sli_agent_receipts r cross join (select packet_id,min(n)/100+1 as sequence from password_test_events group by packet_id) p;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                select p.packet_id,i.envelope,i.packet,p.docs,now() from sli_agent_packet_inbox i cross join
                (select packet_id,jsonb_agg(representation order by n) as docs from password_test_events group by packet_id) p;
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
                select e.id,e.at,h.event_kind,h.domain_id,h.actor,h.target,h.source,h.computer,
                    h.method||jsonb_build_object('$packet_id',e.packet_id::text,'$packet_ordinal',e.ordinal,
                        '$principals',(h.method->'$principals')||jsonb_build_object('TargetUserName',e.account,'IpAddress',e.ip)),h.outcome,h.fields
                from password_test_events e cross join event_hot h order by e.at,e.id;
            analyze event_hot;
            """,db){CommandTimeout=0};
        seed.Parameters.AddWithValue("total",total);seed.Parameters.AddWithValue("spacing",spacing);seed.Parameters.AddWithValue("noise",noise);seed.Parameters.AddWithValue("clients",clients);seed.Parameters.AddWithValue("stand",standNoise);seed.Parameters.AddWithValue("missing",missingTargets);
        seed.Parameters.AddWithValue("accounts",accountCount??0);
        await seed.ExecuteNonQueryAsync(ct);
        await using var count=new NpgsqlCommand("select count(*),count(source_sha256) from event_hot where event_kind=4625",db);
        await using var r=await count.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
        Assert.Equal(total,r.GetInt64(0)); Assert.Equal(total,r.GetInt64(1));
    }
}
