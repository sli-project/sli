using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordLiveFirstPostgresTests
{
    [Fact]
    public async Task Unconfigured_sources_do_not_create_checkpoint_or_fork_and_denied_sources_report_failure()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,occurredAt:DateTimeOffset.UtcNow.AddDays(-2),eventKinds:[4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var read=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await read.ExecuteScalarAsync(ct))!)!["scope"]);
        var poller=new PasswordProducerPoller(runtime,new(),new(new(),new()));
        var unconfigured=Assert.Single(await poller.RunSourceAsync(scope,ct));
        Assert.Equal("unconfigured",unconfigured.Status);
        Assert.False(unconfigured.Failed);
        await using var noArtifacts=new NpgsqlCommand("""
            select not exists(select 1 from public.semantic_password_checkpoints)
               and not exists(select 1 from public.password_passes388)
               and not exists(select 1 from public.semantic_control_audit where action='password_live_first')
            """,owner);
        Assert.Equal(true,await noArtifacts.ExecuteScalarAsync(ct));

        var denied=Assert.Single(await poller.RunSourceAsync(scope with { SourceInstanceId="unbound-synthetic-dc" },ct));
        Assert.True(denied.Failed);
        Assert.Equal("42501",denied.Diagnostic?["sql_state"]?.GetValue<string>());
        Assert.Equal("password_producer_source382",denied.Diagnostic?["step"]?.GetValue<string>());
        Assert.DoesNotContain("unbound-synthetic-dc",denied.Diagnostic!.ToJsonString());
        Assert.Equal(true,await noArtifacts.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task Upgrade_preserves_second_legacy_finding_when_its_episode_gains_evidence()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();
        await fixture.StartAsync(ct,throughVersion:387);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var now=DateTimeOffset.UtcNow;
        var times=Enumerable.Range(0,10).Select(i=>now.AddMinutes(-20).AddSeconds(i))
            .Concat(Enumerable.Range(0,11).Select(i=>now.AddMinutes(-4).AddSeconds(i))).ToArray();
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,eventKinds:times.Select(_=>4625).ToArray(),
            nativeTimestamps:times.Select(t=>t.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")).ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows[..^1],ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var read=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await read.ExecuteScalarAsync(ct))!)!["scope"]);
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')",app);
            bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);
            await bind.ExecuteNonQueryAsync(ct);
        }
        var producer=new PasswordProducer();var rule=new PasswordRule(scope);
        var initial=await producer.RunAsync(worker,rule,ct);
        Assert.False(initial.Failed,initial.Diagnostic?.ToJsonString());
        Assert.Equal(2,initial.Jobs);
        var consumer=new PasswordRiskConsumer(runtime,new());
        var legacy=await consumer.RunOnceAsync(ct);
        Assert.Equal(0,legacy.Failed);Assert.Equal(2,legacy.Published);
        async Task<(Guid Scenario,long Finding,int Evidence)[]> Publications()
        {
            await using var query=new NpgsqlCommand("""
                select p.scenario_id,p.finding_id,f.evidence_count
                from semantic_finding_publications p join semantic_security_scenarios s using(scenario_id)
                join findings f on f.id=p.finding_id order by s.first_seen_utc,p.scenario_id
                """,owner);
            await using var reader=await query.ExecuteReaderAsync(ct);
            var result=new List<(Guid,long,int)>();
            while(await reader.ReadAsync(ct))result.Add((reader.GetGuid(0),reader.GetInt64(1),reader.GetInt32(2)));
            return result.ToArray();
        }
        var before=await Publications();
        Assert.Equal(2,before.Length);Assert.NotEqual(before[0].Finding,before[1].Finding);
        var migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/388_password_live_first.sql");
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,[rows[^1]],ct);
        var next=await producer.RunAsync(worker,rule,ct);
        Assert.False(next.Failed,next.Diagnostic?.ToJsonString());Assert.Equal(1,next.Jobs);
        var continued=await consumer.RunOnceAsync(ct);
        Assert.Equal(0,continued.Failed);Assert.Equal(1,continued.Published);
        Assert.Equal(new[]{before[0],(before[1].Scenario,before[1].Finding,before[1].Evidence+1)},await Publications());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory] [InlineData(384)] [InlineData(385)] [InlineData(386)] [InlineData(387)]
    public async Task Upgrade_preserves_old_checkpoint_and_live_seam_and_history_attacks_are_proved(int version)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:version);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var now=DateTimeOffset.UtcNow;now=now.AddTicks(-now.Ticks%TimeSpan.TicksPerSecond);
        var oldTimes=new[]{now.AddDays(-2)}
            .Concat(Enumerable.Range(0,10).Select(i=>now.AddDays(-2).AddMinutes(30).AddSeconds(i)))
            .Concat(Enumerable.Range(0,5).Select(i=>now.AddDays(-2).AddMinutes(31).AddSeconds(i))).ToArray();
        var oldAccounts=new[]{"marker"}.Concat(Enumerable.Repeat("history",10))
            .Concat(Enumerable.Range(0,5).Select(i=>"spray"+i)).ToArray();
        string[] NativeTimes(IEnumerable<DateTimeOffset> timestamps)=>timestamps
            .Select(at=>at.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")).ToArray();
        var oldRows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,eventKinds:oldTimes.Select(_=>4625).ToArray(),
            nativeTimestamps:NativeTimes(oldTimes),nativeAccounts:oldAccounts);
        // Establish the old checkpoint through the installed producer, without
        // changing the checkpoint, token or episode state directly.
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,[oldRows[0]],ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var read=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await read.ExecuteScalarAsync(ct))!)!["scope"]);
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')",app);
            bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);await bind.ExecuteNonQueryAsync(ct);
        }
        // More than one old event is needed to stop the event clock at history.
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,oldRows[1..],ct);
        var producer=new PasswordProducer();var old=new PasswordRule(scope);
        var first=await producer.RunAsync(worker,old,ct);Assert.False(first.Failed,first.Diagnostic?.ToJsonString());
        var sprayFirst=await producer.RunAsync(worker,new(scope,"spray"),ct);Assert.False(sprayFirst.Failed,sprayFirst.Diagnostic?.ToJsonString());
        foreach(var rule in new[]{old,new PasswordRule(scope,"spray")}) {
            var qualified=await producer.RunAsync(worker,rule,ct);Assert.False(qualified.Failed,qualified.Diagnostic?.ToJsonString());
        }
        await PostCollectionPostgres.Sql(owner,"""
            insert into auth_users(username,password_hash,role) values
                ('synthetic-revised','synthetic-unusable-hash','admin'),
                ('synthetic-cancelled','synthetic-unusable-hash','admin'),
                ('synthetic-new','synthetic-unusable-hash','admin');
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
                select case when username='platform-owner' then 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid else gen_random_uuid() end,
                    id,id,'telegram',true from auth_users
                where username in ('platform-owner','synthetic-revised','synthetic-cancelled');
            """,ct);
        var oldFindings=await new PasswordRiskConsumer(runtime,new()).RunOnceAsync(ct);
        Assert.Equal(0,oldFindings.Failed);Assert.True(oldFindings.Published>0);
        // An administrator closed yesterday's finding before today's attack.
        await using(var close=new NpgsqlCommand("""
            update findings set status='closed',closed_at=@closed;
            insert into finding_status_history(finding_id,old_status,new_status,changed_by,changed_at,note)
                select id,'new','closed','synthetic-admin',@closed,'synthetic resolution' from findings;
            """,owner)) {
            close.Parameters.AddWithValue("closed",now.AddDays(-1));await close.ExecuteNonQueryAsync(ct);
        }
        async Task<string> Checkpoint() {
            await using var cmd=new NpgsqlCommand("select to_jsonb(c)::text from semantic_password_checkpoints c where pin=@pin",owner);
            cmd.Parameters.AddWithValue("pin",old.Pin);return (string)(await cmd.ExecuteScalarAsync(ct))!;
        }
        var before=await Checkpoint();
        foreach(var file in MigrationDirectory.Read(version+1).Where(file=>file.Version<=388))
            await fixture.Pg.ApplyFileAsync(file.Path,null,ct);
        var path=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/388_password_live_first.sql");
        // No fork used yet: migration rollback restores definitions/ACLs without
        // modifying the legacy checkpoint, then the previous maximum reapplies.
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path,".rollback.sql"),null,ct);
        Assert.Equal(before,await Checkpoint());await fixture.Pg.ApplyFileAsync(path,null,ct);
        await using var planQuery=new NpgsqlCommand("select public.password_plan388(@s::jsonb,@r)::text",worker);
        planQuery.Parameters.AddWithValue("s",scope.Document.ToJsonString());planQuery.Parameters.AddWithValue("r",old.Id);
        // Plan both rules with the same database statement timestamp and stamp
        // synthetic rows relative to the seam that migration 388 actually chose.
        await using var planBoth=new NpgsqlCommand("""
            select jsonb_build_object('brute',public.password_plan388(@s::jsonb,'qw.password-brute-force'),
                'spray',public.password_plan388(@s::jsonb,'qw.password-spray'))::text
            """,worker);
        planBoth.Parameters.AddWithValue("s",scope.Document.ToJsonString());
        var plans=JsonNode.Parse((string)(await planBoth.ExecuteScalarAsync(ct))!)!;
        var live=new PasswordRule(scope,revision:plans["brute"]!["live"]!["rule_version"]!.GetValue<int>());
        var liveSpray=new PasswordRule(scope,"spray",plans["spray"]!["live"]!["rule_version"]!.GetValue<int>());
        Assert.NotEqual(old.Pin,live.Pin);
        Assert.NotEmpty(plans["brute"]!["catchup"]!.AsArray());Assert.NotEmpty(plans["spray"]!["catchup"]!.AsArray());
        Assert.Equal(before,await Checkpoint());
        await using var readSeams=new NpgsqlCommand("select live_from from password_passes388 where live_pin=any(@pins) order by live_from",owner);
        readSeams.Parameters.AddWithValue("pins",new[]{live.Pin,liveSpray.Pin});
        DateTimeOffset seam;
        await using(var seams=await readSeams.ExecuteReaderAsync(ct)) {
            Assert.True(await seams.ReadAsync(ct));seam=seams.GetFieldValue<DateTimeOffset>(0);
            Assert.True(await seams.ReadAsync(ct));Assert.Equal(seam,seams.GetFieldValue<DateTimeOffset>(0));
            Assert.False(await seams.ReadAsync(ct));
        }
        const int seamSprayStart=20, seamSpraySize=5;
        const string seamSprayAddress="192.0.2.9";
        var times=Enumerable.Range(0,9).Select(i=>seam.AddSeconds(-110+i)).Append(seam.AddSeconds(40))
            .Concat(Enumerable.Range(0,10).Select(i=>seam.AddSeconds(240+i)))
            .Concat(Enumerable.Range(0,5).Select(i=>seam.AddSeconds(i<4?-90+i:150)))
            .Concat(Enumerable.Range(0,5).Select(i=>seam.AddSeconds(240+i)))
            .Append(seam.AddSeconds(100))
            .Concat(Enumerable.Range(0,10).Select(i=>seam.AddSeconds(-60+i))).ToArray();
        Assert.True(times[8]<seam&&seam<times[9]);
        Assert.True(times[seamSprayStart+3]<seam&&seam<times[seamSprayStart+4]);
        var accounts=Enumerable.Repeat("seam",10).Concat(Enumerable.Repeat("history",10))
            .Concat(Enumerable.Range(0,10).Select(i=>"spray"+(i%5))).Append("pre-spray-marker")
            .Concat(Enumerable.Repeat("overlap",10)).ToArray();
        var addresses=times.Select((_,i)=>i>=seamSprayStart&&i<seamSprayStart+seamSpraySize?seamSprayAddress:"192.0.2.1").ToArray();
        Guid agent=ShortEventAdmissionPostgresTests.Agent;
        var liveRows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,eventKinds:times.Select(_=>4625).ToArray(),
            registered:(agent,agent,900001,1),nativeTimestamps:NativeTimes(times),nativeAccounts:accounts,nativeAddresses:addresses,
            packetId:new Guid("00000000-0000-4000-8000-000000003491"),sequence:2,firstRecordId:oldRows.Length+1);
        bool BeforeFifth(int i)=>times[i]<times[seamSprayStart+4];
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,liveRows.Where((_,i)=>BeforeFifth(i)).ToArray(),ct);
        var current=await producer.RunAsync(worker,live,ct);Assert.False(current.Failed,current.Diagnostic?.ToJsonString());Assert.True(current.Jobs>0);
        Assert.Equal(before,await Checkpoint());
        var early=await producer.RunAsync(worker,liveSpray,ct);Assert.False(early.Failed,early.Diagnostic?.ToJsonString());
        var consumer=new PasswordRiskConsumer(runtime,new());
        var earlyFindings=await consumer.RunOnceAsync(ct);Assert.Equal(0,earlyFindings.Failed);
        string seamSprayEntity=PasswordJson.Hash(new JsonArray("ip",seamSprayAddress));
        string seamBruteEntity=PasswordJson.Hash(new JsonArray("ip",PasswordJson.Hash(new JsonArray("ip","192.0.2.1")),
            PasswordJson.Hash(new JsonArray("example.test","seam"))));
        async Task<long> SeamFindingCount(string rule,string entity)
        {
            await using var query=new NpgsqlCommand("""
                select count(distinct p.finding_id) from semantic_finding_publications p
                join semantic_security_scenarios s using(scenario_id)
                where s.scenario_kind=@rule and s.strict_keys_json->>'entity'=@entity
                """,owner);
            query.Parameters.AddWithValue("rule",rule);query.Parameters.AddWithValue("entity",entity);
            return (long)(await query.ExecuteScalarAsync(ct))!;
        }
        Assert.Equal(0L,await SeamFindingCount(liveSpray.Id,seamSprayEntity));
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,liveRows.Where((_,i)=>!BeforeFifth(i)).ToArray(),ct);
        var latest=await producer.RunAsync(worker,live,ct);Assert.False(latest.Failed,latest.Diagnostic?.ToJsonString());
        Assert.True(PasswordJson.Time(latest.Work!["watermark"])>=times.Max());
        var spray=await producer.RunAsync(worker,liveSpray,ct);Assert.False(spray.Failed,spray.Diagnostic?.ToJsonString());Assert.True(spray.Jobs>0);
        await using(var seamProof=new NpgsqlCommand("""
            select distinct (ref->>'native_id')::bigint as native_id from semantic_qw_signals signal
            cross join lateral jsonb_array_elements(signal.document_json->'evidence_refs') ref
            where signal.document_json->>'rule_id'='qw.password-spray'
                and signal.document_json->>'entity_key'=@entity and signal.document_json->'rule_version'>'2'::jsonb
            order by native_id
            """,owner)) {
            seamProof.Parameters.AddWithValue("entity",seamSprayEntity);
            var actual=new List<long>();await using var proof=await seamProof.ExecuteReaderAsync(ct);
            while(await proof.ReadAsync(ct))actual.Add(proof.GetInt64(0));
            Assert.Equal(liveRows.Skip(seamSprayStart).Take(seamSpraySize).Select(row=>row.EventId),actual);
        }
        // Inspect immutable admitted native proof, not text/source shape.
        await using(var signals=new NpgsqlCommand("select document_json::text from semantic_qw_signals where document_json->'rule_version'>'2'::jsonb",owner)) {
            await using var reader=await signals.ExecuteReaderAsync(ct);var refs=new HashSet<string>();
            while(await reader.ReadAsync(ct)) {
                var signal=PasswordRiskSignal.Read(JsonNode.Parse(reader.GetString(0))!.AsObject());
                refs.UnionWith(signal.Witnesses.Select(w=>w.NativeId.ToString()));
            }
            Assert.Contains(liveRows[0].EventId.ToString(),refs);Assert.Contains(liveRows[9].EventId.ToString(),refs);Assert.Contains(liveRows[^1].EventId.ToString(),refs);
        }
        await using(var status=new NpgsqlCommand("select public.password_catchup_status388()::text",worker))Assert.NotNull(await status.ExecuteScalarAsync(ct));
        var liveFindings=await consumer.RunOnceAsync(ct);Assert.Equal(0,liveFindings.Failed);Assert.True(liveFindings.Published>0);
        Assert.Equal(1L,await SeamFindingCount(liveSpray.Id,seamSprayEntity));
        Assert.Equal(1L,await SeamFindingCount(live.Id,seamBruteEntity));
        await using(var repeated=new NpgsqlCommand("select exists(select 1 from findings where status='repeated' and closed_at is null and repeat_count>0)",owner))
            Assert.Equal(true,await repeated.ExecuteScalarAsync(ct));
        // A revised subscription, a cancelled job, and a new recipient do not
        // acquire coverage merely because the owner has a pending delivery.
        await PostCollectionPostgres.Sql(owner,"""
            update notification_outbox set state='accepted',result_code='accepted'
            where recipient_user_id=(select id from auth_users where username='synthetic-revised');
            update notification_subscriptions set revision=revision+1
            where recipient_user_id=(select id from auth_users where username='synthetic-revised');
            update notification_outbox set state='cancelled',result_code='subscription_changed'
            where recipient_user_id=(select id from auth_users where username='synthetic-cancelled');
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
                select gen_random_uuid(),id,id,'telegram',true from auth_users where username='synthetic-new';
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
                select '00000000-0000-4000-8000-000000000001',id,id,'telegram',true from auth_users where username='platform-owner';
            """,ct);
        // Closing the current problem must survive older catch-up publications.
        await PostCollectionPostgres.Sql(owner,"update findings set status='closed',closed_at=clock_timestamp()",ct);
        foreach(string kind in new[]{"brute","spray"}) {
            var historyRule=new PasswordRule(scope,kind);planQuery.Parameters["r"].Value=historyRule.Id;
            var pending=JsonNode.Parse((string)(await planQuery.ExecuteScalarAsync(ct))!);
            while(pending!["catchup"]!.AsArray().Count>0) {
                var next=await producer.RunAsync(worker,historyRule,ct);Assert.False(next.Failed,next.Diagnostic?.ToJsonString());
                pending=JsonNode.Parse((string)(await planQuery.ExecuteScalarAsync(ct))!);
            }
        }
        await using(var status=new NpgsqlCommand("select public.password_catchup_status388() is null",worker))Assert.Equal(true,await status.ExecuteScalarAsync(ct));
        await using(var history=new NpgsqlCommand("select exists(select 1 from semantic_qw_signals where document_json->'rule_version'='2'::jsonb and (document_json#>>'{password_context,occurrences,0,0}') is not null)",owner))Assert.Equal(true,await history.ExecuteScalarAsync(ct));
        await using(var audit=new NpgsqlCommand("select details->>'previous_watermark' from semantic_control_audit where action='password_live_first'",owner))Assert.NotNull(await audit.ExecuteScalarAsync(ct));
        var historicalFindings=await consumer.RunOnceAsync(ct);Assert.Equal(0,historicalFindings.Failed);Assert.True(historicalFindings.Published>0);
        Assert.Equal(1L,await SeamFindingCount(liveSpray.Id,seamSprayEntity));
        Assert.Equal(1L,await SeamFindingCount(live.Id,seamBruteEntity));
        await using(var closed=new NpgsqlCommand("select bool_and(status='closed') from findings",owner))Assert.Equal(true,await closed.ExecuteScalarAsync(ct));
        await using(var dedup=new NpgsqlCommand("""
            select bool_and(n=1) from (
                select s.partition_key,s.scenario_kind,s.strict_keys_json->>'entity',count(distinct p.finding_id) n
                from semantic_finding_publications p join semantic_security_scenarios s using(scenario_id)
                group by s.partition_key,s.scenario_kind,s.strict_keys_json->>'entity') grouped
            """,owner))Assert.Equal(true,await dedup.ExecuteScalarAsync(ct));
        await using(var shared=new NpgsqlCommand("select exists(select 1 from semantic_finding_publications group by finding_id having count(*)>1)",owner))
            Assert.Equal(true,await shared.ExecuteScalarAsync(ct));
        // An episode proved by both passes is linked twice, but only one delivery
        // is queued. Distant episodes of the same entity still each get a delivery.
        await using(var notifications=new NpgsqlCommand("""
            with proof as (
                select distinct p.scenario_id,p.finding_id,ref->>'native_id' as native_id
                from semantic_finding_publications p join semantic_scenario_steps st using(scenario_id)
                join semantic_qw_signals s on s.signal_id=st.qw_signal_id
                cross join lateral jsonb_array_elements(s.document_json->'evidence_refs') ref
                where s.document_json->>'rule_id'='qw.password-brute-force'
            )
            select count(distinct p.scenario_id),count(distinct n.id),count(distinct p.finding_id)
            from proof p left join notification_outbox n on n.publication_scenario_id=p.scenario_id
                and n.channel='telegram' and n.state='pending'
                and n.recipient_user_id=(select id from auth_users where username='platform-owner')
            where p.native_id=any(@native_ids)
            """,owner)) {
            notifications.Parameters.AddWithValue("native_ids",new[]{liveRows[^1].EventId.ToString()});
            await using(var reader=await notifications.ExecuteReaderAsync(ct)) {
                Assert.True(await reader.ReadAsync(ct));
                Assert.Equal(2L,reader.GetInt64(0));Assert.Equal(1L,reader.GetInt64(1));Assert.Equal(1L,reader.GetInt64(2));
            }
            notifications.Parameters["native_ids"].Value=new[]{oldRows[10].EventId.ToString(),liveRows[19].EventId.ToString()};
            await using var distinct=await notifications.ExecuteReaderAsync(ct);
            Assert.True(await distinct.ReadAsync(ct));
            Assert.True(distinct.GetInt64(0)>=2);Assert.Equal(2L,distinct.GetInt64(1));Assert.Equal(1L,distinct.GetInt64(2));
        }
        await using(var subscriptions=new NpgsqlCommand("""
            select u.username,n.subscription_revision,n.state,count(*)
            from notification_outbox n join auth_users u on u.id=n.recipient_user_id
            where n.channel='telegram' and exists(
                select 1 from semantic_scenario_steps st join semantic_qw_signals s on s.signal_id=st.qw_signal_id
                cross join lateral jsonb_array_elements(s.document_json->'evidence_refs') ref
                where st.scenario_id=n.publication_scenario_id and s.document_json->>'rule_id'='qw.password-brute-force'
                    and ref->>'native_id'=@native_id)
            group by u.username,n.subscription_revision,n.state order by u.username,n.subscription_revision,n.state
            """,owner)) {
            subscriptions.Parameters.AddWithValue("native_id",liveRows[^1].EventId.ToString());
            var actual=new List<(string,long,string,long)>();
            await using var reader=await subscriptions.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct))actual.Add((reader.GetString(0),reader.GetInt64(1),reader.GetString(2),reader.GetInt64(3)));
            Assert.Equal(new[]{("platform-owner",1L,"pending",1L),("synthetic-cancelled",1L,"cancelled",1L),
                ("synthetic-cancelled",1L,"pending",1L),("synthetic-new",1L,"pending",1L),
                ("synthetic-revised",1L,"accepted",1L),("synthetic-revised",2L,"pending",1L)},actual);
        }
        await using(var count=new NpgsqlCommand("select count(*) from event_hot",owner))Assert.Equal((long)oldRows.Length+liveRows.Length,await count.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
