using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordProducerFailuresPostgresTests
{
    [Fact]
    public async Task Rereading_a_late_event_keeps_one_window_member_and_does_not_publish_jobs()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,eventKinds:[4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
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
        var producer=new PasswordProducer();var rules=new[]{new PasswordRule(scope),new PasswordRule(scope,"spray")};
        foreach(var rule in rules) {
            var first=await producer.RunAsync(worker,rule,ct);
            Assert.False(first.Failed,first.Diagnostic?.ToJsonString());Assert.Equal(0,first.Jobs);
        }
        // Admit a second native event behind the committed watermark through
        // the real receipt/inbox/provenance path, then reread its overlap.
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner,ct,total:2,spacing:-1);
        for(int cycle=0;cycle<2;cycle++)foreach(var rule in rules) {
            var replay=await producer.RunAsync(worker,rule,ct);
            Assert.False(replay.Failed,replay.Diagnostic?.ToJsonString());Assert.Equal("committed",replay.Status);Assert.Equal(0,replay.Jobs);
        }
        await using(var retained=new NpgsqlCommand("select count(*) from semantic_password_window_members where member_document->>'reason'='too_late'",owner))
            Assert.Equal(2L,await retained.ExecuteScalarAsync(ct));
        await using(var retained=new NpgsqlCommand("select count(*) from semantic_password_window_members",owner))Assert.Equal(4L,await retained.ExecuteScalarAsync(ct));
        await using(var events=new NpgsqlCommand("select count(*) from event_hot",owner))Assert.Equal(2L,await events.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Replacement_agent_with_late_domain_binding_produces_jobs_and_retries_busy_locks()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:368);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var host=new Guid("00000000-0000-4000-8000-000000000205");
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,
            eventKinds:Enumerable.Repeat(4625,10).Concat(Enumerable.Repeat(4776,10)).ToArray(),hostId:host);
        await PostCollectionPostgres.Sql(owner,"""
            insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,status,assigned_modules)
            values('00000000-0000-4000-8000-000000000206','00000000-0000-4000-8000-000000000206',repeat('d',64),'dc.example.test','replaced','[]');
            """,ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var source=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        Assert.Equal(host.ToString(),scope.SourceInstanceId);
        var rule=new PasswordRule(scope); var producer=new PasswordProducer();
        var unconfigured=await producer.RunAsync(worker,rule,ct);
        Assert.False(unconfigured.Failed); Assert.Equal("unconfigured",unconfigured.Status);
        // Registration/import happened first; bind via the existing explicit API.
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')::text",app);
            bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);
            Assert.Equal("configured",JsonNode.Parse((string)(await bind.ExecuteScalarAsync(ct))!)!["status"]!.GetValue<string>());
        }
        var result=await producer.RunAsync(worker,rule,ct);
        Assert.False(result.Failed,result.Diagnostic?.ToJsonString()); Assert.True(result.Jobs>0);
        var replay=await producer.RunAsync(worker,rule,ct);
        Assert.False(replay.Failed,replay.Diagnostic?.ToJsonString()); Assert.Equal(0,replay.Jobs);

        string migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/370_password_producer_failures.sql");
        string definitions=await Definitions(owner,ct),checkpoint=await Checkpoint(owner,ct);
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        foreach(string kind in new[]{"family","policy","admission","subscription","source","checkpoint","entity"}) {
            await using var blocker=await fixture.Pg.OpenAsync(ct);
            await using var tx=await blocker.BeginTransactionAsync(ct);
            string query=kind switch {
                "family"=>"select pg_advisory_xact_lock(hashtextextended(@family,0))",
                "source"=>"select pg_advisory_xact_lock(hashtextextended(encode(public.password_v2_scope_key(@scope::jsonb),'hex'),0))",
                "checkpoint"=>"select 1 from semantic_password_checkpoints where pin=@pin for update",
                "entity"=>"select pg_advisory_xact_lock(public.password_v2_entity_key(scope_digest,pin,entity)) from semantic_password_episode_budgets where pin=@pin",
                _=>"select 1 from "+(kind switch {"policy"=>"semantic_risk_policies","admission"=>"semantic_policy_admission",_=>"semantic_risk_policy_subscriptions"})+" where policy_id=@policy for update"
            };
            await using(var command=new NpgsqlCommand(query,blocker,tx)) {
                command.Parameters.AddWithValue("family",PasswordSignal.FamilyKey(scope,rule.Id));
                command.Parameters.AddWithValue("scope",NpgsqlTypes.NpgsqlDbType.Jsonb,scope.Document.ToJsonString());
                command.Parameters.AddWithValue("pin",rule.Pin); command.Parameters.AddWithValue("policy",PasswordSignal.PolicyId(rule));
                await command.ExecuteNonQueryAsync(ct);
            }
            var pending=producer.RunAsync(worker,rule,ct);
            try {
                // Observe a waiting backend directly, without a timing threshold.
                // Release our blocker even on regression so the test cannot hang.
                while(!pending.IsCompleted) {
                    await using var waiting=new NpgsqlCommand("select wait_event_type='Lock' from pg_stat_activity where pid=@pid",owner);
                    waiting.Parameters.AddWithValue("pid",worker.ProcessID);
                    Assert.NotEqual(true,await waiting.ExecuteScalarAsync(ct));
                    await Task.Yield(); ct.ThrowIfCancellationRequested();
                }
                var busy=await pending;
                Assert.False(busy.Failed,busy.Diagnostic?.ToJsonString()); Assert.Equal("busy",busy.Status);
                Assert.False(busy.FailureObserved); Assert.Equal(0,busy.Jobs);
                Assert.Equal("55P03",busy.Diagnostic!["sql_state"]!.GetValue<string>());
                Assert.Equal(checkpoint,await Checkpoint(owner,ct));
            } finally { await tx.RollbackAsync(ct); await pending; }
        }
        var retried=await producer.RunAsync(worker,rule,ct);
        Assert.False(retried.Failed,retried.Diagnostic?.ToJsonString()); Assert.Equal("committed",retried.Status); Assert.Equal(0,retried.Jobs);
        // A different generation still has no authority to read this source.
        var denied=await producer.RunAsync(worker,new PasswordRule(scope with{SourceGeneration="unbound"}),ct);
        Assert.True(denied.Failed); Assert.Equal("42501",denied.Diagnostic!["sql_state"]!.GetValue<string>());
        checkpoint=await Checkpoint(owner,ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        Assert.Equal(definitions,await Definitions(owner,ct)); Assert.Equal(checkpoint,await Checkpoint(owner,ct));
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        var reapplied=await producer.RunAsync(worker,rule,ct);
        Assert.False(reapplied.Failed,reapplied.Diagnostic?.ToJsonString()); Assert.Equal(0,reapplied.Jobs);
    }

    private static async Task<string> Checkpoint(NpgsqlConnection db,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("select (to_jsonb(c)-'active_token'-'last_attempt_at')::text from semantic_password_checkpoints c",db);
        return (string)(await command.ExecuteScalarAsync(ct))!;
    }
    private static async Task<string> Definitions(NpgsqlConnection db,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("""
            select jsonb_object_agg(oid::regprocedure::text,jsonb_build_object('definition',pg_get_functiondef(oid),'owner',proowner,'acl',proacl))::text
            from pg_proc where oid=any(array['public.password_policy_ensure_v275(text,integer,text)'::regprocedure,
                'public.password_v2_locked_checkpoint(jsonb,jsonb,boolean)'::regprocedure,
                'public.lock_password_reservation_entities_v2(jsonb,jsonb,bigint,bigint,text[])'::regprocedure])
            """,db);
        return (string)(await command.ExecuteScalarAsync(ct))!;
    }

    [Theory]
    [InlineData("password_v2_context_invalid")]
    [InlineData("password_v2_frozen_zero_unsupported")]
    [InlineData("password_v2_proposal_unavailable")]
    [InlineData("password_v2_successor_conflict")]
    public void Failure_log_contains_code_and_text_without_exception_payload(string code)
    {
        var diagnostics=new DetectionDiagnostics();
        diagnostics.Add(new InvalidOperationException("synthetic-private-event",new PasswordFailure(code)));
        var lines=new List<string>(); diagnostics.Write("password_producer",lines.Add);
        string line=Assert.Single(lines); var record=JsonNode.Parse(line[(line.IndexOf(':')+1)..])!;
        Assert.Equal(code,record["reason"]!.GetValue<string>()); Assert.NotEmpty(record["message"]!.GetValue<string>());
        Assert.DoesNotContain("synthetic-private-event",line);
        var unknown=DetectionDiagnostics.Describe(new PasswordFailure(code+": synthetic-private-event"),"source");
        Assert.Equal("operation_failed",unknown["reason"]!.GetValue<string>()); Assert.DoesNotContain("synthetic-private-event",unknown.ToJsonString());
    }

    [Theory]
    [InlineData((int)PasswordFailure.ContextCheck.Shape)]
    [InlineData((int)PasswordFailure.ContextCheck.EntityOrder)]
    [InlineData((int)PasswordFailure.ContextCheck.EntityFormat)]
    [InlineData((int)PasswordFailure.ContextCheck.MissingEntity)]
    [InlineData((int)PasswordFailure.ContextCheck.MissingBarrierEntity)]
    public void Context_failure_log_identifies_the_failed_check(int checkValue)
    {
        var check=(PasswordFailure.ContextCheck)checkValue;
        var record=DetectionDiagnostics.Describe(new PasswordFailure("password_v2_context_invalid"){Check=check},"prepare_password_producer_batch_v2");
        Assert.Equal("password_v2_context_invalid",record["reason"]!.GetValue<string>());
        Assert.Equal(check.ToString(),record["check"]!.GetValue<string>()); Assert.NotEmpty(record["message"]!.GetValue<string>());
    }
}
