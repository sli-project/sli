using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class ImportedTailDetectionPostgresTests
{
    [Fact]
    public async Task Week_old_imported_tail_creates_password_and_kerberoast_signals_and_problems_at_event_time()
    {
        var ct=TestContext.Current.CancellationToken;
        using var environment=new SemanticProducerPostgresTests.Admission();
        environment.Set("SLI_PLUGIN_LOCK_DIR",Path.Combine(SemanticProduction.SourceBundleRoot(null,AppContext.BaseDirectory),"config/plugin_packages/v3"));
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:357);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var at=new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-7).AddHours(1));
        var kinds=Enumerable.Repeat(4625,10).Concat(Enumerable.Repeat(4776,10)).Concat(Enumerable.Repeat(4769,5)).ToArray();
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,occurredAt:at,eventKinds:kinds);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await PostCollectionPostgres.Sql(owner,"update sli_agent_module_bindings set password_detection_domain_id=1",ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        async Task<JsonObject> Source() {
            await using var cmd=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
            return JsonNode.Parse((string)(await cmd.ExecuteScalarAsync(ct))!)!.AsObject();
        }
        var source=await Source(); var scope=PasswordScope.Read(source["scope"]); var rule=new PasswordRule(scope);
        await using(var tx=await worker.BeginTransactionAsync(ct)) {
            var old=await new PasswordSql(worker,tx).Rows("select * from public.read_default_password_window_v2(@s::jsonb)",ct,("s",scope.Document));
            Assert.Equal(0,old[0]["metadata"]!["candidate_count"]!.GetValue<int>());
            // An earlier empty cycle must not retain a wall-clock watermark
            // that would permanently discard the delayed import after upgrade.
            await new PasswordSql(worker,tx).Call("begin_password_attempt",ct,scope.Document,rule.Execution);
            await tx.CommitAsync(ct);
        }
        await PostCollectionPostgres.Sql(owner,"""
            update semantic_password_checkpoints set history_started=true,state_revision=1,watermark=now()-interval '120 seconds',
                state_document=jsonb_build_object('version','sli.password.v2.state.1','pin',pin,'epoch',0,
                    'watermark',public.password_v2_iso(now()-interval '120 seconds'),'window','[]'::jsonb,'episodes','[]'::jsonb);
            """,ct);
        string migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/362_detection_event_clock.sql");
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await using(var check=new NpgsqlCommand("select watermark is null and state_revision=1 from semantic_password_checkpoints",owner))
            Assert.Equal(true,await check.ExecuteScalarAsync(ct));
        // Provenance remains tied to the admitted packet and current scope.
        await using(var tx=await worker.BeginTransactionAsync(ct)) {
            var sql=new PasswordSql(worker,tx);
            var denied=await Assert.ThrowsAsync<PostgresException>(()=>sql.Rows("select public.password_event_clock362(@s::jsonb,@e::jsonb)",ct,
                ("s",(scope with {SourceGeneration="unbound"}).Document),("e",rule.Execution)));
            Assert.Equal("42501",denied.SqlState);
            await tx.RollbackAsync(ct);
        }
        // Keep the old store empty: all detector inputs must come from event_hot.
        var producer=new PasswordProducer();
        var password=await producer.RunAsync(worker,rule,ct);
        Assert.False(password.Failed,password.Diagnostic?.ToJsonString()); Assert.True(password.Jobs>0);
        await using(var tx=await worker.BeginTransactionAsync(ct)) {
            int jobs=await new IdentityAttackProducer().RunAsync(new DetectionSql(worker,tx),source,DateTimeOffset.UtcNow,ct);
            Assert.True(jobs>0); await tx.CommitAsync(ct);
        }
        var passwordRisk=await new PasswordRiskConsumer(runtime,new()).RunOnceAsync(ct);
        Assert.Equal(0,passwordRisk.Failed); Assert.True(passwordRisk.Published>0);
        var production=new SemanticProduction(runtime,SemanticRuntimeSettings.Read(Environment.GetEnvironmentVariable),SemanticRuntimeSettings.FindingsMode,128);
        var identityRisk=await production.ProcessRisk(worker,ct);
        Assert.Equal(0,identityRisk.Number("failed")); Assert.True(identityRisk.Number("published")>0);
        await using(var check=new NpgsqlCommand("""
            select rule_code,first_seen_utc::timestamptz,last_seen_utc::timestamptz from findings
            where rule_code in('semantic.qw.password-brute-force','semantic.qw.kerberoasting') order by rule_code
            """,owner))
        await using(var read=await check.ExecuteReaderAsync(ct)) {
            var codes=new HashSet<string>();
            while(await read.ReadAsync(ct)) { codes.Add(read.GetString(0)); Assert.Equal(at.UtcDateTime,read.GetDateTime(1)); Assert.Equal(at.UtcDateTime,read.GetDateTime(2)); }
            Assert.Contains("semantic.qw.password-brute-force",codes); Assert.Contains("semantic.qw.kerberoasting",codes);
        }
        var replay=await producer.RunAsync(worker,rule,ct);
        Assert.False(replay.Failed,replay.Diagnostic?.ToJsonString()); Assert.Equal(0,replay.Jobs);
        await using(var check=new NpgsqlCommand("select count(distinct (r.value->>'native_id')::bigint) from semantic_qw_signals s cross join lateral jsonb_array_elements(s.document_json->'evidence_refs') r(value) where (r.value->>'native_id')::bigint=any(@ids)",owner)) {
            check.Parameters.AddWithValue("ids",rows.Where(r=>r.Kind is 4625 or 4776).Select(r=>r.EventId).ToArray());
            Assert.Equal(20L,await check.ExecuteScalarAsync(ct));
        }
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        await using(var check=new NpgsqlCommand("select count(*)>0 from findings",owner)) Assert.Equal(true,await check.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
    }
}
