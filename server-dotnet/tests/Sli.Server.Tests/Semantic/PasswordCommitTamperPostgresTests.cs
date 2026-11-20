using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordCommitTamperPostgresTests(ITestOutputHelper output)
{
    [Fact] public async Task Suffix_only_check_rejects_forged_claims_over_a_verified_prefix()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,occurredAt:DateTimeOffset.UtcNow.AddMinutes(-10),eventKinds:Enumerable.Repeat(4625,20).ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var source=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')",app);
            bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);await bind.ExecuteNonQueryAsync(ct);
        }
        var first=await new PasswordProducer().RunAsync(worker,new PasswordRule(scope),ct);
        Assert.False(first.Failed,first.Diagnostic?.ToJsonString());
        await PostCollectionPostgres.Sql(owner,"grant adlog_storage_owner to sli_semantic_login",ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_storage_owner",ct);
        await using(var count=new NpgsqlCommand("select count(*) from semantic_password_episode_budgets where last_sequence>0",owner)) Assert.True((long)(await count.ExecuteScalarAsync(ct))!>0);
        string[] forgeries=[
            // claim one more admitted sequence in this transaction without any new document
            "last_sequence=last_sequence+1,admission_xid=pg_current_xact_id(),admission_first_sequence=last_sequence+1",
            // claim the committed prefix but change its tail identity
            "last_emission_id=repeat('0',length(last_emission_id)),admission_xid=pg_current_xact_id(),admission_first_sequence=last_sequence+1",
            // shrink the reserved portion count the prefix fence relies on
            "reserved_portions=reserved_portions+1,admission_xid=pg_current_xact_id(),admission_first_sequence=last_sequence+1",
            "reserved_xml_bytes=reserved_xml_bytes+1,admission_xid=pg_current_xact_id(),admission_first_sequence=last_sequence+1"];
        foreach(var set in forgeries)foreach(bool immediateFirst in new[]{false,true}) {
            await using var tx=await worker.BeginTransactionAsync(ct);
            if(immediateFirst)await PostCollectionPostgres.Sql(worker,"update semantic_password_episode_budgets set tracking_through=tracking_through; set constraints all immediate; set constraints all deferred",ct);
            string update=$"update semantic_password_episode_budgets set {set} where episode_key=(select episode_key from semantic_password_episode_budgets where last_sequence>0 order by episode_key limit 1)";
            var error=await Assert.ThrowsAsync<PostgresException>(async()=>{await PostCollectionPostgres.Sql(worker,update,ct);await tx.CommitAsync(ct);});
            output.WriteLine($"{set} / immediateFirst={immediateFirst} -> {error.SqlState} {error.MessageText}");
            Assert.True(error.SqlState=="23514"||error.MessageText.StartsWith("password_v2_"),error.MessageText);
        }
        // Verified native portions stay immutable: tampering with a committed portion is refused outright.
        await using(var tx=await worker.BeginTransactionAsync(ct)) {
            await Assert.ThrowsAnyAsync<PostgresException>(()=>PostCollectionPostgres.Sql(worker,"update semantic_qw_signals set document_json=document_json||'{}'::jsonb",ct));
        }
        await using(var tx=await worker.BeginTransactionAsync(ct)) {
            await Assert.ThrowsAnyAsync<PostgresException>(()=>PostCollectionPostgres.Sql(worker,"delete from semantic_qw_signals",ct));
        }
        await fixture.Pg.DiagnosticsAsync(ct);
    }
}
