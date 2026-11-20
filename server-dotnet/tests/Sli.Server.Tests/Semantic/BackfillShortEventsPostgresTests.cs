using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class BackfillShortEventsPostgresTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("true")]
    [InlineData("false")]
    public async Task Short_path_never_queues_an_exclusive_lock_between_packet_imports(string? setting)
    {
        var ct=TestContext.Current.CancellationToken;
        using var environment=new SemanticProducerPostgresTests.Admission();
        environment.Set("Sli__Storage__ShortEventReads",setting);
        environment.Set("Sli:Storage:ShortEventReads",null);
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct);
        await using var first=await fixture.Pg.OpenAsync(ct);
        await using var firstTx=await first.BeginTransactionAsync(ct);
        await SemanticProducer.LockImportAsync(first,firstTx,ct);
        await using var producer=new NpgsqlConnection(fixture.Dsn("sli_semantic_login")); await producer.OpenAsync(ct);
        await PostCollectionPostgres.Sql(producer,"set role adlog_semantic_worker",ct);

        // An exclusive request would queue behind firstTx and block the next
        // shared importer. Observe lock requests, without asserting elapsed time.
        var backfill=SemanticProducerBackfill.RunAsync(producer,SemanticRuntimeSettings.FindingsMode,1024,ct);
        bool requested=false;
        try {
            await using var locks=new NpgsqlCommand("select exists(select 1 from pg_locks where pid=$1 and locktype='advisory')",owner);
            locks.Parameters.AddWithValue(producer.ProcessID);
            while(!backfill.IsCompleted) {
                if(await locks.ExecuteScalarAsync(ct) is true) { requested=true; break; }
                ct.ThrowIfCancellationRequested(); await Task.Yield();
            }
            Assert.False(requested,"Backfill queued an advisory lock behind the importing packet");
            var skipped=await backfill;
            Assert.Equal("short_events",skipped.Text("status"));
            Assert.Equal(0,skipped.Number("scanned")); Assert.Equal(0,skipped.Number("queued"));
            Assert.Equal(false,await locks.ExecuteScalarAsync(ct));

            await using var next=new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await next.OpenAsync(ct);
            await using var nextTx=await next.BeginTransactionAsync(ct);
            await PostCollectionPostgres.Sql(next,"set local role adlog_storage_worker",ct);
            await SemanticProducer.LockImportAsync(next,nextTx,ct);
            await ShortEventWriter.WriteAsync(next,nextTx,rows,ct);
            await nextTx.CommitAsync(ct);
            // The first packet still holds its shared lock when the second commits.
            await using var count=new NpgsqlCommand("select count(*) from event_hot",owner);
            Assert.Equal((long)rows.Length,await count.ExecuteScalarAsync(ct));
        }
        finally {
            await firstTx.RollbackAsync(CancellationToken.None);
            await backfill;
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

}
