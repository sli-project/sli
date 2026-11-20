using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Semantic;
using Xunit;

namespace Sli.Server.Tests.Storage;

// tests/storage/test_semantic_facts_publication.py: exercise the actual Storage V2
// publisher, including its optimized scalar-read path, with the native worker ACL.
[Collection("Semantic producer environment")]
public sealed class SemanticFactsPublicationTests
{
    [Theory]
    [InlineData("facts-v1", 4624, "explicit_context")]
    [InlineData("investigation-v1", 4625, "signal")]
    [InlineData("findings-v1", 4624, null)]
    public async Task V2_publication_uses_the_admitted_mode_selection(string mode, int eventKey, string? reason)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        var sources=await ShortEventAdmissionPostgresTests.SeedAsync(admin,ct);
        var source=sources.Single(x=>x.Kind==eventKey);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,[source],ct);
        using var admission = new SemanticProducerPostgresTests.Admission(mode);
        await using var worker = new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker, "set role adlog_storage_worker", ct);
        await using (var tx = await worker.BeginTransactionAsync(ct)) {
            await SemanticProducer.PublishAsync(worker, tx, [source.EventId], ct);
            await tx.CommitAsync(ct);
        }
        await using (var check = new NpgsqlCommand("select source_event_id,job_kind,payload_json->>'selection_reason' from semantic_processing_outbox order by source_event_id", admin))
        await using (var rows = await check.ExecuteReaderAsync(ct)) {
            if (reason is null) Assert.False(await rows.ReadAsync(ct));
            else {
                Assert.True(await rows.ReadAsync(ct)); Assert.Equal(source.EventId, rows.GetInt64(0));
                Assert.Equal("normalize_event", rows.GetString(1)); Assert.Equal(reason, rows.GetString(2));
                Assert.False(await rows.ReadAsync(ct));
            }
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task V2_publication_stays_off_without_production_admission()
    {
        using var admission = new SemanticProducerPostgresTests.Admission(null);
        admission.Set("ADLOG_SEMANTIC_ASSEMBLY_ENABLED", "0");
        Assert.Null(SemanticProducer.RuntimeMode());
        // A closed connection proves that an OFF publisher performs no import SQL.
        await using var db = new NpgsqlConnection();
        await SemanticProducer.PublishAsync(db, null!, [12], TestContext.Current.CancellationToken);
        Assert.Equal(System.Data.ConnectionState.Closed, db.State);
    }

    [Theory]
    [InlineData(false, true, false, "semantic production admission is required")]
    [InlineData(true, false, false, "semantic feature chain differs from admitted mode")]
    [InlineData(true, true, true, "facts mode forbids raw downstream flags")]
    public async Task Invalid_facts_publication_is_refused_before_any_import(bool admitted, bool assembly, bool risk, string error)
    {
        using var admission = new SemanticProducerPostgresTests.Admission(SemanticRuntimeSettings.FactsMode);
        admission.Set("ADLOG_SEMANTIC_PRODUCTION_ENABLED", admitted ? "1" : "0");
        admission.Set("ADLOG_SEMANTIC_ASSEMBLY_ENABLED", assembly ? "1" : "0");
        // Correlation is OFF, so this raw risk flag is masked by Read() and must
        // still be rejected by the facts-mode admission guard.
        admission.Set("ADLOG_SEMANTIC_RISK_ENGINE_ENABLED", risk ? "1" : "0");
        await using var db = new NpgsqlConnection();
        var rejected = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            SemanticProducer.PublishAsync(db, null!, [12], TestContext.Current.CancellationToken));
        Assert.Equal(error, rejected.Message);
        Assert.Equal(System.Data.ConnectionState.Closed, db.State);
    }
}
