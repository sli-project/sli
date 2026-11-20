using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed partial class AdDcImportPerformanceTests
{
    [Fact]
    public async Task Late_reserved_DC_packets_publish_and_replay_without_old_link_blocks()
    {
        using var environment=new Sli.Server.Tests.Semantic.SemanticProducerPostgresTests.Admission(mode:null);
        environment.Set("Sli__Storage__ShortEventReads","false");
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString);await admin.OpenAsync(ct);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        await SeedAsync(admin,fixture.Pg.Root,cert,ct);
        await PostCollectionPostgres.Sql(admin,"select setval('entities_v2_id_seq',1001,false); select setval('storage_v2_event_id_seq',2,false)",ct);
        await using var worker=new NpgsqlDataSourceBuilder(fixture.Dsn("sli_storage_login")).Build();
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user"));await app.OpenAsync(ct);
        string catalog=Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json");
        async Task Import(Packet packet,bool receipt=true) {
            if(receipt)await ReceiptAsync(admin,packet,ct);
            await using var tx=await app.BeginTransactionAsync(ct);
            await ImportAsync(app,tx,worker,packet,catalog,ct);await tx.CommitAsync(ct);
        }
        await Import(Sample(2,768));
        long server;int channel;
        await using(var query=new NpgsqlCommand("select s.id,c.id from servers s cross join storage_v2_channel c where s.hostname=@source and c.value='Security'",admin)) {
            query.Parameters.AddWithValue("source",Source);await using var reader=await query.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct));server=reader.GetInt64(0);channel=reader.GetInt32(1);
        }
        var first=Sample(1);var middle=Sample(770);
        // Reserve older identities without publication, as when a worker fails and a newer packet wins.
        async Task Reserve(Packet packet,long expected) {
            var input=Assert.Single(DirectAdDcPacket.PrepareBatch(packet.Rows));
            await using var tx=await app.BeginTransactionAsync(ct);
            var authorization=await DirectRuntimeAuthorization.LoadAsync(app,tx,DateTime.UtcNow,ct);
            Assert.NotNull(authorization);
            var reservation=await DirectEventIdentityStore.ReserveAsync(authorization,worker,server,channel,
                input.Row["record_id"]!.GetValue<long>(),input.Time,input.Row,input.Projection.IdentityHash,ct);
            Assert.Equal(expected,reservation.Id);Assert.False(reservation.Published);await tx.CommitAsync(ct);
        }
        await PostCollectionPostgres.Sql(admin,"select setval('storage_v2_event_id_seq',1,false)",ct);
        await Reserve(first,1);
        await PostCollectionPostgres.Sql(admin,"select setval('storage_v2_event_id_seq',770,false)",ct);
        await Reserve(middle,770);
        await Import(Sample(771,768));
        await Import(middle);await Import(first);
        await Import(middle,false);await Import(first,false);
        await using var counts=new NpgsqlCommand("""
            select (select count(*) from event_hot),(select sum(event_count)::bigint from event_cold_daily)
            """,admin);
        await using var result=await counts.ExecuteReaderAsync(ct);Assert.True(await result.ReadAsync(ct));
        Assert.Equal(1538L,result.GetInt64(0));Assert.Equal(1538L,result.GetInt64(1));
        await result.DisposeAsync();
        await AssertLegacyStoreRetiredAsync(admin,ct);
        await AssertReadbackIntegrityAsync(admin,ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
