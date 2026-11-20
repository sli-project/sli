using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Consumer;
using Sli.Server.Storage.Direct;
using Sli.Server.Entities.State;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Semantic;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed partial class AdDcImportPerformanceTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("true")]
    [InlineData("false")]
    public async Task Short_import_skips_link_blocks_and_replays_without_duplicate_events(string? setting)
    {
        var ct=TestContext.Current.CancellationToken;
        using var environment=new SemanticProducerPostgresTests.Admission(mode:null);
        environment.Set("Sli__Storage__ShortEventReads",setting);
        environment.Set("Sli:Storage:ShortEventReads",null);
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        await SeedAsync(admin,fixture.Pg.Root,cert,ct);
        await AssertLegacyStoreRetiredAsync(admin, ct);
        using var profile=new CommandProfile(output);
        using var logging=LoggerFactory.Create(b=>b.SetMinimumLevel(LogLevel.Debug).AddProvider(profile));
        await using var worker=new NpgsqlDataSourceBuilder(fixture.Dsn("sli_storage_login")).UseLoggerFactory(logging).Build();
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        string catalog=Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json");
        var sample=Sample(1,25,4720); await ReceiptAsync(admin,sample,ct);
        // Both deliveries use the retained JSONB representation, like the poller.
        await using (var retained=new NpgsqlCommand("select event_rows::text from sli_agent_packet_inbox where packet_id=@packet",admin)) {
            retained.Parameters.AddWithValue("packet",Guid.Parse(sample.Envelope["packet_id"]!.GetValue<string>()));
            sample=sample with { Rows=JsonNode.Parse((string)(await retained.ExecuteScalarAsync(ct))!)!.AsArray() };
        }
        var steps=new List<AdDcProjectionStep>();
        string? first=null;
        for(int replay=0;replay<2;replay++) {
            profile.Commands.Clear(); profile.Enabled=true;
            var watch=Stopwatch.StartNew();
            if (replay==0) {
                var consumer=new AgentWorkstationInboxConsumer(new ImportConnection(),new DirectAdDcRuntime(worker,catalog));
                var imported=await consumer.RunOnceAsync(app,1,ct);
                Assert.Equal(1,imported.Imported); Assert.Empty(imported.PendingReasons);
            } else {
                await using var tx=await app.BeginTransactionAsync(ct);
                await DirectAdDcPacket.ImportAsync(app,tx,worker,Guid.Parse(sample.Envelope["packet_id"]!.GetValue<string>()),
                    sample.Envelope,sample.Payload,sample.Rows,catalog,ct,steps.Add);
                await tx.CommitAsync(ct);
            }
            watch.Stop(); profile.Enabled=false;
            var blockCommands=profile.Commands.Where(x=>x.Sql.Contains("event_entity_link_blocks_v2",StringComparison.Ordinal)).ToArray();
            Assert.Empty(blockCommands);
            output.WriteLine($"ShortEventReads={setting??"default"}, replay={replay}: {watch.Elapsed.TotalMilliseconds:F1} ms, block commands={blockCommands.Length}");
            await using var query=new NpgsqlCommand("""
                select (select count(*) from event_hot), (select count(*) from event_cold_facts),
                       (select count(*) from entity_state_projection_jobs)
                """,admin);
            await using var reader=await query.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            Assert.Equal(25L,reader.GetInt64(0));
            Assert.Equal(25L,reader.GetInt64(1));
            string counts=string.Join(',',Enumerable.Range(0,3).Select(reader.GetInt64));
            if(first is null) first=counts; else Assert.Equal(first,counts);
            output.WriteLine("Rows hot/cold/jobs="+counts);
        }
        Assert.DoesNotContain(AdDcProjectionStep.HotLinks,steps);
        if(setting!="false")
        {
            await using var state = await worker.OpenConnectionAsync(ct);
            var projector = new EntityStateProjector();
            var cycle = await projector.RunOnceAsync(state,16,ct);
            var remaining = await projector.RunOnceAsync(state,16,ct);
            Assert.Equal(25,cycle.Completed+remaining.Completed); Assert.Equal(0,cycle.Failed+remaining.Failed);
            await using var query = new NpgsqlCommand("select count(*) from entity_states",admin);
            Assert.Equal(25L,await query.ExecuteScalarAsync(ct));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Storage_s2_import_routes_events_and_replay_does_not_increase_daily_totals()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert = new CertificateRequest("CN=synthetic", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        await SeedAsync(admin, fixture.Pg.Root, cert, ct);
        await AssertLegacyStoreRetiredAsync(admin, ct);
        await using var worker = NpgsqlDataSource.Create(fixture.Dsn("sli_storage_login"));
        await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        string catalog = Path.Combine(PostCollectionPostgres.Repository(), "config/event_catalog.json");
        var sample = Sample(1, 8);
        int[] kinds = [4625, 4625, 4625, 4720, 4634, 4634, 4740, 4625];
        string hostile = "'; select pg_sleep(1); -- <script>" + new string('x', 400);
        for (int i = 0; i < kinds.Length; i++) {
            string time = i == 7 ? "2026-11-01T00:00:00Z" : i == 1 ? "2026-10-31T01:00:00Z" : "2026-10-31T23:59:59Z";
            string data = "<Data Name='SubjectUserName'>" + System.Security.SecurityElement.Escape(hostile) + "</Data>" +
                  "<Data Name='TargetUserName'>synthetic-user</Data><Data Name='IpAddress'>192.0.2.17</Data>" +
                  "<Data Name='Status'>0xc000006d</Data><Data Name='SubStatus'>" + (i == 2 ? "0xc0000064" : "0xc000006a") + "</Data>";
            string xml = $"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{kinds[i]}</EventID><EventRecordID>{i + 1}</EventRecordID><TimeCreated SystemTime='{time}'/><Channel>Security</Channel><Computer>{Source}</Computer></System><EventData>{data}</EventData></Event>";
            sample.Payload["records"]![i]!["payload"] = EventXml.Parse(xml, Source, "fixture-endpoint", "Security");
        }
        var envelope = Envelope.Parse(sample.Envelope) with { PayloadSha256 = Packets.Digest(sample.Payload), PayloadBytes = CanonicalJson.Length(sample.Payload) };
        sample = new(envelope.ToJson(), sample.Payload, AgentAdDcValidator.Validate(envelope, sample.Payload, null, Source));
        await ReceiptAsync(admin, sample, ct);
        for (int replay = 0; replay < 2; replay++) {
            await using var tx = await app.BeginTransactionAsync(ct);
            await ImportAsync(app, tx, worker, sample, catalog, ct);
            // A rollback leaves the short rows and import marker retryable.
            if (replay == 0) await tx.RollbackAsync(ct); else await tx.CommitAsync(ct);
        }
        await using (var query = new NpgsqlCommand("""
            select (select count(*) from event_hot),
                   (select count(*) from event_cold_facts), (select sum(event_count) from event_cold_daily)::bigint,
                   not exists(select 1 from event_hot where event_kind=4634);
            select event_count,first_seen_utc,last_seen_utc from event_cold_daily
            where day='2026-10-31' and outcome->>'SubStatus'='0xc000006a';
            select char_length(actor),actor from event_hot where event_kind=4720;
            """, admin)) {
            await using var r = await query.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            Assert.Equal(6, r.GetInt64(0)); Assert.Equal(2, r.GetInt64(1));
            Assert.Equal(4, r.GetInt64(2)); Assert.True(r.GetBoolean(3));
            Assert.True(await r.NextResultAsync(ct)); Assert.True(await r.ReadAsync(ct));
            Assert.Equal(2, r.GetInt64(0)); Assert.Equal(new DateTime(2026,10,31,1,0,0,DateTimeKind.Utc), r.GetDateTime(1));
            Assert.Equal(new DateTime(2026,10,31,23,59,59,DateTimeKind.Utc), r.GetDateTime(2)); Assert.False(await r.ReadAsync(ct));
            Assert.True(await r.NextResultAsync(ct)); Assert.True(await r.ReadAsync(ct));
            Assert.Equal(256, r.GetInt32(0)); Assert.Equal(hostile[..256], r.GetString(1));
        }
        await using (var size = new NpgsqlCommand("select min(pg_column_size(h)),avg(pg_column_size(h)),max(pg_column_size(h)) from event_hot h",admin)) {
            await using var r = await size.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            output.WriteLine($"Hot row pg_column_size min/mean/max: {r.GetInt32(0)}/{r.GetDecimal(1):F1}/{r.GetInt32(2)} bytes (synthetic AD packet)");
        }
        await fixture.AssertNoSqlErrorsAsync(ct);

        // A cold write failure must roll back the import marker and the hot
        // row together. Its identity reservation remains retryable.
        await PostCollectionPostgres.Sql(admin, "alter table event_cold_facts add constraint synthetic_reject_fact check(event_kind<>4720) not valid", ct);
        var retry = Sample(20, eventKind: 4720); await ReceiptAsync(admin, retry, ct);
        await using (var tx = await app.BeginTransactionAsync(ct)) {
            var error = await Assert.ThrowsAsync<PostgresException>(() => ImportAsync(app, tx, worker, retry, catalog, ct));
            Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
            await tx.RollbackAsync(ct);
        }
        await using (var query = new NpgsqlCommand("""
            select not exists(select 1 from event_hot where event_record_id=20),
                   (select count(*) from event_hot), (select count(*) from event_cold_facts);
            """, admin)) {
            await using var r = await query.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            Assert.True(r.GetBoolean(0)); Assert.Equal(6, r.GetInt64(1)); Assert.Equal(2, r.GetInt64(2));
        }
        await PostCollectionPostgres.Sql(admin, "alter table event_cold_facts drop constraint synthetic_reject_fact", ct);
        await using (var tx = await app.BeginTransactionAsync(ct)) {
            await ImportAsync(app, tx, worker, retry, catalog, ct); await tx.CommitAsync(ct);
        }
        await using (var query = new NpgsqlCommand("""
            select (select count(*) from event_hot), (select count(*) from event_cold_facts),
                   (select count(*) from event_hot where event_record_id=20);
            """, admin)) {
            await using var r = await query.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            Assert.Equal(7, r.GetInt64(0)); Assert.Equal(3, r.GetInt64(1)); Assert.Equal(1, r.GetInt64(2));
        }
    }
    private static async Task AssertLegacyStoreRetiredAsync(NpgsqlConnection db, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("""
            select to_regclass('public.events_v2_core') is null
               and to_regclass('public.event_facts_v2') is null
               and to_regclass('public.event_entity_link_blocks_v2') is null
               and to_regclass('public.event_entity_links_v2') is null
               and to_regclass('public.raw_log_files') is null
            """, db);
        Assert.Equal(true, await query.ExecuteScalarAsync(ct));
    }

    private sealed class ImportConnection : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new NotSupportedException();
    }

}
