using System.Globalization;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Ingress;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Semantic;
using Xunit;

namespace Sli.Server.Tests.Agents;

[Collection("Semantic producer environment")]
public sealed class AgentPacketReportPostgresTests
{
    private const string Intake = "/api/v1/agent/packets";
    private const int EventRecordId = 23;
    internal const int EventKind = 4720;
    private const string ParticipantSid = "S-1-5-21-100000001-200000002-300000003-1101";

    [Fact]
    public async Task Signed_AD_packet_reaches_the_journal_once_and_disabled_modules_leave_no_receipt()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        using var environment = new SemanticProducerPostgresTests.Admission(mode: null);
        environment.Set("ADLOG_POSTGRES_IMPORT_QUEUE_LOCK", Path.Combine(fixture.Pg.Root, "post-collection.lock"));
        environment.Set("SLI_PLUGIN_RUNTIME_DIR", null);
        environment.Set("SLI_PLUGIN_LOCK_DIR", null);
        var token = await fixture.SeedOwnerAsync(ct);
        using var certificates = new WriteSqlPostgresTests.Certificates();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var agent = AdDcImportPerformanceTests.Agent;
        var hostId = AdDcImportPerformanceTests.Host;
        var source = AdDcImportPerformanceTests.Source;
        var certificateRequest = new CertificateRequest("CN=synthetic.example.test", key, HashAlgorithmName.SHA256);
        using var peer = certificates.Ca.Issue(certificateRequest, agent, hostId);
        string root = PostCollectionPostgres.Repository();
        string trustPath = Path.Combine(fixture.Pg.Root, "synthetic-agent-trust.txt");
        await File.WriteAllTextAsync(trustPath, certificates.Root.ExportCertificatePem() + "\n" + certificates.Issuer.ExportCertificatePem(), ct);
        // Program validates installed settings before WebApplicationFactory adds its overrides.
        environment.Set("ConnectionStrings__Sli", fixture.Dsn("adlog_user"));
        environment.Set("Sli__AgentMtlsCaFile", trustPath);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await AdDcImportPerformanceTests.SeedAsync(owner, fixture.Pg.Root, peer, ct, Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())));
        var settings = new Dictionary<string, string?> {
            ["Sli:TrustedProxies"] = "",
            ["Sli:AuthRequired"] = "1",
            ["Sli:AllowUnauthenticated"] = "0",
            ["Sli:OwnerSetup"] = "0",
            ["Sli:ProjectRoot"] = root,
            ["Sli:DataDirectory"] = Path.Combine(fixture.Pg.Root, "data-runtime"),
            ["Sli:LogDirectory"] = Path.Combine(fixture.Pg.Root, "logs-runtime"),
            ["Sli:Storage:ArchiveRoot"] = fixture.Pg.Root,
            ["Sli:Storage:HistoryReadMode"] = "primary",
            ["urls"] = "http://127.0.0.1:0"
        };
        using var app = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder
            .UseTestServer()
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(settings))
            .ConfigureLogging(logging => logging.ClearProviders())
            .ConfigureServices(services => {
                services.RemoveAll<IHostedService>();
                services.AddSingleton(certificates.Ca);
            }));

        // TestServer supplies the transport peer. The route still validates the
        // certificate chain, registry binding, pack signature and receipt.
        HttpClient Client(X509Certificate2? certificate = null) => new(app.Server.CreateHandler(context => {
            context.Features.Get<IHttpRequestFeature>()!.RawTarget = context.Request.Path + context.Request.QueryString;
            context.Connection.ClientCertificate = certificate;
        })) { BaseAddress = new Uri("https://localhost") };
        using var client = Client();
        using var agentClient = Client(peer);
        using var analyst = Client();
        analyst.DefaultRequestHeaders.Add("Cookie", "adlog_session=" + token);

        var now = Iso8601.Truncate(DateTimeOffset.UtcNow);
        var eventTime = now.AddMinutes(-1);
        var sample = CaptureSample(now, source, hostId);
        var signer = new EcdsaPacketSigner(key);
        var packet = Packets.Make(signer, agent.ToString("D"), 1, sample, now);
        string report = $"/api/v2/reports/events.journal/data?period=custom&from={eventTime.AddMinutes(-1).UtcDateTime:O}&to={now.AddMinutes(1).UtcDateTime:O}";

        using (var unauthenticated = await client.PostAsync(Intake, new StringContent(packet.ToCanonical(), Encoding.UTF8, "application/json"), ct))
            Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
        var receipt = await PostAsync(agentClient, packet, ct);
        Assert.Equal("committed", receipt["status"]?.ToString());
        Assert.Equal(packet.Envelope.PacketId, receipt["packet_id"]?.ToString());
        Assert.Equal(packet.Envelope.PayloadSha256, receipt["payload_sha256"]?.ToString());
        Assert.True(JsonNode.DeepEquals(packet.Envelope.CursorAfter.ToJson(), receipt["committed_cursor"]));
        var before = await GetReportAsync(analyst, report, ct);
        Assert.Equal("empty", before["state"]?.ToString());
        Assert.Empty(before["items"]!.AsArray());

        await using var runtime = new DirectAdDcRuntime(NpgsqlDataSource.Create(fixture.Dsn("sli_storage_login")), Path.Combine(root, "config", "event_catalog.json"));
        var consumer = new AgentWorkstationInboxConsumer(app.Services.GetRequiredService<IPostgresConnectionFactory>(), runtime);
        var run = await consumer.RunOnceAsync(1, ct);
        Assert.True(run.Imported == 1, run.Imported + ": " + string.Join(", ", run.PendingReasons));
        Assert.Empty(run.PendingReasons);

        foreach (var (module, channel) in new[] { ("sli.file-audit", "Security"), ("sli.workstations", "workstations") })
        {
            var disabled = Packets.Make(signer, agent.ToString("D"), 1,
                new Sample(module, hostId.ToString("D"), channel, hostId.ToString("D"), new Cursor("record_id", ""),
                    new Cursor("record_id", "1"), new JsonObject { ["contract"] = CollectionPacket.Contract }), now);
            var refused = await PostAsync(agentClient, disabled, ct);
            Assert.True(Receipt.IsModuleDisabled(disabled.Envelope, refused), refused.ToJsonString());
            Assert.Null(refused["committed_at_utc"]);
            Assert.Null(refused["committed_cursor"]);
        }

        var row = Assert.Single((await GetReportAsync(analyst, report, ct))["items"]!.AsArray())!;
        Assert.Equal(EventKind.ToString(CultureInfo.InvariantCulture), row["event_id"]?.ToString());
        Assert.Equal("Security", row["channel"]?.ToString());
        Assert.Equal(ParticipantSid, row["participant"]?.ToString());

        var duplicate = await PostAsync(agentClient, packet, ct);
        receipt["status"] = "duplicate";
        Assert.True(JsonNode.DeepEquals(receipt, duplicate), duplicate.ToJsonString());
        Assert.Equal(0, (await consumer.RunOnceAsync(1, ct)).Scanned);

        // Requeue the one acknowledged packet inside this disposable database.
        // The regular poller must re-attest it without publishing another row.
        await using (var requeue = new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=null where packet_id=@packet", owner))
        {
            requeue.Parameters.AddWithValue("packet", Guid.Parse(packet.Envelope.PacketId));
            Assert.Equal(1, await requeue.ExecuteNonQueryAsync(ct));
        }
        var replayed = await consumer.RunOnceAsync(1, ct);
        Assert.Equal(1, replayed.Imported);
        Assert.Empty(replayed.PendingReasons);
        Assert.True(JsonNode.DeepEquals(row, Assert.Single((await GetReportAsync(analyst, report, ct))["items"]!.AsArray())));

        await using var state = new NpgsqlCommand("""
            select e.event_id, e.domain_id, s.domain_id, e.source_sha256 is not null,
                   (select count(*) from sli_agent_receipts where agent_id=@agent),
                   (select count(*) from sli_agent_packet_inbox where envelope->>'agent_id'=@agent::text),
                   (select count(*) from sli_agent_packet_inbox where packet_id=@packet and imported_at is not null), e.event_record_id, (e.method->>'$server_id')::bigint, s.id
            from event_hot e join servers s on s.fqdn=@source
            where e.event_kind=@kind and e.method#>>'{$origin,source_instance_id}'=@host
            """, owner);
        state.Parameters.AddWithValue("agent", agent);
        state.Parameters.AddWithValue("packet", Guid.Parse(packet.Envelope.PacketId));
        state.Parameters.AddWithValue("source", source);
        state.Parameters.AddWithValue("kind", EventKind);
        state.Parameters.AddWithValue("host", hostId.ToString("D"));
        await using var data = await state.ExecuteReaderAsync(ct);
        Assert.True(await data.ReadAsync(ct));
        Assert.Equal(row["id"]!.ToString(), data.GetInt64(0).ToString(CultureInfo.InvariantCulture));
        Assert.Equal(data.GetInt64(2), data.GetInt64(1));
        Assert.True(data.GetBoolean(3));
        Assert.Equal(1L, data.GetInt64(4));
        Assert.Equal(1L, data.GetInt64(5));
        Assert.Equal(1L, data.GetInt64(6));
        Assert.Equal(EventRecordId, data.GetInt64(7));
        Assert.Equal(data.GetInt64(9), data.GetInt64(8));
        Assert.False(await data.ReadAsync(ct));
    }

    private static async Task<JsonObject> PostAsync(HttpClient client, SignedPacket packet, CancellationToken ct)
    {
        using var response = await client.PostAsync(Intake, new StringContent(packet.ToCanonical(), Encoding.UTF8, "application/json"), ct);
        return await ReadAsync(response, ct);
    }

    private static async Task<JsonObject> GetReportAsync(HttpClient client, string path, CancellationToken ct)
    {
        using var response = await client.GetAsync(path, ct);
        return await ReadAsync(response, ct);
    }

    private static async Task<JsonObject> ReadAsync(HttpResponseMessage response, CancellationToken ct)
    {
        string body = await response.Content.ReadAsStringAsync(ct);
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode}: {body}");
        return JsonNode.Parse(body)!.AsObject();
    }

    internal static Sample CaptureSample(DateTimeOffset now, string source, Guid hostId)
    {
        var catalog = EventCatalog.Load();
        var policy = AgentAdDcValidator.NormalizePolicy(new JsonObject {
            ["source_name"] = source,
            ["connect_address"] = source,
            ["channels"] = new JsonObject { ["Security"] = true, ["System"] = true, ["Directory Service"] = true }
        }, false);
        string xml = $"""
            <Event xmlns="{EventXml.Namespace}"><System>
            <Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{EventKind}</EventID>
            <EventRecordID>{EventRecordId}</EventRecordID><TimeCreated SystemTime="{Iso8601.Format(now.AddMinutes(-1))}"/>
            <Channel>Security</Channel><Computer>{source}</Computer></System><EventData>
            <Data Name="TargetUserSid">{ParticipantSid}</Data>
            <Data Name="TargetUserName">synthetic-replay-user</Data><Data Name="TargetDomainName">EXAMPLE</Data>
            </EventData></Event>
            """;
        var capture = new AdDcModule(hostId.ToString("D"), AdDcConfig.Parse(policy, catalog), new SyntheticSecurityLog(xml), catalog);
        return Assert.IsType<Sample>(capture.Collect(null, now, "Security").Sample);
    }

    private sealed class SyntheticSecurityLog(string xml) : IEventLogSource
    {
        public SourceBatch Read(string channel, ChannelProgress progress, int limit)
        {
            Assert.Equal("Security", channel);
            return new([new(xml, $"<Bookmark Channel='Security' RecordId='{EventRecordId}' IsCurrent='true'/>")]);
        }
    }
}
