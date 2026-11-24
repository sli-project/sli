using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
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
using Sli.Server.Agents.Control;
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
        await fixture.StartAsync(ct, throughVersion: 409);
        string root = PostCollectionPostgres.Repository();
        var prerequisites = MigrationDirectory.Read(410).Where(migration => migration.Version < 413).ToArray();
        Assert.Equal(new[] { 410, 411, 412 }, prerequisites.Select(migration => migration.Version));
        foreach (var migration in prerequisites) await fixture.Pg.ApplyFileAsync(migration.Path, null, ct);
        string upgrade = Path.Combine(root, "config/postgres_migrations/413_workstation_journal_admission.sql");
        using var environment = new SemanticProducerPostgresTests.Admission(mode: null);
        environment.Set("ADLOG_POSTGRES_IMPORT_QUEUE_LOCK", Path.Combine(fixture.Pg.Root, "post-collection.lock"));
        environment.Set("SLI_PLUGIN_RUNTIME_DIR", null);
        environment.Set("SLI_PLUGIN_LOCK_DIR", null);
        environment.Set("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", null);
        environment.Set(Sli.Server.Agents.Radius.RadiusAccountingMode.EnabledSetting, "0");
        var token = await fixture.SeedOwnerAsync(ct);
        using var certificates = new WriteSqlPostgresTests.Certificates();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var agent = AdDcImportPerformanceTests.Agent;
        var hostId = AdDcImportPerformanceTests.Host;
        var source = AdDcImportPerformanceTests.Source;
        var certificateRequest = new CertificateRequest("CN=synthetic.example.test", key, HashAlgorithmName.SHA256);
        using var peer = certificates.Ca.Issue(certificateRequest, agent, hostId);
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
        await using var runtime = new DirectAdDcRuntime(NpgsqlDataSource.Create(fixture.Dsn("sli_storage_login")), Path.Combine(root, "config", "event_catalog.json"));
        var connections = app.Services.GetRequiredService<IPostgresConnectionFactory>();
        var consumer = new AgentWorkstationInboxConsumer(connections, runtime);

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
        await data.DisposeAsync();
        var publishedBefore = await SnapshotPublishedDcAsync(owner, hostId, ct);
        Assert.Single(publishedBefore["hot"]!.AsArray());
        Assert.Single(publishedBefore["facts"]!.AsArray());

        await fixture.Pg.ApplyFileAsync(upgrade, null, ct);
        Assert.True(JsonNode.DeepEquals(publishedBefore, await SnapshotPublishedDcAsync(owner, hostId, ct)));
        await ExerciseWorkstationAsync(fixture, owner, connections, consumer, certificates.Ca, certificate => Client(certificate), analyst, now, ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(upgrade, ".rollback.sql"), null, ct);
        Assert.True(JsonNode.DeepEquals(publishedBefore, await SnapshotPublishedDcAsync(owner, hostId, ct)));
        await using var retained = new NpgsqlCommand("""
            select to_regprocedure('public.workstation_journal_scope412(uuid,text,text)') is null,
                   (select count(*) from event_hot where method#>>'{$origin,plugin_id}'='sli.workstations'),
                   (select coalesce(sum(event_count),0)::bigint from event_cold_daily where method#>>'{$origin,plugin_id}'='sli.workstations');
            """, owner);
        await using var afterRollback = await retained.ExecuteReaderAsync(ct);
        Assert.True(await afterRollback.ReadAsync(ct));
        Assert.True(afterRollback.GetBoolean(0));
        Assert.Equal(3L, afterRollback.GetInt64(1));
        Assert.Equal(1L, afterRollback.GetInt64(2));
    }

    private static async Task<JsonNode> SnapshotPublishedDcAsync(NpgsqlConnection db, Guid source, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("""
            select jsonb_build_object(
                'hot',(select jsonb_agg(to_jsonb(e) order by e.event_id) from public.event_hot e
                    where e.method#>>'{$origin,source_instance_id}'=@source),
                'facts',(select jsonb_agg(to_jsonb(e) order by e.event_id) from public.event_cold_facts e
                    where e.method#>>'{$origin,source_instance_id}'=@source))::text;
            """, db);
        query.Parameters.AddWithValue("source", source.ToString("D"));
        return JsonNode.Parse((string)(await query.ExecuteScalarAsync(ct))!)!;
    }

    private static async Task ExerciseWorkstationAsync(SqlPostgresFixture fixture, NpgsqlConnection owner,
        IPostgresConnectionFactory connections, AgentWorkstationInboxConsumer consumer, Sli.Server.Agents.Certificates.AgentIssuingCa ca,
        Func<X509Certificate2,HttpClient> client, HttpClient analyst, DateTimeOffset now, CancellationToken ct)
    {
        const string name = "ws-fixture.example.test";
        const string defender = "Microsoft-Windows-Windows Defender/Operational";
        var agent = Guid.NewGuid();
        var host = Guid.NewGuid();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var peer = ca.Issue(new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256), agent, host);
        using var station = client(peer);
        await using (var seed = new NpgsqlCommand("""
            insert into servers(domain_id,hostname,fqdn,role) select id,@name,@name,'workstation' from domains where fqdn='example.test';
            insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,policy_revision,assigned_modules)
                values(@agent,@host,@key,@name,1,'[{"module_id":"sli.workstations","enabled":true,"config":{"policy_revision":"1"}}]');
            insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after) values(@agent,@serial,@certificate,@before,@after);
            update plugin_installations_v1 set desired_activation='enabled_manual',component_runtime='running' where plugin_id='sli.workstations';
            """, owner))
        {
            seed.Parameters.AddWithValue("agent", agent);
            seed.Parameters.AddWithValue("host", host);
            seed.Parameters.AddWithValue("name", name);
            seed.Parameters.AddWithValue("key", Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())));
            seed.Parameters.AddWithValue("serial", peer.SerialNumber.TrimStart('0').ToLowerInvariant());
            seed.Parameters.AddWithValue("certificate", Convert.ToHexStringLower(SHA256.HashData(peer.RawData)));
            seed.Parameters.AddWithValue("before", peer.NotBefore.ToUniversalTime());
            seed.Parameters.AddWithValue("after", peer.NotAfter.ToUniversalTime());
            await seed.ExecuteNonQueryAsync(ct);
        }

        var at = now.AddMinutes(-4);
        Sample Capture(WorkstationPolicy policy, int record, int kind, string channel, string provider, CapturedPosition? prior = null)
        {
            string xml = $"""
                <Event xmlns="{EventXml.Namespace}"><System><Provider Name="{provider}"/><EventID>{kind}</EventID>
                <EventRecordID>{record}</EventRecordID><TimeCreated SystemTime="{Iso8601.Format(at)}"/>
                <Channel>{channel}</Channel><Computer>{name}</Computer></System>
                <EventData><Data Name="TargetUserName">station-fixture-user</Data><Data Name="LogonType">2</Data></EventData></Event>
                """;
            var collector = new WorkstationsModule(host.ToString("D"), policy, new WorkstationFixtureLog(channel, record, xml));
            return Assert.IsType<Sample>(collector.Collect(prior, now, channel).Sample);
        }
        var signer = new EcdsaPacketSigner(key);
        var expected = WorkstationPolicy.Parse(AgentModuleAssignmentRules.NormalizeWorkstation(new JsonObject { ["policy_revision"]="2" }, true));
        var preliminary = Packets.Make(signer, agent.ToString("D"), 1, Capture(expected, 1, 4624, "Security", "Microsoft-Windows-Security-Auditing"), now);
        Assert.True(Receipt.IsModuleDisabled(preliminary.Envelope, await PostAsync(station, preliminary, ct)));

        await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await app.OpenAsync(ct);
        async Task<JsonElement> SetRole(bool enabled, int revision)
        {
            await using var tx = await app.BeginTransactionAsync(ct);
            var request = JsonSerializer.SerializeToElement(new { agent_id=agent, module_id=WorkstationsModule.ModuleId, enabled, config=new {}, expected_revision=revision });
            var result = await new AgentModuleAssignmentService(new AgentControlAudit()).AssignAsync(app, tx, request, "session:1", ct);
            await tx.CommitAsync(ct);
            return result;
        }
        var enabled = await SetRole(true, 1);
        Assert.Equal(2, enabled.GetProperty("policy_revision").GetInt32());
        var config = JsonNode.Parse(enabled.GetProperty("assigned_modules")[0].GetProperty("config").GetRawText())!.AsObject();
        var policy = WorkstationPolicy.Parse(config);
        await using (var tx = await app.BeginTransactionAsync(ct))
        {
            JsonObject agentState;
            await using (var locked = new NpgsqlCommand("select to_jsonb(a)::text from sli_agents a where id=@id for update", app, tx))
            {
                locked.Parameters.AddWithValue("id", agent);
                agentState = JsonNode.Parse((string)(await locked.ExecuteScalarAsync(ct))!)!.AsObject();
            }
            await AgentPolicyAssignments.DisableUnavailableAsync(app, tx, agentState, ct);
            Assert.NotNull(AgentPolicyAssignments.FindCurrent(agentState["assigned_modules"]!.AsArray(), WorkstationsModule.ModuleId));
            await tx.CommitAsync(ct);
        }
        var first = Capture(policy, 1, 4624, "Security", "Microsoft-Windows-Security-Auditing");
        var wrongSource = Packets.Make(signer, agent.ToString("D"), 1, first with { SourceInstanceId=Guid.NewGuid().ToString("D") }, now);
        Assert.True(Receipt.IsModuleDisabled(wrongSource.Envelope, await PostAsync(station, wrongSource, ct)));
        var wrongRevision = Packets.Make(signer, agent.ToString("D"), 1, first with { PolicyRevision="1" }, now);
        Assert.True(Receipt.IsModuleDisabled(wrongRevision.Envelope, await PostAsync(station, wrongRevision, ct)));
        var logon = Packets.Make(signer, agent.ToString("D"), 1, first, now);
        var status = await PostAsync(station, logon, ct);
        Assert.Equal("committed", status["status"]?.ToString());
        status["status"]="duplicate";
        Assert.True(JsonNode.DeepEquals(status, await PostAsync(station, logon, ct)));
        var second = Capture(policy, 1, 7045, "System", "Service Control Manager", new(first.Generation, first.CursorAfter));
        var installation = Packets.Make(signer, agent.ToString("D"), 2, second, now);
        var serviceReceipt = await PostAsync(station, installation, ct);
        Assert.True(serviceReceipt["status"]?.ToString()=="committed", serviceReceipt.ToJsonString());
        var third = Capture(policy, 1, 5001, defender, "Microsoft-Windows-Windows Defender", new(second.Generation, second.CursorAfter));
        var protection = Packets.Make(signer, agent.ToString("D"), 3, third, now);
        var protectionReceipt = await PostAsync(station, protection, ct);
        Assert.True(protectionReceipt["status"]?.ToString()=="committed", protectionReceipt.ToJsonString());

        async Task RunWorker()
        {
            var builder = Host.CreateApplicationBuilder([]);
            builder.Logging.ClearProviders();
            builder.Services.AddSingleton(connections);
            builder.Services.AddSingleton(consumer);
            builder.Services.AddSingleton(new AgentImportOptions(true, 10, 4));
            builder.Services.AddSingleton<AgentImportWorker>();
            builder.Services.AddHostedService(services => services.GetRequiredService<AgentImportWorker>());
            using var workerHost = builder.Build();
            var worker = workerHost.Services.GetRequiredService<AgentImportWorker>();
            await workerHost.RunAsync(ct);
            Assert.Equal(0, worker.ExitCode);
        }

        await using var legacy = await fixture.Pg.OpenAsync(ct);
        await using var held = await legacy.BeginTransactionAsync(ct);
        await using (var oldProjection = new NpgsqlCommand("lock sli_plugin_workstations.observations in access exclusive mode", legacy, held))
            await oldProjection.ExecuteNonQueryAsync(ct);
        for (var i = 0; i < 2; i++)
        {
            await RunWorker();
            await using (var imported = new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where envelope->>'agent_id'=@agent and imported_at is not null", owner))
            {
                imported.Parameters.AddWithValue("agent", agent.ToString("D"));
                Assert.Equal(3L, await imported.ExecuteScalarAsync(ct));
            }
            if (i == 0)
            {
                await using var requeue = new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=null where envelope->>'agent_id'=@agent", owner);
                requeue.Parameters.AddWithValue("agent", agent.ToString("D"));
                Assert.Equal(3, await requeue.ExecuteNonQueryAsync(ct));
            }
        }
        await held.RollbackAsync(ct);

        var final = Capture(policy, 2, 4624, "Security", "Microsoft-Windows-Security-Auditing", new(third.Generation, third.CursorAfter));
        var pending = Packets.Make(signer, agent.ToString("D"), 4, final, now);
        var pendingReceipt = await PostAsync(station, pending, ct);
        Assert.True(pendingReceipt["status"]?.ToString()=="committed", pendingReceipt.ToJsonString());
        await SetRole(false, 2);
        Assert.True(Receipt.IsModuleDisabled(logon.Envelope, await PostAsync(station, logon, ct)));
        await RunWorker();

        string period = $"/api/v2/reports/events.journal/data?period=custom&from={at.AddMinutes(-1).UtcDateTime:O}&to={at.AddMinutes(1).UtcDateTime:O}";
        var items = (await GetReportAsync(analyst, period, ct))["items"]!.AsArray();
        Assert.Equal(new[] { "4624", "5001", "7045" }, items.Select(item => item!["event_id"]!.ToString()).Order().ToArray());
        await using var verify = new NpgsqlCommand("""
            select (select count(*) from event_hot where method#>>'{$origin,plugin_id}'='sli.workstations' and source_sha256 is null),
                   (select count(*) from event_cold_facts where method#>>'{$origin,plugin_id}'='sli.workstations'),
                   (select coalesce(sum(event_count),0)::bigint from event_cold_daily where method#>>'{$origin,plugin_id}'='sli.workstations'),
                   (select count(*) from sli_agent_receipts where agent_id=@agent),
                   (select count(*) from sli_agent_packet_inbox where packet_id=@pending and imported_at is null and module_disabled_at is not null),
                   (select count(*) from sli_plugin_workstations.observations where agent_key=@agent::text),
                   (select count(*) from sli_agent_audit where target=@agent::text and action='module_assign' and actor='session:1');
            """, owner);
        verify.Parameters.AddWithValue("agent", agent);
        verify.Parameters.AddWithValue("pending", Guid.Parse(pending.Envelope.PacketId));
        await using var counts = await verify.ExecuteReaderAsync(ct);
        Assert.True(await counts.ReadAsync(ct));
        Assert.Equal(new long[] { 3, 2, 1, 4, 1, 0, 2 }, Enumerable.Range(0, counts.FieldCount).Select(counts.GetInt64));
    }

    private sealed class WorkstationFixtureLog(string expected, int record, string xml) : IEventLogSource
    {
        public SourceBatch Read(string channel, ChannelProgress progress, int limit)
        {
            Assert.Equal(expected, channel);
            return new([new(xml, $"<Bookmark Channel='{channel}' RecordId='{record}' IsCurrent='true'/>")]);
        }
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
