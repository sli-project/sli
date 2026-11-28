using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Ingress;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Reporting;
using Sli.Server.Workstations;
using Xunit;
using AgentIdentity = Sli.Server.Agents.AgentIdentity;

namespace Sli.Server.Tests.Workstations;

public sealed class WorkstationHardwareInventoryTests
{
    private static readonly Guid Agent = new("46500000-0000-4000-8000-000000000001");
    private static readonly Guid Source = new("46500000-0000-4000-8000-000000000002");
    private const string Host = "ws-hardware.example.test";

    private sealed class Connections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }

    private sealed class EmptyEventLog : IEventLogSource
    {
        public SourceBatch Read(string channel, ChannelProgress progress, int limit) => new([]);
    }

    private static JsonObject Snapshot(bool changed)
    {
        var raw = JsonNode.Parse("""
            {"computer":[{"model":"Example Workstation"}],"bios":[{"version":"1.12"}],
             "memory":[{"size":17179869184}],"disk":[{"id":"disk-1","model":"Example SSD"}],
             "security":[{"secure_boot":true,"tpm_enabled":true}],"network":[{"id":"nic-A","name":"Ethernet"}],
             "volume":[{"id":"volume-1","mount":"C:","system":true,"bitlocker":"on"},
                       {"id":"volume-2","mount":"D:","system":false,"bitlocker":"on"}]}
            """)!.AsObject();
        if (changed)
        {
            raw["bios"]![0]!["version"] = "1.15";
            raw["memory"]![0]!["size"] = 34359738368L;
            raw["disk"]!.AsArray().Add(new JsonObject { ["id"] = "disk-2", ["model"] = "Example SSD" });
            raw["security"]![0]!["secure_boot"] = false;
            raw["security"]![0]!["tpm_enabled"] = false;
            raw["network"] = new JsonArray();
            raw["volume"]![0]!["bitlocker"] = "off";
            raw["volume"]![1]!["bitlocker"] = "off";
        }
        return WorkstationHardware.Build(raw)!;
    }

    [Fact]
    public void DiffUsesComponentIdentityAndRanksOnlyEstablishedChanges()
    {
        var before = Snapshot(false);
        var after = Snapshot(true);
        var changes = WorkstationHardwareInventory.Diff(before, after);
        var disk = Assert.Single(changes, row => row.Text("section") == "disk");
        Assert.Equal("added", disk.Text("kind"));
        Assert.Equal("medium", disk.Text("severity"));
        var memory = Assert.Single(changes, row => row.Text("section") == "memory");
        Assert.Equal(17179869184L, memory.Number("before"));
        Assert.Equal(34359738368L, memory.Number("after"));
        Assert.Equal("low", memory.Text("severity"));
        var bios = Assert.Single(changes, row => row.Text("section") == "bios");
        Assert.Equal("version_changed", bios.Text("kind"));
        Assert.Equal("1.12", bios.Text("before"));
        Assert.Equal("1.15", bios.Text("after"));
        Assert.Equal("low", bios.Text("severity"));
        Assert.Equal("low", Assert.Single(changes, row => row.Text("section") == "network").Text("severity"));
        Assert.Equal(2, changes.Count(row => row.Text("section") == "security" && row.Text("severity") == "medium"));
        Assert.Equal("medium", Assert.Single(changes, row => row.Text("component") == "C:").Text("severity"));
        Assert.Null(Assert.Single(changes, row => row.Text("component") == "D:")!["severity"]);
        Assert.Equal("removed", Assert.Single(WorkstationHardwareInventory.Diff(after, before), row => row.Text("section") == "disk").Text("kind"));
        after["disk"] = null;
        after["security"]![0]!["secure_boot"] = null;
        var partial = WorkstationHardwareInventory.Diff(before, after);
        Assert.DoesNotContain(partial, row => row.Text("section") == "disk" || row.Text("field") == "secure_boot");
    }

    [Fact]
    public async Task SignedInventoryReplacesTheSnapshotAndStoresOnlyScopedChangeRows()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        var migrations = MigrationDirectory.Read();
        var (version, _, migration) = migrations.Single(item => item.Name == "workstation_hardware");
        int predecessor = migrations.Last(item => item.Version < version).Version;
        await fixture.StartAsync(ct, throughVersion: predecessor);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        var policy = AgentModuleAssignmentRules.NormalizeWorkstation(new JsonObject { ["policy_revision"] = "1" }, true);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        long domain = (long)(await Ws.Scalar(owner, "select id from public.domains where fqdn='example.test'", ct))!;
        await using (var seed = new NpgsqlCommand("""
            update plugin_installations_v1 set desired_activation='enabled_manual',component_runtime='running' where plugin_id='sli.workstations';
            insert into servers(domain_id,hostname,fqdn,role) values(@domain,@host,@host,'workstation');
            insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,policy_revision,assigned_modules)
              values(@agent,@source,repeat('a',64),@host,1,
                jsonb_build_array(jsonb_build_object('module_id','sli.workstations','enabled',true,'config',@policy)));
            """, owner))
        {
            seed.Parameters.AddWithValue("domain", domain);
            seed.Parameters.AddWithValue("host", Host);
            seed.Parameters.AddWithValue("agent", Agent);
            seed.Parameters.AddWithValue("source", Source);
            seed.Parameters.AddWithValue("policy", NpgsqlDbType.Jsonb, policy.ToJsonString());
            await seed.ExecuteNonQueryAsync(ct);
        }
        Assert.True((bool)(await Ws.Scalar(owner, "select public.set_workstation_journal_grant412(@p0,true)", ct, Agent))!);

        var now = DateTimeOffset.UtcNow.AddMinutes(-15);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = new CertificateRequest("CN=synthetic", key, HashAlgorithmName.SHA256).CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        var identity = new AgentIdentity(Agent, Source, new string('a',64), "active");
        var service = new AgentPacketService(TimeProvider.System,
            AgentInboxLimits.FromEnvironment(_ => null) with { FreeDiskBytes = () => 1_000_000_000_000 },
            new AgentIngressDiagnostics(fixture.Pg.Root, NullLogger<AgentIngressDiagnostics>.Instance, TimeProvider.System));
        SignedPacket Packet(long sequence, JsonObject inventory, Guid source, DateTimeOffset? observation = null)
        {
            var observed = observation ?? now.AddMinutes(sequence);
            var sample = WorkstationHardware.Collect(inventory, null, source.ToString("D"), WorkstationPolicy.Parse(policy), null, observed)!;
            return Packets.Make(new EcdsaPacketSigner(key), Agent.ToString("D"), sequence, sample, observed);
        }
        async Task<JsonObject> Receive(SignedPacket packet, bool commit = true)
        {
            await using var db = await fixture.Pg.OpenAsync(ct, "adlog_user");
            await using var tx = await db.BeginTransactionAsync(ct);
            var receipt = await service.ReceiveAsync(db, tx, identity, certificate, packet.ToJson(), ct);
            if (commit) await tx.CommitAsync(ct); else await tx.RollbackAsync(ct);
            return receipt;
        }
        var first = Packet(1, Snapshot(false), Source);
        var second = Packet(2, Snapshot(true), Source);
        Assert.Equal("committed", (await Receive(first)).Text("status"));
        Assert.Equal(0L, await Ws.Scalar(owner, "select count(*) from public.workstation_hardware_changes465", ct));
        Assert.Equal("committed", (await Receive(second, commit: false)).Text("status"));
        Assert.Equal("1.12", await Ws.Scalar(owner, "select inventory#>>'{bios,0,version}' from public.workstation_hardware_latest465", ct));
        Assert.Equal("committed", (await Receive(second)).Text("status"));
        Assert.Equal("duplicate", (await Receive(second)).Text("status"));
        Assert.Equal("rejected", (await Receive(Packet(3, Snapshot(false), Guid.NewGuid()))).Text("status"));
        Assert.Equal("committed", (await Receive(Packet(3, Snapshot(true), Source))).Text("status"));
        Assert.Equal(1L, await Ws.Scalar(owner, "select count(*) from public.workstation_hardware_latest465", ct));
        Assert.Equal("1.15", await Ws.Scalar(owner, "select inventory#>>'{bios,0,version}' from public.workstation_hardware_latest465", ct));
        Assert.Equal(0L, await Ws.Scalar(owner, "select count(*) from public.sli_agent_packet_inbox", ct));

        var registry = new ReportDefinitionRegistry();
        var facts = new ReportFixture.FactsRepo(WorkstationWorkspaceTests.AuthorizedFacts(journal: false));
        var reader = new WorkstationWorkspaceReader(new Connections(fixture), facts, null!, registry);
        await using var report = await ReportFixture.Start(facts.Value, registry.Get(WorkstationWorkspaceReader.Key), nativeReader: reader, workstationRoutes: true);
        const string route = "/api/v2/reports/workstations.overview";
        async Task<JsonObject> Read(string path)
        {
            using var response = await report.Client.GetAsync(route + path, ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return await ReportFixture.Body(response);
        }
        var fleet = await Read("/data?period=7d");
        Assert.Equal("Example Workstation", Assert.Single(fleet["items"]!.AsArray()).Text("model"));
        var detail = (await Read("/rows/" + Agent.ToString("D") + "/detail?period=7d"))["detail"]!;
        Assert.Equal("denied", detail["events"].Text("state"));
        Assert.Equal("1.15", detail["hardware"]!["inventory"]!["bios"]![0].Text("version"));
        Assert.Equal(8, detail["hardware"]!["changes"]!.AsArray().Count);

        // Expiry advances the shared transport gap. The next normal journal
        // packet still validates at receipt and again in the inbox consumer.
        Assert.Equal("agent_packet_expired", (await Receive(Packet(4, Snapshot(false), Source, now.AddDays(-8)))).Text("error_code"));
        var journal = new WorkstationsModule(Source.ToString("D"), WorkstationPolicy.Parse(policy), new EmptyEventLog());
        var journalAt = now.AddMinutes(5);
        var journalSample = journal.Collect(null, journalAt).Sample! with { ContinuityState = "gap" };
        var next = Packets.Make(new EcdsaPacketSigner(key), Agent.ToString("D"), 5, journalSample, journalAt);
        Assert.Equal("committed", (await Receive(next)).Text("status"));
        await using (var db = await fixture.Pg.OpenAsync(ct, "adlog_user"))
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            Assert.True((await AgentWorkstationInboxConsumer.ProcessNextAsync(db, tx, null, ct)).Imported);
            await tx.CommitAsync(ct);
        }

        Assert.Equal(8L, await Ws.Scalar(owner, "select public.prune_workstation_hardware465(@p0,100)", ct, DateTime.UtcNow));
        Assert.Equal(1L, await Ws.Scalar(owner, "select count(*) from public.workstation_hardware_latest465", ct));
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        Assert.Equal(predecessor, await Ws.Scalar(owner, "select max(version) from public.schema_migrations", ct));
    }
}
