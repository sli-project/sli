using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Groups;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Registry;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Auth.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class WorkstationGroupEnrollmentAssignmentPostgresTests
{
    private const string Machine = "ws-group-fixture";
    private const string Dns = "directory.invalid";
    private const string Fqdn = Machine + "." + Dns;
    private const string Sid = "S-1-5-21-100000001-200000002-300000003";
    private const string ComputerGuid = "00000000-0000-0000-0000-000000002711";
    private const string OuGuid = "88fb307d-54ee-4f18-9e2c-3b4f29f8c503";
    private const string OuDn = "OU=Workstations,DC=directory,DC=invalid";
    private const string Actor = "session:1";

    [Fact]
    public async Task OwnerCanEnableAnApprovedGroupWorkstationWithoutAPreseededServer()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        var (domain, computer, ou) = await PublishDirectoryAsync(fixture, ct);
        await using var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await db.OpenAsync(ct);
        using var certificates = new WriteSqlPostgresTests.Certificates();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var host = Guid.NewGuid();
        var audit = new AgentControlAudit();
        var group = new AgentGroupService(new CredentialTokens(), audit);
        var identity = new AgentIdentityService(certificates.Ca);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Sli:CollectionProfile"] = "beta" }).Build();
        var enrollment = new AgentEnrollmentService(certificates.Ca, identity, config);
        string csr = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256).CreateSigningRequestPem();
        Guid agent;

        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var batch = await group.CreateAsync(db, tx, JsonSerializer.SerializeToElement(new
            {
                domain_id = domain, ou_entity_ids = new[] { ou }, computer_entity_ids = new[] { computer }, max_uses = 1,
            }), Actor, ct);
            var pending = await group.SubmitAsync(db, tx, JsonSerializer.SerializeToElement(new
            {
                token = batch.GetProperty("token").GetString(), host_id = host, csr_pem = csr, computer_entity_id = computer,
            }), ct);
            Assert.Equal("pending", pending["status"]!.GetValue<string>());
            var approved = await group.ApproveAsync(db, tx, JsonSerializer.SerializeToElement(new
            {
                filter = new { group_id = batch.GetProperty("group_id").GetGuid(), token_id = batch.GetProperty("id").GetGuid() },
                evidence = new[] { new
                {
                    request_id = pending["request_id"]!.GetValue<string>(), host_id = host, instance_name = (string?)null,
                    computer_entity_id = computer,
                    key_fingerprint = Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())),
                } },
            }), Actor, ct);
            var entry = Assert.Single(approved.GetProperty("items").EnumerateArray());
            Assert.Equal("approved", entry.GetProperty("status").GetString());
            var issued = await enrollment.EnrollAsync(db, tx, new JsonObject
            {
                ["token"] = entry.GetProperty("token").GetString(), ["csr_pem"] = csr,
                ["machine_role"] = "workstation", ["reported_hostname"] = Machine,
            }, ct);
            agent = Guid.Parse(issued["agent_id"]!.GetValue<string>());
            using var certificate = X509Certificate2.CreateFromPem(issued["certificate_pem"]!.GetValue<string>());
            await identity.AuthenticateAsync(db, tx, certificate, false, ct);
            Assert.Equal(0L, await AgentGroupStore.Scalar(db, tx,
                "select count(*) from public.servers where domain_id=@domain and role='workstation'", ct, ("domain", domain)));
            Assert.Equal(1L, await AgentGroupStore.Scalar(db, tx, """
                select count(*) from public.sli_agent_group_approval_links l
                join public.sli_agent_group_requests r on r.id=l.request_id
                join public.sli_agent_enrollment_tokens e on e.id=l.enrollment_token_id
                where e.enrolled_agent_id=@agent and e.used_at is not null and r.status='approved' and r.computer_entity_id=@computer
                """, ct, ("agent", agent), ("computer", computer)));
            Assert.Null(await WorkstationJournalAdmission.ReadAsync(db, tx, agent, host.ToString("D"), null, ct));
            await tx.CommitAsync(ct);
        }

        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var request = JsonSerializer.SerializeToElement(new
            {
                agent_id = agent, module_id = WorkstationsModule.ModuleId, enabled = true, config = new JsonObject(),
            });
            var assigned = await new AgentModuleAssignmentService(audit).AssignAsync(db, tx, request, Actor, ct);
            string revision = assigned.GetProperty("policy_revision").GetInt64().ToString(CultureInfo.InvariantCulture);
            var scope = Assert.IsType<WorkstationJournalScope>(await WorkstationJournalAdmission.ReadAsync(db, tx, agent, host.ToString("D"), revision, ct));
            Assert.Equal(domain, scope.DomainId);
            Assert.Equal(Fqdn, scope.Computer);
            Assert.Equal(WorkstationJournalAdmission.EventIds,
                scope.Config["allow_event_ids"]!.AsArray().Select(value => value!.GetValue<int>()));
            await tx.CommitAsync(ct);
        }
    }

    private static async Task<(long Domain, long Computer, long Ou)> PublishDirectoryAsync(
        SqlPostgresFixture fixture, CancellationToken ct, [CallerFilePath] string sourceFile = "")
    {
        string vector = await File.ReadAllTextAsync(Path.Combine(Path.GetDirectoryName(sourceFile)!,
            "ad-publication-source-vector.json"), ct);
        var observed = DateTimeOffset.UtcNow.AddMinutes(-2);
        string stamp = observed.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        var data = JsonNode.Parse(vector.Replace("2026-10-08T12:00:00Z", stamp, StringComparison.Ordinal))!.AsObject();
        var policy = data["config"]!.AsObject();
        var families = data["families"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.AsObject());
        var basis = families["ad_context_base"];
        var account = basis["records"]!.AsArray().Single(r => r!["section"]!.GetValue<string>() == "directory_accounts"
            && r["identity"]?["object_guid"]?.GetValue<string>() == ComputerGuid)!;
        account["attributes"]!["distinguished_name"] = $"CN={Machine},{OuDn}";
        account["attributes"]!["dns_host_name"] = Fqdn;
        account["attributes"]!["operating_system"] = "Windows 10 Pro";
        var computer = families["computers_v6"]["objects"]![0]!;
        computer["name"] = Machine;
        computer["distinguishedName"] = $"CN={Machine},{OuDn}";
        computer["dnsHostName"] = Fqdn;
        computer["ou"] = OuDn;
        computer["osName"] = "Windows 10 Pro";
        computer["sources"]!["os"]!["value"] = "Windows 10 Pro";
        computer["deviceType"] = "workstation";
        computer["classification"]!["result"] = "workstation";
        var prepared = AdPublicationPreparation.Prepare(policy, families);
        var posture = prepared.Bundles["ad_domain_posture"];
        posture["records"]!.AsArray().Add(new JsonObject
        {
            ["record_type"] = "entity", ["section"] = "domain_posture", ["observed_at_utc"] = stamp,
            ["record_key"] = $"ad:{Sid.ToLowerInvariant()}:{OuGuid}",
            ["identity"] = new JsonObject { ["domain_sid"] = Sid, ["kind"] = "security_principal", ["object_guid"] = OuGuid },
            ["attributes"] = new JsonObject { ["display_name"] = "Workstations", ["infrastructure_role"] = "organizational_unit", ["distinguished_name"] = OuDn },
        });
        posture["sections"]![0]!["record_count"] = posture["records"]!.AsArray().Count;
        posture.Remove("bundle_sha256");
        posture["bundle_sha256"] = Convert.ToHexStringLower(GpoIdentityWriter.Hash(posture, false));

        long domain;
        await using (var owner = await fixture.Pg.OpenAsync(ct))
        {
            await PostCollectionPostgres.Sql(owner, """
                update plugin_installations_v1 set desired_activation='enabled_manual',component_runtime='running'
                where plugin_id='sli.workstations';
                """, ct);
            await using var insert = new NpgsqlCommand("""
                insert into public.domains(forest_id,fqdn,domain_sid)
                select min(id),@dns,@sid from public.forests returning id
                """, owner);
            insert.Parameters.AddWithValue("dns", Dns);
            insert.Parameters.AddWithValue("sid", Sid);
            domain = Assert.IsType<long>(await insert.ExecuteScalarAsync(ct));
        }

        await using var db = new NpgsqlConnection(fixture.Dsn("sli_context_login"));
        await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, "set role adlog_context_worker", ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        var sources = new List<JsonObject>();
        foreach (var (family, bundle) in prepared.Bundles)
        {
            await AdContextStore.ImportAsync(db, tx, domain, bundle, ct);
            var states = bundle["sections"]!.AsArray().Select(s => s!["status"]!.GetValue<string>()).ToArray();
            string state = states.Any(s => s is "partial" or "skipped") ? "partial" : "complete";
            sources.Add(AdSnapshotManifest.Member(family, bundle["source_pack_id"]!.GetValue<string>(),
                bundle["run_id"]!.GetValue<string>(), stamp, state, bundle["bundle_sha256"]!.GetValue<string>()));
        }
        var payload = prepared.Computers;
        string snapshot = await AdSourceSnapshots.ComputersAsync(db, tx, domain, payload, policy, ct);
        sources.Add(AdSnapshotManifest.Member("computers_v6", "sli.ad-computers.snapshot/2.0", snapshot, stamp,
            payload["metadata"]!["collection_status"]!.GetValue<string>(), Convert.ToHexStringLower(GpoIdentityWriter.Hash(payload, false))));
        string slot = new SnapshotPolicy(SnapshotPolicy.Ad, policy).DueSlot(observed);
        await AdSnapshotManifest.PublishAsync(db, tx, AdSnapshotManifest.Build(domain, Sid, Dns, slot, policy, stamp, sources), ct);
        async Task<long> Resolve(string guid) => Assert.IsType<long>(await AgentGroupStore.Scalar(db, tx, """
            select entity_id::bigint from public.ad_context_entity_aliases
            where domain_id=@domain and alias_type='object_guid' and normalized_value=@guid
            """, ct, ("domain", domain), ("guid", guid)));
        long computerId = await Resolve(ComputerGuid), ouId = await Resolve(OuGuid);
        await tx.CommitAsync(ct);
        return (domain, computerId, ouId);
    }
}
