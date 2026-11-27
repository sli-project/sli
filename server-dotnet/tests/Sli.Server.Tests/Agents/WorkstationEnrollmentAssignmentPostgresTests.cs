using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Registry;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class WorkstationEnrollmentAssignmentPostgresTests
{
    [Theory]
    [InlineData(false, true, true)]
    [InlineData(true, true, true)]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    public async Task PluginAssignsTheSupportedJournalPolicyToAnApprovedWorkstation(bool upgrade, bool pluginEnabled, bool approvedName)
    {
        const string machine = "ws-auto-fixture.example.test";
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using (var owner = await fixture.Pg.OpenAsync(ct))
        {
            await PostCollectionPostgres.Sql(owner, """
                insert into servers(domain_id,hostname,fqdn,role)
                    select id,'ws-auto-fixture','ws-auto-fixture.example.test','workstation'
                    from domains where fqdn='example.test';
                """, ct);
            await PostCollectionPostgres.Sql(owner, pluginEnabled ? """
                update plugin_installations_v1 set desired_activation='enabled_manual',component_runtime='running'
                where plugin_id='sli.workstations';
                """ : """
                update plugin_installations_v1 set desired_activation='disabled',component_runtime='stopped'
                where plugin_id='sli.workstations';
                """, ct);
        }

        await using var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await db.OpenAsync(ct);
        using var certificates = new WriteSqlPostgresTests.Certificates();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var audit = new AgentControlAudit();
        var host = Guid.NewGuid();
        var auth = new AgentIdentityService(certificates.Ca);
        var service = new AgentClientControlService(audit, TimeProvider.System);
        await using var tx = await db.BeginTransactionAsync(ct);
        var issued = await new AgentManagementService(audit).CreateTokenAsync(db, tx, JsonSerializer.SerializeToElement(new
        {
            host_id = host,
            registration_host_name = approvedName ? machine : null,
            key_fingerprint = Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())),
        }), "session:1", ct);
        var request = new JsonObject
        {
            ["token"] = issued.GetProperty("token").GetString(),
            ["csr_pem"] = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256).CreateSigningRequestPem(),
            ["machine_role"] = upgrade ? "file_server" : "workstation",
            ["reported_hostname"] = machine,
        };
        if (!upgrade) request["windows_product_type"] = "WinNT";
        var enrolled = await new AgentEnrollmentService(certificates.Ca, auth).EnrollAsync(db, tx, request, ct);
        var agentId = Guid.Parse(enrolled["agent_id"]!.GetValue<string>());
        using var cert = X509Certificate2.CreateFromPem(enrolled["certificate_pem"]!.GetValue<string>());
        var identity = await auth.AuthenticateAsync(db, tx, cert, false, ct);
        if (upgrade)
        {
            Assert.Null(await WorkstationJournalAdmission.ReadAsync(db, tx, agentId, null, null, ct));
            var before = await service.CheckInAsync(db, tx, identity, ct);
            Assert.True(before["windows_product_type_required"]!.GetValue<bool>());
            await service.ReportAsync(db, tx, identity, new JsonObject
            {
                ["applied_policy_revision"] = before["policy_revision"]!.DeepClone(),
                ["collection_state"] = "active",
                ["windows_product_type"] = "WinNT",
            }, ct);
        }
        else if (pluginEnabled && approvedName)
            Assert.NotNull(await WorkstationJournalAdmission.ReadAsync(db, tx, agentId, host.ToString("D"), "2", ct));

        var policy = await service.CheckInAsync(db, tx, identity, ct);
        if (pluginEnabled && approvedName)
        {
            var assignment = Assert.Single(policy["assigned_modules"]!.AsArray())!;
            Assert.Equal(WorkstationsModule.ModuleId, assignment["module_id"]!.GetValue<string>());
            Assert.True(assignment["enabled"]!.GetValue<bool>());
            Assert.Equal(2L, policy["policy_revision"]!.GetValue<long>());
            Assert.NotNull(await WorkstationJournalAdmission.ReadAsync(db, tx, agentId, host.ToString("D"), "2", ct));
        }
        else
            Assert.Empty(policy["assigned_modules"]!.AsArray());
        await tx.CommitAsync(ct);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmptyEnableUsesJournalDefaultsOnlyForUnchangedFullEnrollment(bool operatorSavedConfiguration)
    {
        const string machine = "ws-full-fixture.example.test";
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using (var owner = await fixture.Pg.OpenAsync(ct))
            await PostCollectionPostgres.Sql(owner, """
                insert into servers(domain_id,hostname,fqdn,role)
                    select id,'ws-full-fixture.example.test','ws-full-fixture.example.test','workstation'
                    from domains where fqdn='example.test';
                update plugin_installations_v1
                    set desired_activation='enabled_manual',component_runtime='running'
                    where plugin_id='sli.workstations';
                """, ct);

        await using var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await db.OpenAsync(ct);
        using var certificates = new WriteSqlPostgresTests.Certificates();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var audit = new AgentControlAudit();
        var host = Guid.NewGuid();
        var csr = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256);
        var profile = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Sli:CollectionProfile"] = "full" }).Build();
        var enrollment = new AgentEnrollmentService(certificates.Ca, new AgentIdentityService(certificates.Ca), profile);
        Guid agent;
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var issued = await new AgentManagementService(audit).CreateTokenAsync(db, tx, JsonSerializer.SerializeToElement(new
            {
                host_id = host,
                registration_host_name = machine,
                key_fingerprint = Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())),
            }), "session:1", ct);
            var identity = await enrollment.EnrollAsync(db, tx, new JsonObject
            {
                ["token"] = issued.GetProperty("token").GetString(),
                ["csr_pem"] = csr.CreateSigningRequestPem(),
                ["machine_role"] = "workstation",
                ["reported_hostname"] = machine,
            }, ct);
            agent = Guid.Parse(identity["agent_id"]!.GetValue<string>());
            await tx.CommitAsync(ct);
        }

        var assignments = new AgentModuleAssignmentService(audit);
        JsonObject full;
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var state = await ReadAgent(tx);
            var module = Assert.Single(state["assigned_modules"]!.AsArray())!.AsObject();
            Assert.True(module["enabled"]!.GetValue<bool>());
            full = module["config"]!.DeepClone().AsObject();
            Assert.Null(full["allow_event_ids"]);
            Assert.Null(await WorkstationJournalAdmission.ReadAsync(db, tx, agent, host.ToString("D"), null, ct));
            if (!operatorSavedConfiguration)
                await AgentPolicyAssignments.DisableUnavailableAsync(db, tx, state, ct);
            await tx.CommitAsync(ct);
        }
        if (operatorSavedConfiguration)
            await Assign(false, 2, full);

        await AssertRefused(full);
        if (operatorSavedConfiguration)
        {
            await AssertRefused(new());
            return;
        }

        var response = await Assign(true, 3, new());
        Assert.Equal(4L, response.GetProperty("policy_revision").GetInt64());

        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var state = await ReadAgent(tx);
            await AgentPolicyAssignments.DisableUnavailableAsync(db, tx, state, ct);
            var effective = Assert.Single(state["assigned_modules"]!.AsArray())!.AsObject();
            Assert.True(effective["enabled"]!.GetValue<bool>());
            var config = effective["config"]!.AsObject();
            Assert.Equal(WorkstationJournalAdmission.EventIds, config["allow_event_ids"]!.AsArray().Select(value => value!.GetValue<int>()));
            Assert.True(config["families"]!["processes"]!.GetValue<bool>());
            Assert.True(config["families"]!["usb"]!.GetValue<bool>());
            var scope = await WorkstationJournalAdmission.ReadAsync(db, tx, agent, host.ToString("D"), "4", ct);
            Assert.NotNull(scope);
            Assert.Equal(machine, scope.Computer);
            Assert.True(JsonNode.DeepEquals(config, scope.Config));
            await tx.CommitAsync(ct);
        }

        async Task<JsonObject> ReadAgent(NpgsqlTransaction tx)
        {
            await using var command = new NpgsqlCommand("select to_jsonb(a)::text from sli_agents a where id=@id for update", db, tx);
            command.Parameters.AddWithValue("id", agent);
            return JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)!.AsObject();
        }

        async Task<JsonElement> Assign(bool enabled, int revision, JsonObject config)
        {
            await using var tx = await db.BeginTransactionAsync(ct);
            var request = JsonSerializer.SerializeToElement(new
            {
                agent_id = agent, module_id = WorkstationsModule.ModuleId, enabled, config, expected_revision = revision,
            });
            var response = await assignments.AssignAsync(db, tx, request, "session:1", ct);
            await tx.CommitAsync(ct);
            return response;
        }

        async Task AssertRefused(JsonObject config)
        {
            var error = await Assert.ThrowsAsync<AgentControlException>(() => Assign(true, 3, config));
            Assert.Equal("workstation_journal_profile_unsupported", error.Message);
            await using var tx = await db.BeginTransactionAsync(ct);
            var state = await ReadAgent(tx);
            Assert.Equal(3L, state["policy_revision"]!.GetValue<long>());
            var module = Assert.Single(state["assigned_modules"]!.AsArray())!.AsObject();
            Assert.False(module["enabled"]!.GetValue<bool>());
            var unchanged = full.DeepClone().AsObject();
            unchanged["policy_revision"] = "3";
            Assert.True(JsonNode.DeepEquals(module["config"], unchanged));
            Assert.Null(await WorkstationJournalAdmission.ReadAsync(db, tx, agent, host.ToString("D"), null, ct));
            await tx.CommitAsync(ct);
        }
    }
}
