using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Sources;
using Xunit;

namespace Sli.Server.Tests.Sources;

public sealed class PluginWorkerCredentialsTests
{
    const string Secret = "fixture-super-secret";
    const string EnvironmentName = "SLI_PLUGIN_SOURCE_CREDENTIAL";
    static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    static CredentialHandleBinding Binding(int generation) => new("credh:v1:" + Hash(generation.ToString()),
        "sli.vpn-radius", "radius-acquisition", "radius-fixture", generation, "source_read", [EnvironmentName], Hash("handler"));
    static CredentialLeaseRequest Request(CredentialHandleBinding binding) => new(binding.HandleId, binding.PluginId,
        binding.ComponentId, binding.SourceInstanceId, binding.CredentialGeneration, binding.Scope, binding.EnvironmentNames,
        binding.HandlerSha256, "worker-fixture-1", "runtime-fixture-1", 60);
    static InMemoryFixtureCredentialBroker Broker(params CredentialHandleBinding[] bindings) => new(bindings,
        bindings.GroupBy(b => b.HandleId).ToDictionary(g => g.Key,
            g => (IReadOnlyDictionary<string, string>)new Dictionary<string, string> { [EnvironmentName] = Secret + g.First().CredentialGeneration }),
        new Dictionary<string, string[]> { ["source_read"] = [EnvironmentName], ["plugin_postgres"] = ["SLI_PLUGIN_PG_DSN"] },
        new HashSet<string> { "ADLOG_PG_DSN", "ADLOG_PG_ADMIN_USER", "ADLOG_PG_ADMIN_PASSWORD" });
    static void Error(string code, Action action) => Assert.Equal(code, Assert.Throws<PluginCredentialError>(action).Message);
    static void Rotate(InMemoryFixtureCredentialBroker broker, CredentialHandleBinding binding, int generation) =>
        broker.RotateToGeneration(binding.PluginId, binding.ComponentId, binding.SourceInstanceId, generation);

    [Fact]
    public void Exact_binding_materializes_only_allowlisted_child_environment_and_audit_omits_material()
    {
        var binding = Binding(1); var broker = Broker(binding);
        var lease = broker.IssueLease(Request(binding), 100);
        var child = broker.MaterializeChildEnvironment(lease, 101);
        Assert.Equal(EnvironmentName, Assert.Single(child).Key);
        Assert.Equal(Secret + "1", child[EnvironmentName]);
        Assert.DoesNotContain(Secret, lease.ToString());
        Assert.DoesNotContain(Secret, broker.ToString());
        Assert.DoesNotContain(Secret, JsonSerializer.Serialize(lease));
        Assert.DoesNotContain(Secret, JsonSerializer.Serialize(broker));
        var audit = lease.AuditMetadata("accepted");
        Assert.DoesNotContain(Secret, audit.ToJsonString());
        var expected = JsonSerializer.SerializeToNode(new {
            lease_id = "credlease:v1:0000000000000001", handle_id = binding.HandleId,
            plugin_id = binding.PluginId, component_id = binding.ComponentId, source_instance_id = binding.SourceInstanceId,
            credential_generation = 1, scope = "source_read", worker_instance_id = "worker-fixture-1",
            runtime_instance_id = "runtime-fixture-1", environment_names = new[] { EnvironmentName },
            issued_at_epoch_seconds = 100, expires_at_epoch_seconds = 160, outcome = "accepted"
        });
        Assert.True(JsonNode.DeepEquals(expected, audit));
        child[EnvironmentName] = "changed"; child["UNREQUESTED"] = "changed";
        Assert.Equal(Secret + "1", Assert.Single(broker.MaterializeChildEnvironment(lease, 102)).Value);
    }

    [Theory]
    [InlineData("plugin_id", "credential_binding_mismatch")]
    [InlineData("component_id", "credential_binding_mismatch")]
    [InlineData("source_instance_id", "credential_binding_mismatch")]
    [InlineData("credential_generation", "credential_binding_mismatch")]
    [InlineData("handler_sha256", "credential_binding_mismatch")]
    [InlineData("runtime_instance_id", "invalid_runtime_instance_id")]
    [InlineData("worker_instance_id", "invalid_worker_instance_id")]
    [InlineData("scope", "credential_binding_mismatch")]
    [InlineData("environment_names", "credential_binding_mismatch")]
    [InlineData("handle_id", "unknown_handle")]
    public void Mismatched_or_invalid_request_fails_closed(string field, string code)
    {
        var binding = Binding(1); var broker = Broker(binding); var request = Request(binding);
        request = field switch {
            "plugin_id" => request with { PluginId = "sli.other" },
            "component_id" => request with { ComponentId = "other-component" },
            "source_instance_id" => request with { SourceInstanceId = "other-source" },
            "credential_generation" => request with { CredentialGeneration = 2 },
            "handler_sha256" => request with { HandlerSha256 = new string('f', 64) },
            "runtime_instance_id" => request with { RuntimeInstanceId = "INVALID SPACE" },
            "worker_instance_id" => request with { WorkerInstanceId = "INVALID SPACE" },
            "scope" => request with { Scope = "plugin_postgres" },
            "environment_names" => request with { EnvironmentNames = ["SLI_PLUGIN_PG_DSN"] },
            "handle_id" => request with { HandleId = "credh:v1:" + Hash("unknown") },
            _ => throw new InvalidOperationException()
        };
        Error(code, () => broker.IssueLease(request, 100));
    }

    [Fact]
    public void Rotation_blocks_new_old_generation_but_existing_lease_drains_to_exact_expiry()
    {
        var first = Binding(1); var second = Binding(2); var broker = Broker(second, first);
        Error("credential_generation_not_active", () => broker.IssueLease(Request(second), 100));
        var oldLease = broker.IssueLease(Request(first), 100);
        Rotate(broker, first, 2);
        Error("credential_generation_not_active", () => broker.IssueLease(Request(first), 101));
        Assert.Equal(Secret + "1", broker.MaterializeChildEnvironment(oldLease, 159)[EnvironmentName]);
        Error("lease_expired", () => broker.MaterializeChildEnvironment(oldLease, 160));
        var newLease = broker.IssueLease(Request(second), 101);
        Assert.Equal(Secret + "2", broker.MaterializeChildEnvironment(newLease, 102)[EnvironmentName]);
    }

    [Fact]
    public void Revoked_lease_and_handle_fail_closed_including_already_issued_lease()
    {
        var binding = Binding(1); var broker = Broker(binding);
        var lease = broker.IssueLease(Request(binding), 100);
        var otherLease = broker.IssueLease(Request(binding), 100);
        broker.RevokeLease(lease.LeaseId);
        Error("lease_revoked", () => broker.MaterializeChildEnvironment(lease, 101));
        Assert.NotEmpty(broker.MaterializeChildEnvironment(otherLease, 101));
        broker.RevokeHandle(binding.HandleId);
        Error("handle_revoked", () => broker.IssueLease(Request(binding), 101));
        Error("handle_revoked", () => broker.MaterializeChildEnvironment(otherLease, 101));
    }

    [Fact]
    public void Rotation_cannot_skip_a_generation_or_select_an_unregistered_generation()
    {
        var first = Binding(1); var broker = Broker(first, Binding(3));
        Error("generation_must_advance_by_one", () => Rotate(broker, first, 3));
        Error("target_generation_not_registered", () => Rotate(broker, first, 2));
        Error("unknown_source_binding", () => Rotate(broker, first with { SourceInstanceId = "other-source" }, 2));
        Assert.NotNull(broker.IssueLease(Request(first), 100));
    }

    [Theory]
    [InlineData("ADLOG_PG_DSN")]
    [InlineData("ADLOG_PG_ADMIN_USER")]
    [InlineData("ADLOG_PG_ADMIN_PASSWORD")]
    public void Admin_or_generic_project_postgres_environment_is_rejected(string environmentName)
    {
        var broken = Binding(1) with { Scope = "plugin_postgres", EnvironmentNames = [environmentName] };
        Error("prohibited_environment_name", () => Broker(broken));
    }

    [Fact]
    public void Source_identity_is_stable_across_credential_rotation()
    {
        Assert.Equal(Binding(1).StableSourceIdentity(), Binding(2).StableSourceIdentity());
        Assert.Equal(Hash("sli.vpn-radius\x1fradius-acquisition\x1fradius-fixture"), Binding(1).StableSourceIdentity());
        Assert.NotEqual(Binding(1).StableSourceIdentity(), (Binding(1) with { SourceInstanceId = "other-source" }).StableSourceIdentity());
    }

    [Fact]
    public void Foreign_broker_lease_with_same_sequence_is_rejected()
    {
        var binding = Binding(1); var broker = Broker(binding); var other = Broker(binding);
        var foreign = other.IssueLease(Request(binding), 100);
        Assert.Equal(foreign.LeaseId, broker.IssueLease(Request(binding), 100).LeaseId);
        Error("lease_not_issued_by_broker", () => broker.MaterializeChildEnvironment(foreign, 101));
    }

    [Theory]
    [InlineData(0, false)] [InlineData(-1, false)] [InlineData(1, true)]
    [InlineData(900, true)] [InlineData(901, false)]
    public void Credential_validity_matches_reference_security_contract(int ttl, bool accepted)
    {
        var binding = Binding(1); var broker = Broker(binding); var request = Request(binding) with { TtlSeconds = ttl };
        if (!accepted) { Error("lease_ttl_out_of_bounds", () => broker.IssueLease(request, 100)); return; }
        var lease = broker.IssueLease(request, 100);
        Assert.NotEmpty(broker.MaterializeChildEnvironment(lease, 100 + ttl - 1));
        Error("lease_expired", () => broker.MaterializeChildEnvironment(lease, 100 + ttl));
    }
}
