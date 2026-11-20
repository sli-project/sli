using System.Text.Json.Nodes;
using Sli.Server.Storage;
using Sli.Server.Tests.Operations;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Vectors from tests/storage/test_storage_v2_transition_controller.py.
public sealed class StorageV2TransitionControllerTests
{
    static readonly string Digest = new('a', 64);
    static StorageV2Settings Settings(string read, string write, string rate = "0.25") => StorageV2Settings.Load(
        (key, fallback) => new Dictionary<string, string>
        {
            ["ADLOG_STORAGE_READ_MODE"] = read, ["ADLOG_STORAGE_WRITE_MODE"] = write,
            ["ADLOG_STORAGE_V2_SHADOW_SAMPLE_RATE"] = rate
        }.GetValueOrDefault(key, fallback));

    [Theory]
    [InlineData("v1", "v1")]
    [InlineData("v2", "v2")]
    public void Configured_route_is_always_v2_before_a_transition(string read, string write)
    {
        var settings = Settings(read, write);
        Assert.True(settings.Valid);
        Assert.Equal(read, settings.ReadMode);
        Assert.Equal(write, settings.WriteMode);
        Assert.Equal(0.25, settings.ShadowSampleRate);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            {"status":"READY","route":"v2","owner":"V2","authorization":"configured"}
            """), StorageV2TransitionController.ResolveStorageRoute()));
    }

    [Fact]
    public void Issued_capability_is_dormant_and_selects_v2_but_its_public_copy_does_not()
    {
        var authorization = StorageV2TransitionController.IssueAuthorization(Digest);
        Assert.True(StorageV2TransitionController.IsControllerAuthorization(authorization));
        Assert.Equal("AUTHORIZED", authorization.Status);
        Assert.Equal("dormant", authorization.Mode);
        Assert.Empty(authorization.SideEffects);
        Assert.Equal(StorageV2TransitionController.Authority, authorization.Authority);
        Assert.Equal(Digest, authorization.PreflightDigest);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            {"status":"READY","route":"v2","owner":"V2","authorization":"controller"}
            """), StorageV2TransitionController.ResolveStorageRoute(authorization)));
        Reject(new JsonObject { ["status"] = "AUTHORIZED", ["route"] = "v2",
            ["authority"] = authorization.Authority, ["preflight_digest"] = authorization.PreflightDigest });
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Issuance_requires_a_digest(string? digest) =>
        Assert.Throws<ArgumentException>(() => StorageV2TransitionController.IssueAuthorization(digest!));

    [Fact]
    public void Selected_or_empty_transition_state_without_authority_stops_routing()
    {
        foreach (var state in new[] { new JsonObject { ["status"] = "V2_SELECTED" }, new JsonObject() })
            Assert.Equal("storage_transition_state_requires_controller_authorization",
                Assert.Throws<StorageRouteAuthorizationException>(() =>
                    StorageV2TransitionController.ResolveStorageRoute(transitionState: state)).Message);
        Reject(new object());
        Assert.False(StorageV2TransitionController.IsControllerAuthorization(null));
    }

    [Fact]
    public void Tampered_or_unsealed_capabilities_cannot_select_a_route()
    {
        var a = StorageV2TransitionController.IssueAuthorization(Digest);
        foreach (var changed in new[] { a with { Route = "v1" }, a with { Authority = "untrusted" },
            a with { Status = "READY" }, a with { Mode = "active" }, a with { Owner = "V1" },
            a with { AuthorizationKind = "configured" }, a with { PreflightDigest = "" },
            new StorageV2TransitionController.Authorization(Digest, new object()) }) Reject(changed);
        // An authorized transition remains V2; rejecting a changed copy never mutates its issuer.
        Assert.Equal("v2", (string?)StorageV2TransitionController.ResolveStorageRoute(a,
            new JsonObject { ["status"] = "V2_SELECTED" })["route"]);
    }

    static void Reject(object value)
    {
        Assert.False(StorageV2TransitionController.IsControllerAuthorization(value));
        Assert.Equal("storage_transition_authorization_invalid", Assert.Throws<StorageRouteAuthorizationException>(
            () => StorageV2TransitionController.ResolveStorageRoute(value)).Message);
    }

    [Theory]
    [InlineData("v1_outbox")]
    [InlineData("v2_primary_compat")]
    public async Task Environment_write_modes_cannot_bypass_controller_authority(string write)
    {
        var settings = Settings("v1", write);
        Assert.False(settings.Valid);
        Assert.False(settings.OutboxEnabled);
        Assert.False(settings.V2PrimaryWriteEnabled);
        Assert.Equal("v2", settings.ReadMode);
        Assert.Equal("v1", settings.WriteMode);
        Assert.Equal(0, settings.ShadowSampleRate);
        Assert.Contains("controller", Assert.Single(settings.Diagnostics));
        // Exercise the existing runtime diagnostic response, using the same settings loader.
        using var app = await OperationsEndpointTests.Start(settings: new()
        {
            ["Sli:Operations:ADLOG_STORAGE_READ_MODE"] = "v1",
            ["Sli:Operations:ADLOG_STORAGE_WRITE_MODE"] = write,
            ["Sli:Operations:ADLOG_STORAGE_V2_SHADOW_SAMPLE_RATE"] = "0.25"
        });
        var runtime = await app.Service.ReadAsync("/api/runtime/status", new(), TestContext.Current.CancellationToken);
        Assert.True(JsonNode.DeepEquals(settings.PublicValues(), runtime["storage_v2"]));
    }
}
