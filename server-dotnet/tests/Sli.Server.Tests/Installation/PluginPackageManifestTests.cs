using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Server.InstallationSetup;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

public sealed class PluginPackageManifestTests
{
    static string Repository()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string path = Path.Combine(directory.FullName, "config", "plugin_packages", "sli.remote-access.json");
            if (File.Exists(path)) return directory.FullName;
        }
        throw new InvalidOperationException("test_manifest_not_found");
    }

    static JsonObject Manifest() => JsonNode.Parse(File.ReadAllText(Path.Combine(Repository(), "config/plugin_packages/sli.remote-access.json")))!.AsObject();
    static JsonObject Validate(JsonObject manifest) => PluginPackageManifest.ValidateRemoteAccess(manifest);
    static string FileHash(string relative) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(Repository(), relative))));

    [Fact]
    public void RemoteAccessManifestValidatesRegisteredComponentInventory()
    {
        var manifest = Manifest();
        var result = Validate(manifest);
        Assert.Equal("sli.remote-access", result["plugin_id"]!.GetValue<string>());
        Assert.Equal("0.1.0", result["plugin_version"]!.GetValue<string>());
        Assert.Equal(7, result["component_count"]!.GetValue<int>());
        Assert.Equal(new[] { "vpn.audit", "vpn.connections" }, manifest["components"]!["reports"]!.AsArray()
            .Select(item => item!["component_id"]!.GetValue<string>()).Order());
        Assert.Equal(new[] { "stage9-radius-manual-worker", "stage9-radius-session-consumer-manual" },
            result["handler_hashes"]!.AsObject().Select(item => item.Key).Order());
        foreach (var hash in result["handler_hashes"]!.AsObject())
            Assert.Matches("^[0-9a-f]{64}$", hash.Value!.GetValue<string>());
        Assert.Matches("^[0-9a-f]{64}$", result["manifest_sha256"]!.GetValue<string>());
        Assert.Equal(FileHash("config/plugin_packages/sli.remote-access.json"), result["manifest_sha256"]!.GetValue<string>());
        Assert.Equal("f27883ba28ff67ed5b9f4bf5b4fb157cec2e45de35a3134935232911a9efa898", result["handler_hashes"]!["stage9-radius-manual-worker"]!.GetValue<string>());
        Assert.Equal("39ea7f373c23def14072bf1ba732de43de7d2dab12903e521e2193bde136aeea", result["handler_hashes"]!["stage9-radius-session-consumer-manual"]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(result, PluginPackageManifest.LoadAndValidateRemoteAccess()));
    }

    [Theory]
    [InlineData("command")]
    [InlineData("COMMAND")]
    [InlineData("argv")]
    [InlineData("dsn")]
    [InlineData("entrypoint")]
    [InlineData("html")]
    [InlineData("import_path")]
    [InlineData("javascript")]
    [InlineData("password")]
    [InlineData("secret")]
    [InlineData("sql")]
    public void ManifestCannotSupplyArbitraryExecutableOrSensitiveMaterial(string key)
    {
        var manifest = Manifest();
        manifest["components"]!["workers"]![0]![key] = "untrusted-material";
        Assert.Equal("executable_or_sensitive_manifest_key:" + key,
            Assert.Throws<InvalidDataException>(() => Validate(manifest)).Message);
    }

    [Fact]
    public void ManifestHandlerMustBeReviewedAllowlistId()
    {
        var manifest = Manifest();
        manifest["components"]!["workers"]![0]!["handler_id"] = "unknown-handler";
        Assert.Equal("manifest_handler_allowlist_mismatch",
            Assert.Throws<InvalidDataException>(() => Validate(manifest)).Message);
    }

    [Theory]
    [InlineData("not_a_registered_component")]
    [InlineData("plugin_radius_session_observation")]
    [InlineData("collection")]
    public void ManifestProductionRuntimeMustMatchRuntimeRegistry(string runtime)
    {
        var manifest = Manifest();
        manifest["production_runtime"]!["components"]!["radius-acquisition"] = runtime;
        Assert.Equal("manifest_production_runtime_mismatch",
            Assert.Throws<InvalidDataException>(() => Validate(manifest)).Message);
    }
}
