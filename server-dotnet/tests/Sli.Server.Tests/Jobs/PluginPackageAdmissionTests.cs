using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using GpoJobPlugin = Sli.Server.Gpo.GpoJobPlugin;
using Sli.Server.Jobs;
using Xunit;

namespace Sli.Server.Tests.Jobs;

public sealed class PluginPackageAdmissionTests
{
    [Fact]
    public void Gpo_package_admission_and_rollback_preserve_compiled_handlers_and_check_dll_integrity()
    {
        using var files = new PluginPackageFixture("sli.gpo", "1.0.1");
        var catalog = CoreJobPluginCatalog.Compiled();
        var baseline = CoreJobTests.Job("gpo-snapshot");
        catalog.Registry(files.Root).Resolve(baseline);
        files.Activate();
        File.WriteAllText(Path.Combine(files.Plugin, "draining.json"), "{}");
        var registry = catalog.Registry(files.Root);
        Assert.Equal("1.0.1", Assert.Single(registry.Manifests, m => m.Text("plugin_id") == "sli.gpo").Text("plugin_version"));
        registry.Resolve(baseline);
        var active = (JsonObject)baseline.DeepClone();
        active["plugin_version"] = "1.0.1"; active["manifest_sha256"] = CoreJobJson.Digest(files.Jobs);
        registry.Resolve(active);
        Assert.NotNull(catalog.Resolve(active));
        Assert.NotNull(catalog.Resolve(CoreJobTests.Job("gpo-acquisition")));
        // Corrupt candidates fail admission. Rolling the pointer back recovers
        // the bundled manifest without making the rejected pinned jobs usable.
        File.AppendAllText(Path.Combine(files.VersionDirectory, "backend", "Sli.Server.dll"), "changed");
        Assert.Equal("update_plugin_payload_changed", Assert.Throws<CoreJobContractException>(() =>
            catalog.Registry(files.Root)).Message);
        File.Delete(Path.Combine(files.Plugin, "active.json"));
        var rolledBack = catalog.Registry(files.Root);
        rolledBack.Resolve(baseline);
        Assert.Equal("handler_version_unavailable", Assert.Throws<CoreJobContractException>(() => rolledBack.Resolve(active)).Message);
        Assert.True(File.Exists(Path.Combine(files.Plugin, "draining.json")));
    }

    [Fact]
    public void Validated_retained_generation_can_be_selected_again_after_rollback()
    {
        using var files = new PluginPackageFixture("sli.gpo", "1.0.1");
        var catalog = CoreJobPluginCatalog.Compiled();
        files.Activate();
        var first = catalog.Registry(files.Root);
        var candidate = CoreJobTests.Job("gpo-snapshot");
        candidate["plugin_version"] = "1.0.1"; candidate["manifest_sha256"] = CoreJobJson.Digest(files.Jobs);
        first.Resolve(candidate);
        File.Delete(Path.Combine(files.Plugin, "active.json"));
        var rollback = catalog.Registry(files.Root);
        Assert.Equal("1.0.0", Assert.Single(rollback.Manifests, m => m.Text("plugin_id") == "sli.gpo").Text("plugin_version"));
        rollback.Resolve(candidate); rollback.Resolve(CoreJobTests.Job("gpo-snapshot"));
        files.Activate(); catalog.Registry(files.Root).Resolve(candidate);
    }

    [Theory]
    [InlineData("dll", "update_plugin_payload_changed")]
    [InlineData("jobs", "update_plugin_payload_changed")]
    [InlineData("size", "update_plugin_payload_changed")]
    [InlineData("missing", "update_invalid_plugin_payload")]
    [InlineData("owner", "update_invalid_plugin_payload")]
    [InlineData("handlers", "update_plugin_handler_mismatch")]
    [InlineData("duplicate-handler", "update_plugin_handler_mismatch")]
    [InlineData("version", "update_plugin_handler_mismatch")]
    [InlineData("core-api", "update_plugin_api_incompatible")]
    [InlineData("ui-api", "update_plugin_api_incompatible")]
    [InlineData("traversal", "update_invalid_plugin_payload")]
    [InlineData("duplicate-file", "update_invalid_plugin_payload")]
    [InlineData("alternate-stream", "update_invalid_plugin_payload")]
    [InlineData("reserved-path", "update_invalid_plugin_payload")]
    [InlineData("ui-version", "update_plugin_ui_mismatch")]
    [InlineData("ui-hash", "update_plugin_ui_mismatch")]
    public void Package_tampering_and_contract_mismatches_fail_closed(string mutation, string code)
    {
        using var files = new PluginPackageFixture("sli.gpo", "1.0.1");
        switch (mutation)
        {
            case "dll": File.AppendAllText(Path.Combine(files.VersionDirectory, "backend", "Sli.Server.dll"), "changed"); break;
            case "jobs": File.AppendAllText(Path.Combine(files.VersionDirectory, "backend", "jobs-v3.json"), " "); break;
            case "size": files.Release["files"]![0]!["size"] = 0; break;
            case "missing": File.Delete(Path.Combine(files.VersionDirectory, "backend", "jobs-v3.json")); break;
            case "owner": files.Release["plugin_id"] = "sli.ad"; break;
            case "handlers": files.Release["handlers"] = new JsonArray("gpo-snapshot"); break;
            case "duplicate-handler": files.Release["handlers"] = new JsonArray("gpo-snapshot", "gpo-snapshot", "gpo-acquisition"); break;
            case "version": files.Jobs["plugin_version"] = "1.0.2"; files.WriteJobs(); break;
            case "core-api": files.Release["core_api"]!["minimum"] = "2.0.0"; break;
            case "ui-api": files.Release["ui_api"]!["maximum_exclusive"] = "1.0.0"; break;
            case "traversal": files.Release["files"]![0]!["path"] = "backend/../../outside.dll"; break;
            case "duplicate-file": files.Release["files"]!.AsArray().Add(files.Release["files"]![0]!.DeepClone()); break;
            case "alternate-stream": files.Release["files"]![0]!["path"] = "backend/file.dll:stream"; break;
            case "reserved-path": files.Release["files"]![0]!["path"] = "backend/NUL.dll"; break;
            case "ui-version": files.Descriptor["version"] = "1.0.2"; files.WriteUi(); break;
            case "ui-hash": files.Descriptor["entry"]!["sha256"] = new string('0', 64); files.WriteUi(); break;
        }
        files.WriteRelease(); files.Activate();
        var error = Assert.Throws<CoreJobContractException>(() => CoreJobPluginCatalog.Compiled().Registry(files.Root));
        Assert.Equal(code, error.Message);
        Assert.Equal(code, CoreJobCommand.Diagnostic(error).Text("error_code"));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Missing_active_package_never_falls_back_to_bundled_or_another_retained_generation(bool retained)
    {
        using var files = new PluginPackageFixture("sli.gpo", "1.0.1");
        if (!retained) Directory.Delete(Path.Combine(files.Plugin, "versions"), true);
        File.WriteAllText(Path.Combine(files.Plugin, "active.json"), new JsonObject { ["generation"] = new string('b', 64) }.ToJsonString());
        Assert.Equal("handler_version_unavailable", Assert.Throws<CoreJobContractException>(() => CoreJobPluginCatalog.Compiled().Registry(files.Root)).Message);
    }

}

internal sealed class PluginPackageFixture : IDisposable
{
    internal string Root { get; } = Path.Combine(Path.GetTempPath(), "sli-plugin-package-" + Guid.NewGuid().ToString("N"));
    internal string Plugin { get; }
    internal string Generation { get; } = new('a', 64);
    internal string VersionDirectory { get; }
    internal JsonObject Jobs { get; }
    internal JsonObject Release { get; }
    internal JsonObject Descriptor { get; }
    internal PluginPackageFixture(string plugin, string version)
    {
        Plugin = Path.Combine(Root, plugin); VersionDirectory = Path.Combine(Plugin, "versions", Generation);
        Directory.CreateDirectory(Path.Combine(VersionDirectory, "backend")); Directory.CreateDirectory(Path.Combine(VersionDirectory, "ui"));
        Jobs = CoreJobRegistry.Bundled(plugin); Jobs["plugin_version"] = version;
        File.WriteAllText(Path.Combine(VersionDirectory, "backend", "jobs-v3.json"), Jobs.ToJsonString());
        // Exercise hashing an actual compiled DLL, never a stand-in text binary.
        File.Copy(typeof(GpoJobPlugin).Assembly.Location, Path.Combine(VersionDirectory, "backend", "Sli.Server.dll"));
        byte[] asset = Encoding.UTF8.GetBytes("export const testOnly = true;");
        File.WriteAllBytes(Path.Combine(VersionDirectory, "ui", "entry.js"), asset);
        Descriptor = new JsonObject { ["plugin_id"] = plugin, ["version"] = version, ["ui_api"] = "sli.plugin-ui.v1",
            ["routes"] = new JsonArray("/extensions/" + plugin + "/reports"), ["required_capabilities"] = new JsonArray(),
            ["entry"] = new JsonObject { ["path"] = "entry.js", ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(asset)) } };
        File.WriteAllText(Path.Combine(VersionDirectory, "ui", "descriptor.json"), Descriptor.ToJsonString());
        Release = new JsonObject { ["schema_version"] = 2, ["component"] = "plugin", ["package_id"] = plugin,
            ["plugin_id"] = plugin, ["version"] = version, ["plugin_version"] = version,
            ["core_api"] = Jobs["core_api"]!.DeepClone(), ["ui_api"] = Jobs["core_api"]!.DeepClone(),
            ["handlers"] = new JsonArray(Jobs["handlers"]!.AsArray().Select(h => h!["handler_id"]!.DeepClone()).ToArray()) };
        Inventory(); WriteRelease();
    }
    internal void Inventory() => Release["files"] = new JsonArray(Directory.GetFiles(VersionDirectory, "*", SearchOption.AllDirectories)
        .Where(p => Path.GetFileName(p) != "release.json").Order(StringComparer.Ordinal).Select(p => (JsonNode)new JsonObject
        { ["path"] = Path.GetRelativePath(VersionDirectory, p).Replace('\\', '/'), ["size"] = new FileInfo(p).Length,
            ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(p))) }).ToArray());
    internal void WriteJobs() { File.WriteAllText(Path.Combine(VersionDirectory, "backend", "jobs-v3.json"), Jobs.ToJsonString()); Inventory(); }
    internal void WriteUi() { File.WriteAllText(Path.Combine(VersionDirectory, "ui", "descriptor.json"), Descriptor.ToJsonString()); Inventory(); }
    internal void WriteRelease() => File.WriteAllText(Path.Combine(VersionDirectory, "release.json"), Release.ToJsonString());
    internal void Activate() => File.WriteAllText(Path.Combine(Plugin, "active.json"), new JsonObject { ["generation"] = Generation }.ToJsonString());
    public void Dispose() => Directory.Delete(Root, true);
}
