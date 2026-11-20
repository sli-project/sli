using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Sli.Server.Agents.Control;
using Sli.Server.InstallationSetup;
using Sli.Server.Jobs;
using Sli.Server.Plugins;
using Xunit;

namespace Sli.Server.Tests.Access;

public sealed class PluginRuntimeTests
{
    [Fact]
    public async Task Health_checks_compiled_handlers_and_ui_under_fence_and_supports_bundled_rollback()
    {
        using var files = new Files(); files.Ui(); files.Fence();
        Assert.Equal(0, await files.Run(["health", Files.Id, "--version", "0.1.0"]));
        Assert.Contains("healthy", files.Output.ToString());
        // Serving still denies the same package while the updater owns the fence.
        Assert.Throws<InstallationException>(() => new InstallationPackages(files.Config).LoadUi(Files.Id));
        files.Activate();
        Assert.Equal(1, await files.Run(["health", Files.Id, "--version", "0.1.0"]));
        Assert.Contains("plugin_update_generation_unsupported", files.Error.ToString());
        Assert.DoesNotContain("healthy", files.Output.ToString());
        File.Delete(Path.Combine(files.Plugin, "active.json")); // Existing host rollback restores bundled pointer.
        Assert.Equal(0, await files.Run(["health", Files.Id, "--version", "0.1.0"]));
        Assert.True(File.Exists(Path.Combine(files.Plugin, "draining.json")));
    }

    [Fact]
    public async Task Health_rejects_missing_handlers_corrupt_assets_and_version_mismatch()
    {
        using var files = new Files(); files.Ui();
        Assert.Equal(1, await files.Run(["health", Files.Id, "--version", "0.1.0"], new CoreJobPluginCatalog()));
        Assert.Contains("plugin_update_handler_mismatch", files.Error.ToString());
        Assert.Equal(1, await files.Run(["health", Files.Id, "--version", "9.9.9"]));
        Assert.Contains("plugin_update_ui_version_mismatch", files.Error.ToString());
        File.WriteAllText(files.Asset, "changed");
        Assert.Equal(1, await files.Run(["health", Files.Id, "--version", "0.1.0"]));
        Assert.Contains("plugin_ui_integrity_failed", files.Error.ToString());
        Assert.DoesNotContain(files.Root, files.Error.ToString());
        Assert.DoesNotContain("healthy", files.Output.ToString());
    }

    [Theory]
    [InlineData("sli.gpo")]
    [InlineData("sli.workstations")]
    [InlineData("sli.sigma")]
    public async Task Metadata_without_a_reviewed_native_health_hook_is_never_healthy(string id)
    {
        using var files = new Files();
        Assert.Equal(1, await files.Run(["health", id, "--version", "1.0.0"]));
        Assert.Contains("plugin_update_health_unavailable", files.Error.ToString());
        Assert.Empty(files.Output.ToString());
    }

    [Theory]
    [InlineData("drain", "../outside")]
    [InlineData("health", Files.Id)]
    [InlineData("unknown", Files.Id)]
    [InlineData("@untrusted-response-file", Files.Id)]
    public async Task Invalid_input_cannot_report_success(string action, string id)
    {
        using var files = new Files();
        Assert.NotEqual(0, await files.Run([action, id]));
        Assert.Empty(files.Output.ToString());
    }

    [Fact]
    public async Task Drain_requires_durable_fence_and_never_creates_a_lock()
    {
        using var files = new Files();
        Assert.Equal(1, await files.Run(["drain", Files.Id]));
        Assert.Contains("plugin_update_fence_required", files.Error.ToString());
        Assert.False(File.Exists(Path.Combine(files.Plugin, "admission.lock")));
        files.Fence();
        Assert.Equal(1, await files.Run(["drain", Files.Id]));
        Assert.Empty(files.Output.ToString());
        Assert.False(File.Exists(Path.Combine(files.Plugin, "admission.lock")));
    }

    [Fact]
    public async Task Linux_flock_waits_for_the_existing_admission_inode_and_emits_progress()
    {
        using var files = new Files(); files.Lock();
        if (!OperatingSystem.IsLinux())
        {
            files.Fence(); Assert.Equal(1, await files.Run(["drain", Files.Id]));
            Assert.Contains("plugin_update_lock_unavailable", files.Error.ToString());
            return;
        }
        var held = CoreJobAdmission.Enter(Files.Id, files.Runtime, files.Locks);
        try
        {
            files.Fence();
            using var output = new ProgressWriter();
            var draining = PluginDrain.WaitAsync(Files.Id, files.Runtime, files.Locks, output, TestContext.Current.CancellationToken);
            await output.Waiting.Task.WaitAsync(TestContext.Current.CancellationToken);
            Assert.False(draining.IsCompleted);
            Assert.Throws<InvalidOperationException>(() => AgentAssignmentPluginAdmission.Enter(Files.Id, files.Runtime, files.Locks));
            held.Dispose();
            await draining;
            Assert.Contains("drained", output.ToString());
            Assert.Contains("heartbeat_utc", output.ToString());
            Assert.True(File.Exists(Path.Combine(files.Plugin, "draining.json")));
            // Drain must not depend on a readable active pointer, otherwise rollback can deadlock.
            File.WriteAllText(Path.Combine(files.Plugin, "active.json"), "{");
            Assert.Equal(0, await files.Run(["drain", Files.Id]));
        }
        finally { held.Dispose(); }
    }

    [Fact]
    public async Task Waiting_drain_can_be_cancelled_or_lose_its_fence_without_success()
    {
        if (!OperatingSystem.IsLinux()) return; // Linux flock only; unsupported platform tested above.
        using var files = new Files(); files.Lock();
        using var held = CoreJobAdmission.Enter(Files.Id, files.Runtime, files.Locks);
        files.Fence();
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        using var output = new ProgressWriter();
        var draining = PluginDrain.WaitAsync(Files.Id, files.Runtime, files.Locks, output, cancel.Token);
        await output.Waiting.Task.WaitAsync(TestContext.Current.CancellationToken);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => draining);
        Assert.DoesNotContain("drained", output.ToString());
        using var second = new ProgressWriter();
        draining = PluginDrain.WaitAsync(Files.Id, files.Runtime, files.Locks, second, TestContext.Current.CancellationToken);
        await second.Waiting.Task.WaitAsync(TestContext.Current.CancellationToken);
        File.Delete(Path.Combine(files.Plugin, "draining.json"));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => draining);
        Assert.Equal("plugin_update_fence_required", error.Message);
        Assert.DoesNotContain("drained", second.ToString());
    }

    sealed class ProgressWriter : StringWriter
    {
        internal TaskCompletionSource Waiting { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override Task WriteLineAsync(string? value)
        {
            var result = base.WriteLineAsync(value);
            if (value?.Contains("waiting", StringComparison.Ordinal) == true) Waiting.TrySetResult();
            return result;
        }
    }

    sealed class Files : IDisposable
    {
        internal const string Id = "sli.remote-access";
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "sli-plugin-runtime-" + Guid.NewGuid().ToString("N"));
        internal string Runtime => Path.Combine(Root, "plugins");
        internal string Plugin => Path.Combine(Runtime, Id);
        internal string Locks => Path.Combine(Root, "locks");
        internal string Asset => Path.Combine(Root, "ui", Id, "entry.js");
        internal IConfiguration Config { get; }
        internal StringWriter Output { get; } = new();
        internal StringWriter Error { get; } = new();
        internal Files()
        {
            Directory.CreateDirectory(Plugin); Directory.CreateDirectory(Locks);
            Config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["Sli:PluginRuntimeDirectory"] = Runtime, ["Sli:PluginLockDirectory"] = Locks,
                ["Sli:PluginUiDirectory"] = Path.Combine(Root, "ui") }).Build();
        }
        internal void Fence() => File.WriteAllText(Path.Combine(Plugin, "draining.json"), "{}");
        internal void Lock() => File.WriteAllText(Path.Combine(Locks, Id + ".json"), "{}");
        internal void Activate()
        {
            string generation = new('a', 64);
            Directory.CreateDirectory(Path.Combine(Plugin, "versions", generation));
            File.WriteAllText(Path.Combine(Plugin, "active.json"), JsonSerializer.Serialize(new { generation }));
        }
        internal void Ui()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Asset)!);
            byte[] payload = Encoding.UTF8.GetBytes("export const fixture = true;");
            File.WriteAllBytes(Asset, payload);
            File.WriteAllText(Path.Combine(Path.GetDirectoryName(Asset)!, "descriptor.json"), JsonSerializer.Serialize(new {
                plugin_id = Id, version = "0.1.0", ui_api = "sli.plugin-ui.v1", routes = new[] { "/extensions/" + Id + "/accounts" },
                required_capabilities = Array.Empty<string>(), entry = new { path = "entry.js", sha256 = Convert.ToHexStringLower(SHA256.HashData(payload)) } }));
        }
        internal Task<int> Run(string[] args, CoreJobPluginCatalog? catalog = null)
        {
            Output.GetStringBuilder().Clear(); Error.GetStringBuilder().Clear();
            return PluginRuntimeCommand.RunAsync(args, Config, catalog ?? CoreJobPluginCatalog.Compiled(), Output, Error, TestContext.Current.CancellationToken);
        }
        public void Dispose()
        {
            string path = Path.GetFullPath(Root);
            if (Path.GetDirectoryName(path) != Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar)
                || !Path.GetFileName(path).StartsWith("sli-plugin-runtime-", StringComparison.Ordinal)) throw new InvalidOperationException("Unexpected test path");
            Output.Dispose(); Error.Dispose(); Directory.Delete(path, true);
        }
    }
}
