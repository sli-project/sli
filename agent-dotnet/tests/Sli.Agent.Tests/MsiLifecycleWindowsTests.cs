using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using Microsoft.Win32;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Service;
using Sli.Agent.Tests.Support;
using Sli.Agent.Windows;
using Xunit;
using Xunit.Abstractions;

namespace Sli.Agent.Tests;

/// <summary>Opt-in only on a disposable Windows machine: creates a real machine-wide service.</summary>
[SupportedOSPlatform("windows")]
public sealed class MsiLifecycleWindowsTests(ITestOutputHelper output)
{
    [MsiLifecycleFact]
    [Trait("Category", "WindowsOnly")]
    public async Task UpgradePreservesIdentityAndUninstallClearsItWithExplicitQueuePurge()
    {
        using var currentUser = WindowsIdentity.GetCurrent();
        Assert.True(new WindowsPrincipal(currentUser).IsInRole(WindowsBuiltInRole.Administrator),
            "Use an elevated disposable Windows runner");
        var baseline = Path.GetFullPath(Environment.GetEnvironmentVariable("SLI_AGENT_MSI_BASELINE")!);
        var upgrade = Path.GetFullPath(Environment.GetEnvironmentVariable("SLI_AGENT_MSI_UPGRADE")!);
        Assert.True(File.Exists(baseline) && File.Exists(upgrade));
        Assert.NotEqual(baseline, upgrade);
        var options = new AgentOptions();
        var dataRoot = Path.GetDirectoryName(options.StateDir)!;
        var program = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SLI", "AgentNet");
        using var registry = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        // Refuse to read or replace any pre-existing registration, files or service.
        using (var existing = registry.OpenSubKey(MsiConfiguration.RegistryPath)) Assert.Null(existing);
        Assert.False(Directory.Exists(dataRoot), "Existing agent data: use a clean disposable runner");
        Assert.False(Directory.Exists(program), "Existing agent program: use a clean disposable runner");
        AssertServiceAbsent();

        var logs = Path.Combine(Path.GetTempPath(), "sli-msi-lifecycle-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(logs);
        var attemptedInstall = false;
        try
        {
            var store = AgentRuntime.CreateIdentityStore(options);
            var prepared = store.Prepare();
            var now = DateTimeOffset.UtcNow;
            using var authority = new TestAuthority(now);
            using var identity = store.Accept(authority.Issue(store), now);
            SignedPacket packet;
            CapturedPosition? cursor;
            using (var queue = new FilePacketQueue(Path.Combine(options.StateDir, "queue"),
                       new PhysicalDurableFiles(new WindowsDirectorySecurity()), options.SpoolMaxBytes, options.SpoolMaxAgeSeconds))
            {
                packet = queue.Capture(identity.Signer, identity.AgentId, Helpers.Sample("", "42"), now);
                cursor = queue.Captured("sli.test");
            }
            var saved = new[] { "host.json", "identity-key.json", "identity.json", "queue/checkpoints.json" }
                .ToDictionary(name => name, name => File.ReadAllBytes(Path.Combine(options.StateDir, name)));
            void AssertState()
            {
                foreach (var (name, bytes) in saved) Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(options.StateDir, name)));
                var restoredStore = AgentRuntime.CreateIdentityStore(options);
                Assert.Equal(prepared, restoredStore.Prepare());
                using var restored = restoredStore.Load();
                Assert.NotNull(restored);
                Assert.Equal(identity.AgentId, restored.AgentId);
                Assert.Equal(identity.Certificate.Thumbprint, restored.Certificate.Thumbprint);
                Assert.True(restored.Certificate.HasPrivateKey);
            }
            void AssertQueue(string directory)
            {
                using var queue = new FilePacketQueue(directory,
                    new PhysicalDurableFiles(new WindowsDirectorySecurity()), options.SpoolMaxBytes, options.SpoolMaxAgeSeconds);
                Assert.Equal(packet.ToCanonical(), Assert.Single(queue.Pending()).ToCanonical());
                Assert.Equal(cursor, queue.Captured("sli.test"));
            }

            // The certificate is issued by a generated test CA. The service can only contact loopback.
            // No real enrollment endpoint, token, AD policy or event collection is used.
            attemptedInstall = true;
            await Msi("install", "/i", baseline, "/qn", "/norestart", "SERVER_URL=https://127.0.0.1:1",
                "ENROLL_TOKEN=synthetic-unused-bootstrap");
            AssertServiceRunning();
            Assert.True(File.Exists(Path.Combine(program, "SliAgent.exe")));
            AssertState();
            string oldProduct;
            Version oldVersion;
            using (var product = registry.OpenSubKey(MsiConfiguration.RegistryPath + @"\Product"))
            {
                Assert.NotNull(product);
                oldProduct = Assert.IsType<string>(product.GetValue("ProductCode"));
                oldVersion = Version.Parse(Assert.IsType<string>(product.GetValue("Version")));
            }
            // Exercise the same out-of-process handoff used by check-in. It runs
            // while the baseline service is active and receives no registration inputs.
            var updateDirectory = Path.Combine(options.StateDir, "update");
            AgentRuntime.CreateFiles().EnsureDirectory(updateDirectory);
            string badPackage = Path.Combine(updateDirectory, "invalid.msi");
            File.WriteAllBytes(badPackage, "synthetic invalid MSI"u8.ToArray());
            await RunUpdate(badPackage, "failed");
            using (var unchanged = registry.OpenSubKey(MsiConfiguration.RegistryPath + @"\Product"))
                Assert.Equal(oldProduct, unchanged?.GetValue("ProductCode"));
            AssertServiceRunning();
            AssertState();

            string staged = Path.Combine(updateDirectory, "upgrade.msi");
            File.Copy(upgrade, staged);
            await RunUpdate(staged, "success");
            using (var updated = registry.OpenSubKey(MsiConfiguration.RegistryPath + @"\Product"))
            {
                Assert.NotNull(updated);
                Assert.NotEqual(oldProduct, updated.GetValue("ProductCode"));
                Assert.True(Version.Parse(Assert.IsType<string>(updated.GetValue("Version"))) > oldVersion);
            }
            AssertServiceRunning();
            AssertState();
            // The running service owns the queue lock. AssertState already checked the checkpoint bytes.
            var packetPath = Assert.Single(Directory.EnumerateFiles(Path.Combine(options.StateDir, "queue"), "*.packet"));
            Assert.Equal(packet.Envelope.PacketId + ".packet", Path.GetFileName(packetPath));
            Assert.Equal(Encoding.ASCII.GetBytes(packet.ToCanonical()), File.ReadAllBytes(packetPath));
            Assert.Equal("https://127.0.0.1:1", MsiConfiguration.ReadSettings()["Agent:ServerUrl"]);
            await Msi("repair", "/i", upgrade, "/qn", "/norestart", "REINSTALL=ALL", "REINSTALLMODE=vamus");
            AssertServiceRunning();
            AssertState();
            Assert.Equal(Encoding.ASCII.GetBytes(packet.ToCanonical()), File.ReadAllBytes(packetPath));
            // Uninstall starts with the service running; MSI itself must stop it before removing files.
            await Msi("uninstall", "/x", upgrade, "/qn", "/norestart");
            AssertServiceAbsent();
            Assert.False(File.Exists(Path.Combine(program, "SliAgent.exe")));
            if (Directory.Exists(program)) Assert.Empty(Directory.EnumerateFiles(program, "*", SearchOption.AllDirectories));
            Assert.False(Directory.Exists(options.StateDir));
            AssertQueue(Path.Combine(dataRoot, "retained-queue-state"));
            Assert.False(MsiConfiguration.ReadSettings().ContainsKey("Agent:ServerUrl"));
            await Msi("reinstall", "/i", upgrade, "/qn", "/norestart", "SERVER_URL=https://127.0.0.1:1",
                "ENROLL_TOKEN=synthetic-unused-bootstrap");
            AssertServiceRunning();
            Assert.False(File.Exists(Path.Combine(options.StateDir, "identity.json")));
            await Msi("remove-reinstalled", "/x", upgrade, "/qn", "/norestart", "PURGE_QUEUE=1");
            AssertServiceAbsent();
            if (Directory.Exists(program)) Assert.Empty(Directory.EnumerateFiles(program, "*", SearchOption.AllDirectories));
            Assert.False(Directory.Exists(options.StateDir));
            Assert.Empty(Directory.EnumerateDirectories(dataRoot, "retained-queue-*"));
        }
        finally
        {
            if (attemptedInstall)
            {
                // Only these two test packages can be removed; never enumerate or uninstall other products.
                await Msi("cleanup-upgrade", "/x", upgrade, "/qn", "/norestart", allowAbsent: true);
                await Msi("cleanup-baseline", "/x", baseline, "/qn", "/norestart", allowAbsent: true);
            }
            AssertServiceAbsent();
            // All three paths were absent before this test. Keep the MSI logs on failure.
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
            registry.DeleteSubKeyTree(MsiConfiguration.RegistryPath, throwOnMissingSubKey: false);
        }

        async Task RunUpdate(string package, string expectedResult)
        {
            string digest;
            await using (var bytes = File.OpenRead(package))
                digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(bytes));
            using var process = MsiAgentUpdate.StartInstaller(package, digest);
            await process.WaitForExitAsync();
            Assert.Equal(0, process.ExitCode);
            Assert.Equal(expectedResult, File.ReadAllText(Path.ChangeExtension(package, ".result")));
            Assert.False(File.Exists(package));
        }

        async Task Msi(string step, string operation, string package, string quiet, string restart,
            string? server = null, string? token = null, bool allowAbsent = false)
        {
            var log = Path.Combine(logs, step + ".log");
            output.WriteLine($"MSI {step}: {log}");
            var start = new ProcessStartInfo("msiexec.exe") { UseShellExecute = false, CreateNoWindow = true };
            foreach (var argument in new[] { operation, package, quiet, restart, "/L*v", log, server, token })
                if (argument is not null) start.ArgumentList.Add(argument);
            using var process = Process.Start(start)!;
            var exited = process.WaitForExitAsync();
            while (!exited.IsCompleted)
            {
                output.WriteLine($"MSI {step} running, PID {process.Id}");
                await Task.WhenAny(exited, Task.Delay(TimeSpan.FromSeconds(5)));
            }
            await exited;
            Assert.True(process.ExitCode == 0 || allowAbsent && process.ExitCode == 1605,
                $"MSI {step} returned {process.ExitCode}; see {log}. A reboot-required result also needs investigation on this clean runner.");
        }
    }

    private static void AssertServiceRunning()
    {
        using var service = new ServiceController(AgentWorker.ServiceName);
        Assert.Equal(ServiceControllerStatus.Running, service.Status);
    }

    private static void AssertServiceAbsent()
    {
        var services = ServiceController.GetServices();
        try { Assert.DoesNotContain(services, service => service.ServiceName == AgentWorker.ServiceName); }
        finally { foreach (var service in services) service.Dispose(); }
    }
}

public sealed class MsiLifecycleFactAttribute : FactAttribute
{
    public MsiLifecycleFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Windows only";
        else if (Environment.GetEnvironmentVariable("SLI_AGENT_MSI_DISPOSABLE") != "1")
            Skip = "Set SLI_AGENT_MSI_DISPOSABLE=1 only on a clean disposable Windows runner";
    }
}
