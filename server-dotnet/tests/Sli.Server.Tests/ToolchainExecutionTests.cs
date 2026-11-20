using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Xml.Linq;
using Xunit;

namespace Sli.Server.Tests;

// GAP-009 checks the real product test executable, not a disposable package probe.
public sealed class ToolchainExecutionTests
{
    static string ServerRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Sli.Server.slnx"))) return dir.FullName;
        throw new InvalidOperationException("Server test source root not found");
    }

    [Fact]
    public void Sdk_runner_and_locked_test_packages_match_verified_toolchain()
    {
        string root = ServerRoot();
        using var global = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "global.json")));
        var sdk = global.RootElement.GetProperty("sdk");
        Assert.Equal("10.0.403", sdk.GetProperty("version").GetString());
        Assert.Equal("disable", sdk.GetProperty("rollForward").GetString());
        Assert.False(sdk.GetProperty("allowPrerelease").GetBoolean());
        Assert.Equal("Microsoft.Testing.Platform", global.RootElement.GetProperty("test").GetProperty("runner").GetString());
        var central = XDocument.Load(Path.Combine(root, "Directory.Packages.props"));
        Assert.Contains(central.Descendants("PackageVersion"), p =>
            (string?)p.Attribute("Include") == "xunit.v3" && (string?)p.Attribute("Version") == "[4.0.2]");
        using var locked = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "tests", "Sli.Server.Tests", "packages.lock.json")));
        var packages = locked.RootElement.GetProperty("dependencies").GetProperty("net10.0");
        foreach (var (name, version) in new[] { ("xunit.v3", "4.0.2"), ("Microsoft.Testing.Platform", "2.5.1"), ("Microsoft.Testing.Platform.MSBuild", "2.5.1") })
        {
            var package = packages.GetProperty(name);
            Assert.Equal(version, package.GetProperty("resolved").GetString());
            Assert.NotEmpty(package.GetProperty("contentHash").GetString()!);
        }
    }

    static async Task<(int Exit, string Output)> Mtp(params string[] options)
    {
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host ? host : "dotnet")
        {
            WorkingDirectory = ServerRoot(), UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        string configuration = typeof(ToolchainExecutionTests).Assembly.GetCustomAttribute<AssemblyConfigurationAttribute>()!.Configuration;
        // MTP options go directly after dotnet test options; no VSTest filter or '--'.
        foreach (string option in new[] { "test", "--project", "tests/Sli.Server.Tests/Sli.Server.Tests.csproj",
            "--configuration", configuration, "--no-build", "--no-restore", "--fail-skips", "on" }.Concat(options))
            start.ArgumentList.Add(option);
        using var process = Process.Start(start)!;
        var ct = TestContext.Current.CancellationToken;
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);
        try { await process.WaitForExitAsync(ct); }
        finally { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); } }
        return (process.ExitCode, await stdout + await stderr);
    }

    [Fact]
    public async Task Mtp_method_filter_runs_exactly_the_named_product_test_without_skips()
    {
        const string type = "Sli.Server.Tests.Access.AccessRuntimeTests";
        const string method = "PerReportCombinedDomainBoundUsesDeduplicatedUnionAndPreservesIndependentReports";
        string results = Path.Combine(Path.GetTempPath(), "sli-gap009-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(results);
        try
        {
            var run = await Mtp("--filter-method", type + "." + method, "--results-directory", results,
                "--report-xunit-xml", "--report-xunit-xml-filename", "gap009-product.xml");
            Assert.True(run.Exit == 0, run.Output);
            var report = XDocument.Load(Path.Combine(results, "gap009-product.xml"));
            var assembly = Assert.Single(report.Root!.Elements("assembly"));
            Assert.Equal("1", (string?)assembly.Attribute("total"));
            Assert.Equal("1", (string?)assembly.Attribute("passed"));
            foreach (string count in new[] { "failed", "errors", "skipped", "not-run" })
                Assert.Equal("0", (string?)assembly.Attribute(count));
            var test = Assert.Single(assembly.Descendants("test"));
            Assert.Equal(type, (string?)test.Attribute("type"));
            Assert.Equal(method, (string?)test.Attribute("method"));
            Assert.Equal("Pass", (string?)test.Attribute("result"));
        }
        finally { Directory.Delete(results, recursive: true); }
    }

    [Fact]
    public async Task Mtp_empty_class_filter_returns_no_tests_exit_code_instead_of_success()
    {
        var run = await Mtp("--filter-class", "Sli.Server.Tests.Gap009MissingTests");
        Assert.True(run.Exit == 8, run.Output);
    }
}
