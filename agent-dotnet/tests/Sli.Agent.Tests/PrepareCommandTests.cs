using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>Runs the real program: <c>SliAgent prepare</c> must print only public values and be repeatable.</summary>
public sealed class PrepareCommandTests : IDisposable
{
    private readonly string _directory = Helpers.TempDirectory();

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private (int ExitCode, string Output, string Error) Run(params string[] arguments) => RunConfigured(null, arguments);

    private static (int ExitCode, string Output, string Error) RunConfigured(Action<ProcessStartInfo>? configure, params string[] arguments)
    {
        var dll = Path.Combine(AppContext.BaseDirectory, "SliAgent.dll");
        var start = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true };
        configure?.Invoke(start);
        start.ArgumentList.Add(dll);
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output, error);
    }

    [Fact]
    public void PrintsTheHostIdAndKeyFingerprintAndNothingElse()
    {
        var first = Run("prepare", "--Agent:StateDir=" + Path.Combine(_directory, "state"));
        Assert.Equal(0, first.ExitCode);
        Assert.Contains("agent_prepare_state_directory=", first.Error, StringComparison.Ordinal);
        Assert.Contains("agent_prepare_custom_state_directory_service_must_match", first.Error, StringComparison.Ordinal);
        var json = JsonNode.Parse(first.Output)!.AsObject();
        Assert.Equal(["host_id", "key_fingerprint"], json.Select(pair => pair.Key).Order());
        Assert.Matches("^[0-9a-f]{64}$", json["key_fingerprint"]!.GetValue<string>());
        // Repeatable: the same identity, no new key.
        var second = Run("prepare", "--Agent:StateDir=" + Path.Combine(_directory, "state"));
        Assert.Equal(first.Output.Trim(), second.Output.Trim());
        // The key file never contains the fingerprint's preimage in clear text form we print; nothing private is on stdout.
        Assert.DoesNotContain("PRIVATE", first.Output + first.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PrepareHonorsTheSameExplicitHostIdAsTheService()
    {
        var result = Run("prepare", "--Agent:StateDir=" + Path.Combine(_directory, "state"), "--Agent:HostId=" + Helpers.HostId);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal(Helpers.HostId, JsonNode.Parse(result.Output)!["host_id"]!.GetValue<string>());
    }

    [Fact]
    public void DifferentWorkingDirectoriesUseTheSameMachineEnvironmentIdentity()
    {
        var state = Path.Combine(_directory, "state");
        var publish = Path.Combine(_directory, "publish");
        var installed = Path.Combine(_directory, "installed");
        Directory.CreateDirectory(publish);
        Directory.CreateDirectory(installed);
        File.WriteAllText(Path.Combine(publish, "appsettings.json"), "{\"Agent\":{\"StateDir\":\"relative-wrong-state\"}}");
        var first = RunConfigured(start =>
        {
            start.WorkingDirectory = publish;
            start.Environment["Agent__StateDir"] = state;
            start.Environment["Agent__HostId"] = Helpers.HostId;
        }, "prepare");
        var second = RunConfigured(start =>
        {
            start.WorkingDirectory = installed;
            start.Environment["Agent__StateDir"] = state;
            start.Environment["Agent__HostId"] = Helpers.HostId;
        }, "prepare");
        Assert.Equal(0, first.ExitCode);
        Assert.Equal(0, second.ExitCode);
        Assert.Equal(first.Output, second.Output);
        Assert.Equal(Helpers.HostId, JsonNode.Parse(first.Output)!["host_id"]!.GetValue<string>());
        Assert.True(File.Exists(Path.Combine(state, "identity-key.json")));
        Assert.False(Directory.Exists(Path.Combine(publish, "relative-wrong-state")));
    }

    [Fact]
    public void RelativeStateDirectoryIsRejectedBeforeWritingAKey()
    {
        var result = RunConfigured(start => start.WorkingDirectory = _directory, "prepare", "--Agent:StateDir=relative-state");
        Assert.Equal(1, result.ExitCode);
        Assert.Contains("agent_state_path_invalid", result.Error, StringComparison.Ordinal);
        Assert.False(Directory.Exists(Path.Combine(_directory, "relative-state")));
    }
}
