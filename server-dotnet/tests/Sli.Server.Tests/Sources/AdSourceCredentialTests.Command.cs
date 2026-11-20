using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Auth.Commands;
using Sli.Server.Sources;
using Xunit;

namespace Sli.Server.Tests.Sources;

public sealed partial class AdSourceCredentialTests
{
    private sealed class Channels : IAuthConsoleIO
    {
        internal readonly StringWriter Captured = new(), Errors = new();
        public TextWriter Output => Captured;
        public TextWriter Error => Errors;
        public bool CanPromptPassword { get; set; } = true;
        internal readonly Queue<string> Answers = new();
        internal Func<string>? Read;
        internal int Prompts;
        public Task<string> ReadPasswordAsync(string prompt, CancellationToken ct)
        {
            Prompts++;
            return Task.FromResult(Read is null ? Answers.Dequeue() : Read());
        }
        internal void AssertPrivate()
        {
            string output = Captured.ToString() + Errors;
            Assert.DoesNotContain(Password, output);
            foreach (string line in Captured.ToString().Split('\n').Where(l => l.StartsWith('{'))) Safe(line);
        }
    }

    [Fact]
    public async Task Cli_hidden_prompt_provision_and_check()
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); var io = new Channels(); io.Answers.Enqueue(Password); io.Answers.Enqueue(Password);
        var cli = new AdSourceCredentialCommand(f.Store, io);
        Assert.Equal(0, await cli.RunAsync(["provision", "--username", Username], TestContext.Current.CancellationToken)); Assert.Equal(2, io.Prompts);
        Assert.Equal(0, await cli.RunAsync(["check", "--username", Username], TestContext.Current.CancellationToken));
        Assert.Equal(1, await cli.RunAsync(["check", "--username", "other@example.test"], TestContext.Current.CancellationToken));
        Assert.Equal(Password, f.Store.Load().Password); io.AssertPrivate();
        Assert.Equal(1, await cli.RunAsync(["provision", "--username", Username], TestContext.Current.CancellationToken)); Assert.Equal(2, io.Prompts);
        io.AssertPrivate();
    }

    [Fact]
    public async Task Cli_vpn_single_entry_preserves_ad()
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); f.Store.Store(Username, Password);
        string path = Path.Combine(f.Parent, "runtime", "ad-source-credentials", AdSourceCredentials.BlobName);
        byte[] before = File.ReadAllBytes(path); var io = new Channels(); io.Answers.Enqueue(Password);
        var cli = new AdSourceCredentialCommand(f.Store, io);
        Assert.Equal(0, await cli.RunAsync(["provision", "--profile", "vpn", "--single-entry", "--username", Username], TestContext.Current.CancellationToken)); Assert.Equal(1, io.Prompts);
        Assert.Equal(0, await cli.RunAsync(["check", "--profile", "vpn", "--username", Username], TestContext.Current.CancellationToken));
        Assert.Equal(before, File.ReadAllBytes(path)); Assert.Equal(Password, f.Store.Load(profile: "vpn").Password); io.AssertPrivate();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cli_pause_retains_success_or_cancelled_outcome_without_reprompt(bool cancelled)
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); int pauses = 0; var io = new Channels { Read = () => cancelled ? throw new OperationCanceledException() : Password };
        var cli = new AdSourceCredentialCommand(f.Store, io, () => pauses++);
        Assert.Equal(cancelled ? 1 : 0, await cli.RunAsync(["provision", "--username", Username, "--single-entry", "--pause"], TestContext.Current.CancellationToken));
        Assert.Equal(1, io.Prompts); Assert.Equal(1, pauses); io.AssertPrivate();
    }

    [Theory]
    [InlineData("")]
    [InlineData("SYNTHETIC\\")]
    [InlineData("bare")]
    [InlineData("a b@example.test")]
    [InlineData("a\u200bb@example.test")]
    [InlineData("a/b@example.test")]
    public async Task Cli_rejects_invalid_username_before_prompt(string username)
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); var io = new Channels();
        Assert.Equal(1, await new AdSourceCredentialCommand(f.Store, io).RunAsync(["provision", "--username", username], TestContext.Current.CancellationToken));
        Assert.Equal(0, io.Prompts); Assert.False(Directory.Exists(Path.Combine(f.Parent, "runtime", "ad-source-credentials")));
        Assert.Contains("invalid_username", io.Captured.ToString());
    }

    [Theory]
    [InlineData("empty", "empty_password")]
    [InlineData("mismatch", "password_confirmation_mismatch")]
    [InlineData("noninteractive", "interactive_console_required")]
    [InlineData("warning", "secure_console_required")]
    [InlineData("cancelled", "cancelled")]
    [InlineData("eof", "cancelled")]
    [InlineData("unexpected", "credential_operation_failed")]
    public async Task Cli_failed_secret_entry_never_writes(string mode, string code)
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); var io = new Channels { CanPromptPassword = mode != "noninteractive" };
        io.Answers.Enqueue(Password); io.Answers.Enqueue("synthetic-different");
        io.Read = mode switch
        {
            "empty" => () => "", "warning" => () => throw new InvalidOperationException(Password),
            "cancelled" => () => throw new OperationCanceledException(Password), "eof" => () => throw new EndOfStreamException(Password),
            "unexpected" => () => throw new Exception(Password), _ => null
        };
        Assert.Equal(1, await new AdSourceCredentialCommand(f.Store, io).RunAsync(["provision", "--username", Username], TestContext.Current.CancellationToken));
        Assert.Contains(code, io.Captured.ToString()); io.AssertPrivate();
        Assert.False(Directory.Exists(Path.Combine(f.Parent, "runtime", "ad-source-credentials")));
        if (mode == "noninteractive") Assert.Equal(0, io.Prompts);
    }

    [Theory]
    [InlineData("--password")]
    [InlineData("--root")]
    [InlineData("--input-file")]
    public async Task Cli_rejects_forbidden_arguments_without_echo(string flag)
    {
        using var f = new Fixture(); var io = new Channels(); var cli = new AdSourceCredentialCommand(f.Store, io);
        foreach (string[] args in new[] { new[] { "provision", "--username", Username, flag, Password }, new[] { "provision", "--username", Username, flag + "=" + Password } })
            Assert.Equal(2, await cli.RunAsync(args, TestContext.Current.CancellationToken));
        Assert.Equal(0, io.Prompts); io.AssertPrivate();
        Assert.False(Directory.Exists(Path.Combine(f.Parent, "runtime", "ad-source-credentials")));
    }

    [Fact]
    public async Task Cli_help_does_not_access_the_store_and_linux_is_explicitly_unsupported()
    {
        using var f = new Fixture(); var io = new Channels(); var cli = new AdSourceCredentialCommand(f.Store, io);
        Assert.Equal(0, await cli.RunAsync(["--help"], TestContext.Current.CancellationToken));
        Assert.Contains("provision", io.Captured.ToString());
        Assert.Equal(2, await cli.RunAsync(["provision", "--username", Username, "--profile", "VPN"], TestContext.Current.CancellationToken));
        if (!IsWindows)
        {
            Assert.Equal(1, await cli.RunAsync(["check"], TestContext.Current.CancellationToken));
            Assert.Contains("windows_dpapi_required", io.Captured.ToString());
        }
        Assert.Equal(0, io.Prompts); Assert.False(Directory.Exists(f.Root));
    }

    [Fact]
    public async Task Separate_process_current_user_roundtrip()
    {
        if (!WindowsAvailable()) return;
        string? childRoot = Environment.GetEnvironmentVariable("SLI_TEST_SOURCE_CREDENTIAL_ROOT");
        if (childRoot is not null)
        {
            string parent = Path.GetDirectoryName(childRoot)!;
            Assert.Equal(Path.TrimEndingDirectorySeparator(Path.GetTempPath()), Path.GetDirectoryName(parent));
            Assert.Equal("store", Path.GetFileName(childRoot));
            string name = Path.GetFileName(parent);
            Assert.StartsWith("sli-source-credentials-", name);
            Assert.True(Guid.TryParseExact(name["sli-source-credentials-".Length..], "N", out _));
            var store = new AdSourceCredentials(parent);
            var loaded = store.Load(childRoot);
            string expected = await Console.In.ReadToEndAsync(TestContext.Current.CancellationToken);
            Assert.True(CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(loaded.Password)), Convert.FromHexString(expected)));
            var status = store.Status(Username, childRoot);
            Assert.Equal("ready", status["status"]!.GetValue<string>());
            Assert.True(status["owner_matches"]!.GetValue<bool>()); Assert.True(status["account_matches"]!.GetValue<bool>());
            Assert.Equal("CurrentUser", status["dpapi_scope"]!.GetValue<string>()); Safe(status.ToJsonString());
            Console.WriteLine("SOURCE_CREDENTIAL_CHILD_OK");
            return;
        }
        using var f = new Fixture(); f.Provision();
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            WorkingDirectory = f.Parent
        };
        start.ArgumentList.Add(typeof(AdSourceCredentialTests).Assembly.Location);
        start.ArgumentList.Add("-method"); start.ArgumentList.Add(typeof(AdSourceCredentialTests).FullName + ".Separate_process_current_user_roundtrip");
        start.Environment["SLI_TEST_SOURCE_CREDENTIAL_ROOT"] = f.Root;
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await process.StandardInput.WriteAsync(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Password)))); process.StandardInput.Close();
        await process.WaitForExitAsync(TestContext.Current.CancellationToken);
        string output = await stdout, errors = await stderr;
        Assert.Equal(0, process.ExitCode); Assert.Equal("", errors); Safe(output + errors);
        Assert.Contains("SOURCE_CREDENTIAL_CHILD_OK", output); // A filter selecting zero tests cannot pass.
    }
}
