using System.Numerics;
using System.Text.Json;
using Sli.Server.Auth.Administration;
using Sli.Server.Auth.Administration.ApiKeys;
using Sli.Server.Auth.Commands;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class AuthConsoleTests
{
    private sealed class Channels(bool interactive = false) : IAuthConsoleIO
    {
        public readonly StringWriter CapturedOutput = new(), CapturedError = new();
        public TextWriter Output => CapturedOutput;
        public TextWriter Error => CapturedError;
        public bool CanPromptPassword => interactive;
        public Queue<string> Passwords { get; } = new();
        public Task<string> ReadPasswordAsync(string prompt, CancellationToken ct) => Task.FromResult(Passwords.Dequeue());
    }

    private sealed class Users : IUserAdministration
    {
        public int Calls;
        public CreateUserCommand? Created;
        public UserAdministrationActor? Actor;
        public Task<JsonElement> CreateAsync(CreateUserCommand command, UserAdministrationActor actor, CancellationToken ct)
        {
            Calls++; Created = command; Actor = actor;
            return Task.FromResult(JsonSerializer.SerializeToElement(new { id = 1, username = command.Username, role = command.Role }));
        }
        public Task<IReadOnlyList<JsonElement>> ListAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonElement> UpdateAsync(UpdateUserCommand command, UserAdministrationActor actor, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonElement> ResetPasswordAsync(BigInteger id, string password, UserAdministrationActor actor, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class Keys : IApiKeyAdministration
    {
        public int Calls;
        public IssueApiKeyCommand? Created;
        public UserAdministrationActor? Actor;
        public Task<ApiKeyIssueResult> IssueAsync(IssueApiKeyCommand command, UserAdministrationActor actor, CancellationToken ct)
        {
            Calls++; Created = command; Actor = actor;
            return Task.FromResult(new ApiKeyIssueResult(JsonSerializer.SerializeToElement(new { id = 1, label = command.Label, role = command.Role }), "adl_" + new string('a', 43)));
        }
        public Task<IReadOnlyList<JsonElement>> ListAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<bool> RevokeAsync(BigInteger id, UserAdministrationActor actor, CancellationToken ct) => Task.FromResult(false);
    }

    [Theory]
    [InlineData("--label=owned-label")]
    [InlineData("--label")]
    public async Task StandardParserAcceptsEqualsAndSeparateValuesWithoutRootOrPasswordGate(string option)
    {
        var io = new Channels(); var users = new Users(); var keys = new Keys();
        var console = new AuthConsole(() => users, () => keys, io);
        string[] args = option == "--label" ? ["create-api-key", option, "owned-label"] : ["create-api-key", option];
        Assert.Equal(0, await console.RunAsync(args, TestContext.Current.CancellationToken));
        Assert.Equal(1, keys.Calls); Assert.Equal("viewer", keys.Created!.Role);
        Assert.Equal("session", keys.Actor!.Type); Assert.Null(keys.Actor.Id); Assert.Null(keys.Actor.RemoteAddress);
        Assert.False(io.CanPromptPassword); // Ordinary key issuance supports source stdout/pipes without root/TTY.
    }

    [Fact]
    public async Task CreateUserUsesOneProducerAfterTwoPrivatePromptsAndSourceDefaultRole()
    {
        var io = new Channels(true); var users = new Users(); var keys = new Keys();
        const string password = "Synthetic-Console-Password-🔐";
        io.Passwords.Enqueue(password); io.Passwords.Enqueue(password);
        var console = new AuthConsole(() => users, () => keys, io);
        Assert.Equal(0, await console.RunAsync(["create-user", "--username=owned-user"], TestContext.Current.CancellationToken));
        Assert.Equal(1, users.Calls); Assert.Equal("admin", users.Created!.Role);
        Assert.Equal("session", users.Actor!.Type); Assert.Null(users.Actor.Id); Assert.Null(users.Actor.RemoteAddress);
        Assert.False(io.CapturedOutput.ToString().Contains(password, StringComparison.Ordinal));
        Assert.False(io.CapturedError.ToString().Contains(password, StringComparison.Ordinal));
    }

    [Fact]
    public async Task RedirectedPasswordAdmissionAndMismatchNeverResolveProducer()
    {
        var io = new Channels();
        var console = new AuthConsole(() => throw new Exception("producer must remain unresolved"), () => throw new Exception(), io);
        Assert.Equal(1, await console.RunAsync(["create-user", "--username=owned-user"], TestContext.Current.CancellationToken));
        Assert.Equal("password_terminal_required", io.CapturedError.ToString().Trim());
        var mismatch = new Channels(true);
        mismatch.Passwords.Enqueue("synthetic-password-one"); mismatch.Passwords.Enqueue("synthetic-password-two");
        console = new(() => throw new Exception("producer must remain unresolved"), () => throw new Exception(), mismatch);
        Assert.Equal(1, await console.RunAsync(["create-user", "--username=owned-user"], TestContext.Current.CancellationToken));
        Assert.Equal("Passwords do not match.", mismatch.CapturedError.ToString().Trim());
    }

    [Fact]
    public async Task HelpAndInvalidArgumentsDoNotResolveDatabaseOrEchoUnknownValues()
    {
        var io = new Channels();
        var console = new AuthConsole(() => throw new Exception(), () => throw new Exception(), io);
        Assert.Equal(0, await console.RunAsync(["create-api-key", "--help"], TestContext.Current.CancellationToken));
        Assert.Contains("--label", io.CapturedOutput.ToString());
        string privateValue = Guid.NewGuid().ToString("N");
        Assert.Equal(2, await console.RunAsync(["create-user", "--username=x", "--password=" + privateValue], TestContext.Current.CancellationToken));
        Assert.False(io.CapturedError.ToString().Contains(privateValue, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("1_2", true)]
    [InlineData("+12", true)]
    [InlineData("-1", true)]
    [InlineData("١٢", true)]
    [InlineData("12_", false)]
    [InlineData("12__3", false)]
    [InlineData("", false)]
    public void RevokeIdUsesSourceIntegerGrammar(string text, bool valid) => Assert.Equal(valid, ApiKeyAdministrationEndpoints.TryId(text, out _));
}
