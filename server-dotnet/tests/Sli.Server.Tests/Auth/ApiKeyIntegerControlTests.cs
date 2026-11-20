using Sli.Server.Auth.Administration.ApiKeys;
using Sli.Server.Auth.Commands;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class ApiKeyIntegerControlTests
{
    private sealed class Channels : IAuthConsoleIO
    {
        public TextWriter Output { get; } = new StringWriter();
        public TextWriter Error { get; } = new StringWriter();
        public bool CanPromptPassword => false;
        public Task<string> ReadPasswordAsync(string prompt, CancellationToken ct) => throw new NotSupportedException();
    }

    [Theory]
    [InlineData('\u001c')]
    [InlineData('\u001d')]
    [InlineData('\u001e')]
    [InlineData('\u001f')]
    public async Task RejectsControlCharactersBeforeResolvingKeyProducer(char control)
    {
        var console = new AuthConsole(() => throw new InvalidOperationException(), () => throw new InvalidOperationException(), new Channels());
        foreach (string id in new[] { control + "12", "12" + control })
            Assert.Equal(2, await console.RunAsync(["revoke-api-key", "--id", id], TestContext.Current.CancellationToken));
    }

    [Fact]
    public void AcceptsNormalIntegerWhitespace() => Assert.True(ApiKeyAdministrationEndpoints.TryId(" \t12\u00a0", out var id) && id == 12);
}
