using System.Runtime.CompilerServices;
using Xunit;

namespace Sli.Server.Tests.Domains;

// A merge can move one command's block inside another and still compile; that
// command would then silently start the web host instead of its worker.
public sealed class CommandDispatchStructureTests
{
    [Fact]
    public void Owner_recovery_dispatch_finishes_before_http_listener_validation()
    {
        string source = File.ReadAllText(ProgramPath());
        int dispatch = source.IndexOf("GetRequiredService<IOwnerRecoveryConsole>()", StringComparison.Ordinal);
        int listenerValidation = source.IndexOf("IngressHosting.ValidateBindSecurity(app.Configuration)", StringComparison.Ordinal);
        Assert.True(dispatch >= 0 && listenerValidation > dispatch,
            "Local owner recovery must run before HTTP authentication/proxy/TLS listener validation.");
        string between = source[dispatch..listenerValidation];
        Assert.Contains("await app.DisposeAsync();", between);
        Assert.Contains("return;", between);
    }

    private static string ProgramPath([CallerFilePath] string path = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "../../../src/Sli.Server/Program.cs"));
}
