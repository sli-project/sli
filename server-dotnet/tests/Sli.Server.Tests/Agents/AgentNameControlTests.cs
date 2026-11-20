using System.Reflection;
using Sli.Server.Agents.Control;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentNameControlTests
{
    private static readonly Type Names = typeof(AgentManagementService).Assembly.GetType("Sli.Server.Agents.Control.AgentControlJson", throwOnError: true)!;
    private static readonly Func<string?, string?> Human = Names.GetMethod("HumanName", BindingFlags.Static | BindingFlags.NonPublic)!.CreateDelegate<Func<string?, string?>>();
    private static readonly Func<string?, string?> Reported = Names.GetMethod("ReportedName", BindingFlags.Static | BindingFlags.NonPublic, [typeof(string)])!.CreateDelegate<Func<string?, string?>>();

    [Theory]
    [InlineData("\u001c")]
    [InlineData("\u001d")]
    [InlineData("\u001e")]
    [InlineData("\u001f")]
    public void PythonC0WhitespaceIsAbsentAndKeepsRealDisplayFallback(string control)
    {
        Assert.Null(Human(control)); Assert.Null(Human(control + " \t" + control));
        Assert.Equal("fallback.example", Human(control) ?? Reported("fallback.example"));
        Assert.Equal("owned.example", Human(control + "owned.example" + control));
        Assert.Null(Human(control + "unknown" + control));
        Assert.Null(Human(control + "00000000-0000-4000-8000-000000000001" + control));
    }
}
