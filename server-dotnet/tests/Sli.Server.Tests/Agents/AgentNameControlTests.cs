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
    [InlineData("user-ПК", "user-ПК")]
    [InlineData("БУХГАЛТЕРИЯ-1", "БУХГАЛТЕРИЯ-1")]
    [InlineData("PC_01", "PC_01")]
    [InlineData("И\u0306-𐐀-٢", "Й-𐐀-٢")]
    [InlineData("localhost", null)]
    [InlineData("192.0.2.1", null)]
    [InlineData("2001:db8::1", null)]
    [InlineData("00000000-0000-4000-8000-000000000001", null)]
    [InlineData("PC\u200B01", null)]
    [InlineData("PC\n01", null)]
    public void ReportedComputerNamesPreserveUnicodeInNfc(string input, string? expected) =>
        Assert.Equal(expected, Reported(input));

    [Fact]
    public void ReportedComputerNamesLimitLabelsAndTotalLength()
    {
        var label = new string('Я', 63);
        Assert.Equal(label, Reported(label));
        Assert.Null(Reported(label + "Я"));
        var max = string.Join('.', label, label, label, label[..61]);
        Assert.Equal(max, Reported(max));
        Assert.Null(Reported(max + "Я"));
    }

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
