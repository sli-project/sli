using System.Text.Json.Nodes;
using Microsoft.VisualBasic.FileIO;
using Sli.Server.Reporting.V2;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class ReportV2CsvSecurityTests
{
    public static IEnumerable<object[]> FormulaVectors()
    {
        foreach (string prefix in new[] { "", " ", "  ", "\t", "\r", "\n", " \t", "\u00a0" })
        foreach (string formula in new[] { "=1+1", "+1+1", "-1+1", "@SUM(1,1)" })
            yield return [prefix, formula];
    }

    [Theory]
    [MemberData(nameof(FormulaVectors))]
    public void FormulasAfterLeadingWhitespaceAreNeutralized(string prefix, string formula)
    {
        string value = prefix + formula;
        string document = ReportCsv.FromColumns(
            [new() { ["key"] = "value", ["label"] = "Value" }],
            [new() { ["value"] = value }]);

        AssertSingleRow(document, ["Value"], ["'" + value]);
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData(0, "0")]
    [InlineData(42, "42")]
    [InlineData("", "")]
    [InlineData("Synthetic value", "Synthetic value")]
    [InlineData("  Synthetic value", "  Synthetic value")]
    [InlineData("\tSynthetic value", "'\tSynthetic value")]
    [InlineData("\rSynthetic value", "'\rSynthetic value")]
    [InlineData("\nSynthetic value", "'\nSynthetic value")]
    [InlineData("'=1+1", "'=1+1")]
    public void ValuesArePreservedAndLeadingControlsAreEscaped(object? value, string expected)
    {
        JsonNode? node = value is int number ? JsonValue.Create(number) : JsonValue.Create((string?)value);
        string document = ReportCsv.FromColumns(
            [new() { ["key"] = "value", ["label"] = "Value" }],
            [new() { ["value"] = node }]);

        AssertSingleRow(document, ["Value"], [expected]);
        if (expected.Length == 0) Assert.Equal("Value\r\n\"\"\r\n", document);
    }

    [Fact]
    public void JoinedValuesAndDisplayLabelsAreNeutralized()
    {
        JsonObject[] columns =
        [
            new() { ["key"] = "values", ["label"] = "Values" },
            new() { ["key"] = "state", ["label"] = "State", ["labels"] = new JsonObject { ["synthetic"] = "  =1+1" } }
        ];
        string document = ReportCsv.FromColumns(columns,
            [new() { ["values"] = new JsonArray("  =1+1", "safe"), ["state"] = "synthetic" }]);

        AssertSingleRow(document, ["Values", "State"], ["'  =1+1, safe", "'  =1+1"]);
    }

    private static void AssertSingleRow(string document, string[] header, string[] row)
    {
        using var parser = new TextFieldParser(new StringReader(document)) { TrimWhiteSpace = false };
        parser.SetDelimiters(",");
        Assert.Equal(header, parser.ReadFields());
        Assert.Equal(row, parser.ReadFields());
        Assert.True(parser.EndOfData);
    }
}
