using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Expectations come from the unchanged tests/unit/test_sigma_compiler.py and
// compiler.py pinned to pySigma 1.3.3 / pyparsing 3.2.5. No runtime Python seam.
public sealed class SigmaCompilerContractTests
{
    private static string Rule(string detection, string metadata = "", bool process = false) =>
        "title: Synthetic compiler contract\nid: 00000000-0000-0000-0000-000000000001\nauthor: Fixture Team\n" +
        metadata + "logsource:\n  product: windows\n  " + (process ? "category: process_creation" : "service: security") +
        "\ndetection:\n" + detection;

    [Theory]
    [InlineData("1 of them", "or")]
    [InlineData("any of them", "or")]
    [InlineData("all of them", "and")]
    [InlineData("any of selection_*", "or")]
    public void Pinned_selectors_preserve_IR_and_match_outcomes(string condition, string op)
    {
        var rule = SigmaRule.Compile(Rule("  selection_a:\n    EventID: 1\n  selection_b:\n    EventID: 2\n  condition: " + condition));
        var expected = JsonNode.Parse("""
            {"op":"OP","args":[
              {"op":"compare","args":[],"field":"EventID","value":{"kind":"number","scalar":1,"parts":[]}},
              {"op":"compare","args":[],"field":"EventID","value":{"kind":"number","scalar":2,"parts":[]}}
            ],"field":null,"value":null}
            """.Replace("OP", op));
        Assert.True(JsonNode.DeepEquals(expected, rule.PlanDocument["expression"]));
        Assert.Equal(new[] { "EventID" }, rule.Fields);
        Assert.Equal(op == "or" ? "matched" : "not_matched", rule.Match(new JsonObject { ["EventID"] = 1 }));
        Assert.Equal("not_evaluable", rule.Match(new JsonObject()));
    }

    [Theory]
    [InlineData("contains|contains")]
    [InlineData("contains|startswith")]
    [InlineData("contains|re")]
    public void Pinned_modifier_chains_have_the_same_safe_reason(string chain)
    {
        var error = Assert.Throws<InvalidDataException>(() => SigmaRule.Compile(Rule(
            "  selection:\n    CommandLine|" + chain + ": 'synthetic'\n  condition: selection", process: true)));
        Assert.Equal("modifier_chain_unsupported", error.Message);
    }

    [Fact]
    public void Pinned_custom_taxonomy_has_a_distinct_unsupported_state()
    {
        var error = Assert.Throws<InvalidDataException>(() => SigmaRule.Compile(Rule(
            "  selection:\n    EventID: 1\n  condition: selection", "taxonomy: custom\n")));
        Assert.Equal("taxonomy_unsupported", error.Message);
    }

    [Theory]
    [InlineData('x', 4092)]
    [InlineData('\u0444', 2000)]
    public void Windash_expanded_UTF8_bytes_are_counted_across_all_selections(char character, int length)
    {
        // Each value has 625 variants. Either selection fits 4 MiB by itself;
        // together they exceed the source pre-expansion budget, even unused.
        string value = "----" + new string(character, length);
        string selection = "    CommandLine|contains|windash: '" + value + "'\n";
        Assert.NotNull(SigmaRule.Compile(Rule("  a:\n" + selection + "  condition: a", process: true)));
        var error = Assert.Throws<InvalidDataException>(() => SigmaRule.Compile(Rule(
            "  a:\n" + selection + "  b:\n" + selection + "  condition: a", process: true)));
        Assert.Equal("complexity_limit", error.Message);
    }

    [Fact]
    public void Windash_variants_remain_OR_groups_inside_all_values()
    {
        var rule = SigmaRule.Compile(Rule("  selection:\n    CommandLine|contains|windash|all: [' -a', ' /b']\n  condition: selection", process: true));
        Assert.Equal("and", rule.Expression.Op);
        Assert.All(rule.Expression.Args, group => { Assert.Equal("or", group.Op); Assert.Equal(5, group.Args.Length); });
        Assert.Equal("matched", rule.Match(new JsonObject { ["CommandLine"] = "synthetic \u2013a \u2015b" }));
        Assert.Equal("not_matched", rule.Match(new JsonObject { ["CommandLine"] = "synthetic \u2013a" }));
    }

    [Fact]
    public void Windash_expanded_value_count_is_bounded_before_lowering()
    {
        string values = string.Join(", ", Enumerable.Repeat("'----'", 7)); // 7 * 625 > 4096.
        var error = Assert.Throws<InvalidDataException>(() => SigmaRule.Compile(Rule(
            "  selection:\n    CommandLine|contains|windash: [" + values + "]\n  condition: selection", process: true)));
        Assert.Equal("complexity_limit", error.Message);
    }

    [Fact]
    public void Repeated_condition_references_cannot_bypass_the_lowered_IR_budget()
    {
        // YAML and each selection fit their budgets; the materialized condition
        // list references the same 100 comparisons 40 times (>4096 lowerer ticks).
        string values = string.Join(", ", Enumerable.Range(1, 100));
        string conditions = string.Join(", ", Enumerable.Repeat("selection", 40));
        var error = Assert.Throws<InvalidDataException>(() => SigmaRule.Compile(Rule(
            "  selection:\n    EventID: [" + values + "]\n  condition: [" + conditions + "]")));
        Assert.Equal("complexity_limit", error.Message);
    }
}
