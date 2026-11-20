using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Xunit;
namespace Sli.Agent.Tests;
public sealed class ScriptSecretsUnicodeParityTests
{
    [Fact]
    public void SourceAliasesAndWordBoundariesMatch()
    {
        var vectors=JsonNode.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory,"vectors","script-unicode-source.json")))!.AsArray();
        foreach(var v in vectors.OfType<JsonObject>()) {
            var actual=ScriptSecrets.Mask(v["script"]!.GetValue<string>());
            Assert.Equal(v["text"]!.GetValue<string>(),actual.Text);
            Assert.Equal(v["count"]!.GetValue<int>(),actual.Count);
            Assert.Equal(v["truncated"]!.GetValue<bool>(),actual.Truncated);
        }
    }
}
