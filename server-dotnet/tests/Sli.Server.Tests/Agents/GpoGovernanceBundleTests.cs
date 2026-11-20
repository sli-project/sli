using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.SnapshotPublication;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class GpoGovernanceBundleTests
{
    [Fact]
    public void NormalizesCapturedBundleAndRejectsSensitiveProperty()
    {
        var vector=JsonNode.Parse(File.ReadAllText(Fixture("SLI_GPO_PUBLICATION_VECTOR","gpo-publication-source-vector.json")))!.AsObject();
        var raw=(JsonObject)vector["families"]!["ad_gpo_governance"]!.DeepClone();
        var snapshot=(JsonObject)vector["families"]!["gpo_v2"]!.DeepClone();
        var result=GpoGovernanceBundle.Normalize(raw,snapshot);
        Assert.Equal(Packets.Digest(vector["bundle"]),Packets.Digest(result));
        raw["records"]![0]!["attributes"]!["gpo_settings"]![0]!["properties"]!["password"]="secret";
        Assert.ThrowsAny<Exception>(()=>GpoGovernanceBundle.Normalize(raw,snapshot));
    }
    [Fact]
    public void SourceBoundaryCasesAgree()
    {
        var cases=JsonNode.Parse(File.ReadAllText(Fixture("SLI_GPO_BOUNDARIES","gpo-governance-boundaries-v4.json")))!.AsArray();
        Assert.Equal(12,cases.Count);
        foreach(var item in cases)
        {
            var policy=item!["config"]!.AsObject(); var source=item["families"]!.AsObject();
            var families=source.ToDictionary(x=>x.Key,x=>x.Value!.AsObject());
            if(item["accepted"]!.GetValue<bool>())
                Assert.True(Packets.Digest(item["result"])==Packets.Digest(GpoPublicationPreparation.Prepare(policy["domain_sid"]!.GetValue<string>(),policy,families)),item["name"]!.GetValue<string>());
            else Assert.ThrowsAny<Exception>(()=>GpoPublicationPreparation.Prepare(policy["domain_sid"]!.GetValue<string>(),policy,families));
        }
    }
    private static string Fixture(string variable,string name,[System.Runtime.CompilerServices.CallerFilePath] string path="") =>
        Environment.GetEnvironmentVariable(variable) ?? Path.Combine(Path.GetDirectoryName(path)!,name);
}
