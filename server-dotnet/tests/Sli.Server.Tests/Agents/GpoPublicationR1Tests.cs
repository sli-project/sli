using System.Text.Json.Nodes;
using Sli.Server.Agents.SnapshotPublication;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class GpoPublicationR1Tests
{
    private static JsonObject Vector([System.Runtime.CompilerServices.CallerFilePath] string path="") => JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"gpo-publication-source-vector.json")))!.AsObject();
    [Theory]
    [InlineData("schema")][InlineData("pack")][InlineData("integer")][InlineData("inactivity")]
    public void SourceRejectsSpecificNormalizationChanges(string name)
    {
        var v=Vector(); var f=v["families"]!.AsObject().ToDictionary(x=>x.Key,x=>(JsonObject)x.Value!.DeepClone());
        var b=f["ad_gpo_governance"];
        switch(name) {
          case "schema": b["schema_version"]=" ad-context-bundle/v1 "; break;
          case "pack": b["source_pack_id"]=" sli.windows.ad-context "; break;
          case "integer": b["sections"]![0]!["record_count"]="\u001c1"; break;
          case "inactivity": b["records"]![0]!["attributes"]!["inactivity_basis"]=" last_logon "; break;
        }
        Assert.ThrowsAny<Exception>(()=>GpoPublicationPreparation.Prepare(v["config"]!["domain_sid"]!.GetValue<string>(),v["config"]!.AsObject(),f));
    }
    [Fact]
    public void LegitimateUnicodeIntegerAndOrdinaryTextWhitespaceRemainAccepted()
    {
        var v=Vector(); var f=v["families"]!.AsObject().ToDictionary(x=>x.Key,x=>(JsonObject)x.Value!.DeepClone());
        f["ad_gpo_governance"]["sections"]![0]!["record_count"]=" \u0661 ";
        f["ad_gpo_governance"]["source_pack_version"]=" 0.9.0 ";
        Assert.NotNull(GpoPublicationPreparation.Prepare(v["config"]!["domain_sid"]!.GetValue<string>(),v["config"]!.AsObject(),f));
    }
}
