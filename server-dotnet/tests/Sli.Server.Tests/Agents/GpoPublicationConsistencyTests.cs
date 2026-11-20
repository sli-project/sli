using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.SnapshotPublication;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class GpoPublicationConsistencyTests
{
    [Fact]
    public void DomainScopeAndPopulationMustAgree()
    {
        var policy=JsonNode.Parse("""{"domain_dns":"example.test","domain_sid":"S-1-5-21-1-2-3","search_bases":[],"dc":[],"max_objects":10,"max_bytes":100000}""")!.AsObject();
        var snapshot=JsonNode.Parse("""{"domain":{"dns_name":"example.test","sid":"S-1-5-21-1-2-3","distinguished_name":"DC=example,DC=test"},"observed_at":"2026-10-07T11:00:00+00:00","gpos":[],"source_states":{"gpo_list":{"status":"observed"},"gpc_directory":{"status":"observed"}},"collection_errors":[]}""")!.AsObject();
        var bundle=JsonNode.Parse("""{"domain":{"dns_name":"example.test","sid":"S-1-5-21-1-2-3"},"scope":{"search_base":"DC=example,DC=test","collection_profile":"gpo_governance_v4","privileged_group_sids":[],"vpn_group_sids":[]},"observed_at_utc":"2026-10-07T11:00:00+00:00","sections":[{"name":"gpo_governance"}],"records":[]}""")!.AsObject();
        var families=new Dictionary<string,JsonObject> { ["gpo_v2"]=snapshot,["ad_gpo_governance"]=bundle };
        GpoPublicationConsistency.Validate("S-1-5-21-1-2-3",policy,snapshot,bundle,families);
        bundle["scope"]!["search_base"]="DC=wrong";
        Assert.Equal("agent_gpo_domain_scope_invalid",Assert.Throws<ProtocolException>(()=>GpoPublicationConsistency.Validate("S-1-5-21-1-2-3",policy,snapshot,bundle,families)).Code);
    }
    [Fact]
    public void SourceNormalizedCapturePasses()
    {
        string path=Fixture("SLI_GPO_PUBLICATION_VECTOR","gpo-publication-source-vector.json");
        var vector=JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        var policy=vector["config"]!.AsObject(); var families=vector["families"]!.AsObject();
        var snapshot=families["gpo_v2"]!.AsObject(); var bundle=vector["bundle"]!.AsObject();
        var originals=families.ToDictionary(x=>x.Key,x=>x.Value!.AsObject());
        GpoPublicationConsistency.Validate(policy["domain_sid"]!.GetValue<string>(),policy,snapshot,bundle,originals);
    }    [Fact]
    public void PrepareSourceCaptureAndKeepPartialExplicit()
    {
        var vector=JsonNode.Parse(File.ReadAllText(Fixture("SLI_GPO_PUBLICATION_VECTOR","gpo-publication-source-vector.json")))!.AsObject();
        var policy=vector["config"]!.AsObject(); var families=vector["families"]!.AsObject().ToDictionary(x=>x.Key,x=>x.Value!.AsObject());
        var bundle=GpoPublicationPreparation.Prepare(policy["domain_sid"]!.GetValue<string>(),policy,families);
        Assert.Equal(Sli.Agent.Protocol.Packets.Digest(vector["bundle"]),Sli.Agent.Protocol.Packets.Digest(bundle));
        families["gpo_v2"]["collection_status"]="partial";
        var partial=GpoPublicationPreparation.Prepare(policy["domain_sid"]!.GetValue<string>(),policy,families);
        var sourcePartial=JsonNode.Parse(File.ReadAllText(Fixture("SLI_GPO_PUBLICATION_PARTIAL","gpo-publication-source-partial.json")));
        Assert.Equal(Sli.Agent.Protocol.Packets.Digest(sourcePartial),Sli.Agent.Protocol.Packets.Digest(partial));
        Assert.Equal("targeted",partial["mode"]!.GetValue<string>());
        Assert.Equal("partial",partial["sections"]![0]!["status"]!.GetValue<string>());
    }    private static string Fixture(string variable,string name,[System.Runtime.CompilerServices.CallerFilePath] string path="") =>
        Environment.GetEnvironmentVariable(variable) ?? Path.Combine(Path.GetDirectoryName(path)!,name);
}
