using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class AgentWorkstationSignatureIntake105Tests
{
    [Fact]
    public void SourceAcceptsIntegralFloatEventIdAndRejectsInvalidEvidence()
    {
        foreach(var v in Fixture().OfType<JsonObject>()) {
            var (env,payload,policy,host)=Prepare(v);
            if(v["source_accepted"]!.GetValue<bool>()) Assert.Single(AgentWorkstationValidator.Validate(env,payload,policy,host));
            else Assert.Throws<ProtocolException>(()=>AgentWorkstationValidator.Validate(env,payload,policy,host));
        }
    }
    [Fact]
    public void SignatureRecordIdRemainsStrictInteger()
    {
        foreach(string invalid in new[]{"true","1.0"}) {
            var v=(JsonObject)Fixture()[0]!.DeepClone();var (env,payload,policy,host)=Prepare(v);
            payload["context"]!["workstations"]!["process_signatures"]![0]!["record_id"]=JsonNode.Parse(invalid);
            Assert.Throws<ProtocolException>(()=>AgentWorkstationValidator.Validate(env,payload,policy,host));
        }
    }
    private static (Envelope,JsonObject,WorkstationPolicy,Guid) Prepare(JsonObject v)
    {
        var payload=v["payload"]!.AsObject();var e=v["envelope"]!;var host=Guid.Parse(v["host_id"]!.GetValue<string>());var policy=WorkstationPolicy.Parse(v["config"]!.AsObject());
        var env=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",host.ToString("D"),"sli.workstations","1.1.0",policy.Revision,"workstations",host.ToString("D"),1,Cursor.FromJson(e["cursor_before"]!),Cursor.FromJson(e["cursor_after"]!),CollectionPacket.Contract,Packets.Digest(payload),payload["records"]!.AsArray().Count,CanonicalJson.Length(payload),payload["header"]!["observed_at_utc"]!.GetValue<string>(),e["continuity_state"]!.GetValue<string>(),e["filtered_count"]!.GetValue<long>(),e["lost_count"]?.GetValue<long>());
        return(env,payload,policy,host);
    }
    private static JsonArray Fixture([CallerFilePath]string path="")=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"workstation-signature-intake.json")))!.AsArray();
}
