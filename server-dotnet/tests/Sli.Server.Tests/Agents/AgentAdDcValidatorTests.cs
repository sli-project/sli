using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Xunit;

namespace Sli.Server.Tests.Agents;
public sealed class AgentAdDcValidatorTests
{
    private static JsonArray Vectors([CallerFilePath] string path="")
    {
        for(var dir=new FileInfo(path).Directory;dir is not null;dir=dir.Parent) {
            var file=Path.Combine(dir.FullName,"agent-dotnet","tests","vectors","ad-dc-scenarios.json");
            if(File.Exists(file)) return JsonNode.Parse(File.ReadAllBytes(file))!.AsArray();
        }
        throw new FileNotFoundException();
    }
    [Fact]
    public void SourceLiveVectorsAcceptedAndTamperedXmlRejected()
    {
        foreach(var scenario in Vectors().OfType<JsonObject>()) foreach(var step in scenario["steps"]!.AsArray().OfType<JsonObject>())
        {
            if(step["expected"] is not JsonObject expected) continue;
            var packet=JsonNode.Parse(expected["payload_canonical"]!.GetValue<string>())!.AsObject();
            var policy=AgentAdDcValidator.NormalizePolicy(scenario["config"]!.AsObject(),false);
            string host=scenario["host_id"]!.GetValue<string>();
            var env=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",host,"sli.windows.ad-dc","1.0.0","1","ad-dc",host,1,Cursor.FromJson(expected["cursor_before"]),Cursor.FromJson(expected["cursor_after"]),CollectionPacket.Contract,Packets.Digest(packet),packet["records"]!.AsArray().Count,CanonicalJson.Length(packet),step["now"]!.GetValue<string>(),expected["continuity_state"]!.GetValue<string>(),expected["filtered_count"]!.GetValue<long>(),expected["lost_count"]?.GetValue<long>());
            var rows=AgentAdDcValidator.Validate(env,packet,policy,policy["source_name"]!.GetValue<string>());
            Assert.Equal(packet["records"]!.AsArray().Count,rows.Count);
            var transportGap=env with { ContinuityState="gap" };
            Assert.Equal(rows.Count,AgentAdDcValidator.Validate(transportGap,packet,policy,policy["source_name"]!.GetValue<string>(),transportGap:true).Count);
            if(env.ContinuityState!="gap")
                Assert.Throws<ProtocolException>(()=>AgentAdDcValidator.Validate(transportGap,packet,policy,policy["source_name"]!.GetValue<string>()));
            var forbiddenPolicy=policy.DeepClone().AsObject();
            forbiddenPolicy["channels"]![packet["header"]!["channel"]!.GetValue<string>()]=false;
            Assert.Throws<ProtocolException>(()=>AgentAdDcValidator.Validate(env,packet,forbiddenPolicy,policy["source_name"]!.GetValue<string>()));
            var deniedExtension=policy.DeepClone().AsObject();
            deniedExtension["channels"]!["Microsoft-Windows-PowerShell/Operational"]=false;
            Assert.Throws<ProtocolException>(()=>AgentAdDcValidator.Validate(env,packet,deniedExtension,policy["source_name"]!.GetValue<string>()));
            var forgedCursor=JsonNode.Parse(env.CursorAfter.Token)!.AsObject();
            forgedCursor["channels"]!["Microsoft-Windows-PowerShell/Operational"]=forgedCursor["channels"]!.AsObject().First().Value!.DeepClone();
            Assert.Throws<ProtocolException>(()=>AgentAdDcValidator.Validate(env with { CursorAfter=new Cursor("bookmark",CanonicalJson.Serialize(forgedCursor)) },packet,policy,policy["source_name"]!.GetValue<string>()));
            var legacy=(JsonObject)packet.DeepClone(); legacy["context"]!["ad_dc"]!["channels"]!["Security"]="enabled";
            if(legacy["header"]!["channel"]!.GetValue<string>()=="Security") Assert.Equal(rows.Count,AgentAdDcValidator.Validate(env,legacy,null,policy["source_name"]!.GetValue<string>()).Count);
            if(rows.Count>0) {
                var numeric=(JsonObject)packet.DeepClone(); var eventId=numeric["records"]![0]!["payload"]!["event_id"]!.GetValue<int>();
                numeric["records"]![0]!["payload"]!["event_id"]=JsonNode.Parse(eventId.ToString()+".0");
                Assert.Equal(rows.Count,AgentAdDcValidator.Validate(env,numeric,policy,policy["source_name"]!.GetValue<string>()).Count);
                var bad=(JsonObject)packet.DeepClone(); bad["records"]![0]!["payload"]!["event_id"]=1; Assert.Throws<ProtocolException>(()=>AgentAdDcValidator.Validate(env,bad,policy,policy["source_name"]!.GetValue<string>()));
            }
        }
    }
    [Fact]
    public void SourceHistoryDataAndCompletionAcceptedBoundedAndTamperedRejected()
    {
        var path=Path.Combine(Path.GetDirectoryName(SourcePath())!,"ad-dc-history-vectors.json");
        foreach(var fixture in JsonNode.Parse(File.ReadAllBytes(path))!.AsArray().OfType<JsonObject>())
        {
            var sample=fixture["sample"]!.AsObject(); var packet=sample["payload"]!.AsObject();
            var invalidConfig=(JsonObject)fixture["config"]!.DeepClone(); invalidConfig["initial_read_hours"]=null;
            Assert.Throws<ArgumentException>(()=>AgentAdDcValidator.NormalizePolicy(invalidConfig,true));
            var policy=AgentAdDcValidator.NormalizePolicy(fixture["config"]!.AsObject(),true);
            Assert.True(JsonNode.DeepEquals(policy,AgentAdDcValidator.NormalizePolicy(fixture["config"]!.AsObject(),false)));
            string host=sample["source_instance_id"]!.GetValue<string>();
            var env=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",host,"sli.windows.ad-dc-history","1.0.0","1","ad-dc",host,1,Cursor.FromJson(sample["cursor_before"]),Cursor.FromJson(sample["cursor_after"]),CollectionPacket.Contract,Packets.Digest(packet),packet["records"]!.AsArray().Count,CanonicalJson.Length(packet),packet["header"]!["observed_at_utc"]!.GetValue<string>(),sample["continuity_state"]!.GetValue<string>(),sample["filtered_count"]!.GetValue<long>(),sample["lost_count"]?.GetValue<long>());
            Assert.Equal(packet["records"]!.AsArray().Count,AgentAdDcValidator.Validate(env,packet,policy,"fixture-dc").Count);
            var bad=(JsonObject)policy.DeepClone(); bad["history_before_utc"]="2026-10-09T00:00:00Z";
            Assert.Throws<ProtocolException>(()=>AgentAdDcValidator.Validate(env,packet,bad,"fixture-dc"));
            foreach(string field in new[]{"bookmark_recovered","channels","channel_generations"}) {
                var invalid=(JsonObject)packet.DeepClone(); invalid["context"]!["ad_dc"]![field]=null;
                Assert.Throws<ProtocolException>(()=>AgentAdDcValidator.Validate(env,invalid,policy,"fixture-dc"));
            }
            var missing=(JsonObject)packet.DeepClone(); missing["context"]!["ad_dc"]!.AsObject().Remove("read_error");
            Assert.Throws<ProtocolException>(()=>AgentAdDcValidator.Validate(env,missing,policy,"fixture-dc"));
            var wrong=(JsonObject)packet.DeepClone(); wrong["header"]!["source"]="another-dc";
            Assert.Throws<ProtocolException>(()=>AgentAdDcValidator.Validate(env,wrong,policy,"fixture-dc"));
        }
    }
    private static string SourcePath([CallerFilePath] string path="")=>path;
    [Fact]
    public void PythonValidWideCursorAndUtcWeekAreAccepted()
    {
        var path=Path.Combine(Path.GetDirectoryName(SourcePath())!,"ad-dc-boundary.json");
        var fixture=JsonNode.Parse(File.ReadAllBytes(path))!.AsObject(); var sample=fixture["sample"]!.AsObject(); var packet=sample["payload"]!.AsObject();
        var policy=AgentAdDcValidator.NormalizePolicy(fixture["config"]!.AsObject(),false); string host=sample["source_instance_id"]!.GetValue<string>();
        var env=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",host,"sli.windows.ad-dc","1.0.0","1","ad-dc",host,1,Cursor.FromJson(sample["cursor_before"]),Cursor.FromJson(sample["cursor_after"]),CollectionPacket.Contract,Packets.Digest(packet),0,CanonicalJson.Length(packet),packet["header"]!["observed_at_utc"]!.GetValue<string>(),sample["continuity_state"]!.GetValue<string>(),sample["filtered_count"]!.GetValue<long>(),sample["lost_count"]?.GetValue<long>());
        Assert.Empty(AgentAdDcValidator.Validate(env,packet,policy,"fixture-dc"));
        var wrong=env with { CursorAfter = new Cursor("bookmark",env.CursorAfter.Token.Replace("2026-W01-1T00:00:00+00:00:00","2026-W54-1T00:00:00+00:00:00")) };
        Assert.Throws<ProtocolException>(()=>AgentAdDcValidator.Validate(wrong,packet,policy,"fixture-dc"));
    }
}





