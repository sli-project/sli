using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Ingress;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentFileAuditValidatorTests
{
    internal static readonly Guid ActionHost=Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    internal static (Envelope Envelope,JsonObject Packet,FileAuditPolicy Policy) ActionPacket(string operation="write",int eventId=4663)
    {
        var policy=FileAuditPolicy.Parse(new JsonObject {
            ["source_name"]="files.example.test",["roots"]=new JsonArray(new JsonObject {
                ["collection_scope_id"]="scope:files",["share_name"]="Files",["path"]="C:\\Files",["important"]=true,
                ["sacl"]=new JsonObject { ["trustee_sids"]=new JsonArray("S-1-5-21-100000001-200000002-300000003-1001"),["inherit_files"]=true,["inherit_directories"]=true }
            }) });
        var row=new JsonObject {
            ["contract"]="sli.file-audit.action.v1",["record_id"]=10,["event_id"]=eventId,
            ["computer_name"]="files.example.test",["channel"]="Security",["provider_name"]=FileAuditPolicy.Provider,
            ["collection_scope_id"]="scope:files",["path"]="C:\\Files\\item.txt",["old_path"]=operation=="rename"?"C:\\Files\\old.txt":null,
            ["operation"]=operation,["subject_user_sid"]="S-1-5-21-100000001-200000002-300000003-1001",
            ["client_ip"]="192.0.2.10",["minute_utc"]="2026-10-01T01:02:00Z",["time_created"]="2026-10-01T01:02:03Z",
            ["first_seen_utc"]="2026-10-01T01:02:03Z",["last_seen_utc"]="2026-10-01T01:02:58Z",["count"]=7,
            ["outcome"]=operation=="access_denied"?"failure":"success"
        };
        var after=new JsonObject { ["record_id"]=10,["bookmark"]="synthetic",["generation"]=ActionHost.ToString() };
        var packet=CollectionPacket.Make("files.example.test","Security",ActionHost.ToString(),
            new JsonObject { ["after_record_id"]=null,["last_record_id"]=10 },
            [new PacketRecord("file_action",10,row)],"not_proven",
            new JsonObject { ["policy_revision"]="1",["filtered_count"]=0,["lost_count"]=0,["read_error"]=null },
            DateTimeOffset.Parse("2026-10-01T01:03:00Z"));
        var envelope=new Envelope(Guid.NewGuid().ToString(),Guid.NewGuid().ToString(),ActionHost.ToString(),"sli.file-audit","1.0.0","1",
            "Security",ActionHost.ToString(),1,new Cursor("bookmark",""),new Cursor("bookmark",after.ToJsonString()),
            CollectionPacket.Contract,Packets.Digest(packet),1,CanonicalJson.Length(packet),"2026-10-01T01:03:00Z","not_proven",0,0);
        return (envelope,packet,policy);
    }

    [Theory]
    [InlineData("read",4663)] [InlineData("write",4663)] [InlineData("delete",4660)]
    [InlineData("rename",4663)] [InlineData("permissions",4670)] [InlineData("access_denied",5145)]
    public void Folded_actions_preserve_weight_and_scope(string operation,int eventId)
    {
        var (e,p,policy)=ActionPacket(operation,eventId);
        var row=Assert.Single(AgentFileAuditValidator.Validate(e,p,policy,ActionHost));
        Assert.Equal(7,row!["count"]!.GetValue<int>());
        Assert.Equal(operation,row["operation"]!.GetValue<string>());
    }

    [Fact]
    public void File_audit_reasons_distinguish_host_revision_scope_and_event_id()
    {
        var (envelope,packet,policy)=ActionPacket();
        string? Reason(Envelope candidate) =>
            Assert.Throws<ProtocolException>(()=>AgentFileAuditValidator.Validate(candidate,packet,policy,ActionHost)).Reason;
        Assert.Equal("host_mismatch",Reason(envelope with { SourceInstanceId=Guid.Empty.ToString() }));
        Assert.Equal("revision_mismatch",Reason(envelope with { PolicyRevision="2" }));
        var action=packet["records"]![0]!["payload"]!;
        action["path"]=@"C:\Files-other\item.txt";
        Assert.Equal("scope_mismatch",Reason(envelope));
        action["event_id"]=4625;
        Assert.Equal("event_id_not_file_audit",Reason(envelope));
    }

    [Fact]
    public void One_native_record_can_supply_distinct_file_actions_but_not_duplicate_buckets()
    {
        var (e,p,policy)=ActionPacket();
        var read=p["records"]![0]!.DeepClone();read["payload"]!["operation"]="read";
        p["records"]!.AsArray().Add(read);
        e=e with { RecordCount=2,PayloadSha256=Packets.Digest(p),PayloadBytes=CanonicalJson.Length(p) };
        Assert.Equal(2,AgentFileAuditValidator.Validate(e,p,policy,ActionHost).Count);
        read["payload"]!["operation"]="write";
        Assert.Throws<ProtocolException>(()=>AgentFileAuditValidator.Validate(e,p,policy,ActionHost));
    }

    [Fact]
    public void Folded_file_actions_cannot_be_used_as_native_DC_events()
    {
        var (_,p,_)=ActionPacket();
        Assert.Throws<ProtocolException>(()=>AgentCollectionRows.ExtractEvents(p));
    }

    [Theory]
    [InlineData("event_id","99999")] [InlineData("count","0")] [InlineData("count","true")]
    [InlineData("path","\"C:\\\\Other\\\\item.txt\"")]
    [InlineData("old_path","\"C:\\\\Other\\\\old.txt\"")]
    [InlineData("collection_scope_id","\"scope:other\"")]
    [InlineData("last_seen_utc","\"2026-10-01T01:03:00Z\"")]
    [InlineData("first_seen_utc","\"2026-10-01T01:02:59Z\"")]
    [InlineData("provider_name","\"forged\"")]
    public void Folded_actions_reject_invalid_weight_time_origin_or_scope(string key,string value)
    {
        var (e,p,policy)=ActionPacket("rename");
        p["records"]![0]!["payload"]![key]=JsonNode.Parse(value);
        e=e with { PayloadSha256=Packets.Digest(p),PayloadBytes=CanonicalJson.Length(p) };
        Assert.Throws<ProtocolException>(()=>AgentFileAuditValidator.Validate(e,p,policy,ActionHost));
    }
    [Theory]
    [InlineData("0x44",true)]
    [InlineData("0x_44",true)]
    [InlineData("0x__44",false)]
    [InlineData("0044",false)]
    [InlineData("0b101",true)]
    [InlineData("0o10",true)]
    [InlineData("0",false)]
    public void SourceHandleBaseZeroCases(string input,bool expected)
    {
        var helper=typeof(AgentFileAuditValidator).Assembly.GetType("Sli.Server.Agents.Ingress.AgentFileAuditEvents")!;
        var method=helper.GetMethod("PositiveNumber",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!;
        Assert.Equal(expected,(bool)method.Invoke(null,[input])!);
    }
    [Fact]
    public void SourcePolicyCountsAstralPathInCodePoints()
    {
        var fixture=Vectors().OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="events-restart-filter");
        var config=(JsonObject)fixture["config"]!.DeepClone(); string path="C:\\"+string.Concat(Enumerable.Repeat("😀",2050));
        config["roots"]![0]!["path"]=path;
        Assert.Throws<AgentException>(()=>FileAuditPolicy.Parse(config));
        var helper=typeof(AgentFileAuditValidator).Assembly.GetType("Sli.Server.Agents.Ingress.AgentFileAuditPolicy")!;
        var method=helper.GetMethod("Parse",System.Reflection.BindingFlags.Public|System.Reflection.BindingFlags.Static)!;
        var parsed=(FileAuditPolicy)method.Invoke(null,[config])!;
        Assert.Equal(path,parsed.Roots[0]!["path"]!.GetValue<string>());
    }
    [Theory]
    [InlineData("STRAßE","straße")]
    [InlineData("STRASSE","strasse")]
    [InlineData("İ","i\u0307")]
    [InlineData("ΟΣ","ος")]
    [InlineData("ΟΣΑ","οσα")]
    [InlineData("ΟΣ\u0301Α","οσ\u0301α")]
    [InlineData("ΟΣ\u0301!","ος\u0301!")]
    public void PythonLowerSourceVectors(string input,string expected)
    {
        Assert.Equal(expected,UnicodeLower.Lower(input));
    }
    [Fact]
    public void ScopePathsDoNotUseUnicodeCaseFold()
    {
        var fixture=Vectors().OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="events-restart-filter");
        var step=fixture["steps"]![0]!.AsObject(); var host=Guid.Parse(fixture["host_id"]!.GetValue<string>());
        var config=(JsonObject)fixture["config"]!.DeepClone(); var root=(JsonObject)config["roots"]![0]!.DeepClone();
        root["collection_scope_id"]="scope:sharp-s"; root["path"]="C:\\STRASSE"; config["roots"]!.AsArray().Add(root);
        var policy=FileAuditPolicy.Parse(config); var payload=JsonNode.Parse(step["payload_canonical"]!.GetValue<string>())!.AsObject();
        var record=payload["records"]![0]!.AsObject(); var old=record["payload"]!.AsObject();
        string xml=old["xml"]!.GetValue<string>().Replace("C:\\synthetic\\item","C:\\STRAßE\\item",StringComparison.Ordinal);
        Assert.Contains("STRAßE",xml); record["payload"]=EventXml.Parse(xml,host.ToString("D"),"localhost","Security");
        var e=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",host.ToString("D"),"sli.file-audit","1.0.0",policy.Revision,
            "Security",payload["header"]!["generation"]!.GetValue<string>(),1,Cursor.FromJson(step["cursor_before"]),Cursor.FromJson(step["cursor_after"]),
            CollectionPacket.Contract,Packets.Digest(payload),payload["records"]!.AsArray().Count,CanonicalJson.Length(payload),step["now"]!.GetValue<string>(),
            step["continuity_state"]!.GetValue<string>(),step["filtered_count"]!.GetValue<long>(),step["lost_count"]?.GetValue<long>());
        Assert.Throws<ProtocolException>(()=>AgentFileAuditValidator.Validate(e,payload,policy,host));
    }
    private static JsonArray Vectors([CallerFilePath] string path="")
    {
        for (var dir=new FileInfo(path).Directory; dir is not null; dir=dir.Parent)
        {
            var candidate=Path.Combine(dir.FullName,"agent-dotnet","tests","vectors","file-audit-scenarios.json");
            if (File.Exists(candidate))
            {
                var bytes=File.ReadAllBytes(candidate);
                Assert.Equal("84474f140f4a8668eb1a7c0907e3c64716ab78e63fbca954cd008285a57b200e",Convert.ToHexStringLower(SHA256.HashData(bytes)));
                return JsonNode.Parse(bytes)!.AsArray();
            }
        }
        throw new InvalidOperationException("Source file-audit vectors required");
    }
    [Fact]
    public void SourceEventsAndJournalGapAreAcceptedAndTamperingIsRejected()
    {
        foreach(var fixture in Vectors().OfType<JsonObject>())
        foreach(var entry in fixture["steps"]!.AsArray())
        {
            var step=entry!.AsObject(); var host=Guid.Parse(fixture["host_id"]!.GetValue<string>());
            var policy=FileAuditPolicy.Parse(fixture["config"]!.AsObject());
            var payload=JsonNode.Parse(step["payload_canonical"]!.GetValue<string>())!.AsObject();
            var e=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",host.ToString("D"),"sli.file-audit","1.0.0",policy.Revision,
                "Security",payload["header"]!["generation"]!.GetValue<string>(),1,Cursor.FromJson(step["cursor_before"]),Cursor.FromJson(step["cursor_after"]),
                CollectionPacket.Contract,Packets.Digest(payload),payload["records"]!.AsArray().Count,CanonicalJson.Length(payload),step["now"]!.GetValue<string>(),
                step["continuity_state"]!.GetValue<string>(),step["filtered_count"]!.GetValue<long>(),step["lost_count"]?.GetValue<long>());
            Assert.Equal(payload["records"]!.AsArray().Count,AgentFileAuditValidator.Validate(e,payload,policy,host).Count);
            Assert.Throws<ProtocolException>(()=>AgentFileAuditValidator.Validate(e with { PolicyRevision="999" },payload,policy,host));
            if (payload["records"]!.AsArray().Count>0)
            {
                var altered=(JsonObject)payload.DeepClone(); var row=altered["records"]![0]!["payload"]!.AsObject();
                var xml=row["xml"]!.GetValue<string>(); int end=xml.IndexOf('>');
                row["xml"]=xml.Insert(end," unexpected=\"private\"");
                Assert.Throws<ProtocolException>(()=>AgentFileAuditValidator.Validate(e,altered,policy,host));
            }
        }
    }
}
