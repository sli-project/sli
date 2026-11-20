using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentIntakeFixRoundTests
{
    private static JsonArray Vectors(string file,[CallerFilePath] string path="")
    {
        for(var dir=new FileInfo(path).Directory;dir is not null;dir=dir.Parent)
        { var candidate=Path.Combine(dir.FullName,"agent-dotnet","tests","vectors",file); if(File.Exists(candidate)) return JsonNode.Parse(File.ReadAllBytes(candidate))!.AsArray(); }
        throw new FileNotFoundException(file);
    }
    private static (Envelope,JsonObject,FileAuditPolicy,Guid) FileCase()
    {
        var f=Vectors("file-audit-scenarios.json").OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="events-restart-filter");
        var s=f["steps"]![0]!.AsObject(); var h=Guid.Parse(f["host_id"]!.GetValue<string>()); var p=FileAuditPolicy.Parse(f["config"]!.AsObject());
        var payload=JsonNode.Parse(s["payload_canonical"]!.GetValue<string>())!.AsObject();
        var e=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",h.ToString("D"),"sli.file-audit","1.0.0",p.Revision,"Security",payload["header"]!["generation"]!.GetValue<string>(),1,Cursor.FromJson(s["cursor_before"]),Cursor.FromJson(s["cursor_after"]),CollectionPacket.Contract,Packets.Digest(payload),payload["records"]!.AsArray().Count,CanonicalJson.Length(payload),s["now"]!.GetValue<string>(),s["continuity_state"]!.GetValue<string>(),s["filtered_count"]!.GetValue<long>(),s["lost_count"]?.GetValue<long>());
        return(e,payload,p,h);
    }
    [Fact]
    public void SplitCdataPreservesScopeAndRejectsPrivateTraversal()
    {
        var (e,payload,policy,host)=FileCase(); var record=payload["records"]![0]!.AsObject(); var original=record["payload"]!["xml"]!.GetValue<string>();
        string good=original.Replace("C:\\synthetic\\item","C:\\synthe<![CDATA[tic\\item]]>",StringComparison.Ordinal);
        Assert.NotEqual(original,good); record["payload"]=EventXml.Parse(good,host.ToString("D"),"localhost","Security");
        Assert.NotEmpty(AgentFileAuditValidator.Validate(e,payload,policy,host));
        string bad=original.Replace("C:\\synthetic\\item","C:\\synthetic<![CDATA[\\..\\private]]>",StringComparison.Ordinal);
        record["payload"]=EventXml.Parse(bad,host.ToString("D"),"localhost","Security");
        Assert.Throws<ProtocolException>(()=>AgentFileAuditValidator.Validate(e,payload,policy,host));
    }
    [Fact]
    public void FileAuditCursorNumericMetadataUsesPythonEquality()
    {
        var (e,payload,policy,host)=FileCase(); var cursor=payload["header"]!["cursor"]!.AsObject();
        var records=payload["records"]!.AsArray(); while(records.Count>1) records.RemoveAt(records.Count-1);
        payload["header"]!["record_id_range"]!["last"]=1;
        var state=JsonNode.Parse(e.CursorAfter.Token)!.AsObject(); state["record_id"]=1;
        e=e with { CursorAfter=new Cursor("bookmark",CanonicalJson.Serialize(state)) }; cursor["last_record_id"]=true;
        Assert.NotEmpty(AgentFileAuditValidator.Validate(e,payload,policy,host));
        records[0]!["record_id"]=true;
        Assert.Throws<ProtocolException>(()=>AgentFileAuditValidator.Validate(e,payload,policy,host));
    }
    [Fact]
    public void MetadataNumericEqualityPreservesLargeIntegerPrecision()
    {
        var helper=typeof(AgentWorkstationValidator).Assembly.GetType("Sli.Server.Agents.Ingress.PythonMetadataEquality")!;
        var method=helper.GetMethod("Equal",System.Reflection.BindingFlags.Public|System.Reflection.BindingFlags.Static)!;
        bool Equal(string a,string b)=>(bool)method.Invoke(null,[JsonNode.Parse(a),JsonNode.Parse(b)])!;
        Assert.True(Equal("{\"n\":[true,60.0]}","{\"n\":[1,60]}"));
        Assert.False(Equal("9007199254740993","9007199254740992.0"));
        Assert.True(Equal("9007199254740992","9007199254740992.0"));
    }
    [Fact]
    public void NpsContextMetadataAcceptsPythonNumericEquality()
    {
        var f=Vectors("nps-scenarios.json").OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="nps-filter-privacy");
        var s=f["steps"]![1]!.AsObject(); var h=Guid.Parse(f["host_id"]!.GetValue<string>()); var p=NpsPolicy.Parse("sli.vpn-nps",s["config"]!.AsObject());
        var payload=JsonNode.Parse(s["payload_canonical"]!.GetValue<string>())!.AsObject();
        var e=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",p.SourceId,"sli.vpn-nps","1.0.0",p.Revision,"Security",h.ToString("D"),1,Cursor.FromJson(s["cursor_before"]),Cursor.FromJson(s["cursor_after"]),CollectionPacket.Contract,Packets.Digest(payload),payload["records"]!.AsArray().Count,CanonicalJson.Length(payload),s["now"]!.GetValue<string>(),s["continuity_state"]!.GetValue<string>(),s["filtered_count"]!.GetValue<long>(),s["lost_count"]?.GetValue<long>());
        payload["context"]!["filtered_count"]=false; payload["context"]!["channel_reset"]=0; payload["header"]!["cursor"]!["last_record_id"]=JsonNode.Parse("4.0");
        Assert.Empty(AgentNpsValidator.Validate(e,payload,p,h));
    }
    [Fact]
    public void NpsCoverageAcceptsSourceWeekAndZeroSecondOffset()
    {
        var f=Vectors("nps-scenarios.json").OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="nps-continuity-restart");
        var s=f["steps"]![1]!.AsObject(); var h=Guid.Parse(f["host_id"]!.GetValue<string>()); var p=NpsPolicy.Parse("sli.vpn-nps",s["config"]!.AsObject());
        var payload=JsonNode.Parse(s["payload_canonical"]!.GetValue<string>())!.AsObject(); const string week="2026-W41-3T12:00:00+00:00:00.1";
        var before=JsonNode.Parse(s["cursor_before"]!["token"]!.GetValue<string>())!.AsObject(); before["coverage_from_utc"]=week;
        var after=JsonNode.Parse(s["cursor_after"]!["token"]!.GetValue<string>())!.AsObject(); after["coverage_from_utc"]=week; payload["continuity"]!["from_utc"]=week;
        var e=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",p.SourceId,"sli.vpn-nps","1.0.0",p.Revision,"Security",h.ToString("D"),1,new Cursor("bookmark",CanonicalJson.Serialize(before)),new Cursor("bookmark",CanonicalJson.Serialize(after)),CollectionPacket.Contract,Packets.Digest(payload),payload["records"]!.AsArray().Count,CanonicalJson.Length(payload),s["now"]!.GetValue<string>(),s["continuity_state"]!.GetValue<string>(),s["filtered_count"]!.GetValue<long>(),s["lost_count"]?.GetValue<long>());
        Assert.NotEmpty(AgentNpsValidator.Validate(e,payload,p,h));
    }
    [Fact]
    public void FileAuditInitialBoundAcceptsSourceWeekAndZeroSecondOffset()
    {
        var f=Vectors("file-audit-scenarios.json").OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="initial-bound");
        var s=f["steps"]![0]!.AsObject(); var h=Guid.Parse(f["host_id"]!.GetValue<string>()); var p=FileAuditPolicy.Parse(f["config"]!.AsObject());
        var payload=JsonNode.Parse(s["payload_canonical"]!.GetValue<string>())!.AsObject();
        var after=JsonNode.Parse(s["cursor_after"]!["token"]!.GetValue<string>())!.AsObject(); after["since_utc"]="2026-W41-3T10:00:00+00:00:00.1";
        var e=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",h.ToString("D"),"sli.file-audit","1.0.0",p.Revision,"Security",h.ToString("D"),1,Cursor.FromJson(s["cursor_before"]),new Cursor("bookmark",CanonicalJson.Serialize(after)),CollectionPacket.Contract,Packets.Digest(payload),payload["records"]!.AsArray().Count,CanonicalJson.Length(payload),s["now"]!.GetValue<string>(),s["continuity_state"]!.GetValue<string>(),s["filtered_count"]!.GetValue<long>(),s["lost_count"]?.GetValue<long>());
        Assert.Empty(AgentFileAuditValidator.Validate(e,payload,p,h));
    }
    [Fact]
    public void UtcSourceWeekAndZeroSecondOffsetAccepted()
    {
        var helper=typeof(AgentWorkstationValidator).Assembly.GetType("Sli.Server.Agents.Ingress.AgentAdDcUtc")!;
        var method=helper.GetMethod("Parse",System.Reflection.BindingFlags.Public|System.Reflection.BindingFlags.Static)!;
        Assert.Equal(method.Invoke(null,["2026-W01-1T00:00:00+00:00:00.1"]),method.Invoke(null,["2025-12-29T00:00:00Z"]));
        Assert.Throws<System.Reflection.TargetInvocationException>(()=>method.Invoke(null,["2026-01-01T00:00:00+01:00"]));
    }
    [Fact]
    public void WorkstationNullRecoveryRejectedAndFloatWindowAccepted()
    {
        var f=Vectors("workstations-scenarios.json").OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="filtered-rate-recovery");
        var s=f["steps"]![0]!.AsObject(); var h=Guid.Parse(f["host_id"]!.GetValue<string>()); var p=WorkstationPolicy.Parse(f["config"]!.AsObject()); var payload=JsonNode.Parse(s["payload_canonical"]!.GetValue<string>())!.AsObject();
        var e=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",h.ToString("D"),"sli.workstations","1.1.0",p.Revision,"workstations",h.ToString("D"),1,Cursor.FromJson(s["cursor_before"]),Cursor.FromJson(s["cursor_after"]),CollectionPacket.Contract,Packets.Digest(payload),payload["records"]!.AsArray().Count,CanonicalJson.Length(payload),s["now"]!.GetValue<string>(),s["continuity_state"]!.GetValue<string>(),s["filtered_count"]!.GetValue<long>(),s["lost_count"]?.GetValue<long>());
        var context=payload["context"]!["workstations"]!.AsObject(); context["bookmark_recovered"]=null;
        Assert.Throws<ProtocolException>(()=>AgentWorkstationValidator.Validate(e,payload,p,h));
        context.Remove("bookmark_recovered"); context["rate_window_seconds"]=JsonNode.Parse("60.0");
        Assert.NotEmpty(AgentWorkstationValidator.Validate(e,payload,p,h));
    }
    [Fact]
    public void SignatureMeasurementRequiresPythonAwareIso()
    {
        var method=typeof(AgentWorkstationValidator).Assembly.GetType("Sli.Server.Agents.Ingress.WorkstationSignatureEvidence")!.GetMethod("Measurement",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!;
        var measurement=new JsonObject { ["scope"]="file_at_measurement",["observed_at_utc"]="10/28/2026 12:00:00+00:00",["status"]="unavailable",["reason"]="timeout",["sha256_before"]=null,["sha256_after"]=null,["identity_before"]=null,["identity_after"]=null,["signer_sha256"]=null,["kind"]=null };
        Assert.Throws<System.Reflection.TargetInvocationException>(()=>method.Invoke(null,[measurement,"2026-10-28T12:00:00+00:00"]));
        measurement["observed_at_utc"]="2026-W44-3T19:00:00+07:00"; method.Invoke(null,[measurement,"2026-10-28T12:00:00+00:00"]);
    }
}
