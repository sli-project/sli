using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentWorkstationValidatorTests
{
    [Theory]
    [InlineData("😀","?",true)]
    [InlineData("😀","??",false)]
    [InlineData("abc","a[!d]c",true)]
    [InlineData("axc","a[b-d]c",false)]
    [InlineData("a]c","a[]]c",true)]
    public void SourceFnmatchCases(string path,string pattern,bool expected)
    {
        var helper=typeof(AgentWorkstationValidator).Assembly.GetType("Sli.Server.Agents.Ingress.AgentWorkstationEvidence")!;
        var method=helper.GetMethod("Glob",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!;
        Assert.Equal(expected,(bool)method.Invoke(null,[path,pattern])!);
    }
    [Fact]
    public void SourceSignatureBindingRejectsForgedPathAndNaiveMeasurementTime()
    {
        const string path=@"C:\Windows\Temp\sample.exe", now="2026-10-28T12:00:00+00:00";
        string xml="<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/><EventID>4688</EventID><EventRecordID>12</EventRecordID><Channel>Security</Channel><TimeCreated SystemTime=\"2026-10-28T12:00:00Z\"/><Computer>fixture</Computer></System><EventData><Data Name=\"NewProcessName\">"+path+"</Data></EventData></Event>";
        var row=EventXml.Parse(xml,"fixture","localhost","Security"); var rows=new JsonArray(row);
        var entry=new JsonObject { ["contract"]="sli.workstation-file-signature.v1",["record_id"]=12,["path"]=path,
            ["source_sha256"]=Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(xml))),
            ["measurement"]=new JsonObject { ["scope"]="file_at_measurement",["observed_at_utc"]=now,["status"]="signed",["reason"]=null,
                ["sha256_before"]=new string('a',64),["sha256_after"]=new string('a',64),["identity_before"]=new string('b',64),["identity_after"]=new string('b',64),["signer_sha256"]=new string('c',64),["kind"]="embedded" } };
        var entries=new JsonArray(entry); var helper=typeof(AgentWorkstationValidator).Assembly.GetType("Sli.Server.Agents.Ingress.AgentWorkstationEvidence")!;
        var method=helper.GetMethod("ValidateSignatures",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!;
        method.Invoke(null,[entries,rows,now]);
        entry["path"]=@"C:\wrong.exe"; Assert.Throws<System.Reflection.TargetInvocationException>(()=>method.Invoke(null,[entries,rows,now]));
        entry["path"]=path; entry["measurement"]!["observed_at_utc"]="2026-10-28T12:00:00";
        Assert.Throws<System.Reflection.TargetInvocationException>(()=>method.Invoke(null,[entries,rows,now]));
    }
    private static JsonArray Vectors([CallerFilePath] string path="")
    {
        for (var dir=new FileInfo(path).Directory; dir is not null; dir=dir.Parent)
        {
            var candidate=Path.Combine(dir.FullName,"agent-dotnet","tests","vectors","workstations-scenarios.json");
            if (File.Exists(candidate))
            {
                var bytes=File.ReadAllBytes(candidate);
                Assert.Equal("b3270f61ab52c44c60fa14fb7f219d1ebd7761a411758a165abcdca5ed0b15b2",Convert.ToHexStringLower(SHA256.HashData(bytes)));
                return JsonNode.Parse(bytes)!.AsArray();
            }
        }
        throw new InvalidOperationException("Source workstation vectors required");
    }
    [Fact]
    public void SourceRotationRateAndTamperScenariosAndWrongBinding()
    {
        foreach(var fixture in Vectors().OfType<JsonObject>())
        foreach(var entry in fixture["steps"]!.AsArray())
        {
            var step=entry!.AsObject(); var host=Guid.Parse(fixture["host_id"]!.GetValue<string>());
            var policy=WorkstationPolicy.Parse(fixture["config"]!.AsObject());
            var payload=JsonNode.Parse(step["payload_canonical"]!.GetValue<string>())!.AsObject();
            var e=new Envelope("00000000-0000-4000-8000-000000000001","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",host.ToString("D"),"sli.workstations","1.1.0",policy.Revision,
                "workstations",host.ToString("D"),1,Cursor.FromJson(step["cursor_before"]),Cursor.FromJson(step["cursor_after"]),
                CollectionPacket.Contract,Packets.Digest(payload),payload["records"]!.AsArray().Count,CanonicalJson.Length(payload),step["now"]!.GetValue<string>(),
                step["continuity_state"]!.GetValue<string>(),step["filtered_count"]!.GetValue<long>(),step["lost_count"]?.GetValue<long>());
            Assert.Equal(payload["records"]!.AsArray().Count,AgentWorkstationValidator.Validate(e,payload,policy,host).Count);
            Assert.Throws<ProtocolException>(()=>AgentWorkstationValidator.Validate(e with { Generation=Guid.Empty.ToString("D") },payload,policy,host));
        }
    }
}
