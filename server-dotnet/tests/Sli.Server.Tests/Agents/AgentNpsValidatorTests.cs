using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentNpsValidatorTests
{
    private static readonly Guid Agent=Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static JsonArray Vectors([CallerFilePath] string sourceFile="")
    {
        string? file=Environment.GetEnvironmentVariable("SLI_NPS_VECTORS");
        if (file is null)
        {
            for (var dir=new FileInfo(sourceFile).Directory; dir is not null; dir=dir.Parent)
            {
                string candidate=Path.Combine(dir.FullName,"agent-dotnet","tests","vectors","nps-scenarios.json");
                if (File.Exists(candidate)) { file=candidate; break; }
            }
        }
        if (file is null) throw new InvalidOperationException("Source NPS vectors required");
        byte[] bytes=File.ReadAllBytes(file);
        Assert.Equal("977e875e70aec0cfb0c0884bd2aa4fb235e70285aac508ac1df7f45e1d3a6dd3",Convert.ToHexStringLower(SHA256.HashData(bytes)));
        return JsonNode.Parse(bytes)!.AsArray();
    }
    private static (Envelope Envelope, JsonObject Payload, NpsPolicy Policy, Guid Host) Case(JsonObject fixture,JsonObject step, string module="sli.vpn-nps")
    {
        var host=Guid.Parse(fixture["host_id"]!.GetValue<string>()); var config=step["config"]!.AsObject();
        var payload=JsonNode.Parse(step["payload_canonical"]!.GetValue<string>())!.AsObject();
        var before=Cursor.FromJson(step["cursor_before"]); var after=Cursor.FromJson(step["cursor_after"]);
        var policy=NpsPolicy.Parse(module,config);
        var e=new Envelope("00000000-0000-4000-8000-000000000001",Agent.ToString("D"),policy.SourceId,module,"1.0.0",policy.Revision,
            module==NpsPolicy.Nps ? "Security" : "radius-accounting",host.ToString("D"),1,before,after,CollectionPacket.Contract,Packets.Digest(payload),payload["records"]!.AsArray().Count,
            CanonicalJson.Length(payload),step["now"]!.GetValue<string>(),step["continuity_state"]!.GetValue<string>(),step["filtered_count"]!.GetValue<long>(),
            step["lost_count"] is null ? null : step["lost_count"]!.GetValue<long>());
        return(e,payload,policy,host);
    }

    [Fact]
    public void PythonRadiusProgressAndRotationScenariosPassAndWrongOffsetFails()
    {
        foreach (var fixture in Vectors().OfType<JsonObject>().Where(x=>new[]{"radius-blank-progress","radius-empty-rotations","radius-bom-quoted-unicode"}.Contains(x["name"]!.GetValue<string>())))
        foreach (var item in fixture["steps"]!.AsArray())
        {
            var c=Case(fixture,item!.AsObject(),NpsPolicy.Accounting);
            Assert.Empty(AgentRadiusValidator.Validate(c.Envelope,c.Payload,c.Policy,c.Host));
            c.Payload["header"]!["cursor"]!["start_offset"]=-1;
            Assert.Throws<ProtocolException>(()=>AgentRadiusValidator.Validate(c.Envelope,c.Payload,c.Policy,c.Host));
        }
    }
    [Fact]
    public void RadiusRotationRequiresPreviousEofAndZeroOffset()
    {
        // Runtime-contract vector: an empty new generation is accepted only
        // after the old generation's EOF, starting at byte zero.
        var fixture = Vectors().OfType<JsonObject>().Single(x =>
            x["name"]!.GetValue<string>() == "radius-empty-rotations");
        int checkedRotations = 0;
        foreach (var step in fixture["steps"]!.AsArray())
        {
            var c = Case(fixture, step!.AsObject(), NpsPolicy.Accounting);
            if (c.Payload["continuity"]!["previous_generation_eof"]!.GetValue<bool>() != true) continue;
            if (c.Payload["header"]!["cursor"]!["end_offset"]!.GetValue<long>() != 0) continue;
            Assert.Empty(c.Payload["records"]!.AsArray());
            Assert.Equal(0, c.Payload["header"]!["cursor"]!["start_offset"]!.GetValue<long>());
            Assert.Equal(0, c.Payload["header"]!["cursor"]!["end_offset"]!.GetValue<long>());
            Assert.Empty(AgentRadiusValidator.Validate(c.Envelope, c.Payload, c.Policy, c.Host));
            Assert.Equal(c.Payload["header"]!["generation"]!.GetValue<string>(),
                RadiusCursor.Parse(JsonNode.Parse(c.Envelope.CursorAfter.Token)).FileGeneration);

            c.Payload["continuity"]!["previous_generation_eof"] = false;
            Assert.Equal("agent_nps_packet_invalid", Assert.Throws<ProtocolException>(() =>
                AgentRadiusValidator.Validate(c.Envelope, c.Payload, c.Policy, c.Host)).Code);
            c.Payload["continuity"]!["previous_generation_eof"] = true;
            // Keep the range and empty-progress proof consistent, so admission
            // must reject the nonzero start of a new generation itself.
            c.Payload["header"]!["cursor"]!["start_offset"] = 1;
            c.Payload["header"]!["cursor"]!["end_offset"] = 1;
            var after = JsonNode.Parse(c.Envelope.CursorAfter.Token)!.AsObject();
            after["byte_offset"] = 1;
            var shifted = c.Envelope with { CursorAfter = new Cursor("file_offset", CanonicalJson.Serialize(after)) };
            Assert.Equal("agent_nps_packet_invalid", Assert.Throws<ProtocolException>(() =>
                AgentRadiusValidator.Validate(shifted, c.Payload, c.Policy, c.Host)).Code);
            checkedRotations++;
        }
        Assert.True(checkedRotations > 0);
    }

    [Fact]
    public void PythonNpsProducerScenariosPassAndModifiedEvidenceFails()
    {
        var fixture=Vectors().OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="nps-filter-privacy");
        foreach(var item in fixture["steps"]!.AsArray())
        {
            var c=Case(fixture,item!.AsObject());
            var rows=AgentNpsValidator.Validate(c.Envelope,c.Payload,c.Policy,c.Host);
            Assert.Equal(c.Payload["records"]!.AsArray().Count,rows.Count);
            if(rows.Count>0)
            {
                c.Payload["records"]![0]!["payload"]!["event_id"]=6272;
                Assert.Throws<ProtocolException>(()=>AgentNpsValidator.Validate(c.Envelope,c.Payload,c.Policy,c.Host));
            }
        }
    }

    [Fact]
    public void RejectsWrongPolicyAndForgedCursorProgress()
    {
        var fixture=Vectors().OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="nps-filter-privacy");
        var c=Case(fixture,fixture["steps"]![0]!.AsObject());
        Assert.Throws<ProtocolException>(()=>AgentNpsValidator.Validate(c.Envelope with { PolicyRevision="other" },c.Payload,c.Policy,c.Host));
        Assert.Throws<ProtocolException>(()=>AgentNpsValidator.Validate(c.Envelope with { Generation=Guid.Empty.ToString("D") },c.Payload,c.Policy,c.Host));
        Assert.Throws<ProtocolException>(()=>AgentNpsValidator.Validate(c.Envelope with { FilteredCount=c.Envelope.FilteredCount+1 },c.Payload,c.Policy,c.Host));
        Assert.Throws<ProtocolException>(()=>AgentNpsValidator.Validate(c.Envelope with { CursorAfter=new Cursor("bookmark","{\"record_id\":-1,\"bookmark\":\"b\",\"generation\":\"1\"}") },c.Payload,c.Policy,c.Host));
    }

    [Fact]
    public void NpsContinuityAndResetSourceScenariosAreAdmitted()
    {
        foreach (var fixture in Vectors().OfType<JsonObject>().Where(x=>new[]{"nps-continuity-restart","nps-record-gap","nps-policy-reset"}.Contains(x["name"]!.GetValue<string>())))
        foreach (var item in fixture["steps"]!.AsArray())
        {
            var c=Case(fixture,item!.AsObject());
            Assert.Equal(c.Payload["records"]!.AsArray().Count,AgentNpsValidator.Validate(c.Envelope,c.Payload,c.Policy,c.Host).Count);
        }
    }
}
