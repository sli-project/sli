using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Investigations;
using Xunit;

namespace Sli.Server.Tests.Investigations;

public sealed class InvestigationCompletionContractTests
{
    static JsonObject Vectors()
    {
        using var stream = typeof(InvestigationCompletionContractTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Investigations.Fixtures.completion-source-vectors.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void UnknownTimelineEventRetainsIdentityWithoutInventingRisk(bool metadataOnly)
    {
        var row = new JsonObject { ["event_db_id"] = 7, ["event_id"] = 999999,
            ["channel"] = "Security", ["provider_name"] = "synthetic-provider",
            ["server"] = "dc1.example.test", ["time_created_utc"] = "2026-11-02T12:00:00Z",
            ["subject"] = "synthetic-actor", ["target"] = "synthetic-target",
            ["subject_user_name"] = "synthetic-actor", ["target_user_name"] = "synthetic-target" };
        var item = InvestigationTimeline.Build(row, "reason", metadataOnly).Item;
        Assert.Equal("7", item["event_db_id"]!.ToString());
        Assert.Equal("999999", item["event_id"]!.ToString());
        Assert.Equal("неизвестный тип события", item["title"]!.ToString());
        Assert.False(item["catalogued"]!.GetValue<bool>());
        foreach (string field in new[] { "severity", "base_risk", "confidence", "assessment_confidence" })
            Assert.Equal("unknown", item[field]!.ToString());
        Assert.Null(item["summary"]);
        Assert.Equal("synthetic-actor", item["actor"]!.ToString());
        Assert.Equal("synthetic-target", item["target"]!.ToString());
    }
    [Fact] public void WorkspaceCursorIsPythonCompatibleAndBoundToEveryContextField()
    {
        var vector = Vectors()["cursor"]!; var ctx = vector["context"]!.AsArray();
        var input = new InvestigationWorkspaceInput(7, null, ctx[3]!.ToString(), null, ctx[5]!.ToString(), ctx[6]!.ToString(), "UTC", vector["token"]!.ToString());
        Assert.Equal("source-relation-cursor", input.DecodeCursor());
        Assert.Equal(vector["token"]!.ToString(), input.EncodeCursor("source-relation-cursor"));
        foreach (var changed in new[] { input with { Event = 8 }, input with { Entity = 1 }, input with { Query = "changed" }, input with { Scope = "all" }, input with { From = null }, input with { To = null }, input with { Zone = "Europe/Moscow" } })
            Assert.Equal("invalid_cursor", Assert.Throws<InvestigationException>(() => changed.DecodeCursor()).Code);
    }
    [Fact] public void TimelineDatabaseTimestampsUsePublicUtcContract()
    {
        var row = new JsonObject { ["event_db_id"] = 7, ["event_id"] = 999999, ["time_created_utc"] = "2026-11-02T15:00:00.1234+03:00" };
        Assert.Equal("2026-11-02T12:00:00.123400Z", InvestigationTimeline.Build(row, "reason").Item["time_utc"]!.ToString());
    }
    [Theory]
    [InlineData("2026-11-01","2026-11-01","Asia/Bangkok","2026-10-31T17:00:00Z","2026-11-01T17:00:00Z")]
    [InlineData("2026-11-01T03:00:00+03:00","2026-11-01T04:00:00+03:00","UTC","2026-11-01T00:00:00Z","2026-11-01T01:00:00Z")]
    public void UtcRangeMatchesExclusiveDateAndOffsetContract(string from,string to,string zone,string start,string end)
    {var result=new InvestigationWorkspaceInput(7,null,"",null,from,to,zone,null).Normalize();Assert.Equal(start,result.From);Assert.Equal(end,result.To);}
    [Theory]
    [InlineData("2026-03-08T02:30:00","nonexistent_local_datetime")]
    [InlineData("2026-11-01T01:30:00","ambiguous_local_datetime_requires_offset")]
    public void DstWallTimesFailClosed(string wall,string error)
    {Assert.Equal(error,Assert.Throws<InvestigationException>(()=>new InvestigationWorkspaceInput(7,null,"",null,wall,null,"America/New_York",null).Normalize()).Code);}
    [Theory]
    [InlineData("vpn_accounting_session",1,"confirmed",null)]
    [InlineData("event",1,"confirmed","invalid_evidence_kind")]
    [InlineData("vpn_accounting_session",0,"confirmed","invalid_evidence_ref")]
    [InlineData("vpn_accounting_session",1,"untrusted","invalid_relation_status")]
    public void EvidenceInputRetainsSourceValidation(string kind,long domain,string relation,string? error)
    {
        var input=new InvestigationEvidenceInput(kind,domain,"radius-session-row:"+new string('a',64),relation);
        if(error is null)input.Validate();else Assert.Equal(error,Assert.Throws<InvestigationException>(()=>input.Validate()).Code);
    }
    static JsonObject Observation(string id,string lifecycle,string time,string key="radius-session:test",string principal="ad:test") => new()
    { ["observation_id"]=id,["lifecycle_event"]=lifecycle,["observed_at_utc"]=time,["identity_state"]="exact",["timestamp_state"]="ready",["session_identity_key"]=key,["exact_principal_key"]=principal,["canonical_record_sha256"]=new string('a',64) };
    static string Session(int generation,string first) => "radius-session-row:"+Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("radius-session:test\0"+generation+"\0"+first)));
    [Fact] public void VpnMembershipUsesExactOrderedGenerations()
    {
        JsonObject[] rows=[Observation("3","stop","2026-11-02T12:03:00Z"),Observation("1","start","2026-11-02T12:00:00Z"),Observation("2","start","2026-11-02T12:01:00Z"),Observation("4","interim_update","2026-11-02T12:04:00Z")];
        Assert.True(InvestigationVpnSessionEvidence.ContainsSession(rows,Session(1,"1")));
        Assert.True(InvestigationVpnSessionEvidence.ContainsSession(rows,Session(2,"2")));
        Assert.True(InvestigationVpnSessionEvidence.ContainsSession(rows,Session(3,"4")));
        Assert.False(InvestigationVpnSessionEvidence.ContainsSession(rows,Session(1,"2")));
    }
    [Fact] public void ConflictingPrincipalsAndDuplicateObservationsCannotAuthorizeEvidence()
    {
        var first=Observation("1","start","2026-11-02T12:00:00Z");
        foreach(var rows in new[]{new[]{first,first},new[]{first,Observation("2","stop","2026-11-02T12:01:00Z",principal:"ad:other")}})
            Assert.Equal("unavailable",Assert.Throws<InvestigationException>(()=>InvestigationVpnSessionEvidence.ContainsSession(rows,Session(1,"1"))).Code);
    }
}
