using System.Security.Cryptography;
using System.Text;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class RadiusSessionV2IdentityRebindTests
{
    private const string Organization="example.test";
    private const string DistinguishedName="CN=User,DC=example,DC=test";
    private static VerifiedRadiusEvidence Evidence(string uid,string packet,string status="",string time="12:00:00",string dn="")
    {
        var fields=Enumerable.Repeat("",66).ToArray();
        fields[1]="NPS";fields[2]="08/11/2026";fields[3]=time;fields[4]=packet;fields[6]=dn;
        fields[11]="gateway";fields[26]="opaque-class";fields[31]=status;fields[35]="session-1";
        string record=string.Join(',',fields.Select(value=>value.Contains(',')?"\""+value.Replace("\"","\"\"")+"\"":value));
        return new(uid,record,Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(record))));
    }
    private static VerifiedRadiusEvidence Accept=>Evidence("11111111-1111-1111-1111-111111111111","2",dn:DistinguishedName);
    private static VerifiedRadiusEvidence Start=>Evidence("22222222-2222-2222-2222-222222222222","4","1","12:01:00");
    private static VerifiedRadiusEvidence Stop=>Evidence("33333333-3333-3333-3333-333333333333","4","2","12:10:00");
    private static ImmutableStoredRadiusObservation Stored(VerifiedRadiusEvidence evidence,string lifecycle="start",int minute=1)=>new(
        lifecycle=="start"?"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        evidence.EvidenceUid,lifecycle,"ready",new DateTimeOffset(2026,8,11,5,minute,0,TimeSpan.Zero),evidence.CanonicalRecordSha256);
    private static Task<RadiusSessionRebindResult> Build(IEnumerable<VerifiedRadiusEvidence> evidence,IEnumerable<ImmutableStoredRadiusObservation> stored,Func<string,string,Task<string?>>? lookup=null)=>
        RadiusSessionRebind.BuildAsync(evidence,stored,"radius.example.test",Organization,"N. Central Asia Standard Time",420,
            lookup ?? ((organization,dn)=>Task.FromResult<string?>(organization==Organization && dn==DistinguishedName?"entity:901":null)));

    // tests/sources/test_radius_session_v2_identity_rebind.py::test_rebind_rebuilds_session_with_current_v2_entity_identity
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RebuildsCompleteSessionWithCurrentV2EntityIdentity(bool reversed)
    {
        VerifiedRadiusEvidence[] evidence=[Accept,Start,Stop];
        if(reversed) Array.Reverse(evidence);
        var stored=new[]{Stored(Start),Stored(Stop,"stop",10)};
        var lookups=new List<(string Organization,string Dn)>();
        var result=await Build(evidence,stored,(organization,dn)=>{
            lookups.Add((organization,dn));return Task.FromResult<string?>(organization==Organization && dn==DistinguishedName?"entity:901":null);
        });
        Assert.Equal(2,result.InputObservations);Assert.Equal(2,result.ExactReadyObservations);
        var session=Assert.Single(result.Sessions);
        Assert.Equal("entity:901",session["exact_principal_key"]!.GetValue<string>());
        Assert.Equal("complete",session["completeness"]!.GetValue<string>());
        Assert.Equal(2,session["observation_count"]!.GetValue<int>());
        Assert.Equal(stored[0].ObservedAtUtc,DateTimeOffset.Parse(session["started_at_utc"]!.GetValue<string>()));
        Assert.Equal(stored[1].ObservedAtUtc,DateTimeOffset.Parse(session["stopped_at_utc"]!.GetValue<string>()));
        Assert.Equal((Organization,DistinguishedName),Assert.Single(lookups));
        Assert.Equal(Start.CanonicalRecordSha256,stored[0].CanonicalRecordSha256);
    }

    // tests/sources/test_radius_session_v2_identity_rebind.py::test_rebind_rejects_evidence_hash_drift
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RejectsEvidenceHashDrift(bool corruptEvidence)
    {
        var evidence=Start;var stored=Stored(evidence);
        if(corruptEvidence) evidence=evidence with { CanonicalRecordSha256=new string('f',64) };
        else stored=stored with { CanonicalRecordSha256=new string('f',64) };
        var error=await Assert.ThrowsAsync<RadiusSessionRebindException>(()=>Build([evidence],[stored]));
        Assert.Equal("rebind_evidence_hash_mismatch",error.Code);
        Assert.DoesNotContain(evidence.CanonicalRecord,error.ToString());
    }

    [Fact]
    public async Task RebuildLooksUpIdentityAgainAndDoesNotReusePreviousEntityKey()
    {
        var first=await Build([Accept,Start,Stop],[Stored(Start),Stored(Stop,"stop",10)]);
        var second=await Build([Accept,Start,Stop],[Stored(Start),Stored(Stop,"stop",10)],(_,_)=>Task.FromResult<string?>("entity:902"));
        Assert.Equal("entity:902",Assert.Single(second.Sessions)["exact_principal_key"]!.GetValue<string>());
        Assert.NotEqual(Assert.Single(first.Sessions)["session_identity_key"]!.GetValue<string>(),second.Sessions[0]["session_identity_key"]!.GetValue<string>());
    }

    [Fact]
    public async Task UnresolvedCurrentIdentityProducesNoInventedSession()
    {
        var result=await Build([Accept,Start,Stop],[Stored(Start),Stored(Stop,"stop",10)],(_,_)=>Task.FromResult<string?>(null));
        Assert.Equal(2,result.InputObservations);Assert.Equal(0,result.ExactReadyObservations);Assert.Empty(result.Sessions);
    }

    [Fact]
    public async Task ConflictingClassBindingsFailClosed()
    {
        var another=Evidence("44444444-4444-4444-4444-444444444444","2",dn:"CN=Another,DC=example,DC=test");
        var error=await Assert.ThrowsAsync<RadiusSessionRebindException>(()=>Build([Accept,another,Start],[Stored(Start)],(_,dn)=>Task.FromResult<string?>(dn==DistinguishedName?"entity:901":"entity:902")));
        Assert.Equal("rebind_class_identity_conflict",error.Code);
    }

    [Theory]
    [InlineData("lifecycle")]
    [InlineData("timestamp")]
    [InlineData("evidence")]
    public async Task ImmutableObservationMetadataCannotBeRewritten(string change)
    {
        var stored=Stored(Start);
        stored=change switch {
            "lifecycle"=>stored with { LifecycleEvent="stop" },
            "timestamp"=>stored with { ObservedAtUtc=stored.ObservedAtUtc!.Value.AddMinutes(1) },
            _=>stored with { EvidenceUid="55555555-5555-5555-5555-555555555555" }
        };
        var error=await Assert.ThrowsAsync<RadiusSessionRebindException>(()=>Build([Accept,Start],[stored]));
        Assert.Equal(change=="evidence"?"rebind_observation_evidence_missing":$"rebind_{change}_mismatch",error.Code);
    }
}
