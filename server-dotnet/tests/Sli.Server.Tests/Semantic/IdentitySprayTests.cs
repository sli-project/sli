using System.Text.Json.Nodes;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public class IdentitySprayTests
{
    private static readonly PasswordScope Scope=new("00000000-0000-0000-0000-000000000001","sli.windows.ad-dc","synthetic","generation","");
    private static readonly DateTimeOffset Start=DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private static PasswordNative Event(int id,int seconds,string user,int eventId=4625,string sid="",bool normalizeAccount=false)
    {
        var at=Start.AddSeconds(seconds);string xml=$"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>{eventId}</EventID><TimeCreated SystemTime='{PasswordJson.Stamp(at)}'/></System><EventData><Data Name='TargetUserName'>{user}</Data><Data Name='TargetDomainName'>fixture</Data><Data Name='TargetUserSid'>{sid}</Data><Data Name='IpAddress'>192.0.2.10</Data><Data Name='Status'>{(eventId==4624?"0x0":"0xc000006d")}</Data><Data Name='SubStatus'>{(eventId==4624?"0x0":"0xc000006a")}</Data><Data Name='LogonType'>3</Data></EventData></Event>";return PasswordNative.Parse(Scope,id,new('a',64),eventId,at,xml,normalizeAccount);
    }
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void BruteForceUsesOneAccountAndEscalatesOnlyAfterSuccessfulLogon(bool failureSid, bool successSid)
    {
        const string sid="S-1-5-21-100000001-200000002-300000003-500";
        string[] names=failureSid?["Administrator","ADMINISTRATOR","АДМИНИСТРАТОР","FIXTURE\\Administrator"]:
            ["Administrator","ADMINISTRATOR","FIXTURE\\Administrator"];
        var rule=new PasswordRule(Scope,revision:395);
        var guesses=Enumerable.Range(1,10).Select(i=>Event(i,i,names[i%names.Length],sid:failureSid?sid:"",normalizeAccount:true)).ToArray();
        var other=Event(20,12,"Admin",normalizeAccount:true);
        var first=rule.Advance(new(),guesses.Append(other).ToArray(),Start.AddSeconds(150));
        var root=Assert.Single(first.Emissions);
        Assert.Equal(10,root.Occurrences.Count);
        var initial=PasswordSignal.Create(rule,root,Assert.Single(root.Contexts(null)),Start.AddSeconds(150),guesses);
        Assert.Equal("medium",initial["effective_severity"]!.ToString());

        var unrelated=Event(21,31,"ADMIN",4624,normalizeAccount:true);
        var success=Event(22,32,"Administrator",4624,successSid?sid:"",normalizeAccount:true);
        var next=rule.Advance(first.State,[unrelated,success],Start.AddSeconds(160),first.Emissions,guesses);
        var update=Assert.Single(next.Emissions);
        Assert.Equal(root.EpisodeKey,update.EpisodeKey);
        Assert.Equal(22,Assert.Single(update.NewEvents).NativeId);
        var proof=guesses.Append(success).ToArray();
        var signal=PasswordSignal.Create(rule,update,Assert.Single(update.Contexts(root.Id)),Start.AddSeconds(160),proof,first.Emissions);
        Assert.Equal("critical",signal["effective_severity"]!.ToString());
        PasswordRiskEpisode.Read([PasswordRiskSignal.Read(initial),PasswordRiskSignal.Read(signal)],PasswordSignal.Id(signal)).Verify(proof);
    }
    [Fact]public void Python_spray_success_continues_same_episode_with_critical_risk_and_exact_native_proof()
    {
        var rule=new PasswordRule(Scope,"spray");var failures=Enumerable.Range(0,5).Select(i=>Event(i+1,i*10,"fixture-"+i)).ToArray();var first=rule.Advance(new(),failures,Start.AddSeconds(200));var root=Assert.Single(first.Emissions);var success=Event(9,100,"fixture-2",4624);
        var second=rule.Advance(first.State,[success],Start.AddSeconds(300),first.Emissions,failures);var update=Assert.Single(second.Emissions);Assert.Equal(root.EpisodeKey,update.EpisodeKey);
        var native=failures.Append(success).ToArray();var rootSignal=PasswordSignal.Create(rule,root,Assert.Single(root.Contexts(null)),Start.AddSeconds(200),failures);var signal=PasswordSignal.Create(rule,update,Assert.Single(update.Contexts(root.Id)),Start.AddSeconds(300),native,first.Emissions);
        Assert.Equal("critical",(string?)signal["effective_severity"]);Assert.Contains("success_after_spray",signal["severity_reasons"]!.AsArray().Select(n=>(string?)n));Assert.Contains(signal["evidence_refs"]!.AsArray(),r=>(string?)r!["native_id"]=="9");
        var episode=PasswordRiskEpisode.Read(new[]{rootSignal,signal}.Select(PasswordRiskSignal.Read).ToArray(),PasswordSignal.Id(signal));episode.Verify(native);var policy=PasswordRiskPolicy.Compile(PasswordSignal.PolicyId(rule),1,PasswordSignal.PolicyDefinition(rule));var proposal=PasswordRiskProposal.Create(policy,PasswordRiskSignal.Read(signal));Assert.Equal("critical",proposal.Assessment.Risk);Assert.Equal(80,proposal.Assessment.Display);
        Assert.Empty(rule.Advance(second.State,[success],Start.AddSeconds(301),first.Emissions.Concat(second.Emissions).ToArray(),native).Emissions);
        var changed=Event(9,100,"unrelated",4624);Assert.Throws<PasswordFailure>(()=>episode.Verify(failures.Append(changed)));
    }
    [Fact]public void Success_alone_and_unrelated_targets_never_qualify()
    {
        var rule=new PasswordRule(Scope,"spray");var successes=Enumerable.Range(0,8).Select(i=>Event(i+1,i,"fixture-"+i,4624)).ToArray();Assert.Empty(rule.Advance(new(),successes,Start.AddSeconds(200)).Emissions);
        var failures=Enumerable.Range(0,4).Select(i=>Event(i+10,i,"fixture-"+i)).ToArray();Assert.Empty(rule.Advance(new(),failures.Concat(successes).ToArray(),Start.AddSeconds(200)).Emissions);
        var five=Enumerable.Range(0,5).Select(i=>Event(i+1,i,"fixture-"+i)).ToArray();var first=rule.Advance(new(),five,Start.AddSeconds(200));Assert.Empty(rule.Advance(first.State,[Event(9,100,"unrelated",4624)],Start.AddSeconds(300),first.Emissions,five).Emissions);
    }
    [Fact]public void Even_intervals_are_additional_evidence_and_cannot_forge_critical_severity()
    {
        var rule=new PasswordRule(Scope,"spray");var failures=Enumerable.Range(0,5).Select(i=>Event(i+1,i*10,"fixture-"+i)).ToArray();var root=Assert.Single(rule.Advance(new(),failures,Start.AddSeconds(200)).Emissions);var signal=PasswordSignal.Create(rule,root,Assert.Single(root.Contexts(null)),Start.AddSeconds(200),failures);
        Assert.Equal(new[]{"machine_tempo_spray","regular_intervals"},signal["severity_reasons"]!.AsArray().Select(n=>(string?)n));Assert.Equal("high",(string?)signal["effective_severity"]);
        signal["severity_reasons"]!.AsArray().Add("success_after_spray");signal["effective_severity"]="critical";var episode=PasswordRiskEpisode.Read([PasswordRiskSignal.Read(signal)],PasswordSignal.Id(signal));Assert.Throws<PasswordRiskFailure>(()=>episode.Verify(failures));
    }
}
