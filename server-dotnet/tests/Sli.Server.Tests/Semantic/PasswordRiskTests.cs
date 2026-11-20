using System.Text.Json.Nodes;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public class PasswordRiskTests
{
    private static readonly PasswordScope Scope=new("00000000-0000-0000-0000-000000000001","sli.windows.ad-dc","synthetic","generation","");
    private static readonly DateTimeOffset Start=DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    internal static (PasswordRule Rule,PasswordNative[] Native,JsonObject[] Signals) Episode(int count=10)
    {
        var rule=new PasswordRule(Scope);
        var native=Enumerable.Range(1,count).Select(i=>{
            var at=Start.AddSeconds(i);string xml=$"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID><TimeCreated SystemTime='{PasswordJson.Stamp(at)}'/></System><EventData><Data Name='TargetUserName'>user</Data><Data Name='TargetDomainName'>domain</Data><Data Name='IpAddress'>192.0.2.1</Data><Data Name='Status'>0xc000006d</Data><Data Name='SubStatus'>0xc000006a</Data></EventData></Event>";
            return PasswordNative.Parse(Scope,i,new string('a',64),4625,at,xml);
        }).ToArray();
        var emission=Assert.Single(rule.Advance(new(),native,Start.AddSeconds(count+120)).Emissions);
        return(rule,native,emission.Contexts(null).Select(c=>PasswordSignal.Create(rule,emission,c,Start.AddSeconds(130))).ToArray());
    }
    [Fact] public void Frozen_source_identity_assessment_and_completeness_vector_match()
    {
        var (rule,_,signals)=Episode();var definition=PasswordSignal.PolicyDefinition(rule);
        var policy=PasswordRiskPolicy.Compile(PasswordSignal.PolicyId(rule),1,definition);
        Assert.Equal("0f93f3dc73a58e76618414ad3d28a3174c3288cf6e93451b961e614a1780139f",policy.Sha256);
        var proposal=PasswordRiskProposal.Create(policy,PasswordRiskSignal.Read(signals[0]));
        Assert.Equal("c546b30b005d95fe493ff8241e438d03fc8813ceafe1fb6933f4f41f37dc9c40",proposal.Partition);
        Assert.Equal("d7daf13397f52a4026fce65704d6ecbd8f950a432b0a84242a96df6efbaae787",proposal.EvidenceKey);
        Assert.Equal("0416f15d697e0a99c5c48d46be002fbe86a64a68a06517afc8682436788052bc",proposal.Identity);
        Assert.Equal("8d38d5269e1add103f90ef42949194589472ee7df0cd586a2da0dffb8248c55e",proposal.StepKey);
        Assert.Equal("599faee63dc0a0275618d39a468e075ff42f7d5cbe69354aea18d3187cb666bc",proposal.ContributionKey);
        Assert.Equal(65,proposal.Assessment.Score);Assert.Equal("medium",proposal.Assessment.Confidence);
        var snapshot=PasswordRiskCompleteness.Capture(Start.AddSeconds(130),proposal.At);
        Assert.Equal(Sli.Server.Storage.EventReports.EventCatalogQuality.ShippedCatalog()["entries"]!.AsArray().Count,snapshot["catalog_completeness"]!["entry_count"]!.GetValue<int>());
        Assert.False(snapshot["supports_negative_conclusion"]!.GetValue<bool>());
        Assert.Null(snapshot["collection_freshness"]!["max_age_seconds"]);
    }
    [Fact] public void Unsupported_policy_never_compiles_as_claimable_and_hash_is_unicode_source_codec()
    {
        var (rule,_,_)=Episode();var definition=PasswordSignal.PolicyDefinition(rule);
        definition["scenario_kind"]="qw.password-spray";
        Assert.Throws<PasswordRiskFailure>(()=>PasswordRiskPolicy.Compile(PasswordSignal.PolicyId(rule),1,definition));
        definition=PasswordSignal.PolicyDefinition(rule);definition["risk"]!["raw_score"]="61";
        Assert.Throws<PasswordRiskFailure>(()=>PasswordRiskPolicy.Compile(PasswordSignal.PolicyId(rule),1,definition));
        Assert.Throws<PasswordRiskFailure>(()=>PasswordRiskPolicy.Compile("custom",1,PasswordSignal.PolicyDefinition(rule)));
    }
    [Fact] public void Complete_chain_proof_rejects_missing_portion_changed_members_and_native_tamper()
    {
        var (rule,native,signals)=Episode(270);var episode=PasswordRiskEpisode.Read(signals.Select(PasswordRiskSignal.Read).ToArray(),PasswordSignal.Id(signals[0]));
        Assert.Equal(2,episode.Signals.Count);Assert.Equal(270,episode.Verify(native).RefOccurrences);
        Assert.False(episode.ContainsExactly([PasswordSignal.Id(signals[0])]));
        Assert.Throws<PasswordRiskFailure>(()=>PasswordRiskEpisode.Read([PasswordRiskSignal.Read(signals[0])],PasswordSignal.Id(signals[0])));
        Assert.Throws<PasswordFailure>(()=>episode.Verify(native[..269]));
        var changed=(JsonObject)signals[1].DeepClone();changed["entity_key"]=new string('b',64);
        Assert.Throws<PasswordRiskFailure>(()=>PasswordRiskSignal.Read(changed));
    }
    [Theory] [InlineData(1,30)] [InlineData(2,60)] [InlineData(8,3600)] [InlineData(100,3600)]
    public void Retry_is_source_bounded(int attempt,int expected)=>Assert.Equal(expected,PasswordRiskConsumer.RetrySeconds(attempt));

    [Fact] public void Source_QW_codec_normalizes_transport_utc_and_omits_default_processing_mode()
    {
        var (_,_,signals)=Episode();var changed=(JsonObject)signals[0].DeepClone();changed["received_at_utc"]="2026-01-01T07:02:10+07:00";
        changed["occurred_at_utc"]="2026-01-01T00:00:10Z";changed["processing_mode"]="live";
        var signal=PasswordRiskSignal.Read(changed);
        Assert.Equal(PasswordSignal.Id(signals[0]),signal.Id);
    }
    [Fact] public void Unicode_policy_hash_uses_source_UTF8_while_execution_pin_uses_ASCII()
    {
        var rule=new PasswordRule(Scope with{SourceInstanceId="синтетический"});var definition=PasswordSignal.PolicyDefinition(rule);
        var policy=PasswordRiskPolicy.Compile(PasswordSignal.PolicyId(rule),1,definition);
        Assert.Equal("default:qw.password-brute-force:a56037937195b7d2b4ca120135d6b5fd",policy.Id);
        Assert.Equal("7c4d1cd62868ef6410e7c45492647882f390a3a3217d08a353edac3084a36360",policy.Sha256);
    }
    [Theory] [InlineData("complete",70)] [InlineData("partial",67)] [InlineData("unavailable",65)] [InlineData("unknown",65)]
    public void Source_confidence_changes_with_current_control_coverage(string coverage,int score)
    {
        var (rule,_,signals)=Episode();var p=PasswordRiskProposal.Create(PasswordRiskPolicy.Compile(PasswordSignal.PolicyId(rule),1,PasswordSignal.PolicyDefinition(rule)),PasswordRiskSignal.Read(signals[0]));
        Assert.Equal(score,PasswordRiskProposal.Assess(60,60,false,"high",p.Assessment.Factors,coverage).Score);
    }
    [Fact] public void Aggregate_counts_same_evidence_once_and_caps_independent_contributions()
    {
        JsonObject C(string evidence,decimal raw,int display)=>new(){["evidence_key"]=evidence,["raw_score"]=raw,["display_points"]=display,["risk_class"]="high",["hard_critical"]=false};
        var result=PasswordRiskScenario.Aggregate([C("same",60,60),C("same",25,25)]);Assert.Equal(60,result.Raw);Assert.Equal(60,result.Display);
        result=PasswordRiskScenario.Aggregate([C("one",60,60),C("two",60,60)]);Assert.Equal(120,result.Raw);Assert.Equal(100,result.Display);Assert.Equal("high",result.Class);
    }
    [Fact] public void Historical_barrier_descriptor_binds_exact_target_sequence_and_prior_revision()
    {
        var (_,native,signals)=Episode();var episode=PasswordRiskEpisode.Read(signals.Select(PasswordRiskSignal.Read).ToArray(),PasswordSignal.Id(signals[0]));var last=episode.Emissions[^1];
        var descriptor=new JsonObject{["version"]="sli.password.v2.historical-barrier.1",["barrier_episode_key"]=new string('b',64),["barrier_first_ledger_revision"]=4L,["barrier_seed"]=native[0].Witness.Document,["target_last_admitted_revision"]=3L,["target_last_sequence"]=(long)last.Sequence,["target_last_emission_id"]=last.Id};
        var ledger=new JsonObject{["historical_barrier"]=descriptor};Assert.Equal(native[0].Witness,PasswordRiskProof.Historical(ledger,episode));
        descriptor["target_last_admitted_revision"]=4L;Assert.Throws<PasswordRiskFailure>(()=>PasswordRiskProof.Historical(ledger,episode));
    }
}
