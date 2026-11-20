using Sli.Server.Semantic.Password;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public class PasswordRuleTests(ITestOutputHelper output)
{
    [Fact] public void Thousand_noise_clients_preserve_the_real_attack_and_checkpoint_progress()
    {
        var scope=Scope with {SourceInstanceId=new string('s',256),SourceGeneration=new string('g',512)};
        PasswordNative Row(int id,int second,string ip,string user) {
            var sample=Event(id,second,ip:ip,user:user);
            return PasswordNative.Parse(scope,id,sample.Witness.Sha256,4625,sample.Witness.At,sample.SourceXml);
        }
        var noise=Enumerable.Range(0,1000).Select(i=>Row(i+1,i%60,
            ((i/256) switch {0=>"192.0.2.",1=>"198.51.100.",2=>"203.0.113.",_=>"::192.0.2."})+(i%256),$"noise{i}")).ToArray();
        var attack=Enumerable.Range(1,10).Select(i=>Row(1000+i,i*5,"192.0.2.1","victim")).ToArray();
        Assert.Equal(noise.Length,noise.Select(n=>n.Member.ClientKey).Distinct().Count());
        var rule=new PasswordRule(scope);var now=Start.AddSeconds(180);
        var expected=Assert.Single(rule.Advance(new(),attack,now).Emissions);
        var actual=rule.Advance(new(),noise.Concat(attack).ToArray(),now);
        Assert.Equal(now.AddSeconds(-120),actual.State.Watermark);
        Assert.Equal(expected.Id,Assert.Single(actual.Emissions).Id);
        Assert.InRange(PasswordJson.SpacedSize(actual.State.Document),1,4194304);
        var expanded=actual.State.Document;
        expanded["episodes"]=PasswordJson.Array(actual.State.Episodes,e=>new System.Text.Json.Nodes.JsonObject {
            ["key"]=e.Key,["entity"]=e.Entity,["seed"]=e.Seed.Document,["last"]=e.Last.Document,
            ["root_id"]=e.RootId,["last_emission"]=e.LastEmission,["sequence"]=e.Sequence,["budget"]=e.Budget.Document,
            ["frozen"]=e.Frozen,["prequalification"]=PasswordJson.Array(e.Prequalification,w=>w.Document)});
        output.WriteLine($"1000 clients plus attack: expanded={PasswordJson.SpacedSize(expanded)}; indexed={PasswordJson.SpacedSize(actual.State.Document)} bytes");
        var saved=PasswordState.Read(actual.State.Document);
        Assert.Equal(actual.State.Document.ToJsonString(),PasswordState.Read(actual.State.Serialize(false)).Document.ToJsonString());
        var legacy=rule.Advance(new(),attack,now).State;
        Assert.Equal(legacy.Document.ToJsonString(),PasswordState.Read(legacy.Serialize(false)).Document.ToJsonString());
        var next=Row(1011,70,"192.0.2.1","victim");
        var continuation=rule.Advance(saved,[next],Start.AddSeconds(190),actual.Emissions,noise.Concat(attack).ToArray());
        Assert.Equal(2,Assert.Single(continuation.Emissions).Sequence);
    }

    [Fact] public void Expired_single_failure_is_removed_but_the_inclusive_boundary_can_still_qualify()
    {
        var rule=new PasswordRule(Scope);var first=Event(1,0);
        var state=rule.Advance(new(),[first],Start.AddSeconds(120)).State;
        var boundary=rule.Advance(state,[],Start.AddSeconds(720),retained:[first]);
        Assert.Single(boundary.State.Episodes);
        var attack=Enumerable.Range(2,9).Select(i=>Event(i,600)).ToArray();
        Assert.Single(rule.Advance(state,attack,Start.AddSeconds(720),retained:[first]).Emissions);
        var expired=rule.Advance(boundary.State,[],Start.AddSeconds(721),retained:[first]);
        Assert.Empty(expired.State.Episodes);Assert.Empty(expired.State.Window);
    }

    [Theory]
    [InlineData("brute",9)]
    [InlineData("spray",4)]
    public void State_pressure_preserves_attack_origin_until_next_batch_qualifies(string kind,int beforeThreshold)
    {
        var scope=Scope with {SourceInstanceId=new string('s',256),SourceGeneration=new string('g',512)};
        PasswordNative Row(int id,int second,string user,string ip="192.0.2.1") {
            var sample=Event(id,second,user:user,ip:ip);
            return PasswordNative.Parse(scope,id,sample.Witness.Sha256,4625,sample.Witness.At,sample.SourceXml);
        }
        var rule=new PasswordRule(scope,kind);
        var noise=Enumerable.Range(1,3000).Select(i=>Row(i,30+i%30,$"noise{i}",NoiseIp((i-1)%1000))).ToArray();
        var attack=Enumerable.Range(1,beforeThreshold).Select(i=>Row(3000+i,i,kind=="brute"?"victim":$"victim{i}","203.0.113.254")).ToArray();
        var firstBatch=noise.Concat(attack).ToArray();
        var unbounded=new PasswordState(rule.Pin,Start.AddSeconds(60),Members:firstBatch.Select(n=>n.Member).ToArray(),
            Active:firstBatch.GroupBy(n=>n.Member.EntityFor(rule)!).Select(g=> {
                var refs=g.OrderBy(n=>n.Witness.At).ThenBy(n=>n.Witness.NativeId).Select(n=>n.Witness).ToArray();
                return new PasswordEpisode(rule.EpisodeKey(0,g.Key,refs[0]),g.Key,refs[0],refs[^1],Origin:refs);
            }).ToArray());
        output.WriteLine($"{kind}: 3000 noise accounts plus pending attack = {PasswordJson.SpacedSize(unbounded.Document)} bytes");
        var proposal=rule.Advance(new(),firstBatch,Start.AddSeconds(180));
        Assert.Equal(Start.AddSeconds(60),proposal.State.Watermark);Assert.Empty(proposal.Diagnostics);Assert.Empty(proposal.Emissions);
        Assert.Equal(firstBatch.Length,proposal.State.Window.Count);
        var saved=PasswordState.Read(proposal.State.Document);
        var last=Row(3010,70,kind=="brute"?"victim":"victim5","203.0.113.254");
        var continued=rule.Advance(saved,[last],Start.AddSeconds(190),retained:firstBatch);
        var found=Assert.Single(continued.Emissions);
        Assert.Equal(attack[0].Witness,found.Seed);Assert.Equal(beforeThreshold+1,found.RootProof.Count);
        Assert.Equal(beforeThreshold+1,rule.VerifyChain([found],firstBatch.Append(last)).RefOccurrences);
    }

    [Theory]
    [InlineData("brute")]
    [InlineData("spray")]
    public void Stand_noise_burst_fits_without_losing_live_events(string kind)
    {
        var scope=Scope with {SourceInstanceId=new string('s',256),SourceGeneration=new string('g',512)};
        PasswordNative Row(int id,int second,string ip,string user) {
            var sample=Event(id,second,ip:ip,user:user);
            return PasswordNative.Parse(scope,id,sample.Witness.Sha256,4625,sample.Witness.At,sample.SourceXml);
        }
        // 400 failures in ten minutes from one IP, plus 1000 distinct IPs in six minutes.
        // Keep the high-cardinality noise live through the end of the window.
        var rows=Enumerable.Range(1,400).Select(i=>Row(i,(i-1)*600/400,"203.0.113.254",$"burst{i}"))
            .Concat(Enumerable.Range(0,1000).Select(i=>Row(401+i,240+i*360/1000,NoiseIp(i),$"noise{i}"))).ToArray();
        var rule=new PasswordRule(scope,kind);
        var proposal=rule.Advance(new(),rows,Start.AddSeconds(720));
        Assert.Equal(Start.AddSeconds(600),proposal.State.Watermark);Assert.Empty(proposal.Diagnostics);
        Assert.Equal(rows.Length,proposal.State.Window.Count);
        var saved=PasswordState.Read(proposal.State.Document);
        Assert.Equal(proposal.State.Document.ToJsonString(),saved.Document.ToJsonString());
        output.WriteLine($"{kind}: 400 failures/10min + 1000 IPs/6min; max scope; live_state={PasswordJson.SpacedSize(proposal.State.Document)} bytes");
    }

    private static string NoiseIp(int i)=>i==766?"::198.51.100.254":((i/256) switch {0=>"192.0.2.",1=>"198.51.100.",2=>"203.0.113.",_=>"::192.0.2."})+(i%256);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Oversized_live_state_rejects_the_whole_batch_without_mutating_checkpoint(bool wideSlice)
    {
        var scope=Scope with {SourceInstanceId=new string('s',256),SourceGeneration=new string('g',512)};
        var rows=Enumerable.Range(1,6000).Select(i=> {
            var sample=Event(i,30+i%30,user:$"noise{i}");
            return PasswordNative.Parse(scope,i,sample.Witness.Sha256,4625,sample.Witness.At,sample.SourceXml);
        }).ToArray();
        var state=new PasswordState();var before=state.Document.ToJsonString();
        var result=new PasswordRule(scope).Advance(state,rows,Start.AddSeconds(wideSlice?1920:180),readFrom:wideSlice?Start:null);
        Assert.Same(state,result.State);Assert.Equal(before,state.Document.ToJsonString());Assert.Empty(result.Emissions);
        Assert.Equal(1,result.Diagnostics["state_bound"]);Assert.True(result.StateBytes>16777216);
    }

    private static readonly PasswordScope Scope = new("00000000-0000-0000-0000-000000000001", "sli.windows.ad-dc", "synthetic", "generation", "");
    private static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    [Fact] public void Wide_slice_preserves_two_separate_attacks_and_their_native_proofs()
    {
        var rule=new PasswordRule(Scope);
        var rows=Enumerable.Range(1,10).Select(i=>Event(i,i)).Concat(Enumerable.Range(11,10).Select(i=>Event(i,1200+i))).ToArray();
        var result=rule.Advance(new(),rows,Start.AddSeconds(1920),readFrom:Start);
        Assert.Equal(2,result.Emissions.Count);
        Assert.Contains(result.State.ClosedAdmissions,e=>e.Key==result.Emissions[0].EpisodeKey);
        Assert.All(result.Emissions,e=>Assert.Equal(10,rule.VerifyChain([e],rows).RefOccurrences));
        Assert.Equal(Start.AddSeconds(1800),result.State.Watermark);
        var idle=rule.Advance(PasswordState.Read(result.State.Document),[],Start.AddSeconds(1921),result.Emissions,rows);
        Assert.Empty(idle.State.ClosedAdmissions);Assert.Empty(idle.Emissions);
    }
    [Fact] public void Qualified_episodes_are_never_evicted_to_make_checkpoint_space()
    {
        var scope=Scope with {SourceInstanceId=new string('s',256),SourceGeneration=new string('g',512)};
        var rule=new PasswordRule(scope);
        var rows=Enumerable.Range(1,10).Select(i=> {
            var e=Event(i,i);return PasswordNative.Parse(scope,i,e.Witness.Sha256,4625,e.Witness.At,e.SourceXml);
        }).ToArray();
        var qualified=rule.Advance(new(),rows,Start.AddSeconds(130)).State;
        var episode=Assert.Single(qualified.Episodes);
        var crowded=qualified with{Active=Enumerable.Range(1,10001).Select(i=>episode with{Entity=i.ToString("x64"),Key=(i+10001).ToString("x64")}).ToArray()};
        var denied=rule.Advance(crowded,[],Start.AddSeconds(140),retained:rows);
        Assert.Same(crowded,denied.State);Assert.Empty(denied.Emissions);Assert.Equal(1,denied.Diagnostics["state_bound"]);
    }
    internal static PasswordNative Event(int id, int seconds, string status="0xc000006a", string ip="192.0.2.1", string user="user")
    {
        var at=Start.AddSeconds(seconds);
        string xml=$"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID><TimeCreated SystemTime='{at:yyyy-MM-ddTHH:mm:sszzz}'/></System><EventData><Data Name='TargetUserName'>{user}</Data><Data Name='TargetDomainName'>domain</Data><Data Name='IpAddress'>{ip}</Data><Data Name='Status'>0xc000006d</Data><Data Name='SubStatus'>{status}</Data></EventData></Event>";
        return PasswordNative.Parse(Scope,id,new string('a',64),4625,at,xml);
    }
    [Fact] public void Qualifies_at_ten_inclusive_and_replays_without_duplicate_emission()
    {
        var rule=new PasswordRule(Scope);var events=Enumerable.Range(1,10).Select(i=>Event(i,(i-1)*60)).ToArray();
        var first=rule.Advance(new(),events,Start.AddSeconds(660));
        var emission=Assert.Single(first.Emissions);Assert.Equal(10,emission.KnownBadPassword);Assert.Equal(1,emission.DistinctNames);
        Assert.Equal(10,emission.Occurrences.Count);Assert.Equal(Start.AddSeconds(540),first.State.Watermark);
        var replay=rule.Advance(first.State,events,Start.AddSeconds(660),first.Emissions,events);
        Assert.Empty(replay.Emissions);Assert.Equal(first.State.Document.ToJsonString(),replay.State.Document.ToJsonString());
    }
    [Fact] public void Internet_noise_does_not_fill_checkpoint_with_expired_unqualified_entities()
    {
        var rule=new PasswordRule(Scope);var state=new PasswordState();var retained=new List<PasswordNative>();
        for(int batch=0;batch<30;batch++) {
            var events=Enumerable.Range(1,100).Select(i=>Event(batch*100+i,batch*300+i,
                ip:$"192.0.2.{i%40+1}",user:$"noise{batch*100+i}")).ToArray();
            var now=Start.AddSeconds(batch*300+220);
            var proposal=rule.Advance(state,events,now,retained:retained);
            Assert.True(proposal.State.Watermark==now.AddSeconds(-120),string.Join(',',proposal.Diagnostics.Select(p=>$"{p.Key}={p.Value}")));
            Assert.Empty(proposal.Emissions);Assert.Empty(proposal.Diagnostics);
            state=proposal.State;
            retained=retained.Concat(events).Where(n=>n.Witness.At>=now.AddSeconds(-720)).ToList();
        }
        var fresh=Enumerable.Range(1,10).Select(i=>Event(3000+i,9000+i)).ToArray();
        Assert.Single(rule.Advance(state,fresh,Start.AddSeconds(9130),retained:retained).Emissions);
    }
    [Fact] public void Continuation_keeps_predecessor_and_requires_native_history()
    {
        var rule=new PasswordRule(Scope);var events=Enumerable.Range(1,10).Select(i=>Event(i,i)).ToArray();
        var first=rule.Advance(new(),events,Start.AddSeconds(130));var next=Event(11,20);
        Assert.Throws<PasswordFailure>(()=>rule.Advance(first.State,[next],Start.AddSeconds(140),first.Emissions,[]));
        var continued=rule.Advance(first.State,[next],Start.AddSeconds(140),first.Emissions,events);
        var emission=Assert.Single(continued.Emissions);Assert.Equal(2,emission.Sequence);Assert.Equal(first.Emissions[0].Endpoint,emission.Predecessor);
        Assert.Equal(1,emission.KnownBadPassword);Assert.Equal(2,emission.Occurrences.Count);
    }
    [Fact] public void Classification_maps_ipv4_and_rejects_ambiguous_or_unbounded_xml()
    {
        Assert.Equal(Event(1,0).Member.ClientKey,Event(1,0,ip:"::ffff:192.0.2.1").Member.ClientKey);
        Assert.Equal(Event(1,0,ip:"::192.0.2.1").Member.ClientKey,Event(1,0,ip:"::c000:201").Member.ClientKey);
        Assert.NotEqual(Event(1,0,ip:"fe80::1%alpha").Member.ClientKey,Event(1,0,ip:"fe80::1%beta").Member.ClientKey);
        Assert.Equal("missing_client",Event(1,0,ip:"::ffff:192.0.2.001").Member.Reason);
        Assert.Equal("unknown_account",Event(2,1,"0xc0000064").Member.Failure);
        Assert.Equal("unclassified_failure",Event(3,2,"invalid").Member.Reason);
        Assert.Equal("known_bad_password",Event(4,3,"+0x_c000_006a").Member.Failure);
        Assert.ThrowsAny<Exception>(()=>PasswordNative.Parse(Scope,1,new string('a',64),4625,Start,"<!DOCTYPE x [<!ENTITY a 'x'>]><Event/>"));
    }
    [Fact] public void Threshold_window_is_inclusive_at_exactly_600_seconds()
    {
        var rule=new PasswordRule(Scope);var firstNine=Enumerable.Range(1,9).Select(i=>Event(i,(i-1)*60)).ToArray();
        Assert.Single(rule.Advance(new(),firstNine.Append(Event(10,600)).ToArray(),Start.AddSeconds(720)).Emissions);
        Assert.Empty(rule.Advance(new(),firstNine.Append(Event(10,601)).ToArray(),Start.AddSeconds(721)).Emissions);
    }
    [Fact] public void Holdback_and_coverage_gap_are_explicit()
    {
        var rule=new PasswordRule(Scope);var events=Enumerable.Range(1,10).Select(i=>Event(i,i)).ToArray();
        var held=rule.Advance(new(),events,Start.AddSeconds(120));Assert.Empty(held.Emissions);
        var emitted=rule.Advance(held.State,events,Start.AddSeconds(130),retained:events);Assert.Single(emitted.Emissions);
        var gap=rule.Advance(emitted.State,[],Start.AddSeconds(1000));Assert.Equal(1,gap.State.Epoch);Assert.Equal(1,gap.Diagnostics["coverage_gap"]);
    }
    [Fact] public void Frozen_python_source_vector_has_exact_pin_episode_emission_and_signal_identity()
    {
        var rule=new PasswordRule(Scope);var events=Enumerable.Range(1,10).Select(i=>Event(i,i)).ToArray();var proposal=rule.Advance(new(),events,Start.AddSeconds(130));var emission=Assert.Single(proposal.Emissions);
        Assert.Equal("43bce1ea3964b96f245ab16c9416d088f7a75816427908b94937b940e3cc5a55",rule.Pin);
        Assert.Equal("392d6f00e2329eb844784f27eb5b5ec3ab74c89fd7e3c2bdaf9b6f495051d5eb",events[0].Member.Entity);
        Assert.Equal("90e934323cd7be522076ce44cd10da24a577da7007da0cfdac55a003324857fc",emission.EpisodeKey);
        Assert.Equal("81d238812e76658fa8a01da8fe3f242ebfbbabcc1a90c7e85bc7bed454b19ffe",emission.Id);
        var signal=PasswordSignal.Create(rule,emission,Assert.Single(emission.Contexts(null)),Start.AddSeconds(130));
        Assert.Equal("18c73d0545a7bbb83ee0b65f9db7ccbe91158004b5192ea8cc042a4e693af269",PasswordSignal.Id(signal));
        signal["received_at_utc"]="2027-01-01T00:00:00+00:00";
        Assert.Equal("18c73d0545a7bbb83ee0b65f9db7ccbe91158004b5192ea8cc042a4e693af269",PasswordSignal.Id(signal));
    }
    [Fact] public void Cross_batch_prequalification_revalidates_origin_and_portion_roundtrip_is_exact()
    {
        var rule=new PasswordRule(Scope);var events=Enumerable.Range(1,270).Select(i=>Event(i,i)).ToArray();
        var first=rule.Advance(new(),events[..5],Start.AddSeconds(125));Assert.Empty(first.Emissions);
        var next=rule.Advance(first.State,events[5..],Start.AddSeconds(390),retained:events[..5]);var emission=Assert.Single(next.Emissions);Assert.Equal(270,emission.Occurrences.Count);Assert.Equal(2,emission.Portions);
        var contexts=emission.Contexts(null);Assert.Equal(emission.Id,PasswordEmission.Reassemble(Scope,contexts).Id);
        contexts[1]["entity"]=new string('b',64);Assert.Throws<PasswordFailure>(()=>PasswordEmission.Reassemble(Scope,contexts));
    }
    [Fact] public void Incomplete_window_never_becomes_a_successful_empty_batch()
    {
        var document=new System.Text.Json.Nodes.JsonObject { ["version"]="sli.password.v2.window.1",["read_from"]="2025-12-31T23:50:10Z",["read_to"]="2026-01-01T00:02:10Z",["finalizable_through"]="2026-01-01T00:00:10Z",["candidate_count"]=0,["native_checked_count"]=0,["unverifiable_count"]=0,["oversized_count"]=0,["truncated"]=false,["native_checks_complete"]=true,["error_code"]=null };
        PasswordProducer.ValidateWindow(document,Start);document["native_checks_complete"]=false;
        Assert.Throws<PasswordFailure>(()=>PasswordProducer.ValidateWindow(document,Start));
    }
    [Fact] public void Spray_requires_five_distinct_accounts_from_one_ip_and_retains_duplicates()
    {
        var rule=new PasswordRule(Scope,"spray");
        var events=Enumerable.Range(1,6).Select(i=>Event(i,i,user:i==6?"user1":$"user{i}")).ToArray();
        Assert.Empty(rule.Advance(new(),events[..4],Start.AddSeconds(130)).Emissions);
        var result=rule.Advance(new(),events,Start.AddSeconds(130));var emission=Assert.Single(result.Emissions);
        Assert.Equal(5,emission.DistinctNames);Assert.Equal(6,emission.Occurrences.Count);
        Assert.Equal(events[0].Member.ClientKey,emission.Entity);
        Assert.Equal("b1fcdd61283314535de48dacb1e6ff65d331b06a4cd184a5bb6927815d87d006",rule.Pin);
        Assert.Equal("5cd6f7ccf3c6bf8caeb1cd141a02252fc85c06c4b0a30d8413afebabe504b0b3",emission.Entity);
        Assert.Equal("669c2225dd54e0ad3b1a7ee0ac6ac87384d87cde3f8fe113f64a93b07df85e82",emission.EpisodeKey);
        Assert.Equal("9929c0cc8d345e15ef813fe0cd972b1434264a3892fb4299367103ca5a5b5488",emission.Id);
        var signal=PasswordSignal.Create(rule,emission,Assert.Single(emission.Contexts(null)),Start.AddSeconds(130));
        Assert.Equal("590bf8b1a05e33e1ba60dc37213bbed16bbc49a3c4134fd1e38428be83b044ac",PasswordSignal.Id(signal));
        var policy=Sli.Server.Semantic.Risk.PasswordRiskPolicy.Compile(PasswordSignal.PolicyId(rule),1,PasswordSignal.PolicyDefinition(rule));
        Assert.Equal("8aa6ba95e0be8d728ac206648a5c05f64a07efbdd9fd35635fb2b1bda40e4c08",policy.Sha256);
        var riskSignal=Sli.Server.Semantic.Risk.PasswordRiskSignal.Read(signal);
        Assert.Equal("spray",riskSignal.Rule.Kind);
        Assert.Equal("spray",Sli.Server.Semantic.Risk.PasswordRiskProposal.Create(policy,riskSignal).Policy.Rule.Kind);
        var next=Event(7,20,user:"another");
        var continuation=rule.Advance(result.State,[next],Start.AddSeconds(140),result.Emissions,events);
        Assert.Equal(2,Assert.Single(continuation.Emissions).Sequence);
    }
    [Fact] public void Spray_rejects_workstation_only_and_honors_inclusive_window()
    {
        var rule=new PasswordRule(Scope,"spray");
        var events=Enumerable.Range(1,4).Select(i=>Event(i,(i-1)*150,user:$"u{i}")).ToArray();
        Assert.Single(rule.Advance(new(),events.Append(Event(5,600,user:"u5")).ToArray(),Start.AddSeconds(720)).Emissions);
        Assert.Empty(rule.Advance(new(),events.Append(Event(5,601,user:"u5")).ToArray(),Start.AddSeconds(721)).Emissions);
        Assert.Empty(rule.Advance(new(),Enumerable.Range(1,5).Select(i=>Event(i,i,ip:"-",user:$"u{i}")).ToArray(),Start.AddSeconds(130)).Emissions);
    }    [Fact] public void Spray_sliding_expiration_and_input_state_are_preserved()
    {
        var rule=new PasswordRule(Scope,"spray");var first=Enumerable.Range(1,4).Select(i=>Event(i,(i-1)*100,user:$"u{i}")).ToArray();
        var pending=rule.Advance(new(),first,Start.AddSeconds(420));string before=pending.State.Document.ToJsonString();
        var more=new[]{Event(5,601,user:"u5"),Event(6,602,user:"u2"),Event(7,603,user:"u6")};
        var result=rule.Advance(pending.State,more,Start.AddSeconds(723),retained:first);
        Assert.Equal(before,pending.State.Document.ToJsonString());var emission=Assert.Single(result.Emissions);
        Assert.Equal(5,emission.DistinctNames);Assert.Equal(6,emission.RootProof.Count);Assert.Equal(first[0].Witness,emission.Seed);
    }
    [Fact] public void Spray_budget_failure_does_not_mutate_input_state()
    {
        var rule=new PasswordRule(Scope,"spray");var rows=Enumerable.Range(1,4).Select(i=>Event(i,i,user:$"u{i}")).ToArray();
        var first=rule.Advance(new(),rows,Start.AddSeconds(130));string before=first.State.Document.ToJsonString();
        var episode=Assert.Single(first.State.Episodes);var damaged=first.State with {Active=[episode with {Origin=[episode.Seed]}]};string damagedBefore=damaged.Document.ToJsonString();
        var next=rule.Advance(damaged,[Event(5,20,user:"u5")],Start.AddSeconds(140),retained:rows);
        Assert.Empty(next.Emissions);Assert.Equal(1,next.Diagnostics["prequalification_native_unavailable"]);
        Assert.Equal(damagedBefore,damaged.Document.ToJsonString());Assert.Equal(before,first.State.Document.ToJsonString());
        Assert.Throws<PasswordFailure>(()=>new PasswordBudget(10000,0,0).Reserve([rows[0].Witness]));
    }}
