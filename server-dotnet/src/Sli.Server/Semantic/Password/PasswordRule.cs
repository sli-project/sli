using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Semantic.Password;

public sealed record PasswordBudget(int RefOccurrences=0,int Portions=0,int XmlBytes=0)
{
    public JsonObject Document=>new(){["ref_occurrences"]=RefOccurrences,["portions"]=Portions,["xml_bytes"]=XmlBytes};
    public PasswordBudget Reserve(IReadOnlyList<PasswordWitness> refs)
    {
        var result=new PasswordBudget(checked(RefOccurrences+refs.Count),checked(Portions+(refs.Count+255)/256),checked(XmlBytes+refs.Sum(w=>w.XmlBytes)));
        if(RefOccurrences<0||Portions<0||XmlBytes<0||result.RefOccurrences>10000||result.Portions>256||result.XmlBytes>33554432)throw new PasswordFailure("password_v2_episode_budget_exhausted");return result;
    }
    internal static PasswordBudget Read(JsonNode? node)=>new(node!["ref_occurrences"]!.GetValue<int>(),node["portions"]!.GetValue<int>(),node["xml_bytes"]!.GetValue<int>());
}

public sealed record PasswordEpisode(string Key,string Entity,PasswordWitness Seed,PasswordWitness Last,string? RootId=null,string? LastEmission=null,int Sequence=0,PasswordBudget? EvidenceBudget=null,bool Frozen=false,IReadOnlyList<PasswordWitness>? Origin=null)
{
    public PasswordBudget Budget=>EvidenceBudget??new();public IReadOnlyList<PasswordWitness> Prequalification=>Origin??[];
    public JsonObject Document {
        get {
            var witnesses=Prequalification.Append(Seed).Append(Last).Distinct().ToList();
            var indexes=witnesses.Select((w,i)=>(w,i)).ToDictionary(p=>p.w,p=>p.i);
            return new(){["key"]=Key,["entity"]=Entity,["witnesses"]=PasswordJson.Array(witnesses,w=>w.Document),["seed"]=indexes[Seed],["last"]=indexes[Last],["root_id"]=RootId,["last_emission"]=LastEmission,["sequence"]=Sequence,["budget"]=Budget.Document,["frozen"]=Frozen,["prequalification"]=PasswordJson.Array(Prequalification,w=>JsonValue.Create(indexes[w]))};
        }
    }
    internal static PasswordEpisode Read(JsonNode? node) {
        var witnesses=node!["witnesses"]?.AsArray().Select(PasswordWitness.Read).ToArray();
        PasswordWitness Witness(JsonNode? value) {
            if(witnesses==null)return PasswordWitness.Read(value);
            if(value is not JsonValue v||!v.TryGetValue<int>(out int index)||index<0||index>=witnesses.Length)throw new PasswordFailure("password_v2_state_invalid");
            return witnesses[index];
        }
        return new(PasswordJson.Text(node["key"]),PasswordJson.Text(node["entity"]),Witness(node["seed"]),Witness(node["last"]),node["root_id"]?.GetValue<string>(),node["last_emission"]?.GetValue<string>(),node["sequence"]!.GetValue<int>(),PasswordBudget.Read(node["budget"]),node["frozen"]!.GetValue<bool>(),node["prequalification"]?.AsArray().Select(Witness).ToArray()??[]);
    }
}

public sealed record PasswordState(string? Pin=null,DateTimeOffset? Watermark=null,long Epoch=0,IReadOnlyList<PasswordMember>? Members=null,IReadOnlyList<PasswordEpisode>? Active=null,IReadOnlyList<PasswordEpisode>? Closed=null)
{
    internal const int MaxBytes=16777216;
    public IReadOnlyList<PasswordMember> Window=>Members??[];public IReadOnlyList<PasswordEpisode> Episodes=>Active??[];
    public IReadOnlyList<PasswordEpisode> ClosedAdmissions=>Closed??[];
    public JsonObject Document {
        get {
            var result=new JsonObject{["version"]="sli.password.v2.state.1",["pin"]=Pin,["watermark"]=Watermark.HasValue?PasswordJson.Stamp(Watermark.Value):null,["epoch"]=Epoch,["window"]=PasswordJson.Array(Window,m=>m.Document),["episodes"]=PasswordJson.Array(Episodes,e=>e.Document)};
            if(ClosedAdmissions.Count>0)result["closed_admissions"]=PasswordJson.Array(ClosedAdmissions,e=>e.Document);
            return result;
        }
    }
    internal JsonObject Serialize(bool indexed)
    {
        var document=Document;if(indexed)return document;
        document["episodes"]=PasswordJson.Array(Episodes,e=>new JsonObject {
            ["key"]=e.Key,["entity"]=e.Entity,["seed"]=e.Seed.Document,["last"]=e.Last.Document,
            ["root_id"]=e.RootId,["last_emission"]=e.LastEmission,["sequence"]=e.Sequence,["budget"]=e.Budget.Document,
            ["frozen"]=e.Frozen,["prequalification"]=PasswordJson.Array(e.Prequalification,w=>w.Document)});
        return document;
    }
    public static PasswordState Read(JsonNode? node)
    {
        if(node==null)return new();if(PasswordJson.Text(node["version"])!="sli.password.v2.state.1"||PasswordJson.SpacedSize(node)>MaxBytes||node["epoch"]!.GetValue<long>()<0)throw new PasswordFailure("password_v2_state_invalid");
        return new(node["pin"]?.GetValue<string>(),node["watermark"]==null?null:PasswordJson.Time(node["watermark"]),node["epoch"]!.GetValue<long>(),node["window"]!.AsArray().Select(PasswordMember.Read).ToArray(),node["episodes"]!.AsArray().Select(PasswordEpisode.Read).ToArray(),node["closed_admissions"]?.AsArray().Select(PasswordEpisode.Read).ToArray());
    }
    internal PasswordState? Fit(out int bytes)
    {
        // Advance has already removed expired state. Every remaining live origin
        // can still qualify; size pressure must reject the batch, never erase it.
        bytes=PasswordJson.SpacedSize(Document);
        return bytes<=MaxBytes&&Window.Count<=10000&&Episodes.Count+ClosedAdmissions.Count<=10000?this:null;
    }
}

public sealed record PasswordEmission(string EpisodeKey,string Pin,long Epoch,string Entity,int Sequence,PasswordWitness Seed,IReadOnlyList<PasswordWitness> RootProof,IReadOnlyList<PasswordWitness> NewEvents,PasswordWitness? Predecessor,string? PreviousId,int KnownBadPassword,int UnknownAccount,int OtherFailure,int DistinctNames,IReadOnlyList<PasswordWitness> Origin)
{
    public PasswordWitness Endpoint=>(NewEvents.Count>0?NewEvents:RootProof)[^1];
    public IReadOnlyList<PasswordWitness> Occurrences=>Predecessor==null?Origin.Concat(NewEvents).ToArray():new[]{Predecessor}.Concat(NewEvents).ToArray();
    public int Portions=>(Occurrences.Count+255)/256;
    public JsonObject Document=>new(){["episode_key"]=EpisodeKey,["pin"]=Pin,["epoch"]=Epoch,["entity"]=Entity,["sequence"]=Sequence,["seed"]=Seed.Document,["root_proof"]=PasswordJson.Array(RootProof,w=>w.Document),["new_events"]=PasswordJson.Array(NewEvents,w=>w.Document),["predecessor"]=Predecessor?.Document,["previous_id"]=PreviousId,["known_bad_password"]=KnownBadPassword,["unknown_account"]=UnknownAccount,["other_failure"]=OtherFailure,["distinct_names"]=DistinctNames,["origin"]=PasswordJson.Array(Origin,w=>w.Document)};
    public string Id=>PasswordJson.Hash(Document);
    public IReadOnlyList<JsonObject> Contexts(string? rootId)
    {
        var refs=Occurrences;if(refs.Count is <1 or >10000||Portions>256||Sequence==1&&rootId!=null&&rootId!=Id||Sequence>1&&(rootId==null||!PasswordJson.Hex(rootId)))throw new PasswordFailure("password_v2_portion_invalid");
        var contexts=new List<JsonObject>();for(int i=0;i<Portions;i++) {
            var context=new JsonObject { ["version"]="sli.password.v2.portion.1",["episode_key"]=EpisodeKey,["pin"]=Pin,["epoch"]=Epoch,["entity"]=Entity,["sequence"]=Sequence,["emission_id"]=Id,["root_id"]=Sequence==1?Id:rootId,["previous_id"]=PreviousId,["seed"]=Seed.Compact,["endpoint_ordinal"]=refs.Count-1,["origin_count"]=Origin.Count,["root_from"]=Origin.Count-RootProof.Count,["root_count"]=RootProof.Count,["new_from"]=Sequence==1?Origin.Count:1,["new_count"]=NewEvents.Count,["occurrence_total"]=refs.Count,["portion_total"]=Portions,["known_bad_password"]=KnownBadPassword,["unknown_account"]=UnknownAccount,["other_failure"]=OtherFailure,["distinct_names"]=DistinctNames,["portion_index"]=i,["occurrence_from"]=256*i,["occurrences"]=PasswordJson.Array(refs.Skip(256*i).Take(256),w=>w.Compact) };
            if(CanonicalJson.Length(context)>65536)throw new PasswordFailure("password_v2_portion_invalid");contexts.Add(context);
        }return contexts;
    }
    internal static PasswordEmission Reassemble(PasswordScope scope,IReadOnlyList<JsonObject> contexts)
    {
        if(contexts.Count is <1 or >256)throw new PasswordFailure("password_v2_chain_invalid");var h=contexts[0];var refs=new List<PasswordWitness>();
        for(int index=0;index<contexts.Count;index++) {
            var c=contexts[index];if(c["portion_index"]!.GetValue<int>()!=index||c["occurrence_from"]!.GetValue<int>()!=index*256||c["portion_total"]!.GetValue<int>()!=contexts.Count)throw new PasswordFailure("password_v2_chain_invalid");
            refs.AddRange(c["occurrences"]!.AsArray().Select(w=>PasswordWitness.FromCompact(scope,w)));
        }
        int origin=h["origin_count"]!.GetValue<int>(),rootFrom=h["root_from"]!.GetValue<int>(),rootCount=h["root_count"]!.GetValue<int>(),newFrom=h["new_from"]!.GetValue<int>(),sequence=h["sequence"]!.GetValue<int>();
        if(refs.Count!=h["occurrence_total"]!.GetValue<int>()||refs.Count>10000||origin<0||origin>refs.Count||rootFrom<0||rootCount<0||rootFrom+rootCount!=origin||newFrom<0||newFrom>refs.Count)throw new PasswordFailure("password_v2_chain_invalid");
        var result=new PasswordEmission(PasswordJson.Text(h["episode_key"]),PasswordJson.Text(h["pin"]),h["epoch"]!.GetValue<long>(),PasswordJson.Text(h["entity"]),sequence,PasswordWitness.FromCompact(scope,h["seed"]),refs.Skip(rootFrom).Take(rootCount).ToArray(),refs.Skip(newFrom).ToArray(),sequence>1?refs[0]:null,h["previous_id"]?.GetValue<string>(),h["known_bad_password"]!.GetValue<int>(),h["unknown_account"]!.GetValue<int>(),h["other_failure"]!.GetValue<int>(),h["distinct_names"]!.GetValue<int>(),refs.Take(origin).ToArray());
        var rebuilt=result.Contexts(PasswordJson.Text(h["root_id"]));if(!rebuilt.Zip(contexts).All(p=>JsonNode.DeepEquals(p.First,p.Second)))throw new PasswordFailure("password_v2_chain_invalid");return result;
    }
}

public sealed record PasswordProposal(PasswordState State,IReadOnlyList<PasswordEmission> Emissions,IReadOnlyDictionary<string,int> Diagnostics,int? StateBytes=null);

// Pure source-compatible brute-force v2 engine. SQL alone grants source and publication authority.
public sealed class PasswordRule
{
    public PasswordScope Scope {get;} public string Kind {get;} public int Revision {get;}
    public PasswordRule(PasswordScope scope,string kind="brute",int revision=2){scope.Validate();if(kind is not ("brute" or "spray")||revision<2)throw new PasswordFailure("password_v2_rule_scope");Scope=scope;Kind=kind;Revision=revision;}
    public string Id=>Kind=="brute"?RuleId:"qw.password-spray";
    public const string RuleId="qw.password-brute-force";
    public JsonObject Execution=>new(){["version"]="sli.qw.execution.v1",["kind"]="threshold",["rule_id"]=Id,["rule_version"]=Revision,["scope"]=Scope.Document,["rule_sha256"]=PasswordJson.Hash(new JsonObject{["contract"]=Revision==2?"sli.password.v2.phase-a.1":"sli.password.v2.live."+Revision.ToString(System.Globalization.CultureInfo.InvariantCulture),["rule"]=Id,["window"]=600,["inclusive"]=true,["threshold"]=Kind=="brute"?10:5,["holdback"]=120,["horizon"]=720,["rows"]=10000,["lifetime_refs"]=10000,["lifetime_portions"]=256,["lifetime_xml_bytes"]=33554432,["classification"]="bad-unknown-other/native-v1",["client"]="native-ip-mapped-or-explicit-workstation/v1",["late"]="drop-finalized/v1",["gap"]="new-epoch/v1",["continuity"]="native-adjacency/v1"})};
    public string Pin=>PasswordJson.Hash(Execution);
    internal string EpisodeKey(long epoch,string entity,PasswordWitness seed)=>PasswordJson.Hash(new JsonArray(Pin,epoch,entity,seed.Params));
    private static PasswordMember[] Ordered(IEnumerable<PasswordMember> members)=>members.OrderBy(m=>m.Witness.At).ThenBy(m=>m.Witness.NativeId).ToArray();
    private static bool Later(PasswordWitness a,PasswordWitness b)=>a.At>b.At||a.At==b.At&&a.NativeId>b.NativeId;
    internal static Dictionary<long,PasswordNative> Records(IEnumerable<PasswordNative> natives)
    {
        var result=new Dictionary<long,PasswordNative>();int bytes=0,count=0;
        foreach(var native in natives) {
            if(++count>10000||(bytes=checked(bytes+System.Text.Encoding.UTF8.GetByteCount(native.SourceXml)))>33554432)throw new PasswordFailure("password_v2_proof_bound");
            var parsed=PasswordNative.Parse(native.Witness.Scope,native.Witness.NativeId,native.Witness.Sha256,native.EventId,native.Witness.At,native.SourceXml);
            if(parsed!=native||result.TryGetValue(native.Witness.NativeId,out var old)&&old!=parsed)throw new PasswordFailure("password_v2_native_content_conflict");result[native.Witness.NativeId]=parsed;
        }return result;
    }
    private void VerifyPath(string entity,IReadOnlyList<PasswordWitness> path,Dictionary<long,PasswordNative> records)
    {
        if(path.Count==0)throw new PasswordFailure("password_v2_continuity_origin_missing");PasswordWitness? previous=null;
        foreach(var w in path){VerifyWitness(entity,w,records);if(previous!=null&&(!Later(w,previous)||w.At-previous.At>TimeSpan.FromSeconds(600)))throw new PasswordFailure("password_v2_continuity_origin_gap");previous=w;}
    }
    private void VerifyWitness(string entity,PasswordWitness w,Dictionary<long,PasswordNative> records)
    {
        if(!records.TryGetValue(w.NativeId,out var n))throw new PasswordFailure("password_v2_native_unavailable");if(n.Witness!=w||w.Scope!=Scope||n.Member.EntityFor(this)!=entity)throw new PasswordFailure("password_v2_continuity_native_conflict");
    }
    public PasswordBudget VerifyChain(IReadOnlyList<PasswordEmission> chain,IEnumerable<PasswordNative> native)
    {
        var records=Records(native);if(chain.Count==0)throw new PasswordFailure("password_v2_continuity_missing");PasswordEmission? previous=null;var budget=new PasswordBudget();
        foreach(var e in chain.OrderBy(e=>e.Sequence)) {
            if(e.Pin!=Pin||e.Sequence!=(previous?.Sequence??0)+1||e.EpisodeKey!=chain[0].EpisodeKey||e.Entity!=chain[0].Entity||e.Epoch!=chain[0].Epoch)throw new PasswordFailure("password_v2_continuity_identity");
            var witnesses=e.Occurrences;if(witnesses.Count==0)throw new PasswordFailure("password_v2_continuity_empty");budget=budget.Reserve(witnesses);foreach(var w in witnesses)VerifyWitness(e.Entity,w,records);
            if(e.EpisodeKey!=EpisodeKey(e.Epoch,e.Entity,e.Seed))throw new PasswordFailure("password_v2_continuity_seed");PasswordWitness endpoint;
            if(previous==null) {
                if(e.Predecessor!=null||e.PreviousId!=null||e.RootProof.Count==0||e.Origin.Count==0||e.Origin[0]!=e.Seed||e.Origin[^1]!=e.RootProof[^1])throw new PasswordFailure("password_v2_continuity_root");
                VerifyPath(e.Entity,e.Origin,records);var expected=e.Origin.Where(w=>w.At>=e.Origin[^1].At.AddSeconds(-600)).ToArray();
                if(!e.RootProof.SequenceEqual(expected)||(Kind=="brute"?e.RootProof.Count<10:e.RootProof.Select(w=>records[w.NativeId].Member.TargetKey).Distinct().Count()<5)||e.RootProof.Any(w=>records[w.NativeId].Member.Reason=="successful_logon")||e.RootProof.Select(w=>w.NativeId).Distinct().Count()!=e.RootProof.Count)throw new PasswordFailure("password_v2_continuity_threshold");endpoint=e.RootProof[^1];
            } else {
                if(e.NewEvents.Count==0||e.Origin.Count!=0||e.RootProof.Count!=0||e.Predecessor!=previous.Endpoint||e.PreviousId!=previous.Id||e.Seed!=previous.Seed)throw new PasswordFailure("password_v2_continuity_predecessor");endpoint=e.Predecessor!;
            }
            foreach(var w in e.NewEvents){if(!Later(w,endpoint)||w.At-endpoint.At>TimeSpan.FromSeconds(600))throw new PasswordFailure("password_v2_continuity_gap");endpoint=w;}
            var counted=(previous==null?e.RootProof:e.NewEvents).Select(w=>records[w.NativeId].Member).ToArray();
            if(e.KnownBadPassword!=counted.Count(m=>m.Failure=="known_bad_password")||e.UnknownAccount!=counted.Count(m=>m.Failure=="unknown_account")||e.OtherFailure!=counted.Count(m=>m.Failure=="other_failure")||e.DistinctNames!=counted.Select(m=>m.TargetKey).Distinct().Count())throw new PasswordFailure("password_v2_continuity_counters");previous=e;
        }return budget;
    }
    public PasswordProposal Advance(PasswordState state,IReadOnlyList<PasswordNative> events,DateTimeOffset now,IReadOnlyList<PasswordEmission>? history=null,IReadOnlyList<PasswordNative>? retained=null,DateTimeOffset? readFrom=null)
    {
        // A larger SQL slice is replayed through the same 600-second engine.
        // In particular, separate episodes of one entity must both be emitted.
        if(readFrom.HasValue&&readFrom.Value<now.AddSeconds(-720)) {
            var slicedState=state;var slicedEmissions=new List<PasswordEmission>();var counts=new Dictionary<string,int>();
            var admitted=new Dictionary<string,PasswordEpisode>(StringComparer.Ordinal);
            var checkedNative=Records(retained??[]);
            foreach(var (id,native) in Records(events)) {
                if(checkedNative.TryGetValue(id,out var previous)&&previous!=native)throw new PasswordFailure("password_v2_native_content_conflict");
                checkedNative[id]=native;
            }
            var nativeRows=checkedNative.Values.ToArray();
            for(var through=readFrom.Value.AddSeconds(720);;through=through.AddSeconds(600)) {
                through=through<now?through:now;
                var incoming=events.Where(n=>n.Witness.At>=through.AddSeconds(-720)&&n.Witness.At<=through).ToArray();
                var part=Advance(slicedState,incoming,through,(history??[]).Concat(slicedEmissions).ToArray(),nativeRows);
                if(part.State.Watermark!=through.AddSeconds(-120))return new(state,[],part.Diagnostics,part.StateBytes);
                slicedState=part.State;slicedEmissions.AddRange(part.Emissions);
                foreach(var emission in part.Emissions)admitted[emission.EpisodeKey]=part.State.Episodes.Single(e=>e.Key==emission.EpisodeKey);
                foreach(var (code,count) in part.Diagnostics)counts[code]=counts.GetValueOrDefault(code)+count;
                if(through==now) {
                    var activeKeys=slicedState.Episodes.Select(e=>e.Key).ToHashSet(StringComparer.Ordinal);
                    slicedState=slicedState with{Closed=admitted.Values.Where(e=>!activeKeys.Contains(e.Key)).OrderBy(e=>e.Key,StringComparer.Ordinal).ToArray()};
                    var bounded=slicedState.Fit(out int bytes);
                    return bounded==null?new(state,[],new Dictionary<string,int>{{"state_bound",1}},bytes):new(bounded,slicedEmissions,counts);
                }
            }
        }
        history??=[];retained??=[];now=now.ToUniversalTime();if(state.Pin!=null&&state.Pin!=Pin)throw new PasswordFailure("password_v2_state_scope");
        var cutoff=now.AddSeconds(-120);var lower=now.AddSeconds(-720);var diagnostics=new SortedDictionary<string,int>(StringComparer.Ordinal);void Note(string code)=>diagnostics[code]=diagnostics.GetValueOrDefault(code)+1;
        PasswordProposal Reject(string code)=>new(state,[],new Dictionary<string,int>{{code,1}});
        if(state.Watermark.HasValue&&cutoff<state.Watermark)return Reject("clock_regression");
        var records=Records(retained);foreach(var (id,native) in Records(events)){if(records.TryGetValue(id,out var old)&&old!=native)throw new PasswordFailure("password_v2_native_content_conflict");if(native.Witness.Scope!=Scope)throw new PasswordFailure("password_v2_native_scope");records[id]=native;}
        long epoch=state.Epoch;var watermark=state.Watermark;var oldWindow=state.Window;var episodes=state.Episodes.ToDictionary(e=>e.Entity,StringComparer.Ordinal);
        if(watermark.HasValue&&lower>watermark){epoch++;Note("coverage_gap");oldWindow=[];episodes.Clear();watermark=null;}
        watermark??=lower.AddTicks(-10);var seen=oldWindow.ToDictionary(m=>m.Witness.NativeId);var pending=seen.Where(p=>p.Value.Witness.At>watermark).Select(p=>p.Key).ToHashSet();
        foreach(var native in events) {
            var m=native.Member;long id=m.Witness.NativeId;
            if(seen.TryGetValue(id,out var old)){if(old with{Reason=m.Reason}!=m)throw new PasswordFailure("password_v2_native_conflict");continue;}
            if(m.Witness.At>now){Note("future_event");continue;}if(m.Witness.At<lower){Note("outside_horizon");continue;}
            if(m.Witness.At<=watermark){seen[id]=m with{Reason="too_late"};Note("too_late");}else{seen[id]=m;pending.Add(id);}
        }
        var finalized=Ordered(pending.Select(id=>seen[id]).Where(m=>m.Witness.At<=cutoff));var proofs=new Dictionary<string,IReadOnlyList<PasswordWitness>>();var newByKey=new Dictionary<string,List<PasswordWitness>>();var originChecked=new HashSet<string>();var queues=new Dictionary<string,Queue<PasswordMember>>();var names=new Dictionary<string,Dictionary<string,int>>();
        var origins=new Dictionary<string,(List<PasswordWitness> Items,long Bytes)>();
        void AddCandidate(string entity,PasswordMember member) {
            if(!queues.TryGetValue(entity,out var queue))queues[entity]=queue=new();
            if(!names.TryGetValue(entity,out var counts))names[entity]=counts=new(StringComparer.Ordinal);
            queue.Enqueue(member);string target=member.TargetKey!;counts[target]=counts.GetValueOrDefault(target)+1;
        }
        foreach(var old in Ordered(oldWindow.Where(m=>m.Witness.At<=watermark)))if(old.Reason!="successful_logon"&&old.EntityFor(this) is string entity)AddCandidate(entity,old);
        foreach(var member in finalized) {
            string? entity=member.EntityFor(this);var witness=member.Witness;if(entity==null){if(member.Reason!="successful_logon")Note(member.Reason??"missing_client");continue;}
            episodes.TryGetValue(entity,out var episode);
            if(member.Reason=="successful_logon"){
                var preceding=records.Values.Where(n=>n.Member.EntityFor(this)==entity&&n.Member.Reason==null&&n.Witness.At>=witness.At.AddSeconds(-600)&&n.Witness.At<witness.At).Select(n=>n.Member).ToArray();
                if(episode==null||episode.RootId==null&&!proofs.ContainsKey(episode.Key)||preceding.Select(m=>m.TargetKey).Distinct().Count()<5||!preceding.Any(m=>m.TargetKey==member.TargetKey))continue;
            }
            if(episode==null||witness.At-episode.Last.At>TimeSpan.FromSeconds(600)) {
                if(episode!=null)VerifyWitness(entity,episode.Last,records);episode=new(EpisodeKey(epoch,entity,witness),entity,witness,witness,Origin:[witness]);originChecked.Add(episode.Key);
            } else {
                if(episode.RootId==null&&!episode.Frozen&&!proofs.ContainsKey(episode.Key)) {
                    if(!originChecked.Contains(episode.Key)){if(episode.Prequalification.Count==0||episode.Prequalification[0]!=episode.Seed||episode.Prequalification[^1]!=episode.Last)return Reject("prequalification_native_unavailable");try{VerifyPath(entity,episode.Prequalification,records);}catch(PasswordFailure e)when(e.Message=="password_v2_native_unavailable"){return Reject("prequalification_native_unavailable");}originChecked.Add(episode.Key);}
                    if(!origins.TryGetValue(episode.Key,out var origin))origin=(episode.Prequalification.ToList(),episode.Prequalification.Sum(w=>(long)w.XmlBytes));
                    long bytes=origin.Bytes+witness.XmlBytes;int count=origin.Items.Count+1;
                    if(count>10000||(count+255)/256>256||bytes>33554432){origins[episode.Key]=origin;episodes[entity]=episode with{Last=witness,Frozen=true};Note("prequalification_proof_budget_exhausted");continue;}
                    origin.Items.Add(witness);origins[episode.Key]=(origin.Items,bytes);
                }episode=episode with{Last=witness};
            }
            episodes[entity]=episode;if(episode.Frozen){Note("episode_evidence_budget_exhausted");continue;}
            if(episode.RootId!=null){if(!newByKey.ContainsKey(episode.Key))newByKey[episode.Key]=[];newByKey[episode.Key].Add(witness);continue;}
            if(!queues.TryGetValue(entity,out var queue))queues[entity]=queue=new();
            if(!names.TryGetValue(entity,out var targets))names[entity]=targets=new(StringComparer.Ordinal);
            while(queue.TryPeek(out var expired)&&expired.Witness.At<witness.At.AddSeconds(-600)){queue.Dequeue();string target=expired.TargetKey!;if(--targets[target]==0)targets.Remove(target);}
            AddCandidate(entity,member);
            if((Kind=="brute"?queue.Count>=10:targets.Count>=5)&&!proofs.ContainsKey(episode.Key))proofs[episode.Key]=queue.Select(m=>m.Witness).ToArray();else if(proofs.ContainsKey(episode.Key)){if(!newByKey.ContainsKey(episode.Key))newByKey[episode.Key]=[];newByKey[episode.Key].Add(witness);}
        }
        foreach(var (entity,episode) in episodes.ToArray())if(origins.TryGetValue(episode.Key,out var origin))episodes[entity]=episode with{Origin=origin.Items.ToArray()};
        var emissions=new List<PasswordEmission>();foreach(var (entity,episode) in episodes.OrderBy(p=>p.Key,StringComparer.Ordinal).ToArray()) {
            var root=proofs.GetValueOrDefault(episode.Key)??[];IReadOnlyList<PasswordWitness> added=newByKey.GetValueOrDefault(episode.Key)??[];if(episode.Frozen||root.Count==0&&added.Count==0)continue;
            var chain=history.Where(e=>e.EpisodeKey==episode.Key).ToArray();PasswordWitness? predecessor=null;
            if(episode.RootId!=null){VerifyChain(chain,records.Values);if(chain[^1].Id!=episode.LastEmission)throw new PasswordFailure("password_v2_continuity_state");predecessor=chain[^1].Endpoint;}
            var counted=(root.Count>0?root:added).Select(w=>records[w.NativeId].Member).ToArray();
            var emission=new PasswordEmission(episode.Key,Pin,epoch,entity,episode.Sequence+1,episode.Seed,root,added,predecessor,episode.LastEmission,counted.Count(m=>m.Failure=="known_bad_password"),counted.Count(m=>m.Failure=="unknown_account"),counted.Count(m=>m.Failure=="other_failure"),counted.Select(m=>m.TargetKey).Distinct().Count(),root.Count>0?episode.Prequalification:[]);
            PasswordBudget budget;try{budget=episode.Budget.Reserve(emission.Occurrences);}catch(PasswordFailure e)when(e.Message=="password_v2_episode_budget_exhausted"){episodes[entity]=episode with{Frozen=true};Note("episode_evidence_budget_exhausted");continue;}
            VerifyChain(chain.Append(emission).ToArray(),records.Values);emissions.Add(emission);episodes[entity]=episode with{RootId=episode.RootId??emission.Id,LastEmission=emission.Id,Sequence=emission.Sequence,EvidenceBudget=budget,Origin=[]};
        }
        // Only an endpoint within 600 seconds can connect to a later decision.
        // Published history and unresolved barriers remain owned by the SQL ledger.
        var next=new PasswordState(Pin,cutoff,epoch,Ordered(seen.Values.Where(m=>m.Witness.At>=cutoff.AddSeconds(-600))),episodes.OrderBy(p=>p.Key,StringComparer.Ordinal).Select(p=>p.Value).Where(e=>e.Frozen||e.Last.At>=cutoff.AddSeconds(-600)).ToArray());
        var fitted=next.Fit(out int stateBytes);if(fitted==null)return new(state,[],new Dictionary<string,int>{{"state_bound",1}},stateBytes);return new(fitted,emissions,diagnostics);
    }
}
