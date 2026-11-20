using Sli.Server.Infrastructure;
using System.Data;
using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Auth.Lifecycle.Security;

namespace Sli.Server.Semantic.Password;

public sealed record PasswordProducerOutcome(int Jobs=0,bool Failed=true,string Status="failed",long? Revision=null,JsonObject? Health=null,bool FailureObserved=false,JsonObject? Work=null,JsonObject? Diagnostic=null);

// Same SQL273/275 transaction boundary as password_attack_producer.py. This owner
// neither grants source identity nor bypasses the deferred SQL reservation guards.
public sealed class PasswordProducer
{
    public async Task<PasswordProducerOutcome> RunAsync(NpgsqlConnection db,PasswordRule rule,CancellationToken ct,Dictionary<long,PasswordNative>? retainedWindow=null)
    {
        RequireOpen(db);JsonObject attempt;bool indexedState;var diagnostics=new DetectionDiagnostics();
        try {
            await using var tx=await db.BeginTransactionAsync(ct);var sql=new PasswordSql(db,tx,diagnostics);
            var readiness = await sql.Rows("select public.password_source_ready_v314(@s::jsonb) as ready",ct,("s",rule.Scope.Document));
            if (readiness.Count != 1 || readiness[0]["ready"] is not JsonValue ready || !ready.TryGetValue<bool>(out var configured))
                throw new PasswordFailure("password_v2_source_unconfirmed");
            if (!configured) { await tx.CommitAsync(ct); return new(Failed:false,Status:"unconfigured"); }
            var pending=await sql.Rows("select public.password_event_clock362(@s::jsonb,@e::jsonb) as event_clock,to_regprocedure('public.password_state_episodes385(jsonb)') is not null as indexed_state",ct,("s",rule.Scope.Document),("e",rule.Execution));
            if(pending[0]["event_clock"] is null) { await tx.CommitAsync(ct); return new(Failed:false,Status:"committed"); }
            indexedState=pending[0]["indexed_state"]!.GetValue<bool>();
            attempt=PasswordJson.Obj(await sql.Call("begin_password_attempt",ct,rule.Scope.Document,rule.Execution));
            if(attempt["token"]!.GetValue<long>()<=0||attempt["state_revision"]!.GetValue<long>()<0)throw new PasswordFailure("password_v2_attempt_invalid");PasswordJson.Time(attempt["attempted_at"]);
            diagnostics.Step="password_attempt_commit";await tx.CommitAsync(ct);
        } catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
        catch (PostgresException error) when(error.SqlState==PostgresErrorCodes.LockNotAvailable) {RequireOpen(db);return new(Failed:false,Status:"busy",Diagnostic:DetectionDiagnostics.Describe(error,diagnostics.Step));}
        catch (Exception error) {if(db.FullState!=ConnectionState.Open)throw;return new(Diagnostic:DetectionDiagnostics.Describe(error,diagnostics.Step));}
        diagnostics.Step="password_batch_begin";
        try {
            JsonObject? completed=null;int jobs=0;JsonObject? work=null;bool enabled;
            await using(var tx=await db.BeginTransactionAsync(ct)) {
                var sql=new PasswordSql(db,tx,diagnostics);
                // First statement: managed family/policy/source locks are held through COMMIT.
                diagnostics.Step="ensure_default_qw_policy";
                await using(var admission=new NpgsqlCommand("select public.ensure_default_qw_policy(@id,1,@definition)",db,tx){CommandTimeout=0}) {
                    admission.Parameters.AddWithValue("id",PasswordSignal.PolicyId(rule));admission.Parameters.AddWithValue("definition",CanonicalJson.Serialize(PasswordSignal.PolicyDefinition(rule),ensureAscii:false));
                    object? result=await admission.ExecuteScalarAsync(ct);if(result is not bool decision)throw new PasswordFailure("password_v2_policy_unconfirmed");enabled=decision;
                }
                if(enabled)(completed,jobs,work)=await Batch(sql,rule,attempt,ct,retainedWindow,indexedState);
                diagnostics.Step="password_batch_commit";await tx.CommitAsync(ct);
            }
            RequireOpen(db);return enabled?new(jobs,false,"committed",completed!["revision"]!.GetValue<long>(),PasswordJson.Obj(completed["health"]),Work:work):new(Failed:false,Status:"disabled");
        } catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
        catch (PostgresException error) when(error.SqlState==PostgresErrorCodes.LockNotAvailable) {RequireOpen(db);return new(Failed:false,Status:"busy",Diagnostic:DetectionDiagnostics.Describe(error,diagnostics.Step));}
        catch (Exception error) {
            var diagnostic=DetectionDiagnostics.Describe(error,diagnostics.Step);if(db.FullState!=ConnectionState.Open)throw;bool observed=false;
            try {
                await using var tx=await db.BeginTransactionAsync(ct);var sql=new PasswordSql(db,tx,diagnostics);
                var result=await sql.Call("observe_password_failure_v2",ct,rule.Scope.Document,rule.Execution,attempt["token"]!.GetValue<long>(),new JsonObject{["source_error"]=new JsonObject{["count"]=1,["from"]=null,["to"]=null}});
                observed=result?.GetValue<bool>()==true;await tx.CommitAsync(ct);
            }catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}catch{observed=false;}
            RequireOpen(db);return new(FailureObserved:observed,Diagnostic:diagnostic);
        }
    }
    private static void RequireOpen(NpgsqlConnection db){if(db.FullState!=ConnectionState.Open)throw new PasswordFailure("password_v2_connection_not_idle");}
    private static readonly HashSet<string> LossCodes=["too_late","coverage_gap","episode_evidence_budget_exhausted","missing_target","unclassified_failure","ambiguous_failure","conflicting_client","missing_client"];

    private static async Task<(JsonObject,int,JsonObject)> Batch(PasswordSql sql,PasswordRule rule,JsonObject attempt,CancellationToken ct,Dictionary<long,PasswordNative>? retainedWindow,bool indexedState)
    {
        long token=attempt["token"]!.GetValue<long>(),revision=attempt["state_revision"]!.GetValue<long>();var scope=rule.Scope.Document;var execution=rule.Execution;
        var checkpoint=PasswordJson.Obj(await sql.Call("read_password_checkpoint_v2",ct,scope,execution));
        if(checkpoint["active_token"]!.GetValue<long>()!=token||checkpoint["last_observed_token"]!.GetValue<long>()>=token||checkpoint["state_revision"]!.GetValue<long>()!=revision)throw new PasswordFailure("password_v2_attempt_conflict");
        var state=PasswordState.Read(checkpoint["state_document"]);
        var rows=await sql.Rows("select * from public.read_password_event_window362(@s::jsonb,@e::jsonb)",ct,("s",scope),("e",execution));
        if(rows.Count==0||rows[0]["record_kind"]?.GetValue<string>()!="metadata")throw new PasswordFailure("password_v2_window_invalid") {WindowCondition=PasswordFailure.WindowCheck.MetadataRecord};
        // The short reader's event clock is checked again by the SQL finalizer;
        // the attempt timestamp still fences the wall-clock reader.
        var window=ValidateWindow(PasswordJson.Obj(rows[0]["metadata"]),PasswordJson.Time(attempt["attempted_at"]),true);
        if(rows.Count-1!=window["candidate_count"]!.GetValue<int>())throw new PasswordFailure("password_v2_window_invalid") {WindowCondition=PasswordFailure.WindowCheck.CandidateCount};
        if(rows.Skip(1).Any(r=>r["record_kind"]?.GetValue<string>()!="event"))throw new PasswordFailure("password_v2_window_invalid") {WindowCondition=PasswordFailure.WindowCheck.EventRecords};
        var incoming=rows.Skip(1).Select(r=>ReadNative(rule.Scope,r)).ToArray();var windowBudget=new NativeBudget(incoming);
        if(windowBudget.Count!=incoming.Length)throw new PasswordFailure("password_v2_window_invalid") {WindowCondition=PasswordFailure.WindowCheck.DuplicateNative};
        var now=PasswordJson.Time(window["read_to"]);var lower=PasswordJson.Time(window["read_from"]);var final=PasswordJson.Time(window["finalizable_through"]);
        if(incoming.Any(n=>n.Witness.At<lower||n.Witness.At>now))throw new PasswordFailure("password_v2_window_invalid") {WindowCondition=PasswordFailure.WindowCheck.EventTimeRange};
        if(state.Watermark.HasValue&&final<state.Watermark)throw new PasswordFailure("password_v2_window_invalid") {WindowCondition=PasswordFailure.WindowCheck.WatermarkRegression};
        var entities=state.Episodes.Select(e=>e.Entity).Concat(state.Window.Select(m=>m.EntityFor(rule))).Concat(incoming.Select(n=>n.Member.EntityFor(rule))).OfType<string>().Distinct().Order(StringComparer.Ordinal).ToArray();
        var context=PasswordJson.Obj(await sql.Call("prepare_password_producer_batch_v2",ct,scope,execution,token,revision,entities));
        if(context["status"]?.GetValue<string>()!="prepared"||context["state_revision"]!.GetValue<long>()!=revision||context["barriers"] is not JsonArray barriersJson||barriersJson.Count>10000||PasswordJson.SpacedSize(context)>4194304||context["prelocked_entities"] is not JsonArray prelockedJson||prelockedJson.Count>10000)throw new PasswordFailure("password_v2_context_invalid") {Check=PasswordFailure.ContextCheck.Shape};
        var prelocked=prelockedJson.Select(PasswordJson.Text).ToArray();
        if(!prelocked.SequenceEqual(prelocked.Distinct().Order(StringComparer.Ordinal)))throw new PasswordFailure("password_v2_context_invalid") {Check=PasswordFailure.ContextCheck.EntityOrder};
        if(prelocked.Any(e=>!PasswordJson.Hex(e)))throw new PasswordFailure("password_v2_context_invalid") {Check=PasswordFailure.ContextCheck.EntityFormat};
        if(entities.Except(prelocked).Any())throw new PasswordFailure("password_v2_context_invalid") {Check=PasswordFailure.ContextCheck.MissingEntity};
        var barriers=barriersJson.Select(PasswordJson.Obj).ToDictionary(b=>PasswordJson.Text(b["entity"]),StringComparer.Ordinal);
        if(barriers.Keys.Except(prelocked).Any())throw new PasswordFailure("password_v2_context_invalid") {Check=PasswordFailure.ContextCheck.MissingBarrierEntity};
        var episodes=state.Episodes.ToDictionary(e=>e.Entity,StringComparer.Ordinal);
        foreach(var (entity,b) in barriers){var frozen=BarrierEpisode(b);if(frozen.Sequence<=0)throw new PasswordFailure("password_v2_frozen_zero_unsupported");if(!episodes.TryGetValue(entity,out var old)||old.Key==frozen.Key)episodes[entity]=frozen;}
        // Fetch the small shared checkpoint overlap once, rather than issuing a
        // retained-proof query for each expired, unqualified account in noise.
        var overlap=episodes.Values.SelectMany(e=>e.Prequalification.Append(e.Seed).Append(e.Last)).Concat(state.Window.Select(m=>m.Witness)).ToArray();
        bool cacheOverlap=true;
        try{windowBudget.Plan(overlap);}catch(PasswordFailure e)when(e.Message=="password_v2_proof_bound"){cacheOverlap=false;}
        if(cacheOverlap)await windowBudget.Fetch(sql,rule.Scope,overlap,ct,retainedWindow);
        var cachedByEntity=windowBudget.Records.Values.ToLookup(n=>n.Member.EntityFor(rule)??"",StringComparer.Ordinal);
        // Keep the input window bounded, but validate one entity's immutable chain
        // at a time. Unrelated chains must not consume each other's proof budget.
        // A retained too_late member keeps its diagnostic reason. When its
        // native row is reread, both copies must still enter the same partition
        // so Advance can deduplicate them before classifying new decisions.
        var incomingEntities=state.Window.Any(m=>m.Reason=="too_late")
            ?incoming.ToDictionary(n=>n.Witness.NativeId,n=>n.Member.EntityFor(rule)??""):null;
        var membersByEntity=state.Window.ToLookup(m=>incomingEntities?.GetValueOrDefault(m.Witness.NativeId)??m.EntityFor(rule)??"",StringComparer.Ordinal);
        var incomingByEntity=incoming.ToLookup(n=>n.Member.EntityFor(rule)??"",StringComparer.Ordinal);
        var queued=new List<JsonObject>();var touched=new HashSet<string>(StringComparer.Ordinal);
        var reservations=new List<(PasswordEmission Emission,JsonObject[] Signals,JsonObject? Expected)>();
        var nextMembers=new List<PasswordMember>();var nextActive=new List<PasswordEpisode>();var nextClosed=new List<PasswordEpisode>();
        var counts=new Dictionary<string,int>(StringComparer.Ordinal);PasswordState? nextState=null;
        var work=windowBudget.Work;work["completion_calls"]=1;work["window_items"]=incoming.Length;
        foreach(string entityKey in entities.Concat(barriers.Keys).Append("").Distinct().Order(StringComparer.Ordinal)) {
            var entityIncoming=incomingByEntity[entityKey].ToArray();var budget=new NativeBudget(cachedByEntity[entityKey]);
            var entityState=state with{Members=membersByEntity[entityKey].ToArray(),Active=state.Episodes.Where(e=>e.Entity==entityKey).ToArray()};
            var working=entityState with{Active=episodes.TryGetValue(entityKey,out var active)?[active]:[]};
            var pending=entityIncoming.Select(n=>n.Member).Concat(entityState.Window).ToArray();
            var affected=pending.Where(m=>m.EntityFor(rule)!=null&&m.Witness.At<=final&&(!state.Watermark.HasValue||m.Witness.At>state.Watermark)).Select(m=>m.EntityFor(rule)!).ToHashSet(StringComparer.Ordinal);
            var entityBarriers=barriers.Where(p=>p.Key==entityKey).ToDictionary(p=>p.Key,p=>p.Value,StringComparer.Ordinal);
            var needed=new List<PasswordWitness>();var histories=new List<PasswordEmission>();var historySignals=new List<JsonObject>();
            foreach(var b in entityBarriers.Values){needed.Add(PasswordWitness.Read(b["seed"]));needed.Add(PasswordWitness.Read(b["tracking_endpoint"]));}
            foreach(var episode in working.Episodes){needed.Add(episode.Seed);needed.Add(episode.Last);needed.AddRange(episode.Prequalification);}
            needed.AddRange(entityState.Window.Where(m=>m.Witness.At>=lower).Select(m=>m.Witness));
            foreach(var episode in working.Episodes) {
                if(!affected.Contains(episode.Entity)||episode.Frozen)continue;
                if(episode.RootId!=null&&!(entityState.Watermark.HasValue&&lower>entityState.Watermark)) {
                    var added=pending.Where(m=>m.EntityFor(rule)==episode.Entity&&m.Witness.At<=final&&(!entityState.Watermark.HasValue||m.Witness.At>entityState.Watermark)).Select(m=>m.Witness).ToArray();
                    if(added.Length>0&&added.Min(w=>w.At)-episode.Last.At<=TimeSpan.FromSeconds(600)){var chain=await History(sql,rule,episode,historySignals,ct);histories.AddRange(chain);needed.AddRange(chain.SelectMany(e=>e.Occurrences));}
                }
            }
            needed.AddRange(entityState.Window.Where(m=>m.EntityFor(rule)!=null&&affected.Contains(m.EntityFor(rule)!)).Select(m=>m.Witness));
            try{budget.Plan(needed);}catch(PasswordFailure e)when(e.Message=="password_v2_proof_bound") {
                var denied=await QualifiedDenial(sql,rule,attempt,state,entityIncoming,budget,final,ct);if(denied!=null){budget.CompletionCalls++;return(denied,0,budget.Work);}throw;
            }
            await budget.Fetch(sql,rule.Scope,needed,ct,retainedWindow);
            foreach(var document in historySignals){var portion=PasswordJson.Obj(document["password_context"]);var chain=histories.Where(e=>e.EpisodeKey==PasswordJson.Text(portion["episode_key"])).OrderBy(e=>e.Sequence).ToArray();int sequence=portion["sequence"]!.GetValue<int>();var emission=chain.Single(e=>e.Sequence==sequence);
                if(!JsonNode.DeepEquals(document,PasswordSignal.Create(rule,emission,portion,PasswordJson.Time(document["received_at_utc"]),budget.Records.Values,chain.Where(e=>e.Sequence<sequence).ToArray())))throw new PasswordFailure("password_v2_chain_invalid");}
            foreach(var (entity,b) in entityBarriers)if(budget.Native(PasswordWitness.Read(b["seed"])).Member.EntityFor(rule)!=entity||budget.Native(PasswordWitness.Read(b["tracking_endpoint"])).Member.EntityFor(rule)!=entity)throw new PasswordFailure("password_v2_barrier_native_conflict");
            var entityIncomingIds=entityIncoming.Select(n=>n.Witness.NativeId).ToHashSet();var retained=budget.Records.Values.Where(n=>!entityIncomingIds.Contains(n.Witness.NativeId)).ToArray();
            var proposal=rule.Advance(working,entityIncoming,now,histories,retained,lower);
            if(proposal.State.Watermark!=final||proposal.Diagnostics.Any(p=>p.Value!=0&&!LossCodes.Contains(p.Key)))throw new PasswordFailure("password_v2_proposal_unavailable") {ProposalDiagnostics=proposal.Diagnostics,WatermarkMatches=proposal.State.Watermark==final,StateBytes=proposal.StateBytes};
            var nextEpisodes=proposal.State.Episodes.ToDictionary(e=>e.Entity,StringComparer.Ordinal);var emissions=proposal.Emissions.ToList();
            foreach(var (entity,b) in entityBarriers) {
                var frozen=BarrierEpisode(b);
                if(nextEpisodes.TryGetValue(entity,out var proposed)&&proposed.Key!=frozen.Key) {
                    if(b["tracking_epoch"]!.GetValue<long>()!=proposal.State.Epoch||lower>PasswordJson.Time(b["tracking_through"])||proposed.Seed.At<=frozen.Last.At.AddSeconds(600)) {
                        emissions.RemoveAll(e=>e.Entity==entity);var candidates=entityIncoming.Where(n=>n.Member.EntityFor(rule)==entity&&n.Witness.At<=final&&n.Witness.At>=frozen.Last.At).Select(n=>n.Witness).OrderBy(w=>w.At).ThenBy(w=>w.NativeId).ToArray();nextEpisodes[entity]=frozen with{Last=candidates.LastOrDefault()??frozen.Last};
                    }
                }else if(proposed==null)nextEpisodes[entity]=frozen;
            }
            var next=proposal.State with{Active=nextEpisodes.OrderBy(p=>p.Key,StringComparer.Ordinal).Select(p=>p.Value).ToArray()};
            if(next.Episodes.Any(e=>e.Frozen&&e.Sequence==0))throw new PasswordFailure("password_v2_frozen_zero_unsupported");
            if(emissions.Sum(e=>e.Occurrences.Count)>10000||emissions.Sum(e=>e.Occurrences.Sum(w=>w.XmlBytes))>33554432)throw new PasswordFailure("password_v2_proof_bound");
            touched.UnionWith(next.Episodes.Where(e=>e.Frozen).Select(e=>e.Key));
            var plannedHistory=histories.ToList();
            foreach(var emission in emissions) {
                var chain=plannedHistory.Where(h=>h.EpisodeKey==emission.EpisodeKey).OrderBy(h=>h.Sequence).ToArray();
                var signals=emission.Contexts(chain.FirstOrDefault()?.Id).Select(c=>PasswordSignal.Create(rule,emission,c,PasswordJson.Time(attempt["attempted_at"]),budget.Records.Values,chain)).ToArray();JsonObject? expected=null;
                if(emission.Sequence>1){if(chain.Length==0)throw new PasswordFailure("password_v2_continuity_state");expected=rule.VerifyChain(chain,budget.Records.Values).Document;expected["last_sequence"]=chain[^1].Sequence;expected["last_emission_id"]=chain[^1].Id;}
                reservations.Add((emission,signals,expected));
                plannedHistory.Add(emission);
            }
            nextState=next;nextMembers.AddRange(next.Window);nextActive.AddRange(next.Episodes);nextClosed.AddRange(next.ClosedAdmissions);
            foreach(var (code,count) in proposal.Diagnostics)
                counts[code]=code=="coverage_gap"?Math.Max(counts.GetValueOrDefault(code),count):counts.GetValueOrDefault(code)+count;
            var entityWork=budget.Work;
            foreach(string key in new[]{"native_items","xml_bytes"})work[key]=Math.Max(work[key]!.GetValue<int>(),entityWork[key]!.GetValue<int>());
            work["retained_queries"]=work["retained_queries"]!.GetValue<int>()+entityWork["retained_queries"]!.GetValue<int>();
        }
        var combined=nextState! with{Members=nextMembers.OrderBy(m=>m.Witness.At).ThenBy(m=>m.Witness.NativeId).ToArray(),Active=nextActive.OrderBy(e=>e.Entity,StringComparer.Ordinal).ToArray(),Closed=nextClosed.OrderBy(e=>e.Key,StringComparer.Ordinal).ToArray()};
        var fitted=combined.Fit(out int stateBytes);
        if(fitted==null)
            throw new PasswordFailure("password_v2_proposal_unavailable"){ProposalDiagnostics=new Dictionary<string,int>{{"state_bound",1}},WatermarkMatches=combined.Watermark==final,StateBytes=stateBytes};
        combined=fitted;
        // Plan every entity before staging any reservation: a qualified denial
        // must still complete against the untouched checkpoint and ledger.
        foreach(var (emission,signals,expected) in reservations) {
            if(barriers.TryGetValue(emission.Entity,out var b)&&emission.EpisodeKey!=PasswordJson.Text(b["episode_key"])) {
                var tracking=await sql.Call("track_password_frozen_entity_v2",ct,scope,execution,token,revision,PasswordJson.Text(b["episode_key"]),emission.Seed.Document,(long)emission.Epoch,lower,final);work["tracking_calls"]=work["tracking_calls"]!.GetValue<int>()+1;
                if(tracking?["status"]?.GetValue<string>()!="successor_authorized"||tracking["successor_episode_key"]?.GetValue<string>()!=emission.EpisodeKey)throw new PasswordFailure("password_v2_successor_conflict");
            }
            var reservation=await sql.Call("reserve_password_episode_emission",ct,scope,execution,token,revision,expected,PasswordJson.Array(signals,s=>s.DeepClone()));work["reservation_calls"]=work["reservation_calls"]!.GetValue<int>()+1;work["reservation_occurrences"]=work["reservation_occurrences"]!.GetValue<int>()+emission.Occurrences.Count;
            if(reservation?["status"]?.GetValue<string>()!="reserved"||!reservation["signal_ids"]!.AsArray().Select(PasswordJson.Text).SequenceEqual(signals.Select(PasswordSignal.Id)))throw new PasswordFailure("password_v2_reservation_conflict");
            queued.AddRange(signals);touched.Add(emission.EpisodeKey);
        }
        int jobs=0;foreach(var signal in queued)jobs+=await Enqueue(sql,rule,signal,ct);
        var diagnostics=new JsonObject();foreach(var (code,count) in counts)if(count!=0)diagnostics[code]=new JsonObject{["count"]=count,["from"]=PasswordJson.Stamp(lower),["to"]=PasswordJson.Stamp(final)};
        var completed=await Complete(sql,rule,attempt,"advance",new JsonObject{["version"]="sli.password.v2.producer-batch.1",["state"]=combined.Serialize(indexedState),["window"]=window,["diagnostics"]=diagnostics,["touched_episode_keys"]=PasswordJson.Array(touched.Order(StringComparer.Ordinal),e=>JsonValue.Create(e))},ct);
        if(retainedWindow!=null) {
            var keep=combined.Window.Select(m=>m.Witness.NativeId).ToHashSet();
            foreach(long id in retainedWindow.Keys.Where(id=>!keep.Contains(id)).ToArray())retainedWindow.Remove(id);
            foreach(var (id,native) in windowBudget.Records)if(keep.Contains(id))retainedWindow[id]=native;
        }
        work["watermark"]=PasswordJson.Stamp(final);return(completed,jobs,work);
    }

    internal static JsonObject ValidateWindow(JsonObject metadata,DateTimeOffset attempted,bool eventClock=false)
    {
        string[] keys=["version","read_from","read_to","finalizable_through","candidate_count","truncated","native_checked_count","native_checks_complete","unverifiable_count","oversized_count","error_code"];
        if(metadata.Count!=keys.Length||keys.Except(metadata.Select(p=>p.Key)).Any())throw new PasswordFailure("password_v2_window_invalid") {WindowCondition=PasswordFailure.WindowCheck.MetadataShape};
        foreach(string key in new[]{"candidate_count","native_checked_count","unverifiable_count","oversized_count"})if(metadata[key]!.GetValue<int>() is <0 or >10000)throw new PasswordFailure("password_v2_window_invalid") {WindowCondition=PasswordFailure.WindowCheck.CountBound};
        if(metadata["version"]?.GetValue<string>()!="sli.password.v2.window.1"||metadata["truncated"]!.GetValue<bool>()||!metadata["native_checks_complete"]!.GetValue<bool>()||metadata["error_code"]!=null||metadata["native_checked_count"]!.GetValue<int>()!=metadata["candidate_count"]!.GetValue<int>()||metadata["unverifiable_count"]!.GetValue<int>()!=0||metadata["oversized_count"]!.GetValue<int>()!=0)throw new PasswordFailure("password_v2_window_incomplete");
        var now=PasswordJson.Time(metadata["read_to"]);var lower=PasswordJson.Time(metadata["read_from"]);
        if(!eventClock&&now<attempted)throw new PasswordFailure("password_v2_window_invalid") {WindowCondition=PasswordFailure.WindowCheck.AttemptClock};
        if(!eventClock&&lower!=now.AddSeconds(-720)||eventClock&&(lower>now.AddSeconds(-720)||lower<now.AddSeconds(-2520)))throw new PasswordFailure("password_v2_window_invalid") {WindowCondition=PasswordFailure.WindowCheck.ReadFrom};
        if(PasswordJson.Time(metadata["finalizable_through"])!=now.AddSeconds(-120))throw new PasswordFailure("password_v2_window_invalid") {WindowCondition=PasswordFailure.WindowCheck.FinalizableThrough};
        var result=(JsonObject)metadata.DeepClone();foreach(string key in new[]{"read_from","read_to","finalizable_through"})result[key]=PasswordJson.Stamp(PasswordJson.Time(metadata[key]));return result;
    }
    private static PasswordNative ReadNative(PasswordScope scope,JsonObject row)=>PasswordNative.Parse(scope,row["source_event_id"]!.GetValue<long>(),PasswordJson.Text(row["sha256"]),row["event_id"]!.GetValue<int>(),PasswordJson.Time(row["occurred_at_utc"]),PasswordJson.Text(row["source_xml"]));
    private static PasswordEpisode BarrierEpisode(JsonObject b)=>new(PasswordJson.Text(b["episode_key"]),PasswordJson.Text(b["entity"]),PasswordWitness.Read(b["seed"]),PasswordWitness.Read(b["tracking_endpoint"]),PasswordJson.Text(b["root_id"]),PasswordJson.Text(b["last_emission_id"]),b["last_sequence"]!.GetValue<int>(),PasswordBudget.Read(b["totals"]),true);
    private static async Task<JsonObject> Complete(PasswordSql sql,PasswordRule rule,JsonObject attempt,string mode,JsonObject payload,CancellationToken ct)
    {
        long revision=attempt["state_revision"]!.GetValue<long>();var result=PasswordJson.Obj(await sql.Call("complete_password_producer_batch_v2",ct,rule.Scope.Document,rule.Execution,attempt["token"]!.GetValue<long>(),revision,mode,payload));
        if(result["status"]?.GetValue<string>()!="staged"||result["revision"]!.GetValue<long>()!=revision+1||result["health"] is not JsonObject)throw new PasswordFailure("password_v2_completion_invalid");return result;
    }
    private static async Task<IReadOnlyList<PasswordEmission>> History(PasswordSql sql,PasswordRule rule,PasswordEpisode episode,List<JsonObject> historySignals,CancellationToken ct)
    {
        var rows=await sql.Rows("select signal_id,document_json from public.read_password_episode_portions_v2(@s::jsonb,@e::jsonb,@key)",ct,("s",rule.Scope.Document),("e",rule.Execution),("key",episode.Key));
        if(rows.Count is <1 or >256)throw new PasswordFailure("password_v2_chain_unavailable");var emissions=new List<PasswordEmission>();var contexts=new List<JsonObject>();var documents=new List<JsonObject>();
        foreach(var row in rows) {
            var document=PasswordJson.Obj(row["document_json"]);var context=PasswordJson.Obj(document["password_context"]);
            if(PasswordSignal.Id(document)!=PasswordJson.Text(row["signal_id"])||document["episode_key"]?.GetValue<string>()!=episode.Key||context["sequence"]!.GetValue<int>()!=emissions.Count+1||context["portion_index"]!.GetValue<int>()!=contexts.Count)throw new PasswordFailure("password_v2_chain_invalid");
            contexts.Add(context);documents.Add(document);
            if(contexts.Count==context["portion_total"]!.GetValue<int>()) {
                var emission=PasswordEmission.Reassemble(rule.Scope,contexts);historySignals.AddRange(documents);
                emissions.Add(emission);contexts=[];documents=[];
            }
        }
        if(contexts.Count!=0||emissions.Count==0||emissions[^1].Id!=episode.LastEmission||emissions[^1].Sequence!=episode.Sequence||emissions[0].Id!=episode.RootId)throw new PasswordFailure("password_v2_chain_invalid");return emissions;
    }
    private static async Task<JsonObject?> QualifiedDenial(PasswordSql sql,PasswordRule rule,JsonObject attempt,PasswordState state,IReadOnlyList<PasswordNative> incoming,NativeBudget budget,DateTimeOffset final,CancellationToken ct)
    {
        foreach(var episode in state.Episodes) {
            if(episode.Sequence<=0||episode.Frozen)continue;var candidates=incoming.Where(n=>n.Member.EntityFor(rule)==episode.Entity&&n.Witness.At<=final&&(!state.Watermark.HasValue||n.Witness.At>state.Watermark)&&(n.Witness.At>episode.Last.At||n.Witness.At==episode.Last.At&&n.Witness.NativeId>episode.Last.NativeId)).OrderBy(n=>n.Witness.At).ThenBy(n=>n.Witness.NativeId).ToArray();
            if(candidates.Length==0||candidates[0].Witness.At-episode.Last.At>TimeSpan.FromSeconds(600))continue;var endpoint=candidates[0].Witness;
            try{await budget.Fetch(sql,rule.Scope,[episode.Last],ct);}catch(PasswordFailure){continue;}
            if(budget.Native(episode.Last).Member.EntityFor(rule)!=episode.Entity)throw new PasswordFailure("password_v2_native_content_conflict");
            if(episode.Budget.RefOccurrences+2<=10000&&episode.Budget.Portions+1<=256&&episode.Budget.XmlBytes+episode.Last.XmlBytes+endpoint.XmlBytes<=33554432)continue;
            return await Complete(sql,rule,attempt,"qualified_denial",new JsonObject{["version"]="sli.password.v2.producer-batch.1",["episode_key"]=episode.Key,["predecessor"]=episode.Last.Document,["endpoint"]=endpoint.Document},ct);
        }return null;
    }
    private static async Task<int> Enqueue(PasswordSql sql,PasswordRule rule,JsonObject signal,CancellationToken ct)
    {
        string sourceId=PasswordSignal.Id(signal);
        // Re-read the SQL-reserved immutable source before applying subscriptions.
        var source=await sql.Rows("select document_json,evaluation_mode from public.semantic_qw_signals where signal_id=@id",ct,("id",sourceId));
        if(source.Count!=1||PasswordSignal.Id(PasswordJson.Obj(source[0]["document_json"]))!=sourceId||source[0]["evaluation_mode"]?.GetValue<string>()!="enabled")throw new PasswordFailure("password_v2_queue_source_invalid");
        var policies=await sql.Rows("""
            select p.policy_id,p.policy_version,encode(p.definition_sha256,'hex') as policy_sha256
            from public.semantic_risk_policy_subscriptions s join public.semantic_risk_policies p
              on p.policy_id=s.policy_id and p.policy_version=s.policy_version and p.definition_sha256=s.definition_sha256
            where s.source_kind='qw_signal' and s.selector_value=@rule
              and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled'
              and p.policy_version=1 and p.definition_json#>'{source_selector,execution}'=@execution::jsonb
              and exists(select 1 from public.semantic_policy_admission a where a.policy_id=p.policy_id and a.policy_version=p.policy_version and a.enabled is true)
            order by p.policy_id,p.policy_version
            """,ct,("rule",rule.Id),("execution",rule.Execution));
        foreach(var policy in policies) {
            var identityDocument=new JsonObject{["policy_id"]=policy["policy_id"]!.DeepClone(),["policy_version"]=policy["policy_version"]!.DeepClone(),["policy_sha256"]=policy["policy_sha256"]!.DeepClone(),["source_kind"]="qw_signal",["source_id"]=sourceId,["evaluation_mode"]="enabled"};
            string identity=PasswordJson.Hash(identityDocument);Guid jobId=AuthAudit.Uuid5("adlog:risk-evaluation:"+identity);
            await sql.Execute("""
                insert into public.semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,source_reference,evaluation_mode,idempotency_key,qw_signal_id)
                values(@job,@policy,1,'qw_signal',@source,'enabled',@identity,@source) on conflict(idempotency_key) do nothing
                """,ct,("job",jobId),("policy",PasswordJson.Text(policy["policy_id"])),("source",sourceId),("identity",Convert.FromHexString(identity)));
            var existing=await sql.Rows("select job_id::text as job_id from public.semantic_risk_evaluation_jobs where idempotency_key=@identity",ct,("identity",Convert.FromHexString(identity)));
            if(existing.Count!=1||PasswordJson.Text(existing[0]["job_id"])!=jobId.ToString())throw new PasswordFailure("password_v2_queue_identity_conflict");
        }return policies.Count;
    }

    private sealed class NativeBudget
    {
        internal Dictionary<long,PasswordNative> Records {get;}=[];
        internal int Count=>Records.Count;private int bytes,retainedQueries;internal int CompletionCalls;
        internal JsonObject Work=>new(){["native_items"]=Count,["xml_bytes"]=bytes,["retained_queries"]=retainedQueries,["reservation_occurrences"]=0,["window_queries"]=1,["reservation_calls"]=0,["tracking_calls"]=0,["completion_calls"]=CompletionCalls};
        internal NativeBudget(IEnumerable<PasswordNative> incoming){foreach(var n in incoming)Add(n);}
        private void Add(PasswordNative native,PasswordWitness? expected=null)
        {
            if(expected!=null&&native.Witness!=expected)throw new PasswordFailure("password_v2_native_content_conflict");long id=native.Witness.NativeId;
            if(Records.TryGetValue(id,out var old)){if(native!=old)throw new PasswordFailure("password_v2_native_content_conflict");return;}
            if(Count+1>10000||bytes+native.Witness.XmlBytes>33554432)throw new PasswordFailure("password_v2_proof_bound");Records[id]=native;bytes+=native.Witness.XmlBytes;
        }
        internal IReadOnlyList<PasswordWitness> Plan(IEnumerable<PasswordWitness> witnesses)
        {
            var missing=new Dictionary<long,PasswordWitness>();foreach(var w in witnesses) {
                if(Records.TryGetValue(w.NativeId,out var old)){if(old.Witness!=w)throw new PasswordFailure("password_v2_native_content_conflict");}
                else if(missing.TryGetValue(w.NativeId,out var prior)&&prior!=w)throw new PasswordFailure("password_v2_native_content_conflict");else missing[w.NativeId]=w;
            }
            if(Count+missing.Count>10000||bytes+(long)missing.Values.Sum(w=>(long)w.XmlBytes)>33554432)throw new PasswordFailure("password_v2_proof_bound");return missing.Values.ToArray();
        }
        internal PasswordNative Native(PasswordWitness w)=>Records.TryGetValue(w.NativeId,out var n)&&n.Witness==w?n:throw new PasswordFailure("password_v2_native_unavailable");
        internal async Task Fetch(PasswordSql sql,PasswordScope scope,IEnumerable<PasswordWitness> witnesses,CancellationToken ct,IReadOnlyDictionary<long,PasswordNative>? cache=null)
        {
            var planned=Plan(witnesses);
            if(cache!=null)foreach(var w in planned)if(cache.TryGetValue(w.NativeId,out var native)&&native.Witness==w)Add(native,w);
            var missing=Plan(planned);if(missing.Count==0)return;
            var rows=await sql.Rows("select * from public.read_password_retained_proof_v2(@s::jsonb,@refs::jsonb)",ct,("s",scope.Document),("refs",PasswordJson.Array(missing,w=>w.Document)));retainedQueries++;
            if(rows.Count!=missing.Count)throw new PasswordFailure("password_v2_native_unavailable");
            for(int i=0;i<rows.Count;i++){var row=rows[i];if(row["occurrence_index"]!.GetValue<int>()!=i+1||row["source_event_id"]!.GetValue<long>()!=missing[i].NativeId)throw new PasswordFailure("password_v2_native_unavailable");var n=ReadNative(scope,row);if(row["xml_bytes"]!.GetValue<int>()!=n.Witness.XmlBytes||row["xml_sha256"]?.GetValue<string>()!=n.Witness.XmlSha256)throw new PasswordFailure("password_v2_native_content_conflict");Add(n,missing[i]);}
        }
    }
}

internal sealed class PasswordSql(NpgsqlConnection db,NpgsqlTransaction tx,DetectionDiagnostics? diagnostics=null)
{
    internal async Task<JsonNode?> Call(string name,CancellationToken ct,params object?[] args)
    {
        diagnostics?.Query(name+"(");SqlArguments.Validate(args);
        string[] types=name switch {
            "begin_password_attempt" or "read_password_checkpoint_v2"=>["jsonb","jsonb"],
            "prepare_password_producer_batch_v2"=>["jsonb","jsonb","bigint","bigint","text[]"],
            "reserve_password_episode_emission"=>["jsonb","jsonb","bigint","bigint","jsonb","jsonb"],
            "track_password_frozen_entity_v2"=>["jsonb","jsonb","bigint","bigint","text","jsonb","bigint","timestamptz","timestamptz"],
            "complete_password_producer_batch_v2"=>["jsonb","jsonb","bigint","bigint","text","jsonb"],
            "observe_password_failure_v2"=>["jsonb","jsonb","bigint","jsonb"],_=>throw new PasswordFailure("password_v2_call_invalid")};
        if(args.Length!=types.Length)throw new PasswordFailure("password_v2_call_invalid");
        SemanticWork.Query(db,name+"(");await using var cmd=new NpgsqlCommand("select public."+name+"("+string.Join(',',types.Select((t,i)=>"@p"+i+"::"+t))+")",db,tx){CommandTimeout=0};
        for(int i=0;i<args.Length;i++){if(args[i]==null)cmd.Parameters.AddWithValue("p"+i,NpgsqlDbType.Jsonb,DBNull.Value);else Add(cmd,"p"+i,args[i]!);}
        object? result=await cmd.ExecuteScalarAsync(ct);return result switch{null or DBNull=>null,bool b=>JsonValue.Create(b),string json=>JsonNode.Parse(json),_=>throw new PasswordFailure("password_v2_storage_unavailable")};
    }
    private static void Add(NpgsqlCommand cmd,string key,object value){if(value is JsonNode node)cmd.Parameters.AddWithValue(key,NpgsqlDbType.Jsonb,CanonicalJson.Serialize(node));else cmd.Parameters.AddWithValue(key,value);}
    internal async Task<List<JsonObject>> Rows(string query,CancellationToken ct,params (string,object)[] args)
    {
        diagnostics?.Query(query);SemanticWork.Query(db,query);await using var cmd=new NpgsqlCommand(query,db,tx){CommandTimeout=0};foreach(var (key,value) in args)Add(cmd,key,value);await using var reader=await cmd.ExecuteReaderAsync(ct);var rows=new List<JsonObject>();
        while(await reader.ReadAsync(ct)){if(rows.Count>=10001)throw new PasswordFailure("password_v2_reader_bound");var row=new JsonObject();for(int i=0;i<reader.FieldCount;i++){if(reader.IsDBNull(i)){row[reader.GetName(i)]=null;continue;}object value=reader.GetValue(i);row[reader.GetName(i)]=reader.GetDataTypeName(i) is "jsonb" or "json"?JsonNode.Parse((string)value):value switch{DateTime time=>JsonValue.Create(PasswordJson.Stamp(new DateTimeOffset(time))),long number=>JsonValue.Create(number),int number=>JsonValue.Create(number),bool flag=>JsonValue.Create(flag),string text=>JsonValue.Create(text),_=>throw new PasswordFailure("password_v2_reader_invalid")};}rows.Add(row);}return rows;
    }
    internal async Task Execute(string query,CancellationToken ct,params (string,object)[] args){diagnostics?.Query(query);SemanticWork.Query(db,query);await using var cmd=new NpgsqlCommand(query,db,tx){CommandTimeout=0};foreach(var (key,value) in args)Add(cmd,key,value);await cmd.ExecuteNonQueryAsync(ct);}
}
