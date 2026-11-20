using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

internal static partial class SemanticInvestigationBackfill
{
    internal static JsonObject[] SelectedRules()
    {
        using var stream=typeof(SemanticProduction).Assembly.GetManifestResourceStream("Sli.Server.Semantic.chain_pack.json")!;
        var byId=JsonNode.Parse(stream)!["rules"]!.AsArray().GroupBy(x=>x.Text("rule_id")!).ToDictionary(x=>x.Key,x=>x.Last()!);
        Require(SemanticRelations.RuleIds.All(byId.ContainsKey),"investigation rule pack is incomplete");
        return SemanticRelations.RuleIds.Select(id=>new JsonObject { ["rule_id"]=id,["rule_version"]=byId[id]["rule_version"].Copy(),["rule_kind"]=byId[id]["rule_kind"].Copy(),["definition_json"]=byId[id]["definition"].Copy(),["definition_sha256"]=SemanticJson.Hash(byId[id]["definition"]) }).ToArray();
    }
    internal static string RulesFingerprint() => SemanticJson.Hash(new JsonObject { ["facts_contract"]=FactsContract(),["source_event_ids_by_semantic_type"]=SourceContract(),
        ["rules"]=new JsonArray(SelectedRules().Select(row=>(JsonNode)new JsonObject { ["rule_id"]=row["rule_id"].Copy(),["rule_version"]=row["rule_version"].Copy(),["rule_kind"]=row["rule_kind"].Copy(),["definition"]=row["definition_json"].Copy() }).ToArray()) });
    internal static bool RulesReady(JsonArray rows)
    {
        foreach(var (id,pin) in SemanticProduction.ReadInvestigationRules()) {
            var exact=rows.Where(x=>x.Text("rule_id")==id && x.Number("rule_version")==pin.Item1 && x.Text("definition_sha256")==pin.Item2).ToArray();
            if(exact.Length!=1 || exact[0].Text("lifecycle_status")!="shadow" || rows.Any(x=>x.Text("rule_id")==id && !ReferenceEquals(x,exact[0]) && x.Text("lifecycle_status") is "test" or "shadow" or "enabled")) return false;
        }
        return true;
    }
    internal static Task<JsonArray> SelectFactTargets(ISemanticSession session,long after,long high,int limit,string phase,CancellationToken ct) => phase switch {
        "anchors"=>new SemanticHistorySession(session).QueryAsync(SemanticInvestigationSql.FactAnchors,ct,after,high,AnchorIds,Page(limit,100)),
        "context"=>new SemanticHistorySession(session).QueryAsync(SemanticInvestigationSql.FactContext,ct,Contract,SemanticEvent.Normalizer,SemanticEvent.Version,4724,after,high,new int[]{4624},Page(limit,100)),
        _=>throw new InvalidDataException("investigation facts phase is invalid")
    };
    internal static Task<JsonArray> SelectRelationTargets(ISemanticSession session,long after,long high,int limit,DateTimeOffset frozen,CancellationToken ct)
    {
        var pairs=SourceContract().SelectMany(pair=>pair.Value!.AsArray().Select(id=>(Type:pair.Key,Id:id!.GetValue<int>()))).ToArray();
        var inputs=SelectedRules().SelectMany(x=>SemanticCorrelation.Compile(x).Inputs).Distinct().Order(StringComparer.Ordinal).ToArray();
        return new SemanticHistorySession(session).QueryAsync(SemanticInvestigationSql.RelationTargets,ct,pairs.Select(x=>x.Type).ToArray(),pairs.Select(x=>x.Id).ToArray(),Contract,SemanticEvent.Normalizer,SemanticEvent.Version,frozen,after,high,inputs,4724,Contract,SemanticEvent.Normalizer,SemanticEvent.Version,frozen,Page(limit,100));
    }
    internal static async Task<JsonObject> FactsCompletion(ISemanticSession session,long[] ids,CancellationToken ct)
    {
        var requested=ids.Distinct().Order().ToArray();
        var rows=requested.Length==0?new JsonArray():await session.QueryAsync(SemanticInvestigationSql.FactsCompletion,ct,requested,Contract,SemanticEvent.Normalizer,SemanticEvent.Version,Contract,Processor,SemanticEvent.Version);
        var byId=rows.GroupBy(x=>x.Number("source_event_id")).ToDictionary(x=>x.Key,x=>x.ToArray());
        var counters=new JsonObject { ["queued"]=0,["leased"]=0,["failed"]=0,["quarantined"]=0,["not_enqueued"]=0,["inconsistent_completed"]=0 }; var unresolved=new JsonArray(); int completed=0;
        foreach(long id in requested) {
            var matches=byId.GetValueOrDefault(id)??[]; var row=matches.Length==1?matches[0]:null; string? status=row.Text("outbox_status");
            if(row.Text("processing_status") is "normalized" or "ignored" && status=="completed") { completed++; continue; }
            unresolved.Add(id); string counter=status is "queued" or "leased" or "failed" or "quarantined"?status:status=="completed"?"inconsistent_completed":"not_enqueued"; counters[counter]=counters.Number(counter)+1;
        }
        counters["state"]=completed==requested.Length?"processed":counters.Number("not_enqueued")==requested.Length?"no_admitted_events":"pending";
        counters["requested"]=requested.Length; counters["completed"]=completed; counters["unresolved_event_ids"]=unresolved; return counters;
    }
    // processExact uses the existing producer/outbox worker. The controller only
    // advances after it independently verifies every exact current-version job.
    internal static async Task<JsonObject> PollFacts(ISemanticSession session,JsonObject checkpoint,string fingerprint,Func<long[],CancellationToken,Task> processExact,CancellationToken ct)
    {
        ValidateCheckpoint(checkpoint,fingerprint); string phase=checkpoint.Text("phase")!; long high=checkpoint.Number("frozen_high_watermark_event_id");
        var targets=(await SelectFactTargets(session,checkpoint.Number("last_committed_event_id"),high,100,phase,ct)).Select(x=>x.Number("id")).ToArray();
        if(targets.Length>0) await processExact(targets,ct);
        var verification=await FactsCompletion(session,targets,ct);
        bool ready=verification.Text("state")=="processed"; if(ready) AdvanceFacts(checkpoint,phase,targets,high);
        return new() { ["status"]=ready?checkpoint.Text("status"):"blocked_batch",["checkpoint"]=checkpoint.Copy(),["target_events"]=targets.Length,["verification"]=verification,["source_contacted"]=false,["collection_cursors_changed"]=false,["risk_evaluated"]=false,["findings_created"]=0 };
    }
    internal static async Task<JsonObject> Activate(ISemanticSession session,CancellationToken ct)
    {
        var ledger=await session.QueryAsync("select exists(select 1 from schema_migrations where version=138 and name='normalized_event_versioned_identity') as ready",ct);
        Require(ledger.Single().Flag("ready"),"migration 138 is required before investigation activation");
        await session.QueryAsync("set local role adlog_storage_worker",ct);
        var statuses=new JsonObject();
        foreach(var row in SelectedRules()) {
            var rule=SemanticCorrelation.Compile(row); var hash=Convert.FromHexString(rule.Sha);
            var existing=await session.QueryAsync("select lifecycle_status from semantic_correlation_rules where rule_id=$1 and rule_version=$2 for update",ct,rule.Id,rule.Version);
            string? current=existing.SingleOrDefault().Text("lifecycle_status");
            Require(current is not ("enabled" or "deprecated"),"investigation rule is unexpectedly enabled or deprecated");
            if(current=="disabled") { await TransitionRule(session,rule.Id,rule.Version,current,"draft",ct); current="draft"; }
            await session.QueryAsync("insert into semantic_correlation_rules(rule_id,rule_version,rule_kind,lifecycle_status,definition_json,definition_sha256) values($1,$2,$3,'draft',$4,$5) on conflict(rule_id,rule_version) do nothing",ct,rule.Id,rule.Version,rule.Kind,row["definition_json"].Copy(),hash);
            var stored=(await session.QueryAsync("select rule_kind,lifecycle_status,definition_json,encode(definition_sha256,'hex') as definition_sha256 from semantic_correlation_rules where rule_id=$1 and rule_version=$2 for update",ct,rule.Id,rule.Version)).Single()!;
            Require(stored.Text("rule_kind")==rule.Kind && stored.Text("definition_sha256")==rule.Sha && JsonNode.DeepEquals(stored["definition_json"],row["definition_json"]),"correlation rule version replay conflict");
            current=stored.Text("lifecycle_status");
            if(current=="draft") {
                await session.QueryAsync("delete from semantic_correlation_subscriptions where rule_id=$1 and rule_version=$2",ct,rule.Id,rule.Version);
                for(int i=0;i<rule.Inputs.Length;i++) await session.QueryAsync("insert into semantic_correlation_subscriptions(rule_id,rule_version,semantic_type,subscription_order,definition_sha256) values($1,$2,$3,$4,$5)",ct,rule.Id,rule.Version,rule.Inputs[i],i,hash);
            }
            var subscriptions=await session.QueryAsync("select semantic_type,subscription_order,encode(definition_sha256,'hex') as definition_sha256 from semantic_correlation_subscriptions where rule_id=$1 and rule_version=$2 order by subscription_order",ct,rule.Id,rule.Version);
            Require(subscriptions.Count==rule.Inputs.Length && subscriptions.Select((s,i)=>s.Text("semantic_type")==rule.Inputs[i] && s.Number("subscription_order")==i && s.Text("definition_sha256")==rule.Sha).All(x=>x),"investigation rule subscriptions differ from accepted definition");
            foreach(var (from,to) in new[]{("draft","validated"),("validated","test"),("test","shadow")}) if(current==from) { await TransitionRule(session,rule.Id,rule.Version,from,to,ct); current=to; }
            Require(current=="shadow","investigation rule did not stop at shadow");
            if(rule.Continuation=="anchor_all_admissible") await RetireSuperseded(session,rule.Id,rule.Version,ct);
            statuses[rule.Id]=current;
        }
        return statuses;
    }
    private static async Task TransitionRule(ISemanticSession session,string id,int version,string from,string to,CancellationToken ct)
    {
        var changed=await session.QueryAsync("update semantic_correlation_rules set lifecycle_status=$1,updated_at=now() where rule_id=$2 and rule_version=$3 and lifecycle_status=$4 returning lifecycle_status",ct,to,id,version,from);
        Require(changed.Count==1,"correlation rule lifecycle changed concurrently");
    }
    internal static async Task RetireSuperseded(ISemanticSession session,string id,int version,CancellationToken ct)
    {
        var rows=await session.QueryAsync("select rule_version,lifecycle_status from semantic_correlation_rules where rule_id=$1 and rule_version<$2 and lifecycle_status in ('draft','validated','test','shadow','enabled','disabled') order by rule_version for update",ct,id,version);
        foreach(var row in rows) {
            string current=row.Text("lifecycle_status")!; int old=(int)row.Number("rule_version");
            if(current is "draft" or "validated" or "test") { await TransitionRule(session,id,old,current,"disabled",ct); current="disabled"; }
            Require(current is "shadow" or "enabled" or "disabled","superseded investigation rule has invalid lifecycle");
            await TransitionRule(session,id,old,current,"deprecated",ct);
        }
    }
}
