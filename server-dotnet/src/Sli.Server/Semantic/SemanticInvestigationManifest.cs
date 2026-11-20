using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

internal static partial class SemanticInvestigationBackfill
{
    private static JsonObject FactsContract() => new() { ["semantic_contract_version"]=Contract,["normalizer_id"]=SemanticEvent.Normalizer,["normalizer_version"]=SemanticEvent.Version };
    private static JsonObject HistoryContract(JsonObject identity,int batch) => new() {
        ["database_identity"]=identity.Copy(),["runtime_mode"]="investigation-v1",["source"]="semantic_event_rows",
        ["semantic_contract_version"]=Contract,["normalizer"]=new JsonObject { ["id"]=SemanticEvent.Normalizer,["version"]=SemanticEvent.Version },
        ["assembler"]=new JsonObject { ["id"]=Assembler,["version"]=AssemblerVersion },["vocabulary"]=Numbers(HistoryEventIds),
        ["batch_limit"]=batch,["moves_collection_cursors"]=false,["contacts_sources"]=false
    };
    private static string SelectionFingerprint(int batch,bool v2)
    {
        var material=HistoryContract(new(),batch); material.Remove("database_identity");
        string v1=SemanticJson.Hash(material);
        return v2 ? SemanticJson.Hash(new JsonObject { ["v1_selection_fingerprint"]=v1,["manifest_type"]=ManifestV2,["logon_semantic_scope"]=ContextStrategy }) : v1;
    }
    private static JsonObject Identity(JsonObject identity)
    {
        var result=new JsonObject(); foreach(string key in new[]{"host","database","role"}) result[key]=identity.Text(key)??"";
        Require(result.All(x=>!string.IsNullOrEmpty(x.Value?.ToString())),"security history manifest identity is invalid"); return result;
    }
    private static JsonObject CohortEntry(int id,JsonNode? supplied)
    {
        long count=supplied.Number("count"), high=supplied.Number("high_watermark"); string digest=supplied.Text("cohort_digest")??CohortDigest([]);
        var min=supplied?["min_id"]; var max=supplied?["max_id"];
        Require(count>=0 && high>=0 && digest.Length==64,"security history cohort is invalid");
        if(count==0) { Require(min is null && max is null && high==0,"empty security history cohort is invalid"); digest=CohortDigest([]); }
        else Require(min is not null && max is not null && supplied.Number("min_id")<=supplied.Number("max_id") && supplied.Number("max_id")==high,"security history cohort bounds are invalid");
        return new() { ["predicate"]=Predicate(id),["high_watermark"]=high,["count"]=count,["cohort_digest"]=digest,["min_id"]=min.Copy(),["max_id"]=max.Copy(),
            ["cursor"]=0,["normalized_count"]=0,["outbox_count"]=0,["action_count"]=0,["state"]=count==0?"no_retained_events":"planned",["terminal_reason"]=count==0?"no_retained_events":null,
            ["samples"]=new JsonObject { ["incomplete_ids"]=new JsonArray(),["errors"]=new JsonArray() } };
    }
    internal static JsonObject NewManifest(JsonObject identity,string planDigest,JsonObject cohorts,int batch=SemanticProducer.MaxBatch)
    {
        Require(planDigest.Length==64,"security history manifest identity is invalid"); Require(batch is >=1 and <=SemanticProducer.MaxBatch,"security history batch limit is invalid");
        var result=HistoryContract(Identity(identity),batch); var events=new JsonObject();
        foreach(int id in HistoryEventIds) events[id.ToString()]=CohortEntry(id,cohorts[id.ToString()]);
        result["manifest_type"]=ManifestV1; result["created_at_utc"]=SemanticJson.Stamp(DateTimeOffset.UtcNow); result["updated_at_utc"]=result["created_at_utc"].Copy();
        result["plan_digest"]=planDigest; result["selection_fingerprint"]=SelectionFingerprint(batch,false); result["events"]=events; return result;
    }
    private static void ValidatePredecessor(JsonNode? predecessor)
    {
        if(predecessor is null) return;
        Require(predecessor is JsonObject && predecessor.Text("manifest_type")==ManifestV1 && predecessor.Text("reason")==SupersedeReason && Sha(predecessor.Text("plan_digest")?.ToLowerInvariant()),"security history v2 supersedes contract is invalid");
    }
    internal static JsonObject NewManifestV2(JsonObject identity,string digest,JsonObject cohorts,JsonObject context,JsonObject? supersedes)
    {
        var result=NewManifest(identity,digest,cohorts); ValidatePredecessor(supersedes);
        long count=context.Number("count"),resetHigh=context.Number("reset_high_watermark"); string contextDigest=context.Text("cohort_digest")??"";
        Require(count>=0 && contextDigest.Length==64 && resetHigh>=0,"security history v2 context cohort is invalid");
        Require(resetHigh==result["events"]!["4724"].Number("high_watermark"),"security history v2 reset context boundary is invalid");
        foreach(var pair in result["events"]!.AsObject()) {
            var entry=pair.Value!; long raw=entry.Number("count"); entry["raw_retained_count"]=raw; entry["raw_cohort_digest"]=entry["cohort_digest"].Copy();
            bool logon=pair.Key=="4624"; entry["semantic_scope"]=logon?"password_reset_context_only":"all_retained";
            entry["semantic_expected_count"]=logon?count:raw; entry["semantic_context_digest"]=logon?contextDigest:null;
            if(logon) { entry["semantic_context_reset_high_watermark"]=resetHigh; entry["count"]=count; entry["state"]=count==0?"no_retained_events":"planned"; entry["terminal_reason"]=count==0?"no_retained_events":null; }
        }
        result["manifest_type"]=ManifestV2; result["selection_fingerprint"]=SelectionFingerprint(SemanticProducer.MaxBatch,true); result["supersedes"]=supersedes.Copy(); result["semantic_context_strategy"]=ContextStrategy; return result;
    }
    private static readonly Dictionary<string,string> StateReasons=new() {
        ["no_retained_events"]="no_retained_events",["complete"]="current_version_normalized_hash_reconciled",["incomplete_original"]="frozen_original_integrity_mismatch",
        ["incomplete_normalization"]="current_version_non_unknown_normalization_missing",["blocked"]="operator_blocked_after_evidence",["failed"]="failed_current_version_work",["quarantined"]="quarantined_current_version_work"
    };
    internal static void ValidateManifest(JsonObject manifest,JsonObject identity,JsonObject? cohorts=null,string? planDigest=null)
    {
        int batch=(int)manifest.Number("batch_limit"); Require(batch is >=1 and <=SemanticProducer.MaxBatch,"security history manifest batch limit is invalid");
        string? type=manifest.Text("manifest_type"); Require(type is ManifestV1 or ManifestV2,"security history manifest type is invalid"); bool v2=type==ManifestV2;
        var expected=HistoryContract(Identity(identity),batch); expected["selection_fingerprint"]=SelectionFingerprint(batch,v2); if(planDigest is not null) expected["plan_digest"]=planDigest;
        Require(expected.All(x=>JsonNode.DeepEquals(manifest[x.Key],x.Value)),"security history manifest immutable contract changed");
        Require(manifest.Text("plan_digest")?.Length==64,"security history manifest plan digest is invalid");
        if(v2) { ValidatePredecessor(manifest["supersedes"]); Require(manifest.Text("semantic_context_strategy")==ContextStrategy,"security history v2 context strategy is invalid"); }
        Require(manifest["events"] is JsonObject,"security history manifest vocabulary is invalid"); var events=manifest["events"]!.AsObject();
        Require(events.Select(x=>x.Key).ToHashSet().SetEquals(HistoryEventIds.Select(x=>x.ToString())),"security history manifest vocabulary is invalid");
        foreach(int id in HistoryEventIds) {
            Require(events[id.ToString()] is JsonObject,"security history manifest cohort is invalid"); var entry=events[id.ToString()]!;
            if(cohorts is not null) {
                var observed=cohorts[id.ToString()]??CohortEntry(id,null);
                foreach(string field in new[]{"high_watermark","count","cohort_digest","min_id","max_id"}) {
                    string stored=v2 && field=="count"?"raw_retained_count":v2 && field=="cohort_digest"?"raw_cohort_digest":field;
                    Require(JsonNode.DeepEquals(entry[stored],observed[field]),"security history manifest frozen cohort changed");
                }
            }
            Require(JsonNode.DeepEquals(entry["predicate"],Predicate(id)),"security history manifest predicate is invalid");
            Require(entry.Number("cursor")>=0 && entry.Number("cursor")<=entry.Number("high_watermark"),"security history manifest cursor is invalid");
            string state=entry.Text("state")??""; bool progress=new[]{"planned","publishing","queued","processing"}.Contains(state);
            Require(progress||StateReasons.ContainsKey(state),"security history manifest state is invalid");
            Require(progress?entry["terminal_reason"] is null:entry.Text("terminal_reason")==StateReasons[state],"security history state reason is invalid");
            Require((entry.Number("count")==0)==(state=="no_retained_events"),"security history empty/nonempty cohort state is invalid");
            if(v2) {
                long raw=entry.Number("raw_retained_count"),semantic=entry.Number("semantic_expected_count"); Require(raw>=0 && semantic>=0 && semantic<=raw,"security history v2 semantic coverage is invalid");
                if(id==4624) Require(entry.Text("semantic_scope")=="password_reset_context_only" && entry.Text("semantic_context_digest")?.Length==64 && entry.Number("semantic_context_reset_high_watermark")>=0 && entry.Number("semantic_context_reset_high_watermark")==events["4724"].Number("high_watermark") && entry.Number("count")==semantic,"security history v2 logon context coverage is invalid");
                else Require(entry.Text("semantic_scope")=="all_retained" && semantic==raw && entry.Number("count")==raw && entry["semantic_context_digest"] is null,"security history v2 event semantic coverage is invalid");
            }
        }
    }
    internal static JsonObject NewCheckpoint(long high,string fingerprint,bool facts=true,long start=1,string? frozen=null)
    {
        Require(high>=0 && start>=1 && start<=high+1,"investigation checkpoint bounds are invalid");
        string suffix=facts?"event_id":"source_event_id";
        var result=new JsonObject { ["checkpoint_type"]=facts?"retained_semantic_investigation_facts_v1":"retained_semantic_investigation_relations_v1",["status"]="active",["source"]=facts?"semantic_event_rows":"normalized_events",
            ["created_at_utc"]=SemanticJson.Stamp(DateTimeOffset.UtcNow),["range_start_"+suffix]=start,["frozen_high_watermark_"+suffix]=high,["last_committed_"+suffix]=start-1,["rules_fingerprint"]=fingerprint,
            ["source_event_ids_by_semantic_type"]=SourceContract(),["batch_limit"]=100,["moves_collection_cursors"]=false,["contacts_sources"]=false };
        if(facts) { result["phase"]="anchors"; result["windows_event_ids"]=Numbers(AnchorIds); result["context_windows_event_ids"]=new JsonArray(4624); }
        else { result["facts_contract"]=FactsContract(); result["rule_ids"]=new JsonArray(SemanticRelations.RuleIds.Select(x=>JsonValue.Create(x)).ToArray()); result["frozen_normalized_at"]=frozen??SemanticJson.Stamp(DateTimeOffset.UtcNow); }
        return result;
    }
    internal static void ValidateCheckpoint(JsonObject checkpoint,string fingerprint,bool facts=true)
    {
        var expected=NewCheckpoint(0,fingerprint,facts); string suffix=facts?"event_id":"source_event_id";
        foreach(var pair in expected.Where(x=>x.Key is not ("created_at_utc" or "status" or "frozen_normalized_at") && x.Key!="range_start_"+suffix && x.Key!="frozen_high_watermark_"+suffix && x.Key!="last_committed_"+suffix)) {
            if(pair.Key=="phase") Require(checkpoint.Text("phase") is "anchors" or "context","investigation facts checkpoint phase is invalid");
            else Require(JsonNode.DeepEquals(checkpoint[pair.Key],pair.Value),"investigation checkpoint contract/fingerprint is invalid");
        }
        foreach(string key in new[]{"range_start_","frozen_high_watermark_","last_committed_"}) Require(checkpoint[key+suffix] is not null && long.TryParse(checkpoint[key+suffix]!.ToString(),out _),"investigation checkpoint bounds are invalid");
        long start=checkpoint.Number("range_start_"+suffix),high=checkpoint.Number("frozen_high_watermark_"+suffix),last=checkpoint.Number("last_committed_"+suffix);
        Require(high>=0 && start>=1 && start<=high+1 && last>=start-1 && last<=high,"investigation checkpoint bounds are invalid");
        if(!facts) Require(DateTimeOffset.TryParse(checkpoint.Text("frozen_normalized_at"),out _) && System.Text.RegularExpressions.Regex.IsMatch(checkpoint.Text("frozen_normalized_at")??"",@"(?:Z|[+-]\d{2}:\d{2})$"),"investigation checkpoint frozen time is invalid");
    }
    internal static void AdvanceFacts(JsonObject checkpoint,string phase,long[] targets,long high)
    {
        long next=targets.Length>0?targets[^1]:high; checkpoint["last_committed_event_id"]=next;
        if(next>=high && phase=="anchors") { checkpoint["phase"]="context"; checkpoint["last_committed_event_id"]=checkpoint.Number("range_start_event_id")-1; checkpoint["status"]="active"; }
        else checkpoint["status"]=next>=high?"complete":"active";
        checkpoint["updated_at_utc"]=SemanticJson.Stamp(DateTimeOffset.UtcNow);
    }
    internal static JsonObject ResumeCheckpoint(JsonObject checkpoint,JsonObject snapshot,string fingerprint,bool facts=true)
    {
        string suffix=facts?"event_id":"source_event_id"; long previous=checkpoint.Number("frozen_high_watermark_"+suffix),high=snapshot.Number(facts?"retained_fact_high_watermark_event_id":"high_watermark_source_event_id");
        if(checkpoint.Text("status")!="complete" || high<=previous) return checkpoint;
        var resumed=NewCheckpoint(high,fingerprint,facts,previous+1,snapshot.Text("frozen_normalized_at")); resumed["database_identity"]=snapshot["database_identity"].Copy();
        var ranges=checkpoint["completed_ranges"].Copy() as JsonArray??new(); var completed=new JsonObject { ["start"]=checkpoint.Number("range_start_"+suffix),["end"]=previous };
        if(ranges.Count==0 || !JsonNode.DeepEquals(ranges[^1],completed)) ranges.Add(completed); resumed["completed_ranges"]=ranges; return resumed;
    }
}
