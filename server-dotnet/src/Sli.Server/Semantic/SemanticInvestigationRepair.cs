using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

internal static partial class SemanticInvestigationBackfill
{
    internal static string ClassifyRepair(JsonNode row,string sourceHash,string historyDigest,string? repairDigest=null)
    {
        string S(string key)=>row.Text(key)??"";
        string H(string key)=>S(key).ToLowerInvariant();
        bool original=row.Number("original_job_count")==1 && S("original_status")=="quarantined" && row.Number("original_attempt_count")>0 && row.Number("original_attempt_count")==row.Number("original_max_attempts")
            && S("original_error_code")=="UniqueViolation" && S("original_error_detail").Contains("\"canonical_actions_pkey\"",StringComparison.Ordinal) && Sha(S("original_error_detail_sha256")) && H("original_source_hash")==sourceHash && !string.IsNullOrWhiteSpace(S("original_job_id"));
        long count=row.Number("repair_job_count"); if(count==0) return original?"absent":"conflict";
        string status=S("repair_status");
        bool repair=count==1 && new[]{"queued","leased","completed","failed","quarantined"}.Contains(status) && row.Number("repair_semantic_contract_version")==Contract
            && H("repair_source_hash")==sourceHash && H("repair_payload_source_hash")==sourceHash && S("repair_original_job_id")==S("original_job_id") && H("repair_history_plan_digest")==historyDigest
            && Sha(S("repair_plan_digest")) && (repairDigest is null || H("repair_plan_digest")==repairDigest.ToLowerInvariant()) && H("repair_original_error_detail_sha256")==H("original_error_detail_sha256")
            && row["repair_original_attempt_count"] is not null && row["repair_original_max_attempts"] is not null && row.Number("repair_original_attempt_count")==row.Number("original_attempt_count") && row.Number("repair_original_max_attempts")==row.Number("original_max_attempts")
            && S("repair_original_error_code")=="UniqueViolation" && S("repair_processor_id")==Processor && S("repair_processor_version")==SemanticEvent.Version;
        bool proof=row.Number("normalized_current_count")==1 && row.Number("normalized_proof_count")==1 && row.Number("normalized_action_count")==1 && H("normalized_proof_hash")==sourceHash;
        if(!original || !repair) return "conflict";
        if(status=="completed") return proof?"completed":"conflict";
        return row.Number("normalized_current_count")!=0?"conflict":status;
    }
    internal sealed record ContextReconciliation(JsonObject Current,JsonObject RepairStates);
    internal static async Task<ContextReconciliation> ReconcileV2Context(ISemanticStreamingSession session,long high,long resetHigh,string historyDigest,CancellationToken ct)
    {
        var pairs=new List<(long Id,string Hash)>(); await foreach(var pair in ContextPairs(session,0,high,resetHigh,false,ct)) pairs.Add(pair);
        var current=await ReconcilePairs(session,pairs,ct); var states=new JsonObject(); foreach(string state in new[]{"absent","queued","leased","completed","failed","quarantined","conflict"}) states[state]=0L;
        foreach(var page in pairs.Chunk(SemanticProducer.MaxBatch)) {
            var rows=await session.QueryAsync(SemanticInvestigationSql.RepairRows,ct,page.Select(x=>x.Id).ToArray(),page.Select(x=>x.Hash).ToArray(),Contract,Processor,SemanticEvent.Version,Contract,SemanticEvent.Normalizer,SemanticEvent.Version);
            Require(rows.Count==page.Length && rows.Select(x=>x.Number("source_event_id")).ToHashSet().SetEquals(page.Select(x=>x.Id)),"security history v2 repair reconciliation is incomplete");
            var hashes=page.ToDictionary(x=>x.Id,x=>x.Hash);
            foreach(var row in rows) {
                Require(row.Text("source_hash")==hashes[row.Number("source_event_id")],"security history v2 repair reconciliation source changed");
                row!["original_error_detail_sha256"]=HashText(row.Text("original_error_detail")??"");
                string state=ClassifyRepair(row,hashes[row.Number("source_event_id")],historyDigest.ToLowerInvariant()); states[state]=states.Number(state)+1;
            }
        }
        return new(current,states);
    }
    internal static string RecoveryConfirmation(string digest) { Require(Sha(digest),"investigation recovery digest is invalid"); return "RECOVER-INVESTIGATION-DISPATCH-"+digest[..16].ToUpperInvariant(); }
    internal static void RecoveryAdmission(string digest,string confirmation,Func<string,string?> get)
    {
        Require(confirmation==RecoveryConfirmation(digest),"investigation recovery confirmation mismatch");
        Require(!SemanticRuntimeSettings.Enabled(get("ADLOG_SEMANTIC_PRODUCTION_ENABLED")),"semantic production must be disabled before quarantine recovery");
    }
    internal static async Task<JsonArray> RecoveryCandidates(ISemanticSession session,DateTimeOffset frozen,long high,CancellationToken ct,bool forUpdate=false)
    {
        Require(high>=0,"investigation recovery high watermark is invalid");
        var args=new List<object?> { "InsufficientPrivilege","%semantic_correlation_rules%",frozen,high }; var arms=new List<string>();
        var pins=SemanticProduction.ReadInvestigationRules();
        foreach(string id in SemanticRelations.RuleIds) { var (version,sha)=pins[id]; int n=args.Count; args.AddRange([id,version,Convert.FromHexString(sha)]); arms.Add($"(rule.rule_id=${n+1} and rule.rule_version=${n+2} and rule.definition_sha256=${n+3})"); }
        args.Add(1025);
        string sql=SemanticInvestigationSql.RecoveryCandidates.Replace("{exact_rules}",string.Join(" or ",arms)).Replace("{job_filter}","").Replace("limit $5","limit $"+args.Count).Replace("{lock_clause}",forUpdate?"for update of job":"");
        var rows=await session.QueryAsync(sql,ct,args.ToArray()); Require(rows.Count<=1024,"investigation recovery candidate set exceeds bound"); var seen=new HashSet<Guid>();
        foreach(var row in rows) {
            Require(Guid.TryParse(row.Text("job_id"),out var id) && seen.Add(id) && pins.TryGetValue(row.Text("rule_id")??"",out var pin) && row.Number("rule_version")==pin.Item1 && row.Text("definition_sha256")==pin.Item2
                && DateTimeOffset.Parse(row.Text("normalized_at")!)<=frozen && row.Number("source_event_id")<=high && row.Text("dispatch_status")=="quarantined" && row.Number("attempt_count")>=row.Number("max_attempts")
                && row.Text("last_error_code")=="InsufficientPrivilege" && (row.Text("last_error_detail")??"").Contains("semantic_correlation_rules",StringComparison.OrdinalIgnoreCase),"investigation recovery candidate is invalid");
        }
        return rows;
    }
    // Match Python datetime.isoformat() for the plan digest, including its UTC offset.
    private static string RecoveryTime(string value)
    {
        var time=DateTimeOffset.Parse(value); return time.ToString(time.Ticks%TimeSpan.TicksPerSecond==0?"yyyy-MM-dd'T'HH:mm:sszzz":"yyyy-MM-dd'T'HH:mm:ss.ffffffzzz",System.Globalization.CultureInfo.InvariantCulture);
    }
    internal static string RecoveryDigest(JsonArray candidates,JsonObject identity,DateTimeOffset frozen,long high)
    {
        var jobs=new JsonArray();
        foreach(var row in candidates.OrderBy(x=>x.Text("job_id"),StringComparer.Ordinal)) {
            var job=new JsonObject(); foreach(string key in new[]{"source_event_id","rule_id","rule_version","definition_sha256","dispatch_status","attempt_count","max_attempts","last_error_code"}) job[key]=row![key].Copy();
            job["job_id"]=Guid.Parse(row.Text("job_id")!).ToString(); job["normalized_event_id"]=Guid.Parse(row.Text("normalized_event_id")!).ToString(); job["normalized_at"]=RecoveryTime(row.Text("normalized_at")!); job["last_error_detail_sha256"]=HashText(row.Text("last_error_detail")??""); jobs.Add(job);
        }
        return SemanticJson.Hash(new JsonObject { ["contract"]="semantic_investigation_acl_quarantine_recovery_v1",["database_identity"]=Identity(identity),["frozen_normalized_at"]=RecoveryTime(frozen.ToString("O")),["high_watermark_source_event_id"]=high,["jobs"]=jobs });
    }
    internal static async Task<string[]> RecoverDispatch(ISemanticDatabase database,string digest,string confirmation,JsonObject identity,DateTimeOffset frozen,long high,Func<string,string?> get,CancellationToken ct)
    {
        RecoveryAdmission(digest,confirmation,get); // Before opening any database connection.
        await using var session=await database.OpenAsync(true,ct);
        var candidates=await RecoveryCandidates(session,frozen,high,ct,true);
        Require(RecoveryDigest(candidates,identity,frozen,high)==digest.ToLowerInvariant(),"investigation recovery candidate set changed");
        var ids=candidates.Select(x=>Guid.Parse(x.Text("job_id")!)).Order().ToArray();
        if(ids.Length==0) return [];
        var rows=await session.QueryAsync(SemanticInvestigationSql.Recover,ct,ids,"InsufficientPrivilege","%semantic_correlation_rules%");
        Require(rows.Select(x=>Guid.Parse(x.Text("job_id")!)).Order().SequenceEqual(ids),"investigation recovery update set changed");
        await session.CommitAsync(ct); return ids.Select(x=>x.ToString()).ToArray();
    }
}
