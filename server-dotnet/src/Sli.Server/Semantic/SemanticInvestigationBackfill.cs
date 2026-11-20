using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Semantic;

// Retained sources only. Callers own the transaction/checkpoint persistence;
// no collectors, collection cursors, risk evaluation or finding publication.
internal static partial class SemanticInvestigationBackfill
{
    internal const int Contract = 1;
    internal const string Processor = "semantic-shadow", Assembler = "semantic-action-assembler", AssemblerVersion = "1.1";
    internal const string ManifestV1 = "retained_security_events_vocabulary_v1", ManifestV2 = "retained_security_events_vocabulary_v2";
    internal const string SupersedeReason = "routine_logons_are_exact_context_only", ContextStrategy = "successful_password_reset_same_domain_sid_within_1h";
    internal static readonly int[] HistoryEventIds = [4740,4767,4723,4724,4720,4722,4725,4726,4738,4781,4728,4729,4732,4733,4756,4757,4727,4730,4737,4731,4734,4735,4754,4755,4758,4764,4624,4625,4771,4776,4719,1102];
    internal static readonly int[] AnchorIds = [4625,4720,4724,4728,4729,4732,4733,4740,4756,4757,4767];
    internal static JsonObject SourceContract() => new()
    {
        ["authentication.session.created"] = new JsonArray(4624), ["authentication.session.failed"] = new JsonArray(4625),
        ["directory.account.created"] = new JsonArray(4720), ["account.password.reset.succeeded"] = new JsonArray(4724),
        ["group.member.added"] = new JsonArray(4728,4732,4756), ["group.member.removed"] = new JsonArray(4729,4733,4757),
        ["authentication.account.locked"] = new JsonArray(4740), ["authentication.account.unlocked"] = new JsonArray(4767)
    };
    internal static string Provider(int eventId) => HistoryEventIds.Contains(eventId) ? eventId == 1102 ? "Microsoft-Windows-Eventlog" : "Microsoft-Windows-Security-Auditing" : throw new ArgumentOutOfRangeException(nameof(eventId));
    private static JsonObject Predicate(int id) => new() { ["channel"]="Security", ["provider"]=Provider(id), ["event_id"]=id };
    private static JsonArray Numbers(IEnumerable<int> ids) => new(ids.Select(x => JsonValue.Create(x)).ToArray());
    private static string HashText(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static bool Sha(string? value) => value is not null && Regex.IsMatch(value, @"\A[0-9a-f]{64}\z");
    private static string SourceHash(string value) => Sha(value.ToLowerInvariant()) ? value.ToLowerInvariant() : throw new InvalidDataException("security history normalized hash is invalid");
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidDataException(message); }
    private static void Append(IncrementalHash hash, long id, string value) => hash.AppendData(Encoding.ASCII.GetBytes(FormattableString.Invariant($"{id}:{SourceHash(value)}\n")));
    internal static string CohortDigest(IEnumerable<(long Id, string Hash)> pairs)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); long previous = -1;
        foreach (var pair in pairs) { Require(pair.Id > previous, "security history cohort pairs must be strictly ordered"); previous=pair.Id; Append(hash,pair.Id,pair.Hash); }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
    private static int Page(int requested, int max = SemanticProducer.MaxBatch) => Math.Clamp(requested, 1, max);
    internal static async Task<long[]> SelectHistoryTargets(ISemanticSession session, int eventId, long after, long high, int limit, CancellationToken ct) =>
        (await new SemanticHistorySession(session).QueryAsync(SemanticInvestigationSql.HistoryTargets,ct,Provider(eventId),eventId,after,high,Contract,SemanticEvent.Normalizer,SemanticEvent.Version,Page(limit))).Select(x=>x.Number("id")).ToArray();

    internal static async Task<JsonObject> HistoryCohorts(ISemanticStreamingSession session, CancellationToken ct, IReadOnlyDictionary<int,long>? highWatermarks = null)
    {
        var cohorts = new JsonObject();
        foreach (int eventId in HistoryEventIds) {
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); long count=0, previous=-1; long? min=null,max=null;
            var args = new List<object?> { Provider(eventId),eventId };
            bool frozen = highWatermarks?.ContainsKey(eventId) == true; if(frozen) args.Add(highWatermarks![eventId]);
            string sql = "select core.id,encode(core.normalized_hash,'hex') as normalized_hash from semantic_event_rows core join storage_v2_channel channel on channel.id=core.channel_id join storage_v2_provider provider on provider.id=core.provider_id where channel.value='Security' and provider.value=$1 and core.event_id=$2 " + (frozen ? "and core.id<=$3 " : "") + "order by core.id";
            await foreach (var row in new SemanticHistorySession(session).StreamAsync(sql,ct,args.ToArray())) {
                long id=row.Number("id"); Require(id>previous,"security history cohort order is invalid"); previous=id;
                Append(digest,id,row.Text("normalized_hash")!); count++; min??=id; max=id;
            }
            cohorts[eventId.ToString()] = new JsonObject { ["high_watermark"]=max??0,["count"]=count,["cohort_digest"]=Convert.ToHexStringLower(digest.GetHashAndReset()),["min_id"]=min,["max_id"]=max };
        }
        return cohorts;
    }
    internal static async IAsyncEnumerable<(long Id,string Hash)> ContextPairs(ISemanticStreamingSession session,long after,long high,long resetHigh,bool residual,[System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var args = new List<object?> { "Security",Provider(4624),new int[]{4724},resetHigh,"Security",Provider(4724),after,high };
        string clause = "";
        if(residual) {
            args.AddRange([Contract,SemanticEvent.Normalizer,SemanticEvent.Version]);
            clause="and not exists (select 1 from normalized_events normalized where normalized.source_event_id=login.id and normalized.semantic_contract_version=$9 and normalized.normalizer_id=$10 and normalized.normalizer_version=$11 and normalized.processing_status='normalized' and normalized.source_event_sha256=login.normalized_hash and normalized.semantic_type<>'event.unknown')";
        }
        long previous=-1; string? hash=null; bool selected=false;
        await foreach(var row in new SemanticHistorySession(session).StreamAsync(SemanticInvestigationSql.ContextCandidates.Replace("{normalized_clause}",clause),ct,args.ToArray())) {
            long id=row.Number("source_event_id"); string current=SourceHash(row.Text("normalized_hash")!);
            Require(id>=previous,"security history context cohort order is invalid");
            if(id!=previous) { if(hash is not null && selected) yield return (previous,hash); previous=id; hash=current; selected=false; }
            string? sid=row.Text("login_target_user_sid");
            if(sid is {Length:<=184} && Regex.IsMatch(sid,@"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z") && sid==row.Text("reset_target_user_sid") && SemanticProducer.AuditOutcome(row.Text("reset_keywords"))=="success") selected=true;
        }
        if(hash is not null && selected) yield return (previous,hash);
    }
    internal static async Task<long[]> SelectContextTargets(ISemanticStreamingSession session,long after,long high,long resetHigh,int limit,CancellationToken ct)
    {
        var ids=new List<long>();
        await foreach(var pair in ContextPairs(session,after,high,resetHigh,true,ct)) { ids.Add(pair.Id); if(ids.Count>=Page(limit)) break; }
        return ids.ToArray();
    }
    internal static async Task<JsonObject> ContextCohort(ISemanticStreamingSession session,long high,long resetHigh,CancellationToken ct)
    {
        using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256); long count=0;
        await foreach(var pair in ContextPairs(session,0,high,resetHigh,false,ct)) { Append(hash,pair.Id,pair.Hash); count++; }
        return new() { ["count"]=count,["cohort_digest"]=Convert.ToHexStringLower(hash.GetHashAndReset()),["reset_high_watermark"]=resetHigh };
    }
    private static readonly string[] ReconciliationFields=["retained_count","normalized_count","normalization_failed","normalization_quarantined","outbox_queued","outbox_leased","outbox_completed","outbox_failed","outbox_quarantined","action_evidence_count"];
    internal static async Task<JsonObject> ReconcileContext(ISemanticStreamingSession session,long high,long resetHigh,CancellationToken ct)
    {
        var pairs=new List<(long Id,string Hash)>();
        // Finish the active source reader before reusing the same connection.
        await foreach(var pair in ContextPairs(session,0,high,resetHigh,false,ct)) pairs.Add(pair);
        return await ReconcilePairs(session,pairs,ct);
    }
    private static async Task<JsonObject> ReconcilePairs(ISemanticSession session,List<(long Id,string Hash)> pairs,CancellationToken ct)
    {
        var totals=new JsonObject(); foreach(string field in ReconciliationFields) totals[field]=0L;
        foreach(var page in pairs.Chunk(SemanticProducer.MaxBatch)) {
            var row=(await new SemanticHistorySession(session).QueryAsync(SemanticInvestigationSql.ContextAggregate,ct,Contract,SemanticEvent.Normalizer,SemanticEvent.Version,Contract,Processor,SemanticEvent.Version,page.Select(x=>x.Id).ToArray())).Single()!;
            Require(row.AsObject().Select(x=>x.Key).ToHashSet().SetEquals(ReconciliationFields),"security history context reconciliation row is invalid");
            foreach(string field in ReconciliationFields) totals[field]=totals.Number(field)+row.Number(field);
        }
        return totals;
    }
}
