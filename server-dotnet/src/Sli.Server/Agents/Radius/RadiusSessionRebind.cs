using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Server.Compatibility;
using Sli.Server.Vpn;

namespace Sli.Server.Agents.Radius;

public sealed record VerifiedRadiusEvidence(string EvidenceUid,string CanonicalRecord,string CanonicalRecordSha256)
{ public override string ToString()=>nameof(VerifiedRadiusEvidence); }
public sealed record ImmutableStoredRadiusObservation(string ObservationId,string EvidenceUid,string LifecycleEvent,string TimestampState,DateTimeOffset? ObservedAtUtc,string CanonicalRecordSha256);
public sealed class RadiusSessionRebindException(string code) : Exception(code)
{ public string Code { get; }=code; }
public sealed record RadiusSessionRebindResult(IReadOnlyList<JsonObject> Sessions,int InputObservations,int ExactReadyObservations);

// Pure counterpart of server/source_packs/radius/session_rebind.py. The caller
// supplies verified local evidence and the current identity spine, never old keys.
public static class RadiusSessionRebind
{
    public static async Task<RadiusSessionRebindResult> BuildAsync(
        IEnumerable<VerifiedRadiusEvidence> evidenceRecords,
        IEnumerable<ImmutableStoredRadiusObservation> storedObservations,
        string sourceInstanceId,string organizationFqdn,string sourceTimezoneId,int sourceUtcOffsetMinutes,
        Func<string,string,Task<string?>> exactLookup)
    {
        var records=evidenceRecords.ToArray();var stored=storedObservations.ToArray();
        if(records.Length==0) throw new RadiusSessionRebindException("rebind_evidence_count_invalid");
        if(stored.Length==0) throw new RadiusSessionRebindException("rebind_observation_count_invalid");
        var byUid=new Dictionary<string,VerifiedRadiusEvidence>(StringComparer.Ordinal);
        var accepts=new List<VerifiedRadiusEvidence>();
        foreach(var item in records)
        {
            string uid=item.EvidenceUid.Trim().ToLowerInvariant();
            if(uid.Length==0 || !byUid.TryAdd(uid,item)) throw new RadiusSessionRebindException("rebind_evidence_identity_invalid");
            var fields=RadiusAccountingRecord.ParseFields(item.CanonicalRecord);
            string hash=Convert.ToHexStringLower(SHA256.HashData(new UTF8Encoding(false,true).GetBytes(item.CanonicalRecord)));
            if(hash!=item.CanonicalRecordSha256.ToLowerInvariant()) throw new RadiusSessionRebindException("rebind_evidence_hash_mismatch");
            if(PythonInt.TryParse(PythonText.Strip(fields[4]),out var packet) && packet==2) accepts.Add(item);
        }
        var seen=new HashSet<string>(StringComparer.Ordinal);
        foreach(var item in stored)
        {
            string id=item.ObservationId.Trim();
            if(id.Length==0 || !seen.Add(id)) throw new RadiusSessionRebindException("rebind_observation_identity_invalid");
            if(!byUid.TryGetValue(item.EvidenceUid.Trim().ToLowerInvariant(),out var evidence)) throw new RadiusSessionRebindException("rebind_observation_evidence_missing");
            if(!string.Equals(evidence.CanonicalRecordSha256,item.CanonicalRecordSha256,StringComparison.OrdinalIgnoreCase)) throw new RadiusSessionRebindException("rebind_evidence_hash_mismatch");
        }

        // Resolve every Access-Accept before accounting, independent of evidence order.
        // This is a rebuild, so the live ingest cache and its previous keys are absent.
        var cache=new Dictionary<string,(string Principal,DateTimeOffset Expires)>(StringComparer.Ordinal);
        Task<string?> Resolve(string dn)=>RadiusIdentity.ResolveAsync(dn,organizationFqdn,exactLookup);
        async Task<RadiusPlan> Project(string line,Func<string,Task<string?>> resolve)=>await RadiusPlanner.ProjectAsync(
            [line],sourceInstanceId,sourceTimezoneId,sourceUtcOffsetMinutes,DateTimeOffset.UnixEpoch,cache,resolve);
        foreach(var item in accepts)
        {
            var plan=await Project(item.CanonicalRecord,Resolve);
            foreach(var (key,value) in plan.Cache)
            {
                if(cache.TryGetValue(key,out var prior) && prior.Principal!=value.Principal) throw new RadiusSessionRebindException("rebind_class_identity_conflict");
                cache[key]=value;
            }
        }
        var rebound=new List<JsonObject>();int exactReady=0;
        foreach(var item in stored)
        {
            var evidence=byUid[item.EvidenceUid.Trim().ToLowerInvariant()];
            var plan=await Project(evidence.CanonicalRecord,_=>Task.FromResult<string?>(null));
            if(plan.Observations.Count!=1) throw new RadiusSessionRebindException("rebind_session_observation_required");
            var rebuilt=plan.Observations[0];
            if(rebuilt.Lifecycle!=item.LifecycleEvent) throw new RadiusSessionRebindException("rebind_lifecycle_mismatch");
            if(item.TimestampState!="ready") throw new RadiusSessionRebindException("rebind_timestamp_state_mismatch");
            if(rebuilt.ObservedAt!=item.ObservedAtUtc) throw new RadiusSessionRebindException("rebind_timestamp_mismatch");
            bool exact=rebuilt.Principal is not null && rebuilt.SessionIdentityKey is not null;
            if(exact) exactReady++;
            rebound.Add(new JsonObject {
                ["observation_id"]=item.ObservationId.Trim(),["lifecycle_event"]=rebuilt.Lifecycle,
                ["identity_state"]=exact?"exact":"unresolved",["timestamp_state"]="ready",
                ["session_identity_key"]=exact?rebuilt.SessionIdentityKey:null,["exact_principal_key"]=exact?rebuilt.Principal:null,
                ["observed_at_utc"]=rebuilt.ObservedAt.ToString("O"),["canonical_record_sha256"]=rebuilt.RecordHash
            });
        }
        return new(RadiusSessionFold.Fold(rebound),stored.Length,exactReady);
    }
}
