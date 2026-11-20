using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Vpn;

public sealed record RadiusSessionFoldResult(IReadOnlyList<JsonObject> Sessions, int InputObservations,
    int ExactReadyObservations, int UnresolvedIdentityObservations, int UnresolvedTimestampObservations,
    int CompleteSessions, int PartialSessions, int OpenObservedSessions)
{
    public string ContractId => "sli.radius-session-read-model.v1";
}

// Canonical Accounting fold; NPS authorizations never supply lifecycle facts.
public static class RadiusSessionFold
{
    public const string ContractId = "sli.radius-session-read-model.v1";

    public static IReadOnlyList<JsonObject> Fold(IEnumerable<JsonObject> observations) => FoldWithCoverage(observations).Sessions;

    public static RadiusSessionFoldResult FoldWithSummary(IEnumerable<JsonObject> observations) => FoldWithCoverage(observations);

    public static RadiusSessionFoldResult FoldWithCoverage(IEnumerable<JsonObject> observations)
    {
        int inputs=0,exactReady=0,unresolvedIdentity=0,unresolvedTimestamp=0;
        var seen=new HashSet<string>();var groups=new Dictionary<string,List<JsonObject>>(StringComparer.Ordinal);
        var principals=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(var row in observations)
        {
            inputs++;
            string id=row.Text("observation_id").Trim(),kind=row.Text("lifecycle_event").Trim(),identity=row.Text("identity_state").Trim(),timestamp=row.Text("timestamp_state").Trim();
            void Require(bool valid,string error) { if(!valid) throw new VpnInputException(error); }
            Require(id.Length is >0 and <=256,"observation_id_invalid");Require(seen.Add(id),"duplicate_observation_id");
            Require(kind is "start" or "interim_update" or "stop","lifecycle_event_invalid");
            Require(identity is "exact" or "unresolved","identity_state_invalid");Require(timestamp is "ready" or "unresolved","timestamp_state_invalid");
            string key=row.Text("session_identity_key").Trim(),principal=row.Text("exact_principal_key").Trim();
            if(identity=="unresolved") { Require(key=="" && principal=="","unresolved_identity_has_exact_keys");unresolvedIdentity++;continue; }
            Require(key!="" && principal!="","exact_identity_keys_required");Require(key.StartsWith("radius-session:",StringComparison.Ordinal),"session_identity_key_invalid");
            string hash=row.Text("canonical_record_sha256").Trim().ToLowerInvariant();Require(hash!="","evidence_sha256_required");Require(Regex.IsMatch(hash,@"\A[0-9a-f]{64}\z"),"evidence_sha256_invalid");
            if(timestamp=="unresolved") { Require(row["observed_at_utc"] is null,"unresolved_timestamp_has_value");unresolvedTimestamp++;continue; }
            Require(row["observed_at_utc"] is not null,"ready_timestamp_value_required");
            Require(row.At("observed_at_utc") is not null,"observed_at_utc_invalid");
            Require(Regex.IsMatch(row.Text("observed_at_utc"),@"(?:Z|[+-]\d\d:?\d\d)\z"),"observed_at_utc_timezone_required");
            Require(!principals.TryGetValue(key,out var prior)||prior==principal,"session_key_principal_conflict");principals[key]=principal;
            if(!groups.TryGetValue(key,out var values)) groups[key]=values=[];values.Add(row);
            exactReady++;
        }
        var result=new List<JsonObject>();
        foreach(var (key,values) in groups.OrderBy(x=>x.Key,StringComparer.Ordinal))
        {
            int generation=0;var current=new List<JsonObject>();
            void Finish(bool restart=false)
            {
                if(current.Count==0) return;
                DateTimeOffset? start=current.FirstOrDefault(r=>r.Text("lifecycle_event")=="start")?.At("observed_at_utc"),stop=current.LastOrDefault(r=>r.Text("lifecycle_event")=="stop")?.At("observed_at_utc");
                string completeness=start is not null?stop is not null?"complete":"missing_stop":stop is not null?"missing_start":"middle_only";
                string lifecycle=start is not null?stop is not null?"closed":"open_observed":stop is not null?"partial_closed":"partial_open";
                string material=$"{key}\0{generation}\0{current[0].Text("observation_id")}";
                result.Add(VpnJson.Obj(new {session_row_id="radius-session-row:"+Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material))),session_identity_key=key,exact_principal_key=principals[key],generation,lifecycle_state=lifecycle,completeness,started_at_utc=VpnJson.Iso(start),last_observed_at_utc=VpnJson.Iso(current[^1].At("observed_at_utc")),stopped_at_utc=VpnJson.Iso(stop),duration_seconds=start is not null && stop is not null?(long?)(stop-start).Value.TotalSeconds:null,observation_count=current.Count,anomalies=restart?new[]{"start_before_stop"}:[],observation_ids=current.Select(r=>r.Text("observation_id")).ToArray(),evidence_sha256s=current.Select(r=>r.Text("canonical_record_sha256").ToLowerInvariant()).ToArray()}));
                current=[];
            }
            foreach(var row in values.OrderBy(r=>r.At("observed_at_utc")).ThenBy(r=>r.Text("observation_id"),StringComparer.Ordinal))
            {
                if(row.Text("lifecycle_event")=="start") Finish(true);
                if(current.Count==0) generation++;current.Add(row);if(row.Text("lifecycle_event")=="stop") Finish();
            }
            Finish();
        }
        var sessions=result.OrderByDescending(r=>r.At("last_observed_at_utc")).ThenByDescending(r=>r.Text("session_row_id"),StringComparer.Ordinal).ToArray();
        return new(sessions,inputs,exactReady,unresolvedIdentity,unresolvedTimestamp,
            sessions.Count(r=>r.Text("completeness")=="complete"),sessions.Count(r=>r.Text("completeness")!="complete"),
            sessions.Count(r=>r.Text("lifecycle_state") is "open_observed" or "partial_open"));
    }
}
