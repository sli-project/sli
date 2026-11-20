using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Storage.EventReports;

// Payload-free catalogue tooling, ported from event_catalog_quality.py.
internal static partial class EventCatalogQuality
{
    internal static JsonObject ShippedCatalog()
    {
        using var stream=typeof(EventCatalogQuality).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    static string Text(JsonNode? n)=>EventCardSemantics.Text(n);
    static string Fold(JsonNode? n)=>UnicodeCaseFold.TrimAndFold(Text(n));
    static bool Field(JsonNode? n)=>Regex.IsMatch(Text(n),@"\A[A-Za-z][A-Za-z0-9_.:-]{0,127}\z");
    static bool In(JsonNode? n,string values)=>values.Split(' ').Contains(Text(n).ToLowerInvariant());
    static (string,string,string) LegacyIdentity(JsonObject e)=>(Fold(e["channel"]),Fold(e["event_id"]),Fold(e["provider_name"]));
    static (string,string,string) Identity(JsonObject e)=>new[]{"source","stream","event_key"}.Any(e.ContainsKey)
        ? (Fold(e["source"]),Fold(e["stream"]),Fold(e["event_key"])) : LegacyIdentity(e);
    static bool Complete((string A,string B,string C) id)=>id.A.Length>0 && id.B.Length>0 && id.C.Length>0;

    internal static JsonObject CoverageSummary(IEnumerable<JsonObject> groups,IEnumerable<JsonObject> entries)
    {
        var identities=new HashSet<(string,string,string)>();
        foreach(var entry in entries) { identities.Add(Identity(entry)); if(Complete(LegacyIdentity(entry))) identities.Add(LegacyIdentity(entry)); }
        int inspected=0,covered=0; long total=0,events=0; var gaps=new List<JsonObject>();
        foreach(var row in groups)
        {
            inspected++; long count=Math.Max(0,(long?)row["count"]??0); total+=count;
            if(identities.Contains(Identity(row))) { covered++; events+=count; }
            else gaps.Add(new JsonObject { ["channel"]=row["channel"]?.DeepClone(),["event_id"]=(long?)row["event_id"]??0,
                ["provider_name"]=row["provider_name"]?.DeepClone(),["count"]=count,["first_seen"]=row["first_seen"]?.DeepClone(),["last_seen"]=row["last_seen"]?.DeepClone() });
        }
        return new() { ["contains_event_payload"]=false,["groups_inspected"]=inspected,["groups_covered"]=covered,
            ["group_coverage_ratio"]=inspected==0?1:(double)covered/inspected,["events_in_groups"]=total,["events_covered"]=events,
            ["event_coverage_ratio"]=total==0?1:(double)events/total,["gap_count"]=gaps.Count,
            ["gaps"]=new JsonArray(gaps.OrderByDescending(g=>(long)g["count"]!).ThenBy(g=>Text(g["channel"]),StringComparer.Ordinal)
                .ThenBy(g=>(long)g["event_id"]!).ThenBy(g=>Text(g["provider_name"]),StringComparer.Ordinal).Select(g=>(JsonNode)g).ToArray()) };
    }

    internal static JsonObject ProposeCatalogPromotion(JsonObject data,JsonObject fixture)
    {
        var identity=new JsonObject(); foreach(string key in new[]{"channel","event_id","provider_name"}) identity[key]=fixture[key]?.DeepClone();
        var id=Identity(identity);
        if(!Complete(id)) throw new ArgumentException("fixture_identity_incomplete");
        if((data["entries"] as JsonArray??[]).OfType<JsonObject>().Any(e=>Identity(e)==id)) throw new ArgumentException("catalog_identity_already_exists");
        if(fixture["verified_semantics"] is not JsonObject semantic) throw new ArgumentException("verified_semantics_required");
        if(fixture["evidence_fields"] is not JsonArray {Count:>0} fields || fields.Any(f=>!Field(f))) throw new ArgumentException("field_level_evidence_required");
        var entry=(JsonObject)identity.DeepClone(); entry["severity"]=Text(semantic["severity"]).ToLowerInvariant();
        foreach(string key in new[]{"title","why","fix","missing"}) entry[key]=Text(semantic[key]).Trim();
        var candidate=(JsonObject)data.DeepClone(); var entries=candidate["entries"] as JsonArray;
        if(entries is null) candidate["entries"]=entries=[];
        entries.Add(entry.DeepClone());
        if(new[]{"title","why","fix"}.Any(k=>Text(entry[k]).Length==0) || !(bool)ValidateCatalogData(candidate)["valid"]!) throw new ArgumentException("promotion_candidate_invalid");
        return new() { ["status"]="proposed",["writes_performed"]=false,["identity"]=identity,["entry"]=entry,["evidence_fields"]=fields.DeepClone() };
    }

    internal static async Task<JsonObject> BuildReportEventDtoAsync(JsonObject row,KnownBundleNormalizer normalizer,CancellationToken ct)
    {
        var card=await normalizer.CardAsync(row,ct);
        var result=new JsonObject { ["event_db_id"]=row["event_db_id"]?.DeepClone()??row["id"]?.DeepClone()??JsonValue.Create(0),["event_id"]=row["event_id"]?.DeepClone()??JsonValue.Create(0) };
        foreach(string key in new[]{"time_created_utc","server","channel","provider_name"}) result[key]=row[key]?.DeepClone();
        foreach(string key in new[]{"title","final_security_severity","purpose_tier","assessment_confidence","noise_class","catalog_match","reasons","evidence_fields"}) result[key]=card[key]?.DeepClone();
        return result;
    }
}
