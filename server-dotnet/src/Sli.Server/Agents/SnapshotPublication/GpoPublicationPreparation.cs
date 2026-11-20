using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Gpo.SnapshotModel;

namespace Sli.Server.Agents.SnapshotPublication;

// Source: plugins/gpo/snapshot_import.py:prepare_gpo_cycle; no writes.
public static class GpoPublicationPreparation
{
    public static JsonObject Prepare(string domainSid,JsonObject policy,IReadOnlyDictionary<string,JsonObject> families)
    {
        if (families.Count!=2 || !families.ContainsKey("ad_gpo_governance") || !families.ContainsKey("gpo_v2")) throw new ProtocolException("agent_gpo_required_families_missing");
        var snapshot=families["gpo_v2"];
        GpoSnapshotValidator.Validate(JsonSerializer.SerializeToElement(snapshot));
        var raw=families["ad_gpo_governance"];
        if(raw.ContainsKey("gpo_v2_snapshot")) throw new ProtocolException("agent_gpo_duplicate_snapshot");
        var bundle=GpoGovernanceBundle.Normalize(raw,snapshot);
        GpoPublicationConsistency.Validate(domainSid,policy,snapshot,bundle,families);
        if(snapshot["collection_status"]!.GetValue<string>()!="complete" || bundle["sections"]![0]!["status"]!.GetValue<string>()!="complete")
        {
            var adjusted=(JsonObject)bundle.DeepClone(); adjusted.Remove("gpo_v2_snapshot"); adjusted.Remove("bundle_sha256");
            adjusted["mode"]="targeted"; adjusted["sections"]![0]!["status"]="partial"; adjusted["sections"]![0]!["error_code"]="agent_gpo_source_partial";
            bundle=GpoGovernanceBundle.Normalize(adjusted,snapshot);
        }
        else if(bundle["mode"]!.GetValue<string>() is not ("full" or "reconcile")) throw new ProtocolException("agent_gpo_population_incomplete");
        return bundle;
    }
}
