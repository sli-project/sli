using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.SnapshotPublication;

// Input documents must first pass their source schema validators.
public static class GpoPublicationConsistency
{
    public static void Validate(string domainSid, JsonObject policy, JsonObject snapshot, JsonObject bundle,
        IReadOnlyDictionary<string, JsonObject> originalFamilies)
    {
        static string S(JsonNode? n) => n?.GetValue<string>() ?? throw new InvalidDataException();
        static string F(string s) => UnicodeCaseFold.Fold(s);
        string dns=S(policy["domain_dns"]), sid=S(policy["domain_sid"]), baseDn=string.Join(",",dns.Split('.').Select(x=>"DC="+x));
        var domain=bundle["domain"]!.AsObject(); var sourceDomain=snapshot["domain"]!.AsObject(); var scope=bundle["scope"]!.AsObject();
        var bases=policy["search_bases"]!.AsArray(); var sections=bundle["sections"]!.AsArray();
        if (domainSid != sid || domain.Count != 2 || S(domain["sid"]) != sid || S(domain["dns_name"]) != dns
            || F(S(sourceDomain["dns_name"])) != dns || S(sourceDomain["sid"]) != sid
            || F(S(sourceDomain["distinguished_name"])) != F(baseDn) || F(S(scope["search_base"])) != F(baseDn)
            || !(bases.Count == 0 || bases.Count == 1 && S(bases[0]) == baseDn)
            || S(scope["collection_profile"]) != "gpo_governance_v4" || scope["privileged_group_sids"]!.AsArray().Count != 0
            || scope["vpn_group_sids"]!.AsArray().Count != 0 || sections.Count != 1 || S(sections[0]!["name"]) != "gpo_governance")
            throw new ProtocolException("agent_gpo_domain_scope_invalid");
        if (!PythonIsoDateTime.TryParse(S(snapshot["observed_at"]).Replace("Z","+00:00"),out var observed)
            || !observed.TryToUtc(out var observation) || !PythonIsoDateTime.TryParse(S(bundle["observed_at_utc"]).Replace("Z","+00:00"),out var b)
            || !b.TryToUtc(out var bundleTime) || observation != bundleTime
            || policy["dc"]!.AsArray() is var dc && dc.Count > 0 && F(S(sourceDomain["query_dc"])) != F(S(dc[0])))
            throw new ProtocolException("agent_gpo_observation_invalid");
        var gpos=snapshot["gpos"]!.AsArray(); var records=bundle["records"]!.AsArray();
        if (Math.Max(gpos.Count,records.Count) > policy["max_objects"]!.GetValue<int>()
            || originalFamilies.Values.Sum(x=>(long)CanonicalJson.Length(x)) > policy["max_bytes"]!.GetValue<int>())
            throw new ProtocolException("agent_gpo_size_limit");
        if (S(snapshot["source_states"]!["gpo_list"]!["status"]) != "observed"
            || S(snapshot["source_states"]!["gpc_directory"]!["status"]) != "observed"
            || snapshot["collection_errors"]!.AsArray().Any(x=>x?["code"]?.GetValue<string>() == "agent_gpo_size_limit"))
            throw new ProtocolException("agent_gpo_population_incomplete");
        var expected=new HashSet<(string Id,JsonNode? Name)>(PopulationComparer.Instance);
        foreach(var gpo in gpos)
        {
            var obj=gpo!.AsObject(); if (obj.ContainsKey("gpc") && obj["gpc"] is not JsonObject) throw new InvalidDataException("agent_gpo_population_mismatch");
            var candidate=obj["gpc"]?["object_guid"]; var node=GpoGovernanceSettings.IsTruthy(candidate) ? candidate : obj["guid"];
            string guid=UnicodeLower.Lower(Sli.Gpo.SnapshotModel.GpoSnapshotDocument.PythonString(System.Text.Json.JsonSerializer.SerializeToElement(node)));
            Add(expected,guid,gpo["display_name"]);
        }
        var found=new HashSet<(string Id,JsonNode? Name)>(PopulationComparer.Instance);
        foreach(var record in records)
        {
            if (S(record!["record_type"]) != "entity" || S(record["identity"]!["kind"]) != "gpo"
                || record["attributes"]!["gpo_security_filtering_effective_evaluated"]?.GetValueKind() != System.Text.Json.JsonValueKind.False)
                throw new ProtocolException("agent_gpo_governance_invalid");
            var attributes=record["attributes"]!.AsObject();
            if (!attributes.ContainsKey("display_name")) throw new InvalidDataException("agent_gpo_population_mismatch");
            Add(found,S(record["identity"]!["object_guid"]),attributes["display_name"]);
        }
        if (expected.Count!=records.Count || !expected.SetEquals(found))
            throw new ProtocolException("agent_gpo_population_mismatch");
    }
    private static void Add(HashSet<(string Id,JsonNode? Name)> set,string id,JsonNode? name)
    {
        if(name is JsonObject or JsonArray) throw new InvalidDataException("agent_gpo_population_mismatch");
        set.Add((id,name));
    }
    private sealed class PopulationComparer : IEqualityComparer<(string Id,JsonNode? Name)>
    {
        public static readonly PopulationComparer Instance=new();
        public bool Equals((string Id,JsonNode? Name) x,(string Id,JsonNode? Name) y) => x.Id==y.Id && Sli.Server.Agents.Ingress.PythonMetadataEquality.Equal(x.Name,y.Name);
        public int GetHashCode((string Id,JsonNode? Name) item)
        {
            var v=item.Name; if(v is null) return HashCode.Combine(item.Id,0);
            var kind=v.GetValueKind();
            if(kind is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False) return HashCode.Combine(item.Id,new System.Numerics.BigInteger(v.GetValue<bool>() ? 1 : 0));
            if(Sli.Agent.Protocol.JsonRead.TryInteger(v,out var integer)) return HashCode.Combine(item.Id,integer);
            if(kind==System.Text.Json.JsonValueKind.Number && double.TryParse(v.ToJsonString(),System.Globalization.NumberStyles.Float,System.Globalization.CultureInfo.InvariantCulture,out var number) && double.IsFinite(number))
                return Math.Truncate(number)==number ? HashCode.Combine(item.Id,new System.Numerics.BigInteger(number)) : HashCode.Combine(item.Id,number);
            if(kind==System.Text.Json.JsonValueKind.String) return HashCode.Combine(item.Id,v.GetValue<string>());
            throw new InvalidDataException("agent_gpo_population_mismatch");
        }
    }
}
