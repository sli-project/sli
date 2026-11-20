using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Gpo.SnapshotModel;

namespace Sli.Server.Agents.SnapshotPublication;

// Source: server/sli/plugins/ad/context/contracts.py:validate_bundle.
// GPO-only normalization; source permits publication only for this entity family.
public static class GpoGovernanceBundle
{
    public static JsonObject Normalize(JsonObject raw, JsonObject snapshot)
    {
        static void Require(bool ok) { if (!ok) throw new InvalidDataException("agent_gpo_governance_invalid"); }
        static string Text(JsonNode? v) => GpoGovernanceSettings.Text(v);
        static string Utc(JsonNode? v)
        {
            string s=Text(v).Replace("Z","+00:00");
            if (!PythonIsoDateTime.TryParse(s,out var value) || !value.TryToUtc(out var utc)) throw new InvalidDataException("agent_gpo_governance_invalid");
            string text=utc.ToString("yyyy-MM-dd'T'HH:mm:ss",System.Globalization.CultureInfo.InvariantCulture);
            long micros=utc.Ticks % TimeSpan.TicksPerSecond / 10;
            return text+(micros==0?"":"."+micros.ToString("D6",System.Globalization.CultureInfo.InvariantCulture))+"Z";
        }
        static void Keys(JsonObject obj, string names) { var allowed=names.Split(' ').ToHashSet(StringComparer.Ordinal); if(obj.Any(x=>!allowed.Contains(x.Key))) throw new InvalidDataException("agent_gpo_governance_invalid"); }
        Keys(raw,"schema_version source_pack_id source_pack_version run_id mode domain scope observed_at_utc sections records bundle_sha256");
        Require(JsonRead.TryString(raw["schema_version"],out var schema) && schema=="ad-context-bundle/v1" && JsonRead.TryString(raw["source_pack_id"],out var pack) && pack=="sli.windows.ad-context");
        string version=Text(raw["source_pack_version"]), mode=Text(raw["mode"]), observed=Utc(raw["observed_at_utc"]);
        string runText=GpoGovernanceSettings.IsTruthy(raw["run_id"]) ? GpoSnapshotDocument.PythonString(JsonSerializer.SerializeToElement(raw["run_id"])) : "";
        Require(PythonGuid(runText,out var runId) && mode is "full" or "targeted" or "reconcile");
        var domain=raw["domain"]!.AsObject(); Keys(domain,"sid dns_name");
        string sid=Text(domain["sid"]),dns=UnicodeLower.Lower(Text(domain["dns_name"]));
        var scope=raw["scope"]!.AsObject(); Keys(scope,"search_base privileged_group_sids vpn_group_sids collection_profile computer_membership_collected");
        Require((!scope.ContainsKey("privileged_group_sids") || scope["privileged_group_sids"] is JsonArray {Count:0}) && (!scope.ContainsKey("vpn_group_sids") || scope["vpn_group_sids"] is JsonArray {Count:0}) && Text(scope["collection_profile"])=="gpo_governance_v4");
        var normalizedScope=new JsonObject { ["search_base"]=Text(scope["search_base"]),["privileged_group_sids"]=new JsonArray(),["vpn_group_sids"]=new JsonArray(),["collection_profile"]="gpo_governance_v4" };
        if(scope.ContainsKey("computer_membership_collected")) { Require(scope["computer_membership_collected"]?.GetValueKind() is JsonValueKind.True or JsonValueKind.False); Require(scope["computer_membership_collected"]!.GetValueKind()==JsonValueKind.False); normalizedScope["computer_membership_collected"]=scope["computer_membership_collected"]!.DeepClone(); }
        Require(raw["sections"] is JsonArray {Count:1} && raw["records"] is JsonArray);
        var section=raw["sections"]![0]!.AsObject(); Keys(section,"name status record_count duration_ms error_code");
        Require(Text(section["name"])=="gpo_governance" && Text(section["status"]) is "complete" or "partial" or "failed" or "skipped");
        var records=raw["records"]!.AsArray(); Require(records.Count<=200000);
        Require(GovernanceInteger.Parse(section["record_count"]) == records.Count);
        var duration = !GpoGovernanceSettings.IsTruthy(section["duration_ms"]) ? System.Numerics.BigInteger.Zero : GovernanceInteger.Parse(section["duration_ms"]); if (duration < 0) duration = 0;
        var normalizedRecords=new JsonArray();
        foreach (var value in records)
        {
            var record=value!.AsObject(); Keys(record,"record_type record_key section observed_at_utc identity attributes");
            Require(Text(record["record_type"])=="entity" && Text(record["section"])=="gpo_governance" && Utc(record["observed_at_utc"])==observed);
            var identity=record["identity"]!.AsObject(); Keys(identity,"kind domain_sid object_guid object_sid");
            Require(Text(identity["kind"])=="gpo" && UnicodeCaseFoldEquivalent(Text(identity["domain_sid"]),sid));
            if (!PythonGuid(UnicodeLower.Lower(Text(identity["object_guid"])),out var guid)) throw new InvalidDataException("agent_gpo_governance_invalid");
            var attributes=GpoGovernanceSettings.IsTruthy(record["attributes"]) ? record["attributes"] as JsonObject ?? throw new InvalidDataException("agent_gpo_governance_invalid") : new JsonObject();
            var cleaned=(JsonObject)attributes.DeepClone();
            foreach (var name in new[] { "attribute_states", "computer_reference_attribute_states" })
            { if(cleaned[name] is not null) throw new InvalidDataException("agent_gpo_governance_invalid"); cleaned.Remove(name); }
            GpoGovernanceAttributes.Validate(cleaned);
            var normalizedAttributes=(JsonObject)cleaned.DeepClone();
            if (attributes.ContainsKey("gpo_settings") && attributes["gpo_settings"] is null) normalizedAttributes.Remove("gpo_settings");
            if(attributes["gpo_settings"] is not null) normalizedAttributes["gpo_settings"]=GpoGovernanceSettings.Normalize(attributes["gpo_settings"]);
            var normalizedIdentity=new JsonObject { ["kind"]="gpo",["domain_sid"]=Text(identity["domain_sid"]),["object_guid"]=guid.ToString("D"),["object_sid"]=OptionalText(identity["object_sid"],256) };
            normalizedRecords.Add(new JsonObject { ["record_type"]="entity",["record_key"]=Text(record["record_key"]),["section"]="gpo_governance",["observed_at_utc"]=observed,["identity"]=normalizedIdentity,["attributes"]=normalizedAttributes });
        }
        Require(normalizedRecords.Select(x=>x!["record_key"]!.GetValue<string>()).Distinct(StringComparer.Ordinal).Count()==normalizedRecords.Count);
        var sorted=normalizedRecords.OrderBy(x=>x!["record_key"]!.GetValue<string>(),Comparer<string>.Create(GpoGovernanceSettings.CompareCodepoints)).Select(x=>x!.DeepClone()).ToArray();
        var normalized=new JsonObject { ["schema_version"]="ad-context-bundle/v1",["source_pack_id"]="sli.windows.ad-context",["source_pack_version"]=version,["run_id"]=runId.ToString("D"),["mode"]=mode,["domain"]=new JsonObject { ["sid"]=sid,["dns_name"]=dns },["scope"]=normalizedScope,["observed_at_utc"]=observed,["sections"]=new JsonArray(new JsonObject { ["name"]="gpo_governance", ["status"]=Text(section["status"]), ["record_count"]=records.Count, ["duration_ms"]=JsonNode.Parse(duration.ToString(System.Globalization.CultureInfo.InvariantCulture)), ["error_code"]=OptionalText(section["error_code"],128) }),["records"]=new JsonArray(sorted),["gpo_v2_snapshot"]=snapshot.DeepClone() };
        string hash=Convert.ToHexStringLower(SHA256.HashData(new UTF8Encoding(false,true).GetBytes(CanonicalJson.Serialize(normalized,false))));
        string supplied=GpoGovernanceSettings.IsTruthy(raw["bundle_sha256"]) ? UnicodeLower.Lower(GpoGovernanceSettings.PythonTrim(GpoSnapshotDocument.PythonString(JsonSerializer.SerializeToElement(raw["bundle_sha256"])))) : "";
        if(supplied.Length>0 && supplied!=hash) throw new InvalidDataException("agent_gpo_governance_invalid");
        normalized["bundle_sha256"]=hash;
        return normalized;
    }
    private static bool PythonGuid(string text,out Guid value)
    {
        string normalized=text.Replace("urn:","").Replace("uuid:","").Trim('{','}').Replace("-","");
        return Guid.TryParseExact(normalized,"N",out value);
    }
    private static string? OptionalText(JsonNode? node,int bound)
    {
        if (node is null || node.GetValueKind()==JsonValueKind.String && node.GetValue<string>()=="") return null;
        string value=GpoGovernanceSettings.PythonTrim(GpoSnapshotDocument.PythonString(JsonSerializer.SerializeToElement(node))); if (GpoGovernanceSettings.Count(value)>bound) throw new InvalidDataException("agent_gpo_governance_invalid"); return value.Length==0 ? null : value;
    }
    private static bool UnicodeCaseFoldEquivalent(string a,string b)=>Registry.UnicodeCaseFold.Fold(a)==Registry.UnicodeCaseFold.Fold(b);
}
