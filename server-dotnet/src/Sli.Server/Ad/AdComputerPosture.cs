using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdComputerPosture
{
    internal sealed class AgentIndex
    {
        internal bool Unavailable,Unbound;
        readonly Dictionary<(long,string),List<JsonObject>> guids=[];
        readonly Dictionary<(long,long),List<JsonObject>> entities=[];
        internal AgentIndex(List<JsonObject>? rows)
        {
            Unavailable=rows is null||rows.Count>10000;if(Unavailable)return;
            foreach(var row in rows!)
            {long domain=row.Int("domain_id"),entity=row.Int("entity_id");string guid=(row.Text("object_guid")??"").Trim('{','}').ToLowerInvariant();Unbound|=entity<=0||guid.Length==0;if(guid.Length>0){var key=(domain,guid);if(!guids.TryGetValue(key,out var values))guids[key]=values=[];values.Add(row);}if(entity>0){var key=(domain,entity);if(!entities.TryGetValue(key,out var values))entities[key]=values=[];values.Add(row);}}
        }
        internal JsonObject[] Candidates(long domain,string? guid,long entity)=>guids.GetValueOrDefault((domain,(guid??"").Trim('{','}').ToLowerInvariant()),[]).Concat(entities.GetValueOrDefault((domain,entity),[])).Distinct(ReferenceEqualityComparer.Instance).Cast<JsonObject>().ToArray();
    }
    internal static void Apply(JsonObject row,JsonObject raw,DateTimeOffset at,long? uac=null)
    {
        uac ??= AdInventoryRows.ComputerUac(raw["userAccountControl"]);
        if((uac.GetValueOrDefault()&8192)!=0)row["computer_type"]="domain_controller";
        bool? unconstrained=uac is not null?(uac.Value&524288)!=0:AdInventoryRows.Bool(raw["trustedForDelegation"]);
        bool? constrained=raw["allowedToDelegateTo"] is JsonArray targets?targets.Count>0:null;
        row["delegation"]=Obj(new{unconstrained,constrained,resource_based=AdInventoryRows.Bool(raw["resourceBasedDelegationPresent"])});row["trusted_for_delegation"]=unconstrained;row["constrained_delegation"]=constrained;
        foreach(var(from,to)in new[]{("allowedToDelegateTo","allowed_to_delegate_to"),("resourceBasedDelegationPresent","resource_based_delegation_present"),("resourceBasedDelegationSids","resource_based_delegation_sids"),("resourceBasedDelegationStatus","resource_based_delegation_status"),("resourceBasedDelegationDescriptorSha256","resource_based_delegation_descriptor_sha256"),("passwordLastSetStatus","password_last_set_status"),("lapsPasswordExpirationStatus","laps_password_expiration_status"),("legacyLapsPasswordExpirationStatus","legacy_laps_password_expiration_status"),("lapsPasswordExpiration","laps_password_expiration_utc"),("legacyLapsPasswordExpiration","legacy_laps_password_expiration_utc")})row[to]=raw[from]?.DeepClone();
        var modern=AdInventoryRows.Date(raw["lapsPasswordExpiration"]);var expiration=modern??AdInventoryRows.Date(raw["legacyLapsPasswordExpiration"]);
        string state=expiration is null?"unknown":expiration<at?"expired":"metadata_present";
        row["laps"]=Obj(new{state,expiration_utc=expiration is null?null:AdInventoryRows.PythonIso(expiration.Value),source_attribute=modern is not null?"msLAPS-PasswordExpirationTime":expiration is not null?"ms-Mcs-AdmPwdExpirationTime":null});row["laps_state"]=state;
    }
    internal static JsonObject ReviewObject(JsonObject raw,DateTimeOffset at)
    {
        var row=new JsonObject();foreach(var(from,to)in new[]{("objectGuid","object_guid"),("sid","object_sid"),("name","display_name"),("enabled","enabled"),("lastLogonTimestamp","last_logon_utc"),("passwordLastSet","password_last_set_utc"),("whenCreated","created_utc"),("osName","operating_system"),("osVersion","operating_system_version"),("deviceType","computer_type"),("ou","ou_path")})row[to]=raw[from]?.DeepClone();
        Apply(row,raw,AdInventoryRows.Date(raw["collectedAt"])??at);
        // The change/check projection intentionally includes only the fields its source supplies.
        foreach(string key in new[]{"resource_based_delegation_sids","resource_based_delegation_status","resource_based_delegation_descriptor_sha256","password_last_set_status","laps_password_expiration_status","legacy_laps_password_expiration_status"})row[key]=null;
        row["dns_ip"]=Dns(raw);return row;
    }
    internal static JsonObject Dns(JsonObject raw)
    {
        var source=raw["sources"]?["dns"];var at=AdInventoryRows.Date(source?["observed_at"]);
        return new JsonObject{["state"]=source.Text("status")??source.Text("state")??"not_collected",["addresses"]=source.Text("status")=="observed"&&at is not null?Array((raw["ipv4s"] as JsonArray??[]).Concat(raw["ipv6s"] as JsonArray??[])):new JsonArray(),["observed_at_utc"]=at is null?null:source?["observed_at"]?.DeepClone()};
    }
    public static DateTimeOffset? SupportEnd(string? os,string? version)
    {
        string name=(os??"").ToLowerInvariant();if(new[]{"embedded","iot","ltsb"}.Any(name.Contains))return null;var match=Regex.Match(version??"",@"\((\d{4,5})\)");int build=match.Success?int.Parse(match.Groups[1].Value,CultureInfo.InvariantCulture):0;
        string? date=null;
        foreach(var (pattern,end) in new[]{(@"windows\s+8\.1(?:\s|$)","2023-01-10"),(@"windows\s+8(?:\s|$)","2016-01-12"),(@"windows\s+vista(?:\s|$)","2017-04-11")})if(Regex.IsMatch(name,pattern)){date=end;break;}
        if(date is null&&name.Contains("windows 10"))date=name.Contains("ltsc")?build==17763?"2029-01-09":null:"2025-10-14";
        if(date is null&&name.Contains("windows 11"))
        {
            if(name.Contains("ltsc")&&build==26100)date="2029-10-09";
            else if(name.Contains("pro"))date=build switch{22000=>"2023-10-10",22621=>"2024-10-08",22631=>"2025-11-11",26100=>"2026-10-13",26200=>"2027-10-13",_=>null};
        }
        foreach(var (marker,end) in new[]{("windows server 2022","2031-10-14"),("windows server 2019","2029-01-09"),("windows server 2016","2027-01-12"),("windows server 2012","2023-10-10"),("windows server 2008","2020-01-14"),("windows server 2003","2015-07-14")})if(date is null&&name.Contains(marker))date=end;
        if(date is null&&Regex.IsMatch(name,@"windows\s+7(?:\s|$)"))date="2020-01-14";
        if(date is null&&Regex.IsMatch(name,@"windows\s+xp(?:\s|$)"))date="2014-04-08";
        return date is null?null:DateTimeOffset.Parse(date+"T00:00:00Z",CultureInfo.InvariantCulture);
    }
    public static JsonObject Agent(JsonObject obj,long domain,AgentIndex agents,DateTimeOffset? historical=null)
    {
        JsonObject Unknown(string reason)=>Obj(new{state="unknown",version=(string?)null,last_seen_utc=(string?)null,age_seconds=(long?)null,reason});
        if(agents.Unavailable)return Unknown("registry_unavailable");
        string? guid=obj.Text("object_guid");long entity=obj.Int("entity_id");
        var matches=agents.Candidates(domain,guid,entity);
        if(matches.Select(a=>a.Int("entity_id")).Distinct().Count()>1)return Unknown("ambiguous_binding");
        if(matches.Length==0)
        {
            bool unbound=agents.Unbound;
            var result=Unknown(unbound?"unbound_registry":"no_registry_match");result["state"]=unbound||guid is null?"unknown":"absent";return result;
        }
        var now=historical??DateTimeOffset.UtcNow;var eligible=matches.Where(a=>historical is null||AdInventoryRows.Date(a["created_at"]) is {} created&&created<=now&&AdInventoryRows.Date(a["bound_at"]) is {} bound&&bound<=now).ToArray();
        if(eligible.Length==0)return Unknown("historical_registry_unknown");
        var present=eligible.Where(a=>a.Text("removal_state")!="state_cleaned"||AdInventoryRows.Date(a["removed_at"]) is not {} removed||removed>now).ToArray();
        if(present.Length==0){var result=Unknown("removal_confirmed");result["state"]="absent";return result;}
        var newest=present.OrderBy(a=>AdInventoryRows.Date(a["last_seen"])).Last();var seen=AdInventoryRows.Date(newest["last_seen"]);long? age=seen is not null&&seen<=now?(long)(now-seen.Value).TotalSeconds:null;
        return Obj(new{state=age>=86400?"silent":"installed",version=historical is null?newest.Text("version"):null,last_seen_utc=age is null?null:Iso(seen!.Value),age_seconds=age});
    }
    public static async Task<List<JsonObject>?> AgentsAsync(NpgsqlConnection db,long[] domains,CancellationToken ct)
    {
        await using var savepoint=new NpgsqlCommand("savepoint ad_optional_registry",db);await savepoint.ExecuteNonQueryAsync(ct);
        try{return await AdJson.ReadAsync(db,AdAgentRegistrySql.Read,ct,domains,domains);}
        catch(NpgsqlException)
        {await using var rollback=new NpgsqlCommand("rollback to savepoint ad_optional_registry",db);await rollback.ExecuteNonQueryAsync(ct);return null;}
    }
}
