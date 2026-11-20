using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Agents.Registry;
using Sli.Server.Compatibility;
using Sli.Agent.Core;
using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Agents.Radius;

// Source: server/source_packs/radius/collection_routes.py. This reads only
// configuration; validation never opens an accounting share or contacts NPS.
public static class RadiusCollectionRoute
{
    private static ArgumentException Invalid(string code)=>new(code);
    private static JsonElement Get(JsonElement obj,string name)=>obj.ValueKind==JsonValueKind.Object && obj.TryGetProperty(name,out var v)?v:default;
    private static string Text(JsonElement v)=>v.ValueKind==JsonValueKind.String ? v.GetString()! : "";
    private static string Trim(string s)=>PythonText.Strip(s);
    private static bool Is(JsonElement obj,string key,string value)=>Text(Get(obj,key))==value;
    private static bool Bool(JsonElement obj,string key,bool value)=>Get(obj,key).ValueKind==(value?JsonValueKind.True:JsonValueKind.False);
    private static bool EqualFold(string a,string b)=>UnicodeCaseFold.Fold(a)==UnicodeCaseFold.Fold(b);
    private static bool IntEquals(JsonElement value,int expected)
    {
        if(value.ValueKind==JsonValueKind.String) return PythonInt.TryParse(value.GetString(),out var n) && n==expected;
        if(value.ValueKind==JsonValueKind.True) return expected==1;
        if(value.ValueKind==JsonValueKind.False) return expected==0;
        return value.ValueKind==JsonValueKind.Number && value.TryGetDouble(out double d) && double.IsFinite(d) && Math.Truncate(d)==expected;
    }
    private static bool NumericEquals(JsonElement value,int expected)=>value.ValueKind==JsonValueKind.Number && value.TryGetDouble(out double d) && d==expected;
    private static bool ForbiddenShares(JsonElement value)
    {
        var expected=new HashSet<string>(["c$","admin$","ipc$"],StringComparer.Ordinal);
        return value.ValueKind switch {
            JsonValueKind.Array=>value.EnumerateArray().All(x=>x.ValueKind==JsonValueKind.String) && value.EnumerateArray().Select(Text).ToHashSet(StringComparer.Ordinal).SetEquals(expected),
            JsonValueKind.Object=>value.EnumerateObject().Select(x=>x.Name).ToHashSet(StringComparer.Ordinal).SetEquals(expected),
            _=>false
        };
    }
    public static string Validate(JsonElement route,IReadOnlyDictionary<string,string?> env)
        => Describe(route,env)["source_name"]!.GetValue<string>();

    public static IReadOnlyDictionary<string,string?> EnvironmentValues()
    {
        string[] keys=["ADLOG_RADIUS_COLLECTION_ROUTES_PATH","ADLOG_RADIUS_SOURCE_NAME","ADLOG_RADIUS_SOURCE_INSTANCE_ID","ADLOG_RADIUS_OWNER_CONFIRMED_IP","ADLOG_RADIUS_ACCOUNTING_SHARE_UNC","ADLOG_RADIUS_REGISTRATION_CONTRACT_PATH"];
        return keys.Where(k=>Environment.GetEnvironmentVariable(k) is not null).ToDictionary(k=>k,Environment.GetEnvironmentVariable);
    }

    public static JsonObject Load(string configRoot,IReadOnlyDictionary<string,string?> env,string? path=null)
    {
        bool explicitPath=path is not null;
        if(path is null) path=env.TryGetValue("ADLOG_RADIUS_COLLECTION_ROUTES_PATH",out var external) && !string.IsNullOrEmpty(external)
            ? external : Path.Combine(configRoot,"stage10_radius_collection_routes_v1.json");
        JsonDocument document;
        try { document=JsonDocument.Parse(File.ReadAllBytes(path)); }
        catch(Exception e) when(e is IOException or UnauthorizedAccessException or JsonException)
        { throw Invalid("route_contract_unreadable"); }
        using(document) return Describe(document.RootElement,explicitPath?new Dictionary<string,string?>():env);
    }

    public static (string ShareUnc,string TimezoneId,int UtcOffsetMinutes) RequireAccountingSource(string configRoot,IReadOnlyDictionary<string,string?> env)
    {
        var route=Load(configRoot,env);
        if(!route["accounting_ready"]!.GetValue<bool>()) throw Invalid("radius_dedicated_read_only_share_not_configured");
        return (route["accounting_share_unc"]!.GetValue<string>(),route["timezone_id"]!.GetValue<string>(),route["utc_offset_minutes"]!.GetValue<int>());
    }

    public static JsonObject Describe(JsonElement route,IReadOnlyDictionary<string,string?> env)
    {
        string? GetEnv(string name)=>env.TryGetValue(name,out var value)?value:null;
        if(route.ValueKind!=JsonValueKind.Object) throw Invalid("route_contract_object_required");
        var version=Get(route,"schema_version");
        if(!IntEquals(version,1)) throw Invalid("unsupported_schema_version");
        if(!Is(route,"contract_id","sli.radius-collection-routes.v1")) throw Invalid("contract_id_mismatch");
        string name=Trim(AuthJsonBody.CredentialString(route,"source_name")),connect=Trim(AuthJsonBody.CredentialString(route,"connect_address")),instance=Trim(AuthJsonBody.CredentialString(route,"source_instance_id"));
        string? overrideName=GetEnv("ADLOG_RADIUS_SOURCE_NAME");
        if(overrideName is not null) { name=Trim(overrideName);if(name.Length==0) throw Invalid("radius_source_not_configured");connect=name;instance=name; }
        string? overrideId=GetEnv("ADLOG_RADIUS_SOURCE_INSTANCE_ID");if(overrideId is not null && Trim(overrideId).Length>0) instance=Trim(overrideId);
        if(name.Length==0 && instance.Length==0) throw Invalid("radius_source_not_configured");
        if(name.Length==0 || instance.Length==0) throw Invalid("source_instance_id_mismatch");
        if(!EqualFold(name,connect)) throw Invalid("source_identity_mismatch");
        if(!Bool(route,"runtime_enabled",false) || !Bool(route,"autostart_enabled",false)) throw Invalid("runtime_must_remain_disabled");
        var ev=Get(route,"event_log_route");var ids=Get(ev,"event_ids");
        if(ev.ValueKind!=JsonValueKind.Object) throw Invalid("event_log_route_object_required");
        if(!Is(ev,"pack_id","sli.windows.vpn-radius") || !Is(ev,"channel","Security") || !Is(ev,"provider_name","Microsoft-Windows-Security-Auditing") ||
           ids.ValueKind!=JsonValueKind.Array || ids.GetArrayLength()!=2 || !NumericEquals(ids[0],6272) || !NumericEquals(ids[1],6273) ||
           !Is(ev,"transport","windows_event_log_rpc") || !Is(ev,"collection_entrypoint","scripts/run_dc_log_pilot.py")) throw Invalid("event_log_route_mismatch");
        string[] adapters=["windows-eventlog-pywin32","windows-eventlog-powershell"];
        if(!adapters.Contains(Text(Get(ev,"primary_adapter")),StringComparer.Ordinal) || !adapters.Contains(Text(Get(ev,"fallback_adapter")),StringComparer.Ordinal)) throw Invalid("event_log_adapter_mismatch");
        var acc=Get(route,"accounting_route");var tz=Get(acc,"timezone_descriptor");var shares=Get(acc,"administrative_shares_forbidden");
        if(acc.ValueKind!=JsonValueKind.Object) throw Invalid("accounting_route_object_required");
        if(tz.ValueKind!=JsonValueKind.Object) throw Invalid("timezone_descriptor_object_required");
        if(!Is(acc,"transport","dedicated_read_only_smb_share") || !ForbiddenShares(shares) || !Bool(acc,"default_windows_logfiles_path_forbidden",true) ||
           !Is(tz,"source","static_accepted_evidence") || !Is(tz,"timezone_id","N. Central Asia Standard Time") ||
           !IntEquals(Get(tz,"utc_offset_minutes"),420) ||
           !Bool(tz,"remote_registry_allowed",false) || !Bool(tz,"drift_check_required_before_activation",false) || !Bool(tz,"drift_check_accepted",false) ||
           !Bool(tz,"owner_assumption_active",true) || !Is(tz,"owner_assumption_recorded_on","2026-08-02")) throw Invalid("accounting_route_mismatch");
        var rawShare=Get(acc,"share_unc");string? share=rawShare.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined?null:Trim(Text(rawShare));
        if(env.ContainsKey("ADLOG_RADIUS_ACCOUNTING_SHARE_UNC")) { share=Trim(GetEnv("ADLOG_RADIUS_ACCOUNTING_SHARE_UNC") ?? "");if(share.Length==0) share=null; }
        if(share is not null)
        {
            var match=Regex.Match(share,@"\A\\\\([^\\]+)\\([^\\]+)\\?\z",RegexOptions.CultureInvariant);
            if(!match.Success) throw Invalid("dedicated_share_unc_required");
            if(!EqualFold(match.Groups[1].Value,name)) throw Invalid("dedicated_share_host_mismatch");
            if(new[]{"c$","admin$","ipc$"}.Any(x=>EqualFold(x,match.Groups[2].Value))) throw Invalid("administrative_share_forbidden");
        }
        string owner=AuthJsonBody.CredentialString(route,"owner_confirmed_ip");
        if(GetEnv("ADLOG_RADIUS_OWNER_CONFIRMED_IP") is {} ip && Trim(ip).Length>0) owner=Trim(ip);
        return new JsonObject {
            ["source_name"]=name,["source_instance_id"]=instance,["owner_confirmed_ip"]=owner,
            ["event_log_ready"]=true,["event_log_adapter"]=Text(Get(ev,"primary_adapter")),["event_log_fallback_adapter"]=Text(Get(ev,"fallback_adapter")),
            ["accounting_ready"]=share is not null,["accounting_share_unc"]=share,["timezone_id"]=Text(Get(tz,"timezone_id")),["utc_offset_minutes"]=420,
            ["runtime_enabled"]=false,["autostart_enabled"]=false,["blockers"]=share is null?new JsonArray("radius_dedicated_read_only_share_not_configured"):new JsonArray(),
            ["timezone_drift_check_accepted"]=false,["timezone_owner_assumption_active"]=true
        };
    }
}
