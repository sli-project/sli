using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Ingress;
using Sli.Server.Auth.Lifecycle.Security;

namespace Sli.Server.Agents.FileAudit;

// Strict management.validate_result and _snapshot. Untrusted inventory never reaches SQL before this check.
public static class FileAuditResult
{
    private static readonly HashSet<string> Reasons=["ok","coverage_incomplete","sacl_missing","policy_missing","restore_incomplete","native_unavailable","policy_blocked","management_disabled","restore_required","restore_scope_mismatch","system_required","managed_by_gpo","unknown","global_sacl_unknown","global_sacl_present","restore_scan_incomplete","inheritance_untracked","restore_conflict"];
    private static readonly HashSet<string> InventoryReasons =
    [
        "share_path_mismatch", "directory_reparse_point", "directory_root_invalid", "inventory_limit"
    ];
    private static readonly HashSet<string> NativeReasons =
    [
        "audit_policy_read_unavailable", "security_log_unavailable", "share_read_unavailable", "local_groups_unavailable",
        "local_group_members_unavailable", "local_group_identity_unavailable", "directory_open_unavailable",
        "directory_read_unavailable", "acl_read_unavailable", "security_privilege_missing", "security_privilege_unavailable",
        "sacl_plan_failed", "sacl_write_failed", "sacl_readback_failed", "inventory_unavailable", "global_sacl_unknown"
    ];

    private static bool NativeReason(string reason)
    {
        var separator = reason.IndexOf(':');
        if (separator < 0) return NativeReasons.Contains(reason);
        var status = reason.AsSpan(separator + 1);
        return status.Length is >= 1 and <= 10 && status[0] is >= '1' and <= '9'
            && status.IndexOfAnyExceptInRange('0', '9') < 0
            && uint.TryParse(status, NumberStyles.None, CultureInfo.InvariantCulture, out _)
            && NativeReasons.Contains(reason[..separator]);
    }
    private static bool Text(JsonNode? n,out string s)=>JsonRead.TryString(n,out s);
    private static string S(JsonNode? n)=>n!.GetValue<string>();
    private static bool Bool(JsonNode? n)=>n is JsonValue v && v.TryGetValue<bool>(out _);
    private static bool Flag(JsonNode? n)=>n is JsonValue v && v.TryGetValue<bool>(out var b) && b;
    private static bool Number(JsonNode? n,int low,int high)=>JsonRead.TryInteger(n,out var i) && i>=low && i<=high;
    private static bool SafeText(JsonNode? n,int limit=65536)=>Text(n,out var s) && s.EnumerateRunes().Count()<=limit && !s.Any(c=>c<32);
    private static bool Sid(JsonNode? n,int limit=184)=>Text(n,out var s) && s.EnumerateRunes().Count()<=limit && Regex.IsMatch(s,@"\AS-1-(?:[0-9]+-)*[0-9]+\z");
    private static bool Utc(JsonNode? n)=>Text(n,out var s) && s.EnumerateRunes().Count()<=40 && PythonIsoDateTime.TryParseUtc(s,out _);
    private static bool Uuid(JsonNode? n) { if(!Text(n,out var s)) return false; try { _=Sli.Server.Agents.Control.AgentControlJson.Id(s);return true; } catch(Sli.Server.Agents.Control.AgentControlException) { return false; } }
    private static string Fold(string path)=>UnicodeLower.Lower(path.Replace('/','\\'));
    private static bool InRoot(string path,string root) { path=Fold(AgentFileAuditPolicy.NormalizePath(path));root=Fold(AgentFileAuditPolicy.NormalizePath(root));return path==root || path.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.Ordinal); }
    private static JsonObject Requirements(JsonObject config,JsonObject root)
    {
        var values=new Dictionary<string,int> { ["921d"]=3,["9224"]=3,["9244"]=Flag(root["important"])?3:2,["922f"]=1,["9215"]=3 };
        if(config["source_kind"]?.GetValue<string>()=="workstation") { values.Remove("9224");values.Remove("9244"); }
        if(Flag(config["optional_events"])) values["9223"]=1;
        var result=new JsonObject();foreach(var (key,value) in values) result[$"0cce{key}-69ae-11d9-bed3-505054503030"]=value;return result;
    }
    public static bool Valid(JsonObject body,JsonObject input,JsonObject command)
    {
        try { return Validate(body,input,command); }
        catch(Exception e) when(e is ArgumentException or InvalidOperationException or FormatException or OverflowException or NullReferenceException or KeyNotFoundException or Sli.Agent.Core.AgentException or ProtocolException) { return false; }
    }
    private static bool Validate(JsonObject body,JsonObject input,JsonObject command)
    {
        var config=AgentFileAuditPolicy.Parse(input).Value; if(!FileAuditCommand.Valid(command,config)) return false;
        if(!JsonRead.HasExactly(body,"contract_id","command_id","policy_revision","action","observed_at_utc","scopes","snapshots","ownership_remaining") || !Text(body["contract_id"],out var contract) || contract!="sli.file-audit.audit-result.v1"
            || new[]{"command_id","policy_revision","action"}.Any(k=>!JsonNode.DeepEquals(body[k],command[k])) || !Bool(body["ownership_remaining"]) || !Utc(body["observed_at_utc"])
            || body["scopes"] is not JsonArray scopes || scopes.Count is < 1 or > 100 || body["snapshots"] is not JsonArray snapshots || snapshots.Count>1 || CanonicalJson.Length(body)>128*1024) return false;
        var selected=command["collection_scope_ids"]!.AsArray().Select(S).ToHashSet(StringComparer.Ordinal); var seen=new HashSet<string>(StringComparer.Ordinal);
        foreach(var item in scopes)
        {
            if(item is not JsonObject row || !ScopeShape(row) || !Text(row["collection_scope_id"],out var id) || !seen.Add(id) || !selected.Contains(id)
                || !Text(row["state"],out var state) || state is not ("verified" or "partial" or "blocked" or "failed") || !Text(row["reason_code"],out var reason)
                || !(Reasons.Contains(reason) || state != "verified" && (InventoryReasons.Contains(reason) || NativeReason(reason)))
                || row["required_masks"] is not JsonObject required || row["actual_masks"] is not JsonObject actual) return false;
            if (row.ContainsKey("read_error") && (state!="failed" || S(command["action"])!="check"
                || !(reason is "native_unavailable" or "unknown" || InventoryReasons.Contains(reason) || NativeReason(reason))
                || selected.Count!=1 || config["source_kind"]?.ToString()=="workstation" || snapshots.Count!=0
                || !FileAuditReadError.Valid(row["read_error"]))) return false;
            var root=config["roots"]!.AsArray().OfType<JsonObject>().Single(x=>S(x["collection_scope_id"])==id);var expected=Requirements(config,root);
            if(state=="failed") { if(required.Count!=0 || actual.Count!=0) return false; }
            else
            {
                if(!JsonNode.DeepEquals(required,expected) || !required.Select(x=>x.Key).ToHashSet().SetEquals(actual.Select(x=>x.Key)) || required.Any(x=>!Number(x.Value,0,3))) return false;
                foreach(var (key,value) in actual)
                {
                    if(value is not null && !Number(value,0,3)) return false;
                    if(state=="verified" && S(command["action"])!="restore" && (value is null || ((int)value.GetValue<int>() & expected[key]!.GetValue<int>())!=expected[key]!.GetValue<int>())) return false;
                }
            }
        }
        foreach(var item in snapshots) if(item is not JsonObject snapshot || !Snapshot(snapshot,config,command) || !seen.Contains(S(snapshot["collection_scope_id"]))) return false;
        foreach(var row in scopes.OfType<JsonObject>().Where(x=>S(x["state"])=="verified"))
        {
            var snapshot=snapshots.OfType<JsonObject>().FirstOrDefault(x=>S(x["collection_scope_id"])==S(row["collection_scope_id"]));
            if(snapshot is null || Flag(snapshot["has_more"]) || !Number(snapshot["unread_objects"],0,0) || !Flag(snapshot["share"]!["complete"]) || !Flag(snapshot["local_groups"]!["complete"])) return false;
            if(S(command["action"])!="restore" && snapshot["objects"]!.AsArray().Any(o=>Flag(o!["sacl_missing"]))) return false;
            if(S(command["action"])=="restore" && Flag(body["ownership_remaining"])) return false;
        }
        return true;
    }
    private static bool ScopeShape(JsonObject row) => row.ContainsKey("read_error")
        ? JsonRead.HasExactly(row,"collection_scope_id","state","reason_code","required_masks","actual_masks","read_error")
        : JsonRead.HasExactly(row,"collection_scope_id","state","reason_code","required_masks","actual_masks");

    private static bool Snapshot(JsonObject snap,JsonObject config,JsonObject command)
    {
        if(!JsonRead.HasExactly(snap,"contract_id","collection_scope_id","policy_revision","observed_at_utc","scan_id","page_number","has_more","completeness","unread_objects","share","local_groups","objects","snapshot_sha256","snapshot_id")
            || !Text(snap["contract_id"],out var contract) || contract!="sli.file-audit.inventory.v1" || !JsonNode.DeepEquals(snap["policy_revision"],command["policy_revision"]) || !Text(snap["collection_scope_id"],out var scope)
            || !command["collection_scope_ids"]!.AsArray().Any(x=>S(x)==scope) || !Number(snap["page_number"],0,100000) || !Bool(snap["has_more"]) || !Text(snap["completeness"],out var completeness) || completeness is not ("complete" or "partial" or "failed")
            || !Number(snap["unread_objects"],0,100000) || completeness=="complete" && (!Number(snap["unread_objects"],0,0) || Flag(snap["has_more"]) || !Number(snap["page_number"],0,0))
            || snap["objects"] is not JsonArray objects || objects.Count>config["inventory_objects"]!.GetValue<int>() || CanonicalJson.Length(snap)>48*1024 || !Utc(snap["observed_at_utc"]) || !Uuid(snap["scan_id"]) || !Uuid(snap["snapshot_id"])) return false;
        var contents=(JsonObject)snap.DeepClone();contents.Remove("snapshot_sha256");contents.Remove("snapshot_id"); string hash=Packets.Digest(contents);
        if(!Text(snap["snapshot_sha256"],out var gotHash) || gotHash!=hash || S(snap["snapshot_id"])!=AuthAudit.Uuid5(S(command["command_id"])+hash).ToString()) return false;
        var root=config["roots"]!.AsArray().OfType<JsonObject>().Single(x=>S(x["collection_scope_id"])==scope);
        if(snap["share"] is not JsonObject share || !JsonRead.HasExactly(share,"name","path","dacl","complete") || !JsonNode.DeepEquals(share["name"],root["share_name"]) || !JsonNode.DeepEquals(share["path"],root["path"]) || !SafeText(share["dacl"]) || !Bool(share["complete"])) return false;
        if(snap["local_groups"] is not JsonObject local || !JsonRead.HasExactly(local,"complete","groups") || !Bool(local["complete"]) || local["groups"] is not JsonArray groups || groups.Count>100) return false;
        foreach(var item in groups) if(item is not JsonObject group || !JsonRead.HasExactly(group,"group_sid","member_sids") || !Sid(group["group_sid"],int.MaxValue) || group["member_sids"] is not JsonArray members || members.Count>100 || members.Any(x=>!Sid(x))) return false;
        var paths=new HashSet<string>(StringComparer.Ordinal);
        foreach(var item in objects)
        {
            if(item is not JsonObject row || !JsonRead.HasExactly(row,"path","object_id","object_type","owner_sid","dacl","sacl","sacl_protected","sacl_missing") || !Text(row["path"],out var path) || !InRoot(path,S(root["path"])) || !paths.Add(Fold(path))
                || !Text(row["object_type"],out var kind) || kind is not ("file" or "directory") || !SafeText(row["object_id"],256) || !Sid(row["owner_sid"]) || !SafeText(row["dacl"]) || !SafeText(row["sacl"]) || !Bool(row["sacl_protected"]) || !Bool(row["sacl_missing"])) return false;
        }
        return true;
    }
}



