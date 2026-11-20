using System.Text.Json.Nodes;
using Sli.Server.Storage.EventReports;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdSecurityHydration
{
    static readonly (string Source,string Target)[] Fields=[("CallerComputerName","caller_computer"),("CallerComputer","caller_computer"),("MemberSid","membership_member_sid"),("MemberName","membership_member_name"),("TargetSid","target_user_sid"),("TargetUserSid","target_user_sid"),("TargetUserName","target_user_name"),("GroupName","target_user_name"),("OldTargetUserName","account_name_before"),("NewTargetUserName","account_name_after"),("OldAccountName","account_name_before"),("NewAccountName","account_name_after")];
    public static async Task HydrateAsync(List<JsonObject> rows,long domain,IEventReadService reader,CancellationToken ct)
    {
        foreach(var batch in rows.Where(r=>r["authentication_session"] is null).Chunk(100))
        {
            long[] ids=batch.Select(r=>r.Int("event_db_id")).ToArray();var allowed=new Dictionary<long,bool>();
            async Task<bool> Admitted(long id,CancellationToken token)
            {
                if(!ids.Contains(id))return false;
                if(allowed.TryGetValue(id,out bool value))return value;
                var resources=await reader.ResourcesAsync(id,token);
                return allowed[id]=resources.Any(r=>r.Kind=="domain"&&r.Id==domain);
            }
            try
            {
                var data=await reader.DetailsAsync(ids,false,Admitted,ct);
                if(data.Keys.Any(id=>!ids.Contains(id)))throw new InvalidDataException("ad_hydration_scope_mismatch");
                foreach(var row in batch)
                {
                    if(!data.TryGetValue(row.Int("event_db_id"),out var detail)||detail["event_data"] is not JsonObject native)
                    {row["archive_field_state"]="partial_archive_missing";continue;}
                    foreach(var (source,target) in Fields)if(row.WindowsText(target) is null && native.WindowsText(source) is {} text)row[target]=text;
                    if(Change(row.Int("event_id"),native) is {} change)row["source_native_change"]=change;
                }
            }
            catch(OperationCanceledException) when(ct.IsCancellationRequested){throw;}
            catch(Exception error) when(error is IOException or InvalidDataException or InvalidOperationException or ArgumentException or TimeoutException or OperationCanceledException)
            {foreach(var row in batch)row["archive_field_state"]=error is InvalidDataException?"partial_archive_corrupt":"partial_archive_unavailable";}
        }
    }
    internal static JsonObject? Change(long id,JsonObject data)
    {
        string? kind=AdHistory.Map("_SECURITY_EVENT_CHANGE_KIND_BY_EVENT_ID")[id.ToString()]?.GetValue<string>();
        if(kind is not ("attributes_changed" or "group_changed" or "group_type_changed" or "audit_policy_changed" or "security_log_cleared"))return null;
        string? Clean(IEnumerable<string> names)
        {
            foreach(string name in names)if(data.WindowsText(name) is {} value)return string.Concat(value.EnumerateRunes().Take(512).Select(r=>r.ToString()));return null;
        }
        var result=Obj(new{state="observed",kind});var fields=new JsonObject();
        if(kind is "attributes_changed" or "group_changed")
        {
            foreach(var pair in AdHistory.Taxonomy[kind=="attributes_changed"?"_SECURITY_EVENT_ACCOUNT_ATTRIBUTE_FIELDS":"_SECURITY_EVENT_GROUP_ATTRIBUTE_FIELDS"]!.AsArray())
                if(Clean(pair![0]!.AsArray().Select(n=>n!.ToString())) is {} value)fields[pair[1]!.ToString()]=value;
            if(fields.Count>0)result["attributes"]=fields;
        }
        else if(kind=="group_type_changed")
        {
            if(Clean(["OldGroupType","old_group_type"]) is {} old)fields["old_group_type"]=old;
            if(Clean(["NewGroupType","new_group_type"]) is {} current)fields["new_group_type"]=current;
        }
        else if(kind=="audit_policy_changed")foreach(var (source,alias,target) in new[]{("CategoryId","audit_category_id","category_id"),("SubcategoryId","audit_subcategory_id","subcategory_id"),("SubcategoryGuid","audit_subcategory_guid","subcategory_guid"),("AuditPolicyChanges","audit_policy_changes","observed_value")})
        {if(Clean([source,alias]) is {} value)fields[target]=value;}
        else if(Clean(["Channel","LogName","cleared_log"]) is {} value)fields["observed_value"]=value;
        if(kind is not ("attributes_changed" or "group_changed"))foreach(var (key,value) in fields)result[key]=value?.DeepClone();
        if(fields.Count==0&&kind!="security_log_cleared")
        {result["state"]="partial";result["detail"]=Unknown(kind switch{"attributes_changed"=>"account_attributes_not_present","group_changed"=>"group_change_attributes_not_present","group_type_changed"=>"group_type_values_not_present",_=>"audit_policy_fields_not_present"});}
        return result;
    }
}
