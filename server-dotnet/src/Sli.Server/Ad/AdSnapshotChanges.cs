using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Storage.Lifecycle;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdSnapshotChanges
{
    static readonly JsonObject UserFields=AdV2Store.Resource("user-change-fields");
    internal static List<JsonObject> CompareUsers(JsonObject current,JsonObject previous)
    {
        string Key(JsonObject u)=>u.Text("objectGuid")??u.Text("sid")??u.Text("id")??"None";
        var before=previous["users"]!.AsArray().OfType<JsonObject>().ToDictionary(Key);var after=current["users"]!.AsArray().OfType<JsonObject>().ToDictionary(Key);var rows=new List<JsonObject>();
        void Push(JsonObject user,string kind,string label,string field,JsonNode? old,JsonNode? value,string group,string note="")
        {rows.Add(new JsonObject{["user_id"]=user["id"]?.DeepClone(),["entity_id"]=user["entityId"]?.DeepClone(),["display_name"]=user["displayName"]?.DeepClone()??user["name"]?.DeepClone(),["sam"]=user["samAccountName"]?.DeepClone(),["type"]=kind,["label"]=label,["field"]=field,["before"]=old?.DeepClone(),["after"]=value?.DeepClone(),["change_group"]=UserFields["groups"]?[group]?.DeepClone()??JsonValue.Create(group),["note"]=note});}
        foreach(var(key,user)in after)if(!before.ContainsKey(key))Push(user,"new_object","Новый объект","object",null,JsonValue.Create("Присутствует в текущем снимке"),"lifecycle");
        foreach(var(key,user)in before)if(!after.ContainsKey(key))Push(user,"missing_current","Отсутствует в текущем снимке","object",JsonValue.Create("Присутствовал в предыдущем"),null,"lifecycle","Причина не установлена: объект мог быть удалён, выйти из SearchBase или не попасть в неполный сбор.");
        Dictionary<string,string> Ids(JsonNode? value)
        {
            var map=new Dictionary<string,string>();foreach(var item in value is JsonArray array?array:value is null?new JsonArray():new JsonArray(value.DeepClone()))
                if(item is JsonObject obj)map[obj.Text("id")??obj.Text("sid")??obj.Text("distinguishedName")??"None"]=obj.Text("name")??obj.Text("id")??"None";else map[item?.ToString()??"None"]=item?.ToString()??"None";return map;
        }
        foreach(var(key,user)in after)
        {
            if(!before.TryGetValue(key,out var old))continue;
            foreach(var(field,kind,label,group)in new[]{("enabled","enabled_changed","Enabled","identity"),("lockedOut","locked_changed","LockedOut","authentication")})
            {string a=AdInventoryRows.Bool(old[field])==true?"True":"False",b=AdInventoryRows.Bool(user[field])==true?"True":"False";if(a!=b)Push(user,kind,$"{label}: {a} → {b}",field,JsonValue.Create(a),JsonValue.Create(b),group);}
            foreach(var entry in UserFields["fields"]!.AsArray())
            {string field=entry![0]!.ToString();if(!JsonNode.DeepEquals(old[field],user[field]))Push(user,field+"_changed",entry[1]!.ToString(),field,old[field],user[field],entry[2]!.ToString());}
            string? aManager=old["manager"]?.Text("distinguishedName")??old["manager"]?.Text("name"),bManager=user["manager"]?.Text("distinguishedName")??user["manager"]?.Text("name");
            if(aManager!=bManager)Push(user,"manager_changed","Руководитель","manager",JsonValue.Create(old["manager"]?.Text("name")??aManager),JsonValue.Create(user["manager"]?.Text("name")??bManager),"organization");
            foreach(var(relation,added,removed)in new[]{("direct","Добавлено прямое членство","Удалено прямое членство"),("effective","Добавлено эффективное членство","Удалено эффективное членство")})
            {var a=Ids(old["memberships"]?[relation]);var b=Ids(user["memberships"]?[relation]);foreach(string id in b.Keys.Except(a.Keys).Order(StringComparer.Ordinal))Push(user,relation+"_group_added",added,b[id],null,JsonValue.Create(b[id]),"groups");foreach(string id in a.Keys.Except(b.Keys).Order(StringComparer.Ordinal))Push(user,relation+"_group_removed",removed,a[id],JsonValue.Create(a[id]),null,"groups");}
            var aPrimary=Ids(old["memberships"]?["primary"]);var bPrimary=Ids(user["memberships"]?["primary"]);
            if(!aPrimary.Keys.ToHashSet().SetEquals(bPrimary.Keys))Push(user,"primary_group_changed","Изменена основная группа","primaryGroupID",JsonValue.Create(aPrimary.Values.FirstOrDefault()),JsonValue.Create(bPrimary.Values.FirstOrDefault()),"groups");
            foreach(string name in (old["sourceStates"] as JsonObject??new()).Select(p=>p.Key).Union((user["sourceStates"] as JsonObject??new()).Select(p=>p.Key)).Order(StringComparer.Ordinal))
                if(old["sourceStates"]?[name]?.Text("status")!=user["sourceStates"]?[name]?.Text("status"))Push(user,"source_status_changed","Состояние источника",name,old["sourceStates"]?[name]?["status"],user["sourceStates"]?[name]?["status"],"quality");
        }
        return rows;
    }
    internal static List<JsonObject> CompareComputers(JsonObject current,JsonObject previous,long domain,string? name,DateTimeOffset at)
    {
        Dictionary<string,JsonObject> Objects(JsonObject source)=>source["objects"]!.AsArray().OfType<JsonObject>().Where(r=>r.Text("objectGuid") is not null).ToDictionary(r=>r.Text("objectGuid")!,r=>AdComputerPosture.ReviewObject(r,at));
        var before=Objects(previous);var after=Objects(current);var rows=new List<JsonObject>();
        foreach(string guid in before.Keys.Union(after.Keys).Order(StringComparer.Ordinal))
        {
            before.TryGetValue(guid,out var old);after.TryGetValue(guid,out var value);var obj=value??old!;
            void Push(string kind,string field,JsonNode? a,JsonNode? b)
            {var row=(JsonObject)obj.DeepClone();row["row_id"]=$"{domain}:{guid}:{kind}:{field}";row["domain_id"]=domain;row["domain_name"]=name;row["change_type"]=kind;row["field"]=field;row["before"]=a?.DeepClone();row["after"]=b?.DeepClone();row["observed_at_utc"]=AdInventoryRows.PythonIso(at);row["actor"]=null;row["account_state"]=AdInventoryRows.Bool(obj["enabled"]) switch{true=>"enabled",false=>"disabled",_=>"unknown"};rows.Add(row);}
            if(old is null||value is null){Push(value is null?"missing_current":"new_object","presence",JsonValue.Create(old is not null),JsonValue.Create(value is not null));continue;}
            foreach(var(field,kind)in new[]{("enabled","enabled_changed"),("ou_path","ou_changed"),("operating_system","os_changed"),("computer_type","classification_changed"),("laps_password_expiration_utc","laps_changed")})if(old[field] is not null&&value[field] is not null&&!JsonNode.DeepEquals(old[field],value[field]))Push(kind,field,old[field],value[field]);
            foreach(string field in new[]{"unconstrained","constrained","resource_based"})if(AdInventoryRows.Bool(old["delegation"]?[field]) is {} a&&AdInventoryRows.Bool(value["delegation"]?[field]) is {} b&&a!=b)Push("delegation_changed",field,JsonValue.Create(a),JsonValue.Create(b));
        }
        return rows;
    }
    static readonly JsonObject FieldCategories=AdV2Store.Resource("user-field-categories");
    static bool Visible(JsonObject row,Func<IEnumerable<string>,bool> fields)
    {
        string type=row.Text("type")??"",field=row.Text("field")??"";
        if(type is "source_status_changed")return fields(["identity_basic","technical","security","privilege","contact","hr"])||
            fields(["security"])&&field is "directory" or "exact_last_logon" or "password_last_set" or "last_logon_timestamp";
        if(type.StartsWith("direct_group_",StringComparison.Ordinal)||type.StartsWith("effective_group_",StringComparison.Ordinal)||type=="primary_group_changed")return fields(["privilege"]);
        return FieldCategories.All(p=>fields([p.Key])||!p.Value!.AsArray().Any(k=>k!.ToString()==field));
    }
    public static async Task<JsonObject> ReadAsync(NpgsqlConnection db,AdV2Request request,List<JsonObject> sources,Func<IEnumerable<string>,bool> fields,CancellationToken ct,IConfiguration? config=null)
    {
        bool users=request.Key=="ad.users.v2";var changes=new List<JsonObject>();var missing=new List<string>();bool partial=false;
        var fromTimes=new List<string>();var toTimes=new List<string>();
        foreach(var source in sources)
        {
            var previous=await AdV2Store.PreviousSnapshot(db,source,users?"users_v2":"computers_v6",ct);
            var currentAt=AdInventoryRows.Date(source["observed_at_utc"]);var previousAt=AdInventoryRows.Date(previous?["observed_at_utc"]);
            if(source["snapshot"] is not JsonObject now||previous?["snapshot"] is not JsonObject prior||currentAt is null||previousAt is null||currentAt<=previousAt){missing.Add(source.Text("fqdn")??source.Int("domain_id").ToString());continue;}
            partial|=source.Text("source_state")!="complete"||previous.Text("source_state")!="complete";now=(JsonObject)now.DeepClone();prior=(JsonObject)prior.DeepClone();
            if(config is not null&&SnapshotChangeStore.PostgresReads(config))
            {
                var stored=await SnapshotChangeStore.DisplayAsync(db,Guid.Parse(source.Text("manifest_id")!),source.Int("domain_id"),users?"users_v2":"computers_v6",ct);
                if(stored is null){missing.Add(source.Text("fqdn")??source.Int("domain_id").ToString());continue;}
                changes.AddRange(stored.Value.Items.Where(r=>!users||Visible(r,fields)));
                if(users){if(stored.Value.Header.Text("from_utc") is {} from)fromTimes.Add(from);if(stored.Value.Header.Text("to_utc") is {} to)toTimes.Add(to);}
                continue;
            }
            if(users)
            {
                if(prior["metadata"].Text("observed_at") is {} from)fromTimes.Add(from);
                if(now["metadata"].Text("observed_at") is {} to)toTimes.Add(to);
                foreach(var snapshot in new[]{now,prior})foreach(var user in snapshot["users"]!.AsArray().OfType<JsonObject>())AdInventoryRows.RedactUser(user,fields);
                foreach(var row in CompareUsers(now,prior)){row["observed_at_utc"]=now["metadata"]?["observed_at"]?.DeepClone();changes.Add(row);}
            }
            else changes.AddRange(CompareComputers(now,prior,source.Int("domain_id"),source.Text("fqdn"),currentAt.Value));
        }
        string? q=request.Params.Text("q");if(q is not null)changes=changes.Where(r=>new[]{"display_name","sam","domain_name","computer_type","operating_system","ou_path"}.Any(k=>r.Text(k)?.Contains(q,StringComparison.OrdinalIgnoreCase)==true)).ToList();
        string state=sources.Count==0||missing.Count==sources.Count?"not_collected":partial||missing.Count>0?"partial":sources.Any(s=>s.Time("observed_at_utc")<DateTimeOffset.UtcNow.AddDays(-1))?"stale":changes.Count>0?"ok":"empty";
        var coverage=AdV2Store.Coverage(sources);coverage["comparison_missing_domains"]=Array(missing);coverage["history_mode"]="latest_compatible_agent_pair";var result=AdV2Store.Result(request.Key,state,changes,coverage);
        if(users)
        {
            AdV2Store.Page(result,request,changes);
            result["window"]=new JsonObject{["from_utc"]=fromTimes.Order(StringComparer.Ordinal).FirstOrDefault(),["to_utc"]=toTimes.Order(StringComparer.Ordinal).FirstOrDefault()};
        }
        else
        {
            changes=changes.OrderByDescending(r=>r.Text("observed_at_utc"),StringComparer.Ordinal).ThenByDescending(r=>r.Text("row_id"),StringComparer.Ordinal).ToList();int offset=0;
            if(request.Cursor is {} cursor){int index=changes.FindIndex(r=>r.Text("row_id")==cursor);if(index<0)throw new AdInputException("computer_changes_cursor_invalid");offset=index+1;}
            var page=changes.Skip(offset).Take(request.Limit).ToArray();bool more=offset+page.Length<changes.Count;result["items"]=Array(page);result["filtered_count"]=state=="not_collected"?null:JsonValue.Create(changes.Count);result["has_more"]=more;result["next_cursor"]=more?page[^1].Text("row_id"):null;
        }
        result["collections"]!["changes"]=result["items"]!.DeepClone();return result;
    }
}
