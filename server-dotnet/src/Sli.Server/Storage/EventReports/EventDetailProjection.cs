using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Storage.History;

namespace Sli.Server.Storage.EventReports;
internal static class EventDetailProjection
{
    static readonly string[] Priority=["SubjectUserName","SubjectDomainName","TargetUserName","TargetDomainName","IpAddress","WorkstationName","LogonType","LogonProcessName","AuthenticationPackageName","ProcessName","TaskName","ServiceName","MemberName","GroupName","TargetServerName","Status","SubStatus"];
    internal static JsonObject Normalize(JsonObject input,IReadOnlyList<int> scheduledTaskFamily)
    {
        var row=(JsonObject)input.DeepClone();
        JsonObject data=ParseObject(input["event_data_json"]);
        string message=Value(input["message_text"]).Trim();
        row["subject"]=Principal(input,"subject"); row["target"]=Principal(input,"target");
        string[] source=[Value(input["ip_address"]).Trim(),Value(input["workstation_name"]).Trim(),Value(input["computer"]).Trim()];
        row["source"]=source.Any(x=>x.Length>0) ? string.Join(" / ",source.Where(x=>x.Length>0)) : "—";
        row["event_data"]=data.DeepClone(); row["event_data_summary"]=Summary(data);
        row["time_created_utc_display"]=Display(input["time_created_utc"],true);
        row["time_created_local_display"]=string.IsNullOrEmpty(Value(input["time_created_local"])) ? "—" : Display(input["time_created_local"],false);
        var runes=message.EnumerateRunes().ToArray(); row["message_preview"]=runes.Length<=240 ? message : string.Concat(runes.Take(239).Select(r=>r.ToString()))+"…";
        row["message_text"]=message; row["investigation_links"]=Links(input,data,scheduledTaskFamily,null);
        return row;
    }
    static JsonObject ParseObject(JsonNode? value)
    {
        if(value is JsonObject obj) return (JsonObject)obj.DeepClone();
        if(value is not JsonValue) return [];
        try { return JsonNode.Parse(value.ToString()) as JsonObject ?? []; }
        catch(JsonException) { return []; }
    }
    static string Principal(JsonObject row,string role)
    {
        string domain=Value(row[$"{role}_domain_name"]).Trim(), name=Value(row[$"{role}_user_name"]).Trim(), sid=Value(row[$"{role}_user_sid"]).Trim();
        return name.Length>0 ? domain.Length>0 ? domain+"\\"+name : name : sid.Length>0 ? sid : "—";
    }
    static string Summary(JsonObject data)
    {
        var parts=new List<string>();
        foreach(string key in Priority) { var value=data[key]; if(value is not null && Value(value) is not ("" or "-")) parts.Add(key+"="+Value(value)); }
        if(parts.Count==0) foreach(var (key,value) in data.Take(12)) if(value is not null && Value(value)!="") parts.Add(key+"="+Value(value));
        return parts.Count>0 ? string.Join("; ",parts) : "—";
    }
    static string Value(JsonNode? value)
    {
        if(value is null) return "";
        if(value is JsonValue v && v.GetValueKind()==JsonValueKind.False) return "False";
        if(value is JsonValue w && w.GetValueKind()==JsonValueKind.True) return "True";
        return value.ToString();
    }
    static string Display(JsonNode? value,bool suffix)
    {
        string text=Value(value); if(text.Length==0) return "—";
        try { var parsed=SourceTimestamp.Parse(text,false); return parsed.ToString("dd.MM.yyyy HH:mm:ss",CultureInfo.InvariantCulture)+(suffix ? " UTC" : ""); }
        catch(InvalidDataException) { return text; }
    }
    static string Query(params (string Key,string Value)[] values) => string.Join("&",values.Select(x=>Uri.EscapeDataString(x.Key)+"="+Uri.EscapeDataString(x.Value).Replace("%20","+")));
    internal static string Detail(string? user=null,string? ip=null,string? logon=null,string? server=null,string? channel=null,string? from=null,string? to=null,string order="desc",IReadOnlyList<int>? eventIds=null)
    {
        var parts=new List<(string,string)> { ("limit","300"),("order",order) };
        if(eventIds is { Count:>0 }) parts.Add(("event_id",string.Join(",",eventIds)));
        if(!string.IsNullOrEmpty(channel)) parts.Add(("channel",channel)); if(!string.IsNullOrEmpty(server)) parts.Add(("server",server));
        if(from is not null) parts.Add(("time_from",from)); if(to is not null) parts.Add(("time_to",to));
        if(!string.IsNullOrEmpty(user)) parts.Add(("user",user)); if(!string.IsNullOrEmpty(ip)) parts.Add(("ip",ip)); if(!string.IsNullOrEmpty(logon)) parts.Add(("logon_id",logon));
        return "/reports/event-details.html?"+Query(parts.ToArray());
    }
    static (string From,string To)? Window(string value,int minutes)
    {
        try { var time=SourceTimestamp.Parse(value,false); return (Iso(time.AddMinutes(-minutes)),Iso(time.AddMinutes(minutes))); }
        catch(InvalidDataException) { return null; }
        catch(ArgumentOutOfRangeException) { return null; }
    }
    static string Iso(DateTimeOffset value) => value.ToString(value.Ticks%TimeSpan.TicksPerSecond==0 ? "yyyy-MM-dd'T'HH:mm:sszzz" : "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz",CultureInfo.InvariantCulture);
    static JsonArray Links(JsonObject row,JsonObject data,IReadOnlyList<int> scheduledTaskFamily,IReadOnlyList<int>? relatedEventIds)
    {
        string server=Value(row["server"]).Trim(), channel=Value(row["channel"]).Trim(), time=Value(row["time_created_utc"]).Trim();
        string target=Value(row["target_user_name"]).Trim(), subject=Value(row["subject_user_name"]).Trim();
        string user=target.Length>0 && target!="-" ? target : subject, ip=Value(row["ip_address"]).Trim(), logon=Value(row["logon_id"]).Trim();
        var links=new JsonArray(); void Add(string label,string url)=>links.Add(new JsonObject { ["label"]=label,["url"]=url });
        if(user.Length>0) { Add("Цепочка учетной записи","/reports/account-timeline.html?"+Query(("q",user),("limit","500"),("order","asc"))); Add("Тот же пользователь",Detail(user:user,server:server,channel:"Security")); Add("Сущность: учетная запись","/reports/entity-details.html?"+Query(("q",user),("limit","300"))); }
        if(ip.Length>0 && ip is not ("-" or "::1" or "127.0.0.1")) { Add("Тот же IP",Detail(ip:ip,server:server)); Add("Сущность: IP","/reports/entity-details.html?"+Query(("q",ip),("role","source"),("limit","300"))); }
        if(logon.Length>0 && logon is not ("-" or "0x0")) { Add("Тот же LogonId",Detail(logon:logon,server:server)); Add("Сущность: сеанс","/reports/entity-details.html?"+Query(("q",logon),("role","context"),("limit","300"))); }
        if(Window(time,15) is {} near) Add("Соседние события ±15 минут",Detail(server:server,from:near.From,to:near.To));
        if(server.Length>0 && relatedEventIds is { Count:>0 } && int.TryParse(Value(row["event_id"]),out int eventId) && scheduledTaskFamily.Contains(eventId))
            Add("Задания планировщика на этом DC",Detail(server:server,eventIds:relatedEventIds));
        string task=Value(data["TaskName"]).Trim();
        if(task.Length>0) { var parts=new List<(string,string)> { ("q",task),("channel",channel),("limit","200"),("order","asc") }; if(server.Length>0) parts.Add(("server",server)); if(Window(time,60) is {} window) { parts.Add(("time_from",window.From)); parts.Add(("time_to",window.To)); } Add("Изменения этого задания за период","/reports/search-deep.html?"+Query(parts.ToArray())); }
        if(relatedEventIds is { Count:>0 }) Add("Связанные типы событий",Detail(server:server,eventIds:relatedEventIds));
        return links;
    }
}
