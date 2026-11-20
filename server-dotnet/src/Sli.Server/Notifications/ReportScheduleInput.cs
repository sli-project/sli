using System.Globalization;
using System.Text.Json;
using Sli.Server.Access;
namespace Sli.Server.Notifications;

public sealed class ReportScheduleException(string code):Exception(code)
{
    public string Code=>Message;
    public int Status=>Code switch {"notifications_access_denied"=>403,"notification_schedule_conflict"=>409,"notification_queue_full"=>429,"invalid_notification_request"=>400,_=>503};
}
public sealed record ReportScheduleInput(string ReportKey,JsonElement Filters,string Timezone,string LocalTime,int? Weekday,int PeriodDays,string Language,bool Enabled,Guid[] Subscriptions,long Revision)
{
    public static ReportScheduleInput Parse(JsonElement body,bool update)
    {
        try {
            var names=new HashSet<string>{"report_key","filters","timezone","local_time","weekday","period_days","language","enabled","subscription_ids"};
            if(update)names.Add("revision");
            if(body.ValueKind!=JsonValueKind.Object || !names.SetEquals(body.EnumerateObject().Select(p=>p.Name)))throw new FormatException();
            string key=body.GetProperty("report_key").GetString()!;var filters=body.GetProperty("filters");
            if(!Choices.TryGetValue(key,out var choices) || filters.ValueKind!=JsonValueKind.Object)throw new FormatException();
            foreach(var f in filters.EnumerateObject())if(!choices.TryGetValue(f.Name,out var values) || f.Value.ValueKind!=JsonValueKind.String || !values.Contains(f.Value.GetString()!))throw new FormatException();
            string zone=body.GetProperty("timezone").GetString()!;
            // Python ZoneInfo accepts IANA names, not platform-specific Windows IDs.
            if(zone.Length>100 || !TimeZoneInfo.TryConvertIanaIdToWindowsId(zone,out _) && zone!="UTC")throw new FormatException();
            _=TimeZoneInfo.FindSystemTimeZoneById(zone);
            string time=body.GetProperty("local_time").GetString()!;
            if(!TimeOnly.TryParseExact(time,"HH:mm",CultureInfo.InvariantCulture,DateTimeStyles.None,out _))throw new FormatException();
            var rawDay=body.GetProperty("weekday");int? day=rawDay.ValueKind==JsonValueKind.Null?null:rawDay.GetInt32();
            int period=body.GetProperty("period_days").GetInt32();string language=body.GetProperty("language").GetString()!;
            bool enabled=body.GetProperty("enabled").GetBoolean();
            if(day is <0 or >6 || period is not (1 or 7 or 30) || language is not ("ru" or "en"))throw new FormatException();
            var ids=body.GetProperty("subscription_ids").EnumerateArray().Select(v=>Identifier(v.GetString()!)).ToArray();
            long revision=update?Positive(body.GetProperty("revision")):0;
            if(ids.Length is <1 or >100 || ids.Distinct().Count()!=ids.Length)throw new FormatException();
            return new(key,filters.Clone(),zone,time,day,period,language,enabled,ids,revision);
        }catch(Exception e) when(e is FormatException or InvalidOperationException or KeyNotFoundException or ArgumentException or TimeZoneNotFoundException or InvalidTimeZoneException or OverflowException or NullReferenceException){throw new ReportScheduleException("invalid_notification_request");}
    }
    public static Guid Identifier(string value)
    {
        // UUID() in the reference also accepts the compact and URN forms.
        string hex=value.Replace("urn:","",StringComparison.Ordinal).Replace("uuid:","",StringComparison.Ordinal).Trim('{','}').Replace("-","",StringComparison.Ordinal);
        return Guid.TryParseExact(hex,"N",out var id)?id:throw new ReportScheduleException("invalid_notification_request");
    }
    static long Positive(JsonElement v)=>v.ValueKind==JsonValueKind.Number && v.TryGetInt64(out var n) && n>0 && n<long.MaxValue?n:throw new FormatException();
    public static readonly IReadOnlyDictionary<string,IReadOnlyDictionary<string,string[]>> Choices=new Dictionary<string,IReadOnlyDictionary<string,string[]>> {
        ["security.problems"]=new Dictionary<string,string[]> {["severity"]=["info","low","medium","high","critical"],["status"]=["new","repeated","confirmed","active","review","false_positive","closed"],["population"]=["open","attention","all"]},
        ["file-audit.mass-operations"]=new Dictionary<string,string[]> {["operation"]=["read","write","delete","rename","delete_right","permissions","share_change","audit_change","access_check","unknown"],["source_kind"]=["server","workstation"]}
    };
}
public static class ReportScheduleCalendar
{
    public static DateTimeOffset Instant(DateTime wall,TimeZoneInfo zone)
    {
        wall=DateTime.SpecifyKind(wall,DateTimeKind.Unspecified);
        for(int i=0;i<=1440;i++,wall=wall.AddMinutes(1)) {
            if(zone.IsInvalidTime(wall))continue;
            var offset=zone.IsAmbiguousTime(wall)?zone.GetAmbiguousTimeOffsets(wall).Max():zone.GetUtcOffset(wall);
            return new DateTimeOffset(wall,offset).ToUniversalTime();
        }
        throw new ReportScheduleException("invalid_notification_request");
    }
    public static DateTimeOffset? Latest(JsonElement schedule,DateTimeOffset now)
    {
        var zone=TimeZoneInfo.FindSystemTimeZoneById(schedule.GetProperty("timezone").GetString()!);
        var local=TimeZoneInfo.ConvertTime(now,zone).Date;var time=TimeOnly.ParseExact(schedule.GetProperty("local_time").GetString()!,"HH:mm",CultureInfo.InvariantCulture);
        var weekday=schedule.GetProperty("weekday");var created=schedule.GetProperty("created_at").GetDateTimeOffset();
        for(int days=0;days<9;days++) {
            var day=local.AddDays(-days);if(weekday.ValueKind!=JsonValueKind.Null && ((int)day.DayOfWeek+6)%7!=weekday.GetInt32())continue;
            var slot=Instant(day.Add(time.ToTimeSpan()),zone);if(slot>=created && slot<=now)return slot;
        }
        return null;
    }
    public static DateTimeOffset Start(JsonElement schedule,DateTimeOffset slot)
    {var zone=TimeZoneInfo.FindSystemTimeZoneById(schedule.GetProperty("timezone").GetString()!);return Instant(TimeZoneInfo.ConvertTime(slot,zone).DateTime.AddDays(-schedule.GetProperty("period_days").GetInt32()),zone);}
}
public static class ReportScheduleAccess
{
    static readonly HashSet<string> FileFields=["identity_basic","technical","security","privilege"];
    public static bool Configure(AccessDecision access,string action)=>access.CoarseRole=="admin" && access.Capabilities.Capabilities.Contains("access.manage") && access.Capabilities.Decide("access.manage").Allowed && ResourceAccessDecisions.ReportAction(access,"notifications.channels",action,null,new HashSet<string>{"technical"}).Allowed;
    public static bool Report(AccessDecision access,string key,string action="view")=>key switch {
        "security.problems"=>ResourceAccessDecisions.ReportAction(access,"security.queue",action,null,new HashSet<string>{"security"}).Allowed,
        "file-audit.mass-operations"=>access.Capabilities.Capabilities.Contains("file-audit.view") && (action!="export" || access.Capabilities.Capabilities.Contains("file-audit.export")) && ResourceAccessDecisions.ReportAction(access,key,action,null,FileFields).Allowed,
        _=>false};
    public static bool FileRoot(AccessDecision access,JsonElement root,string action)
    {
        string Text(string key){var s=root.GetProperty(key).GetString()!;if(s.Length is <1 or >256 || s.Trim()!=s)throw new FormatException();return s;}
        var resource=new AccessResource("file-audit"){PluginId="sli.file-audit",DeviceId=Text("agent_id"),SourceInstanceId=Text("source_instance_id"),CollectionScopeId=Text("collection_scope_id")};
        return ResourceAccessDecisions.Capability(access.Capabilities,"file-audit."+action,[[resource]]).Allowed;
    }
}
