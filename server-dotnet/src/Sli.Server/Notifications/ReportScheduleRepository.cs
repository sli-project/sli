using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
namespace Sli.Server.Notifications;

public sealed class ReportScheduleRepository(IPostgresConnectionFactory connections):IReportScheduleRepository
{
    public const string ScheduleFields="id,owner_user_id,report_key,filters,timezone,local_time,weekday,period_days,language,enabled,revision,created_at";
    // Administrative readers never see source aggregates.
    public const string RunFields="id,schedule_id,schedule_revision,report_key,slot,period_from,period_to,generated_at,quality,truncated,delayed,language";
    public async Task<IReadOnlyList<JsonObject>> ListAsync(bool runs,CancellationToken ct)
    {
        string sql=runs?"select "+RunFields+" from report_schedule_runs order by generated_at desc,id limit 200":
            "select "+ScheduleFields+",array(select subscription_id from report_schedule_subscriptions b where b.schedule_id=report_schedules.id order by subscription_id) as subscription_ids from report_schedules order by id limit 200";
        await using var db=await connections.OpenAsync(ct);await using var cmd=new NpgsqlCommand("select to_jsonb(r) from ("+sql+") r",db);
        var rows=new List<JsonObject>();await using var reader=await cmd.ExecuteReaderAsync(ct);while(await reader.ReadAsync(ct))rows.Add(Project(reader.GetString(0)));return rows;
    }
    static JsonObject Project(string json)
    {
        var row=JsonNode.Parse(json)!.AsObject();
        foreach(string field in new[]{"created_at","slot","period_from","period_to","generated_at"})
            if(row[field] is JsonValue value && value.TryGetValue<string>(out var stamp))row[field]=AssignmentAudit.Stamp(DateTimeOffset.Parse(stamp,System.Globalization.CultureInfo.InvariantCulture));
        return row;
    }
    public async Task<JsonObject> SaveAsync(Principal actor,Guid? id,ReportScheduleInput input,CancellationToken ct)
    {
        if(actor.Type!="session" || actor.Id<1)throw new ReportScheduleException("notifications_access_denied");
        await using var db=await connections.OpenAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);long owner=actor.Id;Guid key=id??Guid.NewGuid();
        if(id.HasValue) {
            await using var old=new NpgsqlCommand("select owner_user_id,revision from report_schedules where id=@id for update",db,tx);old.Parameters.AddWithValue("id",key);
            await using var r=await old.ExecuteReaderAsync(ct);if(!await r.ReadAsync(ct) || r.GetInt64(1)!=input.Revision)throw new ReportScheduleException("notification_schedule_conflict");owner=r.GetInt64(0);
        }
        var recipients=new HashSet<long>{owner};
        foreach(var sub in input.Subscriptions.Order()) {
            await using var cmd=new NpgsqlCommand("select owner_user_id,recipient_user_id,enabled from notification_subscriptions where id=@id for share",db,tx);cmd.Parameters.AddWithValue("id",sub);
            await using var r=await cmd.ExecuteReaderAsync(ct);
            if(!await r.ReadAsync(ct) || r.GetInt64(0)!=owner || input.Enabled && !r.GetBoolean(2))throw new ReportScheduleException("notifications_access_denied");recipients.Add(r.GetInt64(1));
        }
        if(input.Enabled)foreach(var user in recipients) {
            var access=await ReportScheduleAuthority.LoadAsync(connections,user,ct);
            if(access is null || !ReportScheduleAccess.Report(access,input.ReportKey))throw new ReportScheduleException("notifications_access_denied");
        }
        string values="report_key=@report,filters=@filters::jsonb,timezone=@zone,local_time=@time,weekday=@day,period_days=@period,language=@language,enabled=@enabled,revision=revision+1";
        string sql=id.HasValue?"update report_schedules set "+values+" where id=@id returning "+ScheduleFields:
            "insert into report_schedules(id,owner_user_id,report_key,filters,timezone,local_time,weekday,period_days,language,enabled) values(@id,@owner,@report,@filters::jsonb,@zone,@time,@day,@period,@language,@enabled) returning "+ScheduleFields;
        JsonObject saved;
        await using(var cmd=new NpgsqlCommand("with saved as ("+sql+") select to_jsonb(saved) from saved",db,tx)) {
            cmd.Parameters.AddWithValue("id",key);cmd.Parameters.AddWithValue("owner",owner);cmd.Parameters.AddWithValue("report",input.ReportKey);cmd.Parameters.AddWithValue("filters",input.Filters.GetRawText());cmd.Parameters.AddWithValue("zone",input.Timezone);cmd.Parameters.AddWithValue("time",input.LocalTime);cmd.Parameters.AddWithValue("day",NpgsqlDbType.Integer,(object?)input.Weekday??DBNull.Value);cmd.Parameters.AddWithValue("period",input.PeriodDays);cmd.Parameters.AddWithValue("language",input.Language);cmd.Parameters.AddWithValue("enabled",input.Enabled);
            saved=Project((string)(await cmd.ExecuteScalarAsync(ct))!);
        }
        await using(var clear=new NpgsqlCommand("delete from report_schedule_subscriptions where schedule_id=@id",db,tx)){clear.Parameters.AddWithValue("id",key);await clear.ExecuteNonQueryAsync(ct);}
        foreach(var sub in input.Subscriptions) {
            await using var bind=new NpgsqlCommand("insert into report_schedule_subscriptions(schedule_id,subscription_id) values(@id,@sub)",db,tx);bind.Parameters.AddWithValue("id",key);bind.Parameters.AddWithValue("sub",sub);await bind.ExecuteNonQueryAsync(ct);
        }
        // Notification audit is not part of the administrative journal bridge allowlist.
        await using(var audit=new NpgsqlCommand("insert into access_audit_v4(actor_type,actor_id,action,target_type,target_key,details_json,outcome) values(@type,@actor,'notification_schedule_update','notification',@id,@details::jsonb,'ok')",db,tx)) {
            audit.Parameters.AddWithValue("type",actor.Type);audit.Parameters.AddWithValue("actor",actor.Id);audit.Parameters.AddWithValue("id",key.ToString());audit.Parameters.AddWithValue("details",new JsonObject{["id"]=key.ToString(),["revision"]=saved["revision"]!.DeepClone()}.ToJsonString());await audit.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);saved["subscription_ids"]=JsonSerializer.SerializeToNode(input.Subscriptions.Select(v=>v.ToString()));return saved;
    }
}
public static class ReportScheduleAuthority
{
    public static async Task<AccessDecision?> LoadAsync(IPostgresConnectionFactory connections,long user,CancellationToken ct)
    {
        var principal=await new AccessReadService(connections).FindUserAsync(user,ct);if(principal is null)return null;
        var facts=await new AccessFactsRepository(connections).LoadAsync(principal,ct);return new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts));
    }
    public static AccessDecision Compose(JsonElement actor,string? reportKey=null,DateTimeOffset? evaluated=null)
    {
        var subject=actor.GetProperty("subject");var raw=actor.GetProperty("facts");
        if(subject.ValueKind!=JsonValueKind.Object || subject.GetProperty("type").GetString()!="session" || !subject.GetProperty("is_active").GetBoolean() || subject.GetProperty("id").GetInt64()<1)throw new UnauthorizedAccessException();
        string[] expected=["is_owner","groups","role_packages","subject_packages","owner_packages","package_capabilities","direct_capabilities","all_capabilities","package_reports","report_assignments","definitions"];
        if(!expected.ToHashSet().SetEquals(raw.EnumerateObject().Select(p=>p.Name)))throw new FormatException();
        var now=evaluated??DateTimeOffset.UtcNow;long user=subject.GetProperty("id").GetInt64();
        bool Active(JsonElement row)=>
            (row.Get("valid_from").ValueKind is JsonValueKind.Undefined or JsonValueKind.Null || row.Get("valid_from").GetDateTimeOffset()<=now) &&
            (row.Get("valid_until").ValueKind is JsonValueKind.Undefined or JsonValueKind.Null || row.Get("valid_until").GetDateTimeOffset()>now);
        JsonElement[] Rows(string name) {
            var array=raw.GetProperty(name);if(array.ValueKind!=JsonValueKind.Array || array.GetArrayLength()>2048)throw new FormatException();
            return array.EnumerateArray().Where(Active).Select(x=>x.Clone()).ToArray();
        }
        var groups=Rows("groups").Select(r=>r.GetProperty("id").GetInt64()).ToHashSet();
        bool Subject(JsonElement row)=>row.Text("subject_type")=="user" && row.Get("subject_id").GetInt64()==user || row.Text("subject_type")=="group" && groups.Contains(row.Get("subject_id").GetInt64());
        var definitions=Rows("definitions");string accessKey=reportKey=="security.problems"?"security.queue":reportKey??definitions.FirstOrDefault().Text("report_key");
        if(definitions.Length!=1 || definitions[0].Text("report_key")!=accessKey || Rows("package_reports").Concat(Rows("report_assignments")).Any(r=>r.Text("report_key")!=accessKey))throw new FormatException();
        var subjectPackages=Rows("subject_packages").Where(r=>r.Text("source_key")=="user:"+user || groups.Any(g=>r.Text("source_key")=="group:"+g));
        var facts=new AccessFacts(Rows("is_owner").FirstOrDefault().Get("is_owner").ValueKind==JsonValueKind.True,subject.GetProperty("role").GetString()!,
            Rows("role_packages").Concat(subjectPackages).Concat(Rows("owner_packages")).ToArray(),Rows("package_capabilities"),Rows("direct_capabilities").Where(Subject).ToArray(),Rows("all_capabilities"),Rows("package_reports"),Rows("report_assignments").Where(Subject).ToArray(),definitions);
        return new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts));
    }
}
