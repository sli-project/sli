using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Entities;
using Sli.Server.Reporting.V2;

namespace Sli.Server.Workstations;

internal static class WorkstationActivityReader
{
    internal static async Task<WorkstationActivity> ReadAsync(NpgsqlConnection db, ReportQueryContext context,
        JsonObject station, DateTimeOffset boundary, CancellationToken ct)
    {
        var from = Ws.Time(context.Params["period"].Text("from_utc"));
        var to = Ws.Time(context.Params["period"].Text("to_utc"));
        string[] channels = new[] { "Security", "System" }
            .Where(channel => WorkstationWorkspaceReader.CanReadChannel(context.Access, station, channel)).ToArray();
        string host = station.Text("host_name") ?? station.Text("display_name") ?? "";
        if (channels.Length == 0) return WorkstationActivity.Rank([], from, to, host);

        bool identities = WorkstationWorkspaceReader.CanReadChannel(context.Access, station, "Security", identities: true);
        string SourceScope(string alias) => $$"""
            {{alias}}.domain_id=@p0 and {{alias}}.method->>'$server_id'=@p1 and
            {{alias}}.method#>>'{$origin,source_instance_id}'=@p2 and {{alias}}.method#>>'{$origin,plugin_id}'='sli.workstations' and
            {{alias}}.method->>'$channel'=any(@p3)
            """;
        string Selection = $"""
            h.time_created_utc<@p5 and
            (h.event_kind in (4688,6416) or h.time_created_utc>=@p4 and h.event_kind in (1102,4624,4625,4719,4720,4732,7045)) and
            {SourceScope("h")}
            """;
        string source = EntityShortSql.Source("@p6", daily: from < boundary)
            .Replace("from event_hot h where ", "from event_hot h where " + Selection + " and ", StringComparison.Ordinal)
            .Replace("from event_cold_facts h where ", "from event_cold_facts h where " + Selection + " and ", StringComparison.Ordinal)
            .Replace("from event_cold_daily d where ", """
                from event_cold_daily d where d.first_seen_utc>=@p4 and d.last_seen_utc<@p5
                    and d.day>=(@p4 at time zone 'UTC')::date and d.day<=(@p5 at time zone 'UTC')::date
                    and d.event_kind in (1102,4624,4625,4719,4720) and
                """ + " " + SourceScope("d") + " and ", StringComparison.Ordinal);
        string programKey = WorkstationActivity.ProgramKeySql("btrim(fields->>'NewProcessName')");

        var rows = await Ws.Rows(db, $$"""
            with source as ({{source}}),
            observations as materialized (
                select id,nullif(summary_key,'') as summary_key,event_id,channel,provider_name,first_seen_utc,last_seen_utc,event_count,
                       case event_id when 4688 then nullif(btrim(fields->>'NewProcessName'),'-')
                                     when 7045 then nullif(btrim(coalesce(fields->>'ImagePath',fields->>'ServiceFileName')),'-') end as path,
                       case when event_id=4688 then lower({{programKey}}) end as program_key,
                       fields->>'ProcessSignatureStatus' as signature_status, fields->>'ProcessDriveType' as drive_type,
                       case event_id when 6416 then fields->>'DeviceDescription'
                                     when 7045 then coalesce(fields->>'ServiceName',target)
                                     when 4732 then case when @p7 then coalesce(fields->>'MemberName',fields->>'MemberSid') end end as name,
                       case when @p7 then
                         case when nullif(nullif(p.account_name,''),'-') is not null then
                           case when nullif(nullif(p.account_domain,''),'-') is not null
                                     and strpos(p.account_name,chr(92))=0 and strpos(p.account_name,'@')=0
                                then p.account_domain||chr(92)||p.account_name else p.account_name end
                         else p.account_sid end
                       end as account,
                       coalesce(outcome->>'LogonType',method->>'LogonType',fields->>'LogonType') as logon_type,
                       fields->>'DeviceId' as device_id,coalesce(fields->>'ClassName',fields->>'ClassId') as device_class,
                       coalesce(method#>>'{$principals,TargetSid}',method#>>'{$principals,TargetUserSid}') as group_sid,
                       method#>>'{$principals,TargetDomainName}' as target_domain
                from source
                cross join lateral (
                    select case when event_id=4688 then coalesce(nullif(nullif(method#>>'{$principals,TargetUserName}','-'),''),
                                  case when coalesce(method#>>'{$principals,TargetUserSid}','S-1-0-0')='S-1-0-0'
                                       then method#>>'{$principals,SubjectUserName}' end)
                                else method#>>'{$principals,TargetUserName}' end as account_name,
                           case when event_id=4688 and nullif(nullif(method#>>'{$principals,TargetUserName}','-'),'') is null
                                  then method#>>'{$principals,SubjectDomainName}' else method#>>'{$principals,TargetDomainName}' end as account_domain,
                           coalesce(nullif(method#>>'{$principals,TargetUserSid}','S-1-0-0'),
                                  case when event_id=4688 then nullif(method#>>'{$principals,SubjectUserSid}','S-1-0-0') end,
                                  case when event_id in (4624,4625) then actor
                                       when event_id=4720 then target
                                       when event_id=4688 then coalesce(target,actor) end) as account_sid
                ) p
            ),
            first_process as (
                select * from observations where first_seen_utc<@p4 and event_id=4688 and path is not null and path<>''
                    and channel='Security' and provider_name='Microsoft-Windows-Security-Auditing'
                order by first_seen_utc,id limit 1
            ),
            previous_programs as (
                select distinct on (program_key) * from observations
                where first_seen_utc>=@p4-@p8 and first_seen_utc<@p4 and event_id=4688 and path is not null
                    and channel='Security' and provider_name='Microsoft-Windows-Security-Auditing'
                order by program_key,first_seen_utc desc,id desc
            ),
            first_program_starts as (
                select distinct on (program_key) * from observations
                where first_seen_utc<@p4 and event_id=4688 and channel='Security'
                    and provider_name='Microsoft-Windows-Security-Auditing'
                    and program_key in (select program_key from observations where first_seen_utc>=@p4 and event_id=4688)
                order by program_key,first_seen_utc,id
            ),
            previous_devices as (
                select distinct on (lower(device_id)) * from observations
                where first_seen_utc<@p4 and event_id=6416 and device_id is not null
                    and channel='Security' and provider_name='Microsoft-Windows-Security-Auditing'
                order by lower(device_id),first_seen_utc,id
            )
            select * from observations where first_seen_utc>=@p4
            union all select * from first_process
            union all select * from previous_programs
            union all select * from first_program_starts
            union all select * from previous_devices
            """, ct, Ws.Number(station, "domain_id"), Ws.Number(station, "server_id").ToString(System.Globalization.CultureInfo.InvariantCulture),
            station.Text("source_instance_id"), channels, from, to, boundary, identities, WorkstationActivity.ProgramHistory);

        return WorkstationActivity.Rank(rows.Select(row => new StationObservation(row["id"]?.GetValue<long>(),
            row.Text("summary_key"), (int)row.Number("event_id"), row.Text("channel") ?? "", row.Text("provider_name") ?? "",
            Ws.Time(row.Text("first_seen_utc")), Ws.Time(row.Text("last_seen_utc")), row.Number("event_count"))
        {
            Path = Clean(row, "path"), Name = Clean(row, "name"), Account = Clean(row, "account"),
            Signed = row.Text("signature_status") switch { "signed" => true, "unsigned" => false, _ => null },
            DriveType = Clean(row, "drive_type"),
            LogonType = Clean(row, "logon_type"), DeviceId = Clean(row, "device_id"), DeviceClass = Clean(row, "device_class"),
            GroupSid = Clean(row, "group_sid"), TargetDomain = Clean(row, "target_domain"),
        }), from, to, host);
    }

    private static string? Clean(JsonObject row, string field) =>
        row.Text(field)?.Trim() is { Length: > 0 } text && text is not ("-" or "—" or "S-1-0-0") ? text : null;
}
