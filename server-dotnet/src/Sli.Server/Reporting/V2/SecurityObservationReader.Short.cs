using System.Text.Json.Nodes;
using Sli.Server.Agents.Consumer;
using Sli.Server.Semantic;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Reporting.V2;

internal sealed partial class SecurityObservationReader
{
    internal static async Task<JsonArray> ShortEvents(ISemanticSession db, long domain, int[] codes,
        DateTimeOffset start, DateTimeOffset end, IConfiguration? config, CancellationToken ct, int? limit = null)
    {
        // Facts have a hot copy too. Read them once, from the durable layer;
        // authentication switches by whole UTC days using the journal's boundary.
        string source = EventReadService.ShortSource("$5");
        var rows = await db.QueryAsync($"""
            with short_events as (
                select f.event_id as id,f.time_created_utc,f.event_kind as event_id,f.domain_id,
                    f.actor,f.target,f.source,f.computer,f.method,f.outcome,f.fields,
                    (f.method->>'$server_id')::bigint as server_id,
                    f.method->>'$channel' as channel,f.method->>'$provider' as provider_name,
                    null::date as day,1::bigint as event_count,f.time_created_utc as first_seen_utc,
                    f.time_created_utc as last_seen_utc,''::text as summary_key
                from event_cold_facts f where f.domain_id=$1 and f.event_kind=any($2)
                    and f.time_created_utc>=$3 and f.time_created_utc<$4
                union all
                select a.* from ({source}) a where a.domain_id=$1 and a.event_id=any($2)
                    and a.event_id in (4624,4625,4771,4776)
                    and a.last_seen_utc>=$3 and a.first_seen_utc<$4
            )
            select e.*,s.hostname as dc from short_events e
            join servers s on s.id=e.server_id and s.domain_id=e.domain_id
            where s.role='domain_controller'
                and ((e.event_id=7045 and e.channel='System' and e.provider_name='Service Control Manager')
                    or (e.event_id<>7045 and e.channel='Security' and e.provider_name='Microsoft-Windows-Security-Auditing'))
            order by e.time_created_utc desc,e.id desc limit $6
            """, ct, domain, codes, start, end, EventReadService.ShortBoundary(config), limit);
        var output = new JsonArray();
        foreach (var stored in rows.OfType<JsonObject>())
        {
            var row = EventReadService.ShortRow(stored);
            row["event_db_id"] = stored["id"]?.DeepClone();
            row["short_event"] = true;
            JsonNode? principals = stored["method"]?["$principals"];
            var fields = stored["fields"];
            bool authentication = N(row, "event_id") is 4624 or 4625 or 4771 or 4776;
            // Retained principal dimensions are source values, never identities
            // inferred by joining names. In particular 7045 may have no initiator.
            foreach (string prefix in new[] { "target", "subject" })
            {
                string native = prefix == "target" ? "Target" : "Subject";
                if (principals?[native + "UserSid"] is {} sid) row[prefix + "_user_sid"] = sid.DeepClone();
                if (principals?[native + "UserName"] is {} name) row[prefix + "_user_name"] = name.DeepClone();
            }
            row["source"] = stored["computer"]?.DeepClone();
            row["result_code"] = stored["outcome"]?["Status"]?.DeepClone()
                ?? stored["outcome"]?["FailureCode"]?.DeepClone() ?? stored["outcome"]?["ResultCode"]?.DeepClone();
            row["facts_json"] = new JsonObject {
                ["caller_computer"] = fields?["CallerComputerName"]?.DeepClone(),
                ["workstation"] = principals?["Workstation"]?.DeepClone(),
                ["result_code"] = row["result_code"]?.DeepClone()
            };
            if (N(row,"event_id") == 4625)
            {
                string? status = T(stored["outcome"],"Status") ?? T(stored["outcome"],"SubStatus");
                if (T(stored["outcome"],"SubStatus") is {} sub && WorkstationLogonProjection.PositiveHexStatus(sub)) status = sub;
                row["facts_json"]!["failure_status"] = status;
            }
            row["ip_address"] = principals?["IpAddress"]?.DeepClone() ?? principals?["ClientAddress"]?.DeepClone() ?? row["ip_address"]?.DeepClone();
            row["workstation_name"] = principals?["WorkstationName"]?.DeepClone() ?? principals?["Workstation"]?.DeepClone();
            if (!authentication)
            {
                foreach (var (key, native) in new[] { ("service_name", "ServiceName"), ("task_name", "TaskName"),
                    ("service_file", N(row,"event_id") == 7045 ? "ImagePath" : "ServiceFileName"),
                    ("service_account", N(row,"event_id") == 7045 ? "AccountName" : "ServiceAccount"),
                    ("service_start_type", N(row,"event_id") == 7045 ? "StartType" : "ServiceStartType"),
                    ("run_as", "task_user") }) row[key] = fields?[native]?.DeepClone();
                row["task_action"] = string.Join(' ', new[] { T(fields,"task_command"), T(fields,"task_arguments") }.OfType<string>()) is { Length: > 0 } action ? action : null;
                row["process_user_sid"] = row["subject_user_sid"]?.DeepClone();
                row["process_user_name"] = row["subject_user_name"]?.DeepClone();
                row["process_user_domain"] = principals?["SubjectDomainName"]?.DeepClone();
            }
            output.Add(row);
        }
        return output;
    }
}
