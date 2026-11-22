using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdParameterHistory
{
    static readonly IReadOnlyDictionary<string, (string Kind, string Field, JsonObject Template)> Parameters =
        AdInfrastructure.ControlTemplates().ToDictionary(parameter => parameter.Template.Text("control_id")!);

    internal static async Task<JsonObject> DetailAsync(NpgsqlConnection db, AdV2Request request, CancellationToken ct)
    {
        var parts = request.Row?.Split(':', 2);
        if (request.Tab != "controls" || parts is not [var rawEntity, var control]
            || !long.TryParse(rawEntity, NumberStyles.None, CultureInfo.InvariantCulture, out long entity) || entity <= 0
            || !Parameters.TryGetValue(control, out var parameter)) throw new KeyNotFoundException();
        if (!int.TryParse(request.Cursor ?? "0", NumberStyles.None, CultureInfo.InvariantCulture, out int offset))
            throw new AdInputException("report_cursor_invalid");

        var versions = await ReadAsync(db, """
            with observations as (
                select v.id, v.valid_from_utc as observed_at_utc, v.attributes_json->'attributes'->$3::text as value
                from ad_context_entity_versions v join entities_v2 e on e.id=v.entity_id
                join storage_v2_entity_type kind on kind.id=e.entity_type_id
                join ad_context_runs r on r.run_id=v.source_run_id and r.domain_id=e.domain_id and r.status='completed'
                where e.domain_id=any($1) and e.id=$2 and entity_v2_is_active(e.id) and
                    ((kind.value='ad_computer' and $4='domain_controller' and v.source_section='domain_health'
                      and v.attributes_json->'attributes'->>'infrastructure_role'='domain_controller')
                    or (kind.value=$4 and v.source_section in ('domain_posture','domain_health')))
            ), observed as (
                select *, lag(value) over(order by observed_at_utc,id) as previous_value
                from observations where value is not null and value <> 'null'::jsonb
                    and value #>> '{}' not in ('','unknown','unavailable','timeout','not_collected','not_evaluated','partial')
            )
            select id as row_id,observed_at_utc,value::text
            from observed where value is distinct from previous_value
            order by observed_at_utc desc,id desc limit $5 offset $6
            """, ct, request.Domains, entity, parameter.Field, parameter.Kind, request.Limit + 1, offset);
        if (versions.Count == 0 && offset == 0) throw new KeyNotFoundException();
        bool hasMore = versions.Count > request.Limit;
        if (hasMore) versions.RemoveAt(request.Limit);
        foreach (var row in versions)
        {
            AdInfrastructure.SetObservedValue(row, JsonNode.Parse(row.Text("value")!));
            row.Remove("value");
        }
        var result = AdV2Store.Result(request.Key, "ok", versions);
        result["has_more"] = hasMore;
        result["next_cursor"] = hasMore ? (offset + versions.Count).ToString(CultureInfo.InvariantCulture) : null;
        return result;
    }

    internal static async Task AddPreviousAsync(NpgsqlConnection db, AdV2Request request, List<JsonObject> controls, CancellationToken ct)
    {
        var comparable = controls.Where(row => row["actual_value"] is not null && row.Text("qualification") != "not_evaluated")
            .DistinctBy(row => row.Text("row_id"))
            .ToDictionary(row => row.Text("row_id")!);
        if (comparable.Count == 0) return;
        var selected = Array(comparable.Values.Select(row => Obj(new
        {
            row_id = row.Text("row_id"), entity_id = row.Int("entity_id"), source_section = row.Text("source_section"),
            field = Parameters[row.Text("control_id")!].Field, value = row["actual_value"]?.DeepClone()
        })));
        var previous = await ReadAsync(db, """
            select selected.row_id, prior.value::text
            from jsonb_to_recordset($2::jsonb) selected(row_id text,entity_id bigint,source_section text,field text,value jsonb)
            join entities_v2 e on e.id=selected.entity_id and e.domain_id=any($1)
            cross join lateral (
                select v.attributes_json->'attributes'->selected.field as value
                from ad_context_entity_versions v join ad_context_runs r on r.run_id=v.source_run_id and r.domain_id=e.domain_id and r.status='completed'
                where v.entity_id=selected.entity_id and v.source_section=selected.source_section and v.valid_to_utc is not null
                    and v.attributes_json->'attributes'->selected.field is distinct from selected.value
                    and v.attributes_json->'attributes'->>selected.field not in ('','unknown','unavailable','timeout','not_collected','not_evaluated','partial')
                order by v.valid_from_utc desc,v.id desc limit 1
            ) prior
            """, ct, request.Domains, selected.ToJsonString());
        foreach (var row in previous)
            AdInfrastructure.SetObservedValue(comparable[row.Text("row_id")!], JsonNode.Parse(row.Text("value")!), "previous");
    }

    internal static async Task<JsonObject> ChangesAsync(NpgsqlConnection db, AdV2Request request, CancellationToken ct)
    {
        var period = request.Params["period"]!;
        if (!int.TryParse(request.Cursor ?? "0", NumberStyles.None, CultureInfo.InvariantCulture, out int offset))
            throw new AdInputException("report_cursor_invalid");
        var fields = Array(Parameters.Select(entry => Obj(new { control_id = entry.Key, kind = entry.Value.Kind, field = entry.Value.Field })));
        var rows = await ReadAsync(db, """
            select e.id as entity_id,e.domain_id,d.fqdn as domain_name,e.display_name as entity_name,
                   p.kind as entity_type,p.control_id,v.id as version_id,v.valid_from_utc as observed_at_utc,
                   (v.attributes_json->'attributes'->p.field)::text as value,
                   (previous.attributes_json->'attributes'->p.field)::text as previous_value,
                   count(*) over() as total
            from entities_v2 e join storage_v2_entity_type kind on kind.id=e.entity_type_id
            join domains d on d.id=e.domain_id
            join ad_context_entity_versions v on v.entity_id=e.id
            join ad_context_runs r on r.run_id=v.source_run_id and r.domain_id=e.domain_id and r.status='completed'
            join ad_context_entity_versions previous on previous.entity_id=e.id and previous.source_section=v.source_section and previous.valid_to_utc=v.valid_from_utc
            join ad_context_runs pr on pr.run_id=previous.source_run_id and pr.domain_id=e.domain_id and pr.status='completed'
            join jsonb_to_recordset($2::jsonb) p(control_id text,kind text,field text) on p.kind=kind.value
                or (p.kind='domain_controller' and kind.value='ad_computer' and v.source_section='domain_health'
                    and v.attributes_json->'attributes'->>'infrastructure_role'='domain_controller')
            where e.domain_id=any($1) and v.source_section in ('domain_posture','domain_health')
                and v.valid_from_utc >= $3 and v.valid_from_utc < $4
                and v.attributes_json->'attributes'->p.field is distinct from previous.attributes_json->'attributes'->p.field
                and v.attributes_json->'attributes'->>p.field not in ('','unknown','unavailable','timeout','not_collected','not_evaluated','partial')
                and previous.attributes_json->'attributes'->>p.field not in ('','unknown','unavailable','timeout','not_collected','not_evaluated','partial')
            order by v.valid_from_utc desc,v.id desc,p.control_id limit $5 offset $6
            """, ct, request.Domains, fields.ToJsonString(), period.Time("from_utc"), period.Time("to_utc"), request.Limit, offset);
        var total = rows.FirstOrDefault().Int("total");
        foreach (var row in rows)
        {
            AdInfrastructure.SetLabel(row, Parameters[row.Text("control_id")!].Template);
            AdInfrastructure.SetObservedValue(row, JsonNode.Parse(row.Text("value")!));
            AdInfrastructure.SetObservedValue(row, JsonNode.Parse(row.Text("previous_value")!), "previous");
            row["row_id"] = row.Text("version_id") + ":" + row.Text("control_id");
            foreach (var key in new[] { "value", "version_id", "total" }) row.Remove(key);
        }
        string state = rows.Count > 0 ? "ok" : "empty";
        if (rows.Count == 0 && offset == 0)
        {
            var observed = await ReadAsync(db, """
                select count(distinct run.domain_id) as domains
                from ad_context_runs run join ad_context_sections section on section.run_id=run.run_id
                where run.domain_id=any($1) and run.status='completed' and section.status='complete'
                    and section.section_name in ('domain_posture','domain_health')
                    and run.observed_at_utc >= $2 and run.observed_at_utc < $3
                """, ct, request.Domains, period.Time("from_utc"), period.Time("to_utc"));
            state = observed[0].Int("domains") == request.Domains.Length ? "empty" : "not_collected";
        }
        var result = AdV2Store.Result(request.Key, state);
        result["collections"]!["parameter_changes"] = Array(rows);
        result["filtered_count"] = state == "not_collected" ? null : total;
        result["has_more"] = offset + rows.Count < total;
        result["next_cursor"] = offset + rows.Count < total ? (offset + rows.Count).ToString(CultureInfo.InvariantCulture) : null;
        result["window"] = Obj(new { from_utc = period.Text("from_utc"), to_utc_exclusive = period.Text("to_utc") });
        return result;
    }
}
