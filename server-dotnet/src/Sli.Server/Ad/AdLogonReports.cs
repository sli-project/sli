using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdLogonReports
{
    internal static JsonObject Result(string key, string rawState, List<JsonObject> rows, JsonObject coverage)
    {
        string state = Sli.Server.Reporting.V2.ReportResult.SourceState(rawState);
        if (state == "ok" && rows.Count == 0) state = "empty";
        coverage = (JsonObject)coverage.DeepClone();
        coverage["state"] = coverage["observation_state"]?.DeepClone();
        coverage["inventory"] = coverage["inventory_state"]?.DeepClone();
        var result = AdV2Store.Result(key, state, rows, coverage);
        AdV2Result.Finish(result);
        return result;
    }
    internal static List<JsonObject> Population(List<JsonObject> sources)
    {
        var computers = new List<JsonObject>();
        foreach (var source in sources.Where(s => s["snapshot"] is not null)) foreach (var raw in source["snapshot"]!["objects"]!.AsArray().OfType<JsonObject>())
        {
            var row = AdInventoryRows.Computer(raw, source, source.Text("observed_at_utc")!, new());
            if (row.Text("computer_type") == "workstation" && row.Int("entity_id") > 0) computers.Add(row);
        }
        return computers;
    }
    public static async Task<JsonObject> ReadAsync(NpgsqlConnection db, AdV2Request r, List<JsonObject> sources, CancellationToken ct)
    {
        var computers = Population(sources);
        if (sources.All(s => s["snapshot"] is null)) return AdV2Store.Result(r.Key, "error", coverage: Obj(new { reason = "inventory_unavailable" }));
        var period = r.Params["period"]!; DateTimeOffset start = period.Time("from_utc"), end = period.Time("to_utc");
        var stateRows = await AdJson.ReadAsync(db, "select backfill_completed,last_cycle_at_utc from what_where_when_projection_state where singleton=true", ct);
        string projection = stateRows.Count == 0 || stateRows[0]["last_cycle_at_utc"] is null ? "not_collected" : stateRows[0]["backfill_completed"]!.GetValue<bool>() ? "available" : "partial";
        var users = await AdV2Store.Snapshots(db, "users_v2", r.Domains, ct);
        var names = users.Where(s => s["snapshot"] is not null).SelectMany(s => s["snapshot"]!["users"]!.AsArray().OfType<JsonObject>()).Where(u => u.Text("samAccountName") is not null).GroupBy(u => u.Text("samAccountName")!.ToLowerInvariant()).Where(g => g.Count() == 1).ToDictionary(g => g.Key, g => g.Single().Text("displayName"));
        string userQuery = (r.Params.Text("user") ?? "").ToLowerInvariant();
        string[] matching = names.Where(p => p.Value?.Contains(userQuery, StringComparison.OrdinalIgnoreCase) == true).Select(p => p.Key).ToArray();
        string userSql = userQuery.Length == 0 ? "" : " and (lower(user_name) like $4 escape E'\\\\' or lower(case when strpos(user_name,E'\\\\')>0 then split_part(user_name,E'\\\\',2) else split_part(user_name,'@',1) end)=any($5))";
        object[] args = userQuery.Length == 0 ? [computers.Select(c => Guid.Parse(c.Text("object_guid")!)).ToArray(), start, end] : [computers.Select(c => Guid.Parse(c.Text("object_guid")!)).ToArray(), start, end, "%" + userQuery.Replace("\\","\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%", matching];
        string scope = " from what_where_when_observations where computer_object_guid=any($1) and observed_at_utc>=$2 and observed_at_utc<$3" + userSql;
        string cursorKind=r.Row is null?"computers":"observations";
        var bindingValues=Obj(new{domains=r.Domains.Order(),user_q=userQuery,from=AdInventoryRows.PythonIso(start),to=AdInventoryRows.PythonIso(end)});
        if(r.Row is null){bindingValues["q"]=(r.Params.Text("q")??"").ToLowerInvariant();bindingValues["with_logons"]=r.Params.Text("with_logons")=="yes";if(r.Descending)bindingValues["descending"]=true;}
        else {if(!long.TryParse(r.Row,out long rowId))throw new KeyNotFoundException();bindingValues["entity_id"]=rowId;}
        string binding=AdCursors.LogonBinding(cursorKind,bindingValues);var after=r.Cursor is null?null:AdCursors.LogonDecode(r.Cursor,cursorKind,binding);
        List<JsonObject> rows;
        JsonObject? activity = null;
        if (r.Row is not null)
        {
            if (!long.TryParse(r.Row, out long entity)) throw new KeyNotFoundException();
            var computer = computers.FirstOrDefault(c => c.Int("entity_id") == entity) ?? throw new KeyNotFoundException();
            args[0] = new[] { Guid.Parse(computer.Text("object_guid")!) };
            if (after is null)
            {
                string zone = TimeZoneInfo.TryConvertWindowsIdToIanaId(r.Timezone, out var iana) ? iana : r.Timezone;
                string day = $"(observed_at_utc at time zone ${args.Length + 1}::text)::date";
                var buckets = await AdJson.ReadAsync(db, $"""
                    with buckets as (
                        select to_char({day}, 'YYYY-MM-DD') as day, min(user_name) as account, count(*) as count
                        {scope}
                        group by grouping sets (({day}), (lower(user_name)))
                    )
                    select day, account, count from buckets where day is not null
                    union all
                    (select day, account, count from buckets where day is null
                     order by count desc, account collate "C" limit 1)
                    """, ct, [..args, zone]);
                activity = Activity(buckets);
            }
            string continuation="";
            if(after is not null){if(after.Int("projection_id")<=0||AdInventoryRows.Date(after["observed_at_utc"]) is not {} positionTime)throw new AdInputException("invalid_cursor");continuation=$" and (observed_at_utc,projection_id)<(${args.Length+1},${args.Length+2})";args=[..args,positionTime,after.Int("projection_id")];}
            rows = await AdJson.ReadAsync(db, "select projection_id,source_event_id,user_name,observed_at_utc" + scope + continuation + $" order by observed_at_utc desc,projection_id desc limit {r.Limit+1}", ct, args);
            foreach (var row in rows)
            {
                string login = row.Text("user_name")!; string key = login.Split('\\')[^1].Split('@')[0].ToLowerInvariant(); string? display = names.GetValueOrDefault(key);
                row["user_display_name"] = display; row["user_identity_state"] = display is null ? "not_found" : "resolved"; row["user_text"] = display is null ? login + " — имя в AD не найдено" : display + " (" + login + ")"; row["source_event_state"] = row.Int("source_event_id") > 0 ? "available" : "unavailable"; if (row.Int("source_event_id") <= 0) row["source_event_id"] = null;
            }
        }
        else
        {
            var summaries = (await AdJson.ReadAsync(db, "select computer_object_guid::text,count(*)::bigint as login_count,max(observed_at_utc) as last_observed_logon_at_utc" + scope + " group by computer_object_guid", ct, args))
                .ToDictionary(s => Guid.Parse(s.Text("computer_object_guid")!));
            rows = [];
            foreach (var computer in computers.OrderBy(c => c.Text("display_name"), StringComparer.OrdinalIgnoreCase).ThenBy(c => c.Int("entity_id")))
            {
                if (r.Params.Text("q") is {} q && !new[] { computer.Text("display_name"), computer.Text("dns_host_name") }.Any(v => v?.Contains(q, StringComparison.OrdinalIgnoreCase) == true)) continue;
                var summary = summaries.GetValueOrDefault(Guid.Parse(computer.Text("object_guid")!));
                long count = summary?.Int("login_count") ?? 0; if ((userQuery.Length > 0 || r.Params.Text("with_logons") == "yes") && count == 0) continue;
                rows.Add(Obj(new { entity_id = computer.Int("entity_id"), domain_id = computer.Int("domain_id"), display_name = computer.Text("display_name"), last_observed_logon_at_utc = summary?.Text("last_observed_logon_at_utc"), login_count = count, observation_state = count > 0 ? "observed" : projection == "partial" ? "partial" : projection == "not_collected" ? "not_collected" : "empty_unverified" }));
            }
            if (r.Descending) rows.Reverse();
        }
        string state = projection == "not_collected" ? "not_collected" : projection == "partial" || sources.Any(s => s.Text("source_state") != "complete") ? "partial" : rows.Count == 0 ? "empty" : "ok";
        var coverage = AdV2Store.Coverage(sources); coverage["observation_state"] = projection; coverage["completeness"] = "unverified";
        var result = Result(r.Key, state, rows, coverage); result["window"] = Obj(new { from_utc = Iso(start), to_utc_exclusive = Iso(end) });
        if (r.Row is null && projection != "not_collected") result["filtered_count"] = rows.Count;
        if (activity is not null) result["computer_logon_activity"] = activity;
        int offset=0;if(r.Row is null&&after is not null){int index=rows.FindIndex(row=>row.Int("entity_id")==after.Int("entity_id")&&row.Text("display_name")?.ToLowerInvariant()==after.Text("display_name"));if(index<0)throw new AdInputException("invalid_cursor");offset=index+1;}
        var page=rows.Skip(offset).Take(r.Limit).ToArray();bool more=rows.Count>offset+page.Length;
        result["items"]=Array(page);result["has_more"]=more;result["next_cursor"]=more?AdCursors.LogonEncode(cursorKind,binding,r.Row is null?Obj(new{display_name=page[^1].Text("display_name")?.ToLowerInvariant(),entity_id=page[^1].Int("entity_id")}):Obj(new{observed_at_utc=page[^1].Text("observed_at_utc"),projection_id=page[^1].Int("projection_id")})):null;
        if (r.Row is not null) foreach (var item in result["items"]!.AsArray().OfType<JsonObject>())
        {
            item["row_id"] = item.Int("projection_id").ToString(CultureInfo.InvariantCulture);
            item.Remove("projection_id");
        }
        return result;
    }

    internal static JsonObject Activity(List<JsonObject> buckets)
    {
        var days = buckets.Where(row => row.Text("day") is not null).OrderBy(row => row.Text("day"), StringComparer.Ordinal).ToArray();
        var counts = days.Select(row => row.Int("count")).Order().ToArray();
        decimal? typical = counts.Length == 0 ? null : ((decimal)counts[(counts.Length - 1) / 2] + counts[counts.Length / 2]) / 2;
        var top = buckets.Where(row => row.Text("day") is null)
            .OrderByDescending(row => row.Int("count")).ThenBy(row => row.Text("account"), StringComparer.Ordinal).FirstOrDefault();
        return Obj(new
        {
            days = days.Select(row => new { day = row.Text("day"), count = row.Int("count") }),
            total = counts.Length > 0 ? (long?)counts.Sum() : null,
            typical,
            top = top is null ? null : new { account = top.Text("account"), count = top.Int("count") }
        });
    }
}
