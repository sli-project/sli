using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Entities;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Storage.EventReports;

internal sealed partial class EventReadService
{
    // Lifecycle callers are migrated separately. These adapters cannot select
    // the retired event store, including when an old installation passes false.
    internal static bool ShortReads(IConfiguration? configuration) => true;
    internal static bool WorkerShortReads(Func<string,string?> get) => true;

    // Compatibility for Lifecycle (176i1); the retired setting no longer selects a store.
    internal static bool ShortReadsSetting(string? value) => true;

    // Whole UTC days follow the partition/summary boundary; a daily group is
    // never split or counted alongside the same day's individual hot events.
    internal static DateTimeOffset ShortBoundary(IConfiguration? configuration) =>
        new DateTimeOffset(DateTime.UtcNow.Date, TimeSpan.Zero).AddDays(
            -((int.TryParse(configuration?["Sli:Storage:HotRetentionDays"] ?? "14", out int days) && days > 0)
                ? days : throw new EventReadConfigurationException("hot_retention_days_invalid")));

    internal static string ShortSource(string boundary, bool daily = true) => $"""
        select h.event_id as id,h.time_created_utc,h.event_kind as event_id,h.domain_id,
               h.actor,h.target,h.source,h.computer,h.method,h.outcome,h.fields,
               (h.method->>'$server_id')::bigint as server_id,
               h.method->>'$channel' as channel,h.method->>'$provider' as provider_name,
               null::date as day,1::bigint as event_count,h.time_created_utc as first_seen_utc,
               h.time_created_utc as last_seen_utc,''::text as summary_key
        from event_hot h where h.time_created_utc>={boundary}
        """ + (daily ? $"""

        union all
        select null::bigint,d.day::timestamp at time zone 'UTC',d.event_kind,d.domain_id,
               d.actor,d.target,d.source,d.computer,d.method,d.outcome,jsonb_build_object(),
               (d.method->>'$server_id')::bigint,d.method->>'$channel',d.method->>'$provider',
               d.day,d.event_count,d.first_seen_utc,d.last_seen_utc,encode(d.grouping_key,'hex')
        from event_cold_daily d where d.day<({boundary} at time zone 'UTC')::date
        """ : "");

    internal const string ShortJoins = "from short_events e left join servers s on s.id=e.server_id and s.domain_id=e.domain_id";

    internal static JsonObject ShortRow(JsonObject stored)
    {
        var row = (JsonObject)stored.DeepClone();
        row.Remove("subject_user_name"); row.Remove("target_user_name");
        if(row["day"] is {} day) row["day"]=DateTime.Parse(day.ToString(),CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind).ToString("yyyy-MM-dd",CultureInfo.InvariantCulture);
        JsonObject Object(string key) => row[key] is JsonObject obj ? obj :
            JsonNode.Parse(row[key]?.ToString() ?? "{}")!.AsObject();
        var data = new JsonObject();
        foreach (string key in new[] { "fields", "method", "outcome" })
            foreach (var (name, value) in Object(key))
                if (!name.StartsWith('$') && name != "keywords") data[name] = value?.DeepClone();
        var meaning = EventStorageMeaning.Current.Events.FirstOrDefault(m => m.EventId == Long(row,"event_id") &&
            m.Channel.Equals(row["channel"]?.ToString(), StringComparison.OrdinalIgnoreCase) &&
            m.Provider.Equals(row["provider_name"]?.ToString(), StringComparison.OrdinalIgnoreCase));
        void Principal(string prefix, JsonNode? value)
        {
            string? text = value?.ToString(); if (text is null) return;
            if (text.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) row[prefix+"_user_sid"] = text;
            else {
                string[] parts = text.Split('\\', 2);
                row[prefix+"_user_name"] = parts[^1];
                if (parts.Length == 2) row[prefix+"_domain_name"] = parts[0];
            }
        }
        string[] actorFields = meaning?.ActorFields ?? EventStorageMeaning.Current.Common.ActorFields;
        bool actorIsTarget = actorFields.Any(f => f.StartsWith("TargetUser", StringComparison.Ordinal));
        Principal(actorIsTarget ? "target" : "subject", row["actor"]);
        if (!actorIsTarget) Principal("target", row["target"]);
        // Source has already been reduced by the writer; do not reconstruct
        // discarded workstation/IP alternatives, source text, hashes or record IDs.
        row["ip_address"] = System.Net.IPAddress.TryParse(row["source"]?.ToString(), out _) ? row["source"]?.DeepClone() : null;
        row["workstation_name"] = row["ip_address"] is null ? row["source"]?.DeepClone() : null;
        foreach (var (field, name) in new[] { ("logon_type","LogonType"), ("result_code","Status"),
            ("process_name","ProcessName"), ("task_name","TaskName"), ("service_name","ServiceName"),
            ("logon_id","TargetLogonId"), ("object_name","ObjectName") }) row[field] = data[name]?.DeepClone();
        row["event_data"] = data.DeepClone(); row["event_data_json"] = data;
        row["keywords"] = Object("outcome")["keywords"]?.DeepClone();
        return row;
    }

    async Task<List<JsonObject>> ShortRowsAsync(string sql, IReadOnlyDictionary<string,object> parameters, CancellationToken ct) =>
        (await QueryPgAsync(sql, parameters, ct)).Select(ShortRow).ToList();

    async Task<JsonObject> ListShortAsync(EventListInput input, CapabilityDecisionSet capabilities, CancellationToken ct)
    {
        var compiler = new EventSearchSql();
        var parts = new List<string>();
        string Value(object value) => compiler.Value(value);
        if (!capabilities.IsOwner) {
            // Missing/mismatched routing identity cannot defeat a scoped deny.
            parts.Add("s.id is not null and e.channel is not null and e.provider_name is not null");
            if (!capabilities.Capabilities.Contains("events.view")) parts.Add(compiler.Scope(capabilities.Policies
                .Where(p => p.CapabilityKey=="events.view" && p.Valid && p.Effect=="allow").Select(p => p.Scope)));
            foreach (var deny in capabilities.Policies.Where(p => p.CapabilityKey=="events.view" && p.Effect=="deny"))
                parts.Add(deny.Valid ? "not ("+compiler.Scope([deny.Scope])+")" : "false");
        }
        // Old periods select whole daily groups by their UTC day, never by a
        // fabricated event timestamp within that day.
        if (input.From is {} from) parts.Add($"(case when e.day is null then e.time_created_utc>={Value(from)} else e.day>=({Value(from)} at time zone 'UTC')::date end)");
        if (input.To is {} to) parts.Add($"e.time_created_utc<{Value(to)}");
        if (input.Channel is {} channel) parts.Add("e.channel="+Value(channel));
        if (input.Provider is {} provider) parts.Add("lower(e.provider_name)=lower("+Value(provider)+")");
        if (input.EventIds.Length>0) parts.Add("e.event_id in ("+string.Join(',',input.EventIds.Select(id=>Value(id)))+")");
        if (input.Servers.Length>0) parts.Add("s.hostname in ("+string.Join(',',input.Servers.Select(s=>Value(s)))+")");
        string Account(string value, params string[] fields) {
            string normalized=value.Trim().ToLowerInvariant();
            var exact=new[]{normalized,normalized.Split('\\').Last().Split('@')[0]}.Distinct().ToArray();
            bool prefix=value.Length>=3 && !value.All(char.IsAsciiDigit) && !value.StartsWith("0x",StringComparison.OrdinalIgnoreCase) && !value.Replace(".","").All(char.IsAsciiDigit);
            return "("+string.Join(" or ",fields.SelectMany(f=>exact.SelectMany(v=>new[]{
                "lower("+f+")="+Value(v), "lower(split_part("+f+",E'\\\\',2))="+Value(v)
            }.Concat(prefix ? new[]{"starts_with(lower("+f+"),"+Value(v)+")", "starts_with(lower(split_part("+f+",E'\\\\',2)),"+Value(v)+")"} : []))))+")";
        }
        if(input.Subject is {} subject) parts.Add(Account(subject,"e.actor"));
        if(input.Target is {} target) parts.Add(Account(target,"e.target"));
        if(input.Account is {} account) parts.Add(Account(account,"e.actor","e.target"));
        else if(input.Q is {} q) parts.Add("("+Account(q,"e.actor","e.target")+" or e.source="+Value(q)+" or e.fields->>'TargetLogonId'="+Value(q)+(int.TryParse(q,out int kind)?" or e.event_id="+Value(kind):"")+")");
        string where=parts.Count==0 ? "true" : string.Join(" and ",parts.Select(p=>"("+p+")"));
        string cte="with short_events as ("+ShortSource(Value(ShortBoundary(config)))+") ";
        string direction=input.Asc?"asc":"desc", comparison=input.Asc?">":"<";
        int size=Math.Max(input.Limit+1,200),queries=0; long scanned=0;
        var selected=new List<(JsonObject Raw,JsonObject Item)>(); JsonObject? cursor=input.Cursor;
        while(selected.Count<=input.Limit) {
            ct.ThrowIfCancellationRequested();
            string paging=cursor is null ? "" : $" and (e.time_created_utc,coalesce(e.id,0),e.summary_key) {comparison} ({Value(Stamp(cursor["time"]))},{Value(cursor["id"]?.GetValue<long>()??0)},{Value(cursor["group"]?.ToString()??"")})";
            var rows=await ShortRowsAsync(cte+"select e.*,s.hostname as server "+ShortJoins+" where "+where+paging+$" order by e.time_created_utc {direction},coalesce(e.id,0) {direction},e.summary_key {direction} limit {size}",compiler.Parameters,ct);
            queries++;
            logger?.LogInformation("Short event search: batch {Batch}, scanned {Scanned}, matches {Matches}",queries,scanned,selected.Count);
            foreach(var row in rows) {
                scanned++; var item=EventListProjection.Project(row);
                item["event_db_id"]=row["id"]?.DeepClone();
                foreach(string key in new[]{"actor","target","source","computer","day","event_count","first_seen_utc","last_seen_utc"}) item[key]=row[key]?.DeepClone();
                if(!EventListProjection.Matches(item,input)) continue;
                selected.Add((row,item)); if(selected.Count>input.Limit) break;
            }
            if(selected.Count>input.Limit || rows.Count<size) break;
            cursor=ShortCursor(rows[^1]);
        }
        bool more=selected.Count>input.Limit; var visible=selected.Take(input.Limit).ToArray();
        return new JsonObject { ["api_version"]="v1",["items"]=new JsonArray(visible.Select(v=>(JsonNode)v.Item).ToArray()),
            ["has_more"]=more,["next_cursor"]=more?EncodeShortCursor(visible[^1].Raw):null,["query_status"]="ok",["warning"]=null,
            ["filters"]=new JsonObject { ["risk"]=input.Risk,["tier"]=input.Tier,["category"]=input.Category },
            ["performance"]=new JsonObject { ["semantic_filter_before_page"]=true,["semantic_query_count"]=queries,["scanned_rows"]=scanned },["category_counts"]=null };
    }

    internal static JsonObject ShortCursor(JsonObject row) => new() { ["time"]=row["time_created_utc"]?.DeepClone(),
        ["id"]=row["id"]?.DeepClone()??JsonValue.Create(0),["group"]=row["summary_key"]?.DeepClone(),["short"]=true };
    internal static string EncodeShortCursor(JsonObject row) => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(ShortCursor(row).ToJsonString())).TrimEnd('=').Replace('+','-').Replace('/','_');

    readonly Dictionary<long,string> shortResourceIdentities=[];
    static string ShortIdentity(JsonObject row) => new JsonArray(row["server_id"]?.DeepClone(),row["domain_id"]?.DeepClone(),
        row["channel"]?.DeepClone(),row["provider_name"]?.DeepClone(),JsonValue.Create(Stamp(row["time_created_utc"]).ToString("O",CultureInfo.InvariantCulture))).ToJsonString();

    async Task<IReadOnlyList<AccessResource>> ShortResourcesAsync(long id,CancellationToken ct)
    {
        if(id<=0) return [];
        var rows=await QueryPgAsync("with short_events as ("+EntityShortSql.Source("@boundary",daily:false)+") select e.id,e.time_created_utc,e.server_id,e.domain_id,e.channel,e.provider_name "+ShortJoins+" where e.id=@id and s.id is not null",new Dictionary<string,object>{{"id",id},{"boundary",ShortBoundary(config)}},ct);
        if(rows.Count==0) return [];
        if(rows.Count!=1) throw new InvalidDataException("event_core_duplicate");
        var row=rows[0]; if(row["channel"] is null || row["provider_name"] is null) return [];
        shortResourceIdentities[id]=ShortIdentity(row);
        return [new("server",Long(row,"server_id")),new("domain",Long(row,"domain_id")),new("channel",Value:row["channel"]!.ToString())];
    }

    async Task<Dictionary<long,JsonObject>> ShortDetailsAsync(long[] ids,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct)
    {
        if(ids.Length>100 || ids.Any(id=>id<=0)) throw new ArgumentOutOfRangeException(nameof(ids));
        var rows=await EventReportAdmission.ReadAsync(ids,admitted,async (permitted,token)=> {
            if(permitted.Length==0) return new Dictionary<long,JsonObject>();
            var values=await ShortRowsAsync("with short_events as ("+EntityShortSql.Source("@boundary",daily:false)+") select e.*,s.hostname as server "+ShortJoins+" where e.id=any(@ids)",new Dictionary<string,object>{{"ids",permitted},{"boundary",ShortBoundary(config)}},token);
            var result=new Dictionary<long,JsonObject>();
            foreach(var row in values) {
                long id=Long(row,"id");
                if(!shortResourceIdentities.TryGetValue(id,out var identity) || identity!=ShortIdentity(row)) throw new InvalidDataException("event_resource_identity_changed");
                if(!result.TryAdd(id,row)) throw new InvalidDataException("event_core_duplicate");
            }
            return result;
        },ct);
        if(rows.Count==0) return rows;
        string root=new FileAuditHookAdmission(host).PackageRoot()??throw new InvalidOperationException("source_normalizer_bundle_unsupported");
        var normalizer=new KnownBundleNormalizer(root,Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"),Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
        var output=new Dictionary<long,JsonObject>();
        foreach(var (id,row) in rows) output.Add(id,await normalizer.ProjectAsync(row,ct));
        return output;
    }
}
