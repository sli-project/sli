using System.Data;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdLogonPairs
{
    internal static Task<List<JsonObject>> DomainControllers(NpgsqlConnection db,long[] domains,CancellationToken ct) =>
        AdJson.ReadAsync(db,"select id,domain_id from servers where domain_id=any($1) and role='domain_controller' order by id",ct,domains);

    internal static Dictionary<string,bool> Accounts(JsonObject[] users) => users
        .Where(u=>u.Text("samAccountName") is not null)
        .GroupBy(u=>u.Text("samAccountName")!.ToLowerInvariant()).Where(g=>g.Count()==1)
        .ToDictionary(g=>g.Key,g=>
        {
            var account=g.Single();
            return System.Text.RegularExpressions.Regex.IsMatch(account.Text("distinguishedName")??"",@"(?:^|,)OU=ServiceAcc(?:,|$)",System.Text.RegularExpressions.RegexOptions.IgnoreCase)
                || new[]{account.Text("samAccountName"),account.Text("userPrincipalName")?.Split('@')[0],account.Text("displayName"),account.Text("id")?.Split('\\')[^1]}
                    .Any(name=>name is not null&&(name.Contains("service",StringComparison.OrdinalIgnoreCase)||System.Text.RegularExpressions.Regex.IsMatch(name,@"(?:^|[._-])svc(?:[._-]|$)",System.Text.RegularExpressions.RegexOptions.IgnoreCase)));
        });

    // The reference reads the latest retained source, independently of job manifests.
    // An older stand may have source snapshots without any assembled manifest.
    internal static async Task<List<JsonObject>> ContextSnapshots(NpgsqlConnection db,string family,long[] domains,CancellationToken ct)
    {
        bool users=family=="users_v2";
        string source=users ? """
            select snapshot_id::text as snapshot_identity,captured_at_utc as observed_at_utc,source_state,
                null::text as base_inventory_status,null::integer as object_count,payload_sha256,payload_json
            from users_report_v2_snapshots where domain_id=d.id and source_state in ('complete','partial')
            order by captured_at_utc desc,snapshot_id desc limit 1
            """ : """
            select snapshot_uuid::text as snapshot_identity,source_completed_at_utc as observed_at_utc,collection_status as source_state,
                base_inventory_status,object_count,payload_sha256,payload_json
            from computers_v6_source_snapshots where domain_id=d.id
            order by source_completed_at_utc desc,source_snapshot_id desc limit 1
            """;
        var rows = new List<JsonObject>();
        await using (var command = new NpgsqlCommand("""
            select d.id,d.fqdn,s.snapshot_identity,s.observed_at_utc,s.source_state,s.base_inventory_status,
                   s.object_count,encode(s.payload_sha256,'hex'),convert_to(s.payload_json::text,'UTF8')
            from domains d left join lateral (
            """ + source + ") s on true where d.id=any($1) order by d.id", db) { CommandTimeout = 0 })
        {
            command.Parameters.AddWithValue(domains);
            await using var reader = await command.ExecuteReaderAsync(CommandBehavior.SequentialAccess, ct);
            while (await reader.ReadAsync(ct))
            {
                string? TextAt(int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
                var row = new JsonObject
                {
                    ["domain_id"] = reader.GetInt64(0),
                    ["fqdn"] = TextAt(1),
                    ["snapshot_identity"] = TextAt(2),
                    ["observed_at_utc"] = reader.IsDBNull(3) ? null : Iso(reader.GetFieldValue<DateTimeOffset>(3)),
                    ["source_state"] = TextAt(4),
                    ["base_inventory_status"] = TextAt(5),
                    ["object_count"] = reader.IsDBNull(6) ? null : reader.GetInt32(6),
                };
                string? digest = TextAt(7);
                if (!reader.IsDBNull(8))
                {
                    // Avoid retaining the complete snapshot as both text and a JSON tree.
                    await using var stream = reader.GetStream(8);
                    var payload = (await JsonNode.ParseAsync(stream, cancellationToken: ct))!.AsObject();
                    if (AdJobPlugin.Digest(payload) != digest) throw new InvalidDataException("stored_snapshot_hash_mismatch");
                    row["snapshot"] = payload;
                }
                rows.Add(row);
            }
        }
        if (users) return rows;
        foreach(var row in rows)
        {
            if(row["snapshot"] is not JsonObject payload)continue;
            if(!Sli.Server.Domains.HomeComputerSource.Valid(payload))throw new InvalidDataException("stored_snapshot_status_mismatch");
            if(payload["objects"]!.AsArray().Count!=row.Int("object_count"))throw new InvalidDataException("stored_snapshot_object_count_mismatch");
            if(payload["metadata"]!.Text("snapshot_id")!=row.Text("snapshot_identity"))throw new InvalidDataException("stored_snapshot_identity_mismatch");
            if(payload["metadata"]!.Text("collection_status")!=row.Text("source_state"))throw new InvalidDataException("stored_snapshot_status_mismatch");
            string? status=payload["metadata"]!["sources"]!.AsArray().FirstOrDefault(s=>s!.Text("name")=="ad")?.Text("status");
            if(row.Text("base_inventory_status")!=status)throw new InvalidDataException("stored_base_inventory_status_mismatch");
            var aliases=await AdJson.ReadAsync(db,"select normalized_value,entity_id from ad_context_entity_aliases where domain_id=$1 and alias_type='object_guid' and normalized_value=any($2)",ct,row.Int("domain_id"),payload["objects"]!.AsArray().Select(o=>o!.Text("objectGuid")!.ToLowerInvariant()).ToArray());
            var ids=new JsonObject();foreach(var alias in aliases)ids[alias.Text("normalized_value")!]=alias["entity_id"]!.DeepClone();row["entity_ids"]=ids;
        }
        return rows;
    }
    static readonly JsonObject Failures=AdV2Store.Resource("pair-failures");
    internal static JsonObject Failure(string code)
    {if(Failures["_FAILURE_TEXT"]?[code] is null)code="comparison_failed";var result=AdV2Store.Result("ad.new-logon-pairs","error");result["limitations"]=new JsonArray(Obj(new{code,text=Failures["_FAILURE_TEXT"]!.Text(code)}));return result;}
    internal static JsonObject Failure(Exception error,string fallback)
    {
        string code=error is TimeoutException or NpgsqlException { InnerException: TimeoutException }?fallback=="context_read_failed"?"context_read_timeout":"read_timeout":error is PostgresException{SqlState:"57014"}?fallback=="context_read_failed"?"context_read_cancelled":"read_cancelled":Failures["_REASON_CODES"]?.Text(error.Message)??(error is InvalidDataException?fallback=="context_read_failed"?"context_verification_failed":"history_verification_failed":fallback);return Failure(code);
    }
    internal static async Task<(List<JsonObject> Sources, JsonObject? Error)> ReadContextAsync(Func<Task<List<JsonObject>>> load)
    {
        try { return (await load(), null); }
        catch (PostgresException error) when (error.SqlState == PostgresErrorCodes.InsufficientPrivilege) { throw; }
        catch (Exception error) when (error is NpgsqlException or IOException or InvalidDataException or InvalidOperationException or TimeoutException or System.Text.Json.JsonException)
        { return ([], Failure(error, "context_read_failed")); }
    }
    internal sealed record Context(List<JsonObject> Computers, JsonObject[] Users, long[] Servers, bool Partial);
    internal sealed record History(List<JsonObject> Baseline, List<JsonObject> Period, List<JsonObject> Bounds,
        bool BaselineCovered = true, bool PeriodCovered = true, bool BaselineTruncated = false,
        bool PeriodTruncated = false, bool FactsIncomplete = false,
        bool? BaselineBoundsCovered = null, bool? PeriodBoundsCovered = null);

    public static Task<JsonObject> ReadAsync(NpgsqlConnection db, AdV2Request request, IConfiguration config, CancellationToken ct)
        => QueryAsync(request, async () =>
        {
            // Match the reference's context order before attempting any history read.
            var servers = await DomainControllers(db, request.Domains, ct);
            if (servers.Count == 0) throw new InvalidOperationException("logon_domain_controllers_missing");
            var users = await ContextSnapshots(db, "users_v2", request.Domains, ct);
            if (users.All(s => s["snapshot"] is null)) throw new InvalidOperationException("what_where_when_users_snapshot_unavailable");
            var sources = await ContextSnapshots(db, "computers_v6", request.Domains, ct);
            var computers = AdLogonReports.Population(sources);
            if (computers.Count == 0) throw new InvalidOperationException("logon_inventory_unavailable");
            var userRows = users.Where(s => s["snapshot"] is not null).SelectMany(s => s["snapshot"]!["users"]!.AsArray().OfType<JsonObject>()).ToArray();
            // Entity pivots use unique domain-scoped aliases, not optional snapshot fields.
            var aliases = userRows.All(u => u.Text("sid") is null) ? new List<JsonObject>() : await AdJson.ReadAsync(db, """
                select a.normalized_value,min(a.entity_id) as entity_id from ad_context_entity_aliases a
                join entities_v2 e on e.id=a.entity_id
                join storage_v2_entity_type t on t.id=e.entity_type_id and t.value='ad_user'
                where a.domain_id=$1 and a.alias_type='object_sid' and a.normalized_value=any($2)
                group by a.normalized_value having count(distinct a.entity_id)=1
                """, ct, request.Domains.Single(), userRows.Select(u => u.Text("sid")?.ToLowerInvariant()).OfType<string>().Distinct().ToArray());
            foreach (var user in userRows) user["entityId"] = aliases.FirstOrDefault(a => a.Text("normalized_value") == user.Text("sid")?.ToLowerInvariant())?["entity_id"]?.DeepClone();
            return new Context(computers, userRows, servers.Select(s => s.Int("id")).ToArray(), sources.Concat(users).Any(s => s.Text("source_state") != "complete"));
        }, async (context, baseline, start, end) =>
        {
            var prior=await AdAuthenticationHistory.ReadAsync(db,request.Domains.Single(),context.Servers,baseline,start,ct,config:config,forComparison:true);
            var current=await AdAuthenticationHistory.ReadAsync(db,request.Domains.Single(),context.Servers,start,end,ct,config:config,forComparison:true);
            // Retention is not proof of collection coverage.
            return new History(prior.Events,current.Events,[],false,false);
        }, ct);

    internal static async Task<JsonObject> QueryAsync(AdV2Request request, Func<Task<Context>> loadContext,
        Func<Context, DateTimeOffset, DateTimeOffset, DateTimeOffset, Task<History>> loadHistory, CancellationToken ct)
    {
        if (request.Params.Int("baseline_days") is < 1 or > 365) throw new AdInputException("report_parameter_invalid:baseline_days");
        var period = request.Params["period"]!; var start = period.Time("from_utc"); var end = period.Time("to_utc");
        var binding = Obj(new { domain = request.Domains.Single(), period = period.Text("preset"), baseline_days = request.Params.Int("baseline_days"), q = (request.Params.Text("q") ?? "").ToLowerInvariant(), user = (request.Params.Text("user") ?? "").ToLowerInvariant() });
        if (period.Text("preset") == "custom") { binding["start"] = AdInventoryRows.PythonIso(start); binding["end"] = AdInventoryRows.PythonIso(end); }
        var after = request.Cursor is null ? null : AdCursors.Read(request.Cursor, binding);
        if (after is not null)
        {
            if (AdInventoryRows.Date(after["start"]) is not {} pinnedStart || AdInventoryRows.Date(after["end"]) is not {} pinnedEnd || pinnedStart >= pinnedEnd || (pinnedEnd - pinnedStart).TotalDays > 365 || after.Text("first_seen") is null || after.Text("id") is null) throw new AdInputException("invalid_cursor");
            start = pinnedStart; end = pinnedEnd;
        }
        var baseline = start.AddDays(-request.Params.Int("baseline_days"));
        var window = Obj(new { from_utc = AdInventoryRows.PythonIso(start), to_utc_exclusive = AdInventoryRows.PythonIso(end) });
        JsonObject Failed(Exception error, string fallback) { var result = Failure(error, fallback); result["window"] = window.DeepClone(); return result; }
        Context context;
        try { context = await loadContext(); }
        catch (Exception error) when (error is not (UnauthorizedAccessException or AdAccessException or OperationCanceledException or PostgresException { SqlState: "42501" })) { return Failed(error, "context_read_failed"); }
        History history;
        try { history = await loadHistory(context, baseline, start, end); }
        catch (Exception error) when (error is not (UnauthorizedAccessException or AdAccessException or OperationCanceledException or PostgresException { SqlState: "42501" })) { return Failed(error, "history_read_failed"); }
        try
        {
            bool truncated = history.BaselineTruncated || history.PeriodTruncated;
            bool baselineHistory = history.BaselineCovered;
            bool periodCovered = history.PeriodCovered;
            bool unproven = history.Baseline.Concat(history.Period).Any(e => e["authentication_session"]?.Text("completeness") == "unproven");
            bool confirmed = false, incomplete = false;
            var rows = Compute(history.Baseline, history.Period, context.Computers, context.Users, start,
                baselineHistory && !truncated && !history.FactsIncomplete && !context.Partial && !unproven, value => confirmed = value,
                baseline, end, value => incomplete = value);
            rows = rows.Where(r => (request.Params.Text("q") is not {} q || r.Text("computer")!.Contains(q, StringComparison.OrdinalIgnoreCase)) && (request.Params.Text("user") is not {} u || r.Text("user")!.Contains(u, StringComparison.OrdinalIgnoreCase))).ToList();
            if (after is not null) rows = rows.Where(r => string.CompareOrdinal(r.Text("first_seen"), after.Text("first_seen")) > 0 || r.Text("first_seen") == after.Text("first_seen") && string.CompareOrdinal(r.Text("id"), after.Text("id")) > 0).ToList();
            var first = history.Bounds.Select(b => b.Text("first_utc")).OfType<string>().Order(StringComparer.Ordinal).FirstOrDefault();
            var last = history.Bounds.Select(b => b.Text("last_utc")).OfType<string>().OrderDescending(StringComparer.Ordinal).FirstOrDefault();
            bool historyEmpty = first is null && history.Baseline.Count == 0 && history.Period.Count == 0 && !truncated && !history.FactsIncomplete;
            string? Stamp(string? value) => value is null ? null : AdInventoryRows.PythonIso(DateTimeOffset.Parse(value + "+00:00", CultureInfo.InvariantCulture));
            var coverage = Obj(new { baseline_covered = confirmed, baseline_from_utc = AdInventoryRows.PythonIso(baseline), baseline_to_utc_exclusive = AdInventoryRows.PythonIso(start), history_from_utc = Stamp(first), history_to_utc = Stamp(last), truncated, baseline_history_covered = history.BaselineBoundsCovered ?? history.BaselineCovered, period_history_covered = history.PeriodBoundsCovered ?? history.PeriodCovered, period_covered = periodCovered, baseline_truncated = history.BaselineTruncated, period_truncated = history.PeriodTruncated });
            var page = rows.Take(request.Limit).ToArray(); bool more = rows.Count > request.Limit;
            var result = AdV2Store.Result(request.Key, historyEmpty ? "empty" : !confirmed || !periodCovered ? "partial" : rows.Count > 0 ? "ok" : "empty", page, coverage);
            result["window"] = window.DeepClone();
            result["has_more"] = more;
            result["next_cursor"] = more ? AdCursors.Encode(binding, Obj(new { first_seen = page[^1].Text("first_seen"), id = page[^1].Text("id"), start = AdInventoryRows.PythonIso(start), end = AdInventoryRows.PythonIso(end) })) : null;
            var limitations = new JsonArray();
            void Add(string code, string text) => limitations.Add(Obj(new { code, text }));
            if (historyEmpty) Add("history_empty", Failures["_FAILURE_TEXT"]!.Text("history_empty")!);
            if (!baselineHistory) Add("no_baseline", "Базовое окно не покрыто полностью: нет базы сравнения. Отсутствие предыдущих входов не установлено.");
            if (truncated) Add("truncated", "История прочитана частично; даты и счётчики неполны, новизна не определена.");
            if (!history.PeriodCovered) Add("period_missing", "Текущее окно не покрыто сохранёнными наблюдениями всех разрешённых источников. Полнота сбора не подтверждена.");
            if (history.FactsIncomplete) Add("facts_incomplete", "Часть опубликованных фактов недоступна. Результат частичный, новизна не определена.");
            if (incomplete) Add("identity_incomplete", "Часть пользователей или компьютеров не сопоставлена с текущим AD-контекстом либо отсутствует SID. Новизна не определена.");
            if (context.Partial) Add("inventory_partial", "Снимок AD-контекста неполон. Классификация и новизна пар не подтверждены.");
            if (!confirmed && baselineHistory) Add("novelty_unverified", "Ограничения истории или AD-контекста не позволяют подтвердить новизну пар.");
            Add("observations", "Сравнение относится к сохранённым наблюдениям, а не ко всем входам. Полнота сбора не доказана. Сопоставление ПК и классификация пользователей используют текущий AD-контекст.");
            result["limitations"] = limitations;
            return result;
        }
        catch (Exception error) when (error is not (UnauthorizedAccessException or AdAccessException or OperationCanceledException or PostgresException { SqlState: "42501" })) { return Failed(error, "comparison_failed"); }
    }
    internal static List<JsonObject> Compute(List<JsonObject> prior,List<JsonObject> current,List<JsonObject> computers,JsonObject[] users,DateTimeOffset start,bool covered,Action<bool>? completeness=null,DateTimeOffset? baselineStart=null,DateTimeOffset? end=null,Action<bool>? identityIncomplete=null)
    {
        var accounts=Accounts(users);
        var usersBySid = users.Where(u => u.Text("sid") is not null)
            .GroupBy(u => u.Text("sid")!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => (User: g.First(), Unique: g.Count() == 1), StringComparer.OrdinalIgnoreCase);
        var names=new Dictionary<string,HashSet<string>>(StringComparer.OrdinalIgnoreCase); var addresses=new Dictionary<string,HashSet<string>>(); var byGuid=computers.ToDictionary(c=>c.Text("object_guid")!);
        void Add(Dictionary<string,HashSet<string>> index,string key,string guid){if(key.Length==0)return;if(!index.TryGetValue(key,out var values))index[key]=values=[];values.Add(guid);}
        foreach(var c in computers){string guid=c.Text("object_guid")!;foreach(string? name in new[]{c.Text("display_name"),c.Text("dns_host_name")})if(name is not null){Add(names,name,guid);Add(names,name.Split('.')[0],guid);}foreach(var ip in c["ip_addresses"]!.AsArray())if(IPAddress.TryParse(ip!.ToString(),out var parsed))Add(addresses,parsed.MapToIPv6().ToString(),guid);}
        bool incomplete=false;
        var priorUsers=new HashSet<string>();var priorPairs=new HashSet<(string,string)>();var groups=new Dictionary<(string,string),List<JsonObject>>();
        foreach(var e in prior.Concat(current).DistinctBy(AdAccountEvents.Identity))
        {
            var observed=e.Time("time_created_utc");
            if(observed<(baselineStart??DateTimeOffset.MinValue)||observed>=(end??DateTimeOffset.MaxValue)||e.Int("event_id")!=4624)continue;
            string? login=e.Text("target_user_name"),sid=e.Text("target_user_sid");
            // The compact row prioritizes SID over name. Resolve a missing name
            // only from an unambiguous account in the caller's AD context.
            if (login is null && sid is not null && usersBySid.TryGetValue(sid, out var match) && match.Unique)
            {
                login = match.User.Text("samAccountName");
                e["target_user_name"] = login;
            }
            string sam=login?.Split('\\')[^1].ToLowerInvariant()??"";
            if(login is null||login.EndsWith('$')||sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20"||login.ToLowerInvariant() is "system" or "local service" or "network service" or "anonymous logon")continue;
            if(e.Text("logon_type") is {} type && type is not ("2" or "3" or "4" or "5" or "7" or "8" or "9" or "10" or "11"))continue;
            if(!accounts.TryGetValue(sam,out bool service)){incomplete=true;continue;}
            if(service)continue;
            string identity=sid is null or "-" ? ((e.Text("target_domain_name")??"")+"\\"+login).Trim().ToLowerInvariant() : sid.ToLowerInvariant(); if(sid is null or "-") incomplete=true;
            var byName=names.GetValueOrDefault(e.Text("workstation_name")??"")??[];var byIp=IPAddress.TryParse(e.Text("ip_address"),out var ip)?addresses.GetValueOrDefault(ip.MapToIPv6().ToString())??[]:[];
            var candidates=byName.Union(byIp).ToArray();bool conflict=byName.Count>0&&byIp.Count>0&&!byName.SetEquals(byIp);
            bool old=e.Time("time_created_utc")<start;
            if(old)priorUsers.Add(identity);
            if(candidates.Length!=1||conflict){incomplete=true;continue;}
            var pair=(identity,candidates[0]);if(old){priorPairs.Add(pair);continue;}
            if(!groups.TryGetValue(pair,out var events))groups[pair]=events=[];events.Add(e);
        }
        covered &= !incomplete;identityIncomplete?.Invoke(incomplete);
        completeness?.Invoke(covered);var rows=new List<JsonObject>();foreach(var (pair,events) in groups)
        {
            if(priorPairs.Contains(pair))continue;var first=events.OrderBy(e=>e.Time("time_created_utc")).ThenBy(e=>e.Int("id")).First();var computer=byGuid[pair.Item2];string? sid=first.Text("target_user_sid");
            long? entityId = sid is null or "-" || !usersBySid.TryGetValue(sid, out var account)
                ? null : account.User["entityId"]?.GetValue<long>();
            rows.Add(Obj(new{id=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(pair.Item1+"\0"+pair.Item2))),user=first.Text("target_domain_name") is {} domain?domain+"\\"+first.Text("target_user_name"):first.Text("target_user_name"),user_sid=sid,computer=computer.Text("display_name"),computer_guid=pair.Item2,computer_entity_id=computer.Int("entity_id"),user_entity_id=entityId,first_seen=AdInventoryRows.PythonIso(first.Time("time_created_utc")),source_event_id=first["id"]?.DeepClone(),count=events.Sum(e=>e["event_count"] is null?1:e.Int("event_count")),logon_types=events.Select(e=>e.Text("logon_type")).Where(s=>s is not null).Distinct().Order(),sources=events.Select(e=>e.Text("computer")).Where(s=>s is not null).Distinct().Order(),novelty=covered?priorUsers.Contains(pair.Item1)?"new_pair":"new_user":"no_baseline",prior_user_logon=priorUsers.Contains(pair.Item1)?"yes":covered?"no":"unknown"}));
            if(events.Any(e=>e["day"] is not null&&e["event_count"] is null))rows[^1]["count"]=null;
        }
        var sourceRows=current.Where(e=>e["id"] is not null).GroupBy(e=>e.Int("id")).ToDictionary(g=>g.Key,g=>g.First());
        foreach(var row in rows) if(sourceRows.TryGetValue(row.Int("source_event_id"),out var sourceRow))
            foreach(string key in new[]{"read_representation","source_event_state","authentication_session"}) if(sourceRow[key] is {} value)row[key]=value.DeepClone();
        return rows.OrderBy(r=>r.Text("first_seen"),StringComparer.Ordinal).ThenBy(r=>r.Text("id"),StringComparer.Ordinal).ToList();
    }
}
