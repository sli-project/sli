using System.Data;
using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

public sealed class AdV2Store(IPostgresConnectionFactory connections, IConfiguration configuration) : IAdV2Store
{
    internal static JsonObject Resource(string name) => JsonNode.Parse(new StreamReader(typeof(AdV2Store).Assembly.GetManifestResourceStream("Sli.Server.Ad." + name + ".json")!).ReadToEnd())!.AsObject();
    static readonly JsonObject Messages = Resource("state-messages");
    public async Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant grant, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        return await AdJson.ReadAsync(db, """
            with effective as (select d.id from domains d
                left join lateral(select max(observed_at_utc) as stamp from ad_context_runs where domain_id=d.id and status='completed' and observed_at_utc<=now()) o on true
                where not d.is_archived and (lower(d.fqdn)=lower((select value from platform_settings where key='reports.domain_fqdn')) or o.stamp is not null)
                order by (lower(d.fqdn)=lower((select value from platform_settings where key='reports.domain_fqdn'))) desc nulls last,o.stamp desc nulls last,d.id limit 1)
            select d.id,d.fqdn as display_name,d.is_archived,observed.observed_at_utc,
                   lower(d.fqdn)=lower((select value from platform_settings where key='reports.domain_fqdn')) as is_preferred,
                   d.id=(select id from effective) as is_report_domain,(select id from effective) as report_domain_id
            from domains d left join lateral(select max(observed_at_utc) as observed_at_utc from ad_context_runs where domain_id=d.id and status='completed') observed on true
            where ($1 or d.id=any($2)) order by d.fqdn,d.id
            """, ct, grant.Kind == DomainGrantKind.All, grant.DomainIds.ToArray());
    }
    internal static JsonObject Result(string key, string state, IEnumerable<JsonObject>? items = null, JsonObject? coverage = null)
    {
        coverage ??= new(); string reason = state switch { "ok" => "query_completed", "empty" => "query_completed_zero_rows", "not_collected" => "collection_not_confirmed", "partial" => "coverage_incomplete", "stale" => "freshness_exceeded", "processing" => "import_or_projection_pending", "denied" => "access_denied", _ => "source_or_storage_error" };
        return new JsonObject { ["contract_id"] = "sli.report-result.v2", ["report_key"] = key, ["state"] = state, ["state_message"] = Messages[state]!.DeepClone(),
            ["state_details"] = Obj(new { reason = coverage.Text("reason") ?? reason, source = coverage["source"]?.DeepClone(), stage = coverage.Text("stage") ?? "query", limitations = new object[0], missing_sources = new object[0], missing_domains = new object[0], observed_at_utc = coverage["observed_at_utc"]?.DeepClone(), stale_since_utc = (string?)null, source_issues = new object[0] }),
            ["items"] = Array(items ?? []), ["has_more"] = false, ["next_cursor"] = null, ["filtered_count"] = null, ["metrics"] = new JsonArray(), ["series"] = new JsonObject(), ["coverage"] = coverage, ["filter_options"] = new JsonObject(), ["limitations"] = new JsonArray(), ["window"] = new JsonObject(), ["collections"] = new JsonObject() };
    }
    public async Task<JsonObject> ReadAsync(AdV2Request request, Func<IEnumerable<string>, bool> fields, CancellationToken ct)
    {
        bool checks=request.Tab=="checks"&&request.Key is "ad.users.v2" or "ad.computers.v6";
        if(checks&&!fields(AdV2Endpoints.Strings(AdV2Endpoints.Definitions[request.Key]!["view_fields"]!["checks"])))return Result(request.Key,"denied");
        try{return await ReadCoreAsync(request,fields,ct);}
        catch(Exception error)when(checks&&error is NpgsqlException or IOException or InvalidDataException or InvalidOperationException or System.Text.Json.JsonException or FormatException)
        {return Result(request.Key,"error",coverage:Obj(new{reason="ad_review_unavailable"}));}
    }
    async Task<JsonObject> ReadCoreAsync(AdV2Request request, Func<IEnumerable<string>, bool> fields, CancellationToken ct)
    {
        if (request.Domains.Length == 0) return Empty(request);
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await using (var command = new NpgsqlCommand("set transaction read only", db, tx)) await command.ExecuteNonQueryAsync(ct);
        JsonObject result;
        if (request.Key == "ad.infrastructure") result = request.Tab switch
        {
            "controls" when request.Action == "detail" => await AdParameterHistory.DetailAsync(db, request, ct),
            "parameter_changes"=>await AdParameterHistory.ChangesAsync(db,request,ct),
            "spn_collisions"=>await AdInfrastructureExtras.SpnAsync(db,request,ct),
            "privileged_changes"=>await AdInfrastructureExtras.PrivilegedAsync(db,request,ct),
            "changes"=>await AdSnapshotHistory.ReadAsync(db,request,configuration,ct),
            _=>await Infrastructure(db,request,ct)
        };
        else if (request.Key == "ad.new-logon-pairs") result = await AdLogonPairs.ReadAsync(db, request, configuration, ct);
        else
        {
            bool users = request.Key == "ad.users.v2";
            var sources = await Snapshots(db, users ? "users_v2" : "computers_v6", request.Domains, ct);
            if (users && request.Action == "detail") result = await AdUserCard.ReadAsync(db, request, sources, fields, configuration, ct);
            else if (request.Key == "ad.computer-logons") result = await AdLogonReports.ReadAsync(db, request, sources, ct);
            else if(users&&request.Tab is "disabled_active" or "temporary_memberships") result=await AdUsersActivity.QueryAsync(db,request,sources,fields,ct,configuration);
            else result = await Inventory(db, request, sources, fields, ct);
        }
        if(result.Text("state")=="error")await tx.RollbackAsync(ct);else await tx.CommitAsync(ct);return result;
    }
    internal static JsonObject Empty(AdV2Request request)
    {
        var result = Result(request.Key, "empty", coverage: Coverage([]));
        result["filtered_count"] = 0;
        if (request.Tab == "changes") result["collections"]!["changes"] = new JsonArray();
        return result;
    }
    internal static async Task<List<JsonObject>> Snapshots(NpgsqlConnection db, string family, long[] domains, CancellationToken ct)
    {
        string table = family == "users_v2" ? "users_report_v2_snapshots" : "computers_v6_source_snapshots", identifier = family == "users_v2" ? "snapshot_id" : "snapshot_uuid",scope=family=="users_v2"?"scope_json":"source_options_json";
        var rows = await AdJson.ReadAsync(db, $"""
            select d.id as domain_id,d.fqdn,m.manifest_id::text,m.coverage_state,s.source_state,s.observed_at_utc,
                   encode(s.payload_sha256,'hex') as payload_sha256,snap.payload_json::text as payload,snap.{scope}::text as scope
            from domains d left join lateral(select manifest_id,coverage_state from ad_snapshot_manifests where domain_id=d.id
                order by slot_start_utc desc,manifest_id desc limit 1) m on true
            left join ad_snapshot_manifest_sources s on s.manifest_id=m.manifest_id and s.family=$2
            left join {table} snap on snap.domain_id=d.id and snap.{identifier}::text=s.source_id and snap.payload_sha256=s.payload_sha256
            where d.id=any($1) order by d.id
            """, ct, domains, family);
        foreach (var row in rows) if (row.Text("payload") is {} text)
        {
            JsonObject payload;
            try
            {
                payload = JsonNode.Parse(text)!.AsObject();
                if (AdJobPlugin.Digest(payload) != row.Text("payload_sha256")) throw new InvalidDataException("ad_snapshot_hash_mismatch");
                if (payload[family == "users_v2" ? "users" : "objects"] is not JsonArray || payload["metadata"] is not JsonObject)
                    throw new InvalidDataException("ad_snapshot_invalid");
            }
            catch (Exception error) when (error is InvalidDataException or System.Text.Json.JsonException or InvalidOperationException)
            {
                row["source_state"] = "unavailable";
                row.Remove("payload");
                continue;
            }
            row["snapshot"] = payload;
            if(family=="computers_v6")
            {
                var aliases=await AdJson.ReadAsync(db,"select normalized_value,entity_id from ad_context_entity_aliases where domain_id=$1 and alias_type='object_guid' and normalized_value=any($2)",ct,row.Int("domain_id"),payload["objects"]!.AsArray().Select(o=>o!.Text("objectGuid")!.ToLowerInvariant()).ToArray());
                var ids=new JsonObject(); foreach(var alias in aliases) ids[alias.Text("normalized_value")!]=alias["entity_id"]!.DeepClone(); row["entity_ids"]=ids;
            }
        }
        return rows;
    }
    internal static async Task<JsonObject?> PreviousSnapshot(NpgsqlConnection db,JsonObject source,string family,CancellationToken ct,DateTimeOffset? at=null)
    {
        if(source["manifest_id"] is null)return null;
        bool users=family=="users_v2";string table=users?"users_report_v2_snapshots":"computers_v6_source_snapshots",identifier=users?"snapshot_id":"snapshot_uuid",scope=users?"scope_json":"source_options_json";
        var rows=await AdJson.ReadAsync(db,$"""
            select m.manifest_id::text,m.domain_id,snap.payload_json::text as payload,encode(s.payload_sha256,'hex') as hash,s.source_state,s.observed_at_utc,snap.{scope}::text as scope
            from (select * from ad_snapshot_manifests where domain_id=$1
                  and (($4::timestamptz is null and slot_start_utc<(select slot_start_utc from ad_snapshot_manifests where manifest_id=$3::uuid))
                       or ($4::timestamptz is not null and slot_start_utc<=$4 and assembled_at_utc<=$4))
                  and slot_start_utc>=now()-interval '365 days'
                  order by slot_start_utc desc,manifest_id desc limit 1)m
            left join ad_snapshot_manifest_sources s on s.manifest_id=m.manifest_id and s.family=$2
            left join {table} snap on snap.domain_id=m.domain_id and snap.{identifier}::text=s.source_id and snap.payload_sha256=s.payload_sha256
            """,ct,source.Int("domain_id"),family,source.Text("manifest_id"),at);
        if(rows.Count==0||rows[0].Text("payload") is not {} payload||rows[0].Text("scope")!=source.Text("scope"))return null;
        var snapshot=JsonNode.Parse(payload)!.AsObject();if(AdJobPlugin.Digest(snapshot)!=rows[0].Text("hash"))throw new InvalidDataException("ad_snapshot_hash_mismatch");
        rows[0]["snapshot"]=snapshot;rows[0]["fqdn"]=source["fqdn"]?.DeepClone();rows[0]["entity_ids"]=source["entity_ids"]?.DeepClone();return rows[0];
    }
    async Task<JsonObject> Inventory(NpgsqlConnection db, AdV2Request request, List<JsonObject> sources, Func<IEnumerable<string>, bool> fields, CancellationToken ct)
    {
        bool users = request.Key == "ad.users.v2";
        if (request.Tab == "checks") return await AdReviewChecks.ReadAsync(db, request, sources, ct,configuration);
        if (request.Tab == "changes") return await AdSnapshotChanges.ReadAsync(db, request, sources, fields, ct,configuration);
        JsonObject? activity=null;
        if(users&&request.Tab is "users" or "all"&&fields(["technical","security","privilege"]))
        {
            var current=AdUsersActivity.Current(sources);
            if(current["metadata"]?["watch_groups"] is JsonArray{Count:>0})activity=await AdUsersActivity.LoadAsync(db,current,request.Domains,request.Params,false,ct,configuration);
        }
        var policy=Obj(new{password_age=365,inactivity=90});var exceptions=new JsonObject();
        if(users)
        {
            var settings=await AdJson.ReadAsync(db,"select key,value from platform_settings where key=any($1)",ct,(object)new[]{"ad.password_max_age_days","ad.inactivity_days","ad.service_account_exceptions"});
            foreach(var setting in settings)
            {
                string key=setting.Text("key")!;
                if(key=="ad.service_account_exceptions")
                {foreach(var entry in JsonNode.Parse(setting.Text("value")??"[]")!.AsArray()){var value=entry is JsonObject obj?obj:new JsonObject{["sid"]=entry?.DeepClone()};if(value.Text("sid") is {} sid)exceptions[sid.ToUpperInvariant()]=value.DeepClone();}}
                else {if(!int.TryParse(setting.Text("value"),out int days)||days is <1 or >3650)throw new InvalidDataException("value_must_be_days_1_3650");policy[key=="ad.inactivity_days"?"inactivity":"password_age"]=days;}
            }
            if(request.Tab=="privileged"&&request.Params.Text("as_of") is {} rawDate)
            {
                var zone=TimeZoneInfo.FindSystemTimeZoneById(request.Timezone);var today=DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow,zone).Date);
                if(!DateOnly.TryParseExact(rawDate,"yyyy-MM-dd",CultureInfo.InvariantCulture,DateTimeStyles.None,out var day)||day>today||day<today.AddDays(-365))throw new AdInputException("report_as_of_invalid");
                var wall=DateTime.SpecifyKind(day.AddDays(1).ToDateTime(TimeOnly.MinValue),DateTimeKind.Unspecified);var cutoff=new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(wall,zone)).AddTicks(-10);
                var historical=new List<JsonObject>();
                foreach(var source in sources)
                {
                    var previous=await PreviousSnapshot(db,source,"users_v2",ct,cutoff);
                    if(previous?["snapshot"] is JsonObject saved)
                    {
                        // A dated slice uses the saved observation, including an unknown time.
                        saved["metadata"]!["observed_at"]=previous["observed_at_utc"]?.DeepClone();
                        if(AdInventoryRows.Date(previous["observed_at_utc"]) is null)
                        {
                            previous["source_state"]="partial";
                            saved["metadata"]!["coverage"]??=new JsonObject();
                            saved["metadata"]!["coverage"]!["state"]="partial";
                        }
                        foreach(var user in saved["users"]!.AsArray())
                        {
                            user!["sourceStates"]??=new JsonObject();
                            user["sourceStates"]!["directory"]??=new JsonObject();
                            user["sourceStates"]!["directory"]!["observed_at"]=previous["observed_at_utc"]?.DeepClone();
                        }
                    }
                    historical.Add(previous??new JsonObject{["domain_id"]=source["domain_id"]?.DeepClone(),["fqdn"]=source["fqdn"]?.DeepClone()});
                }
                sources=historical;
            }
        }
        if (users)
        {
            bool workplaceAllowed = fields(["security", "technical"]) && !(request.Tab == "privileged" && request.Params["as_of"] is not null);
            var workplaceUsers = sources.Where(s => s["snapshot"] is not null)
                .SelectMany(s => s["snapshot"]!["users"]!.AsArray().OfType<JsonObject>()
                    .Select(u => (SourceDomain: s.Int("domain_id"), Domain: u.Int("domainId"), Sid: u.Text("sid")?.ToLowerInvariant() ?? ""))).ToArray();
            var workplaceAccounts = workplaceUsers.GroupBy(u => (u.Domain, u.Sid)).ToDictionary(g => g.Key, g => g.Count());
            var eligibleWorkplaces = workplaceUsers.GroupBy(u => (u.SourceDomain, u.Sid))
                .Where(g => g.Count() == 1 && g.First().Domain == g.Key.SourceDomain && workplaceAccounts[(g.First().Domain, g.Key.Sid)] == 1)
                .Select(g => g.Key).ToHashSet();
            var workplaces = workplaceAllowed ? await AdLastWorkplace.ReadAsync(db, request.Domains,
                eligibleWorkplaces.Select(k => k.Sid).Where(s => s.Length > 0).Distinct().ToArray(), ct, configuration, request.Facts, request.Access, request.Action) : [];
            workplaces = workplaces.Where(p => eligibleWorkplaces.Contains(p.Key)).ToDictionary(p => p.Key, p => p.Value);
            if (request.Tab == "semantic")
            {
                try
                {
                    var ids = sources.Where(s => s["snapshot"] is not null).SelectMany(s => s["snapshot"]!["users"]!.AsArray()).Select(u => u.Int("entityId")).Where(id => id > 0).ToArray();
                    var findings = await AdJson.ReadAsync(db, AdUsersSemanticSql, ct, ids);
                    var workers = await AdJson.ReadAsync(db, "select status,heartbeat_at,expected_interval_seconds,details_json::text as details from runtime_worker_heartbeats where worker_name='semantic'", ct);
                    var worker = workers.FirstOrDefault();
                    if (worker is not null) worker["details_json"] = JsonNode.Parse(worker.Text("details") ?? "{}");
                    return AdUsersTabs.Query(request, sources, policy, fields, exceptions, workplaces, findings.ToDictionary(r => r.Int("entity_id"), r => r.Int("finding_count")), AdUsersTabs.SemanticState(worker));
                }
                catch (PostgresException e) when (e.SqlState == "42501") { return Result(request.Key, "denied"); }
                catch (NpgsqlException) { return Result(request.Key, "error", coverage: Obj(new { reason = "semantic_unavailable" })); }
            }
            if (activity is not null)
            {
                sources = sources.Select(source => (JsonObject)source.DeepClone()).ToList();
                foreach (var source in sources.Where(s => s["snapshot"] is not null))
                    foreach (var user in source["snapshot"]!["users"]!.AsArray().OfType<JsonObject>())
                        AdUsersActivity.Enrich(user, activity);
            }
            var userResult = AdUsersTabs.Query(request, sources, policy, fields, exceptions, workplaces);
            if (activity is not null) AdUsersActivity.ApplyCoverage(userResult, activity, false);
            return userResult;
        }
        var rows = new List<JsonObject>();
        var allRows=new List<JsonObject>();
        var agents=new AdComputerPosture.AgentIndex(await AdComputerPosture.AgentsAsync(db,request.Domains,ct));
        var semantic=await AdJson.ReadAsync(db,"""
            select distinct finding.id as finding_id,linked.entity_id,computer.display_name,finding.title,finding.status,finding.summary,finding.why_it_matters,finding.recommended_action,finding.last_seen_utc
            from findings finding join finding_entities linked on linked.finding_id=finding.id join entities_v2_active computer on computer.id=linked.entity_id
            join storage_v2_entity_type entity_type on entity_type.id=computer.entity_type_id where linked.entity_id=any($1) and entity_type.value='ad_computer'
              and is_semantic_finding_published_v1(finding.id) order by finding.last_seen_utc desc,finding.id desc limit 201
            """,ct,sources.Where(s=>s["entity_ids"] is JsonObject).SelectMany(s=>s["entity_ids"]!.AsObject()).Select(p=>p.Value!.GetValue<long>()).Take(5000).ToArray());
        var semanticIndex=semantic.GroupBy(s=>s.Int("entity_id")).ToDictionary(g=>g.Key,g=>g.ToArray());
        bool inputTruncated=sources.Sum(s=>(s["snapshot"]?["objects"] as JsonArray??[]).Count)>5000;
        foreach (var source in sources.Where(s => s["snapshot"] is not null))
        {
            var snapshot = source["snapshot"]!; string observed = snapshot["metadata"]!.Text("completed_at")!;
            foreach (var node in snapshot["objects"]!.AsArray())
            {
                if(allRows.Count>=5000)break;
                var raw = (JsonObject)node!.DeepClone();
                var row = AdInventoryRows.Computer(raw, source, observed, request.Params);
                row["dns_ip"]=AdComputerPosture.Dns(raw);row["sli_agent"]=AdComputerPosture.Agent(row,source.Int("domain_id"),agents);row["semantic_findings"]=Array(semanticIndex.GetValueOrDefault(row.Int("entity_id"),[]));if(request.QualifyNames)row["display_name"]=source.Text("fqdn")+"\\"+row.Text("display_name");
                allRows.Add(row);if (AdInventoryRows.Matches(request, raw, row, false)) rows.Add(row);
            }
        }
        string state = SourceState(sources, rows.Count);
        if(inputTruncated&&state is "ok" or "empty")state="partial";
        var result = Result(request.Key, state, rows, Coverage(sources));
        result["coverage"]!["truncated"]=inputTruncated;
        result["summary"] = Obj(new { total_computers = allRows.Count });
        result["metrics"]=ComputerMetrics(allRows);
        foreach(var(key,field)in new[]{("os","operating_system"),("os_version","operating_system_version"),("os_family","operating_system_family"),("ou","ou_path"),("ad_site","site_text")})result["filter_options"]![key]=Array(allRows.Select(r=>r.Text(field)??"__missing__").Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).Select(value=>new{value,label=value=="__missing__"?"Нет данных":value}));
        if (request.Params["period"] is {} period) result["window"] = period.DeepClone();
        Page(result, request, rows);
        return result;
    }
    internal static JsonArray ComputerMetrics(List<JsonObject> rows) => Array(new[]
    {
        ("all", "Всего в AD", rows.Count, Obj(new { view = "all" })),
        ("attention", "Требуют внимания", rows.Count(r => r["reasons"] is JsonArray { Count: > 0 }), Obj(new { view = "attention" })),
        ("ws", "Рабочие станции (вкл.)", rows.Count(r => r.Text("computer_type") == "workstation" && AdInventoryRows.Bool(r["enabled"]) == true), Obj(new { view = "workstation_enabled" })),
        ("srv", "Серверы (вкл.)", rows.Count(r => r.Text("computer_type") is "server" or "domain_controller" && AdInventoryRows.Bool(r["enabled"]) == true), Obj(new { view = "server_enabled" })),
        ("unknown", "Тип не определён (вкл.)", rows.Count(r => r.Text("computer_type") == "unknown" && AdInventoryRows.Bool(r["enabled"]) == true), Obj(new { view = "all", type = "unknown", enabled = "enabled" })),
        ("disabled", "Отключены (все типы)", rows.Count(r => AdInventoryRows.Bool(r["enabled"]) == false), Obj(new { view = "all", enabled = "disabled" })),
        ("unknown_state", "Состояние учётной записи не определено", rows.Count(r => AdInventoryRows.Bool(r["enabled"]) is null), Obj(new { view = "all", enabled = "unknown" }))
    }.Select(m => Obj(new { key = m.Item1, label = m.Item2, value = m.Item3, filter = m.Item4 })));

    internal static string SourceState(List<JsonObject> sources, int count)
    {
        // Keep collection failures and pending work distinct even for zero rows.
        var statuses = sources.Select(s => s["snapshot"]?["metadata"]?.Text("collection_status") ?? s.Text("source_state")).ToArray();
        if (statuses.Any(s => s is "failed" or "error" or "unavailable"))
            return sources.Any(s => s["snapshot"] is not null && s.Text("source_state") is not ("failed" or "error" or "unavailable")) ? "partial" : "error";
        if (statuses.Contains("processing")) return "processing";
        if (!sources.Any(s => s["snapshot"] is not null)) return "not_collected";
        if (statuses.All(s => s == "not_collected")) return "not_collected";
        if (statuses.Any(s => s is not ("complete" or "completed"))) return "partial";
        if (sources.Any(s => s["snapshot"] is null)) return "partial";
        if (sources.Any(s => s.Time("observed_at_utc") < DateTimeOffset.UtcNow.AddDays(-1))) return "stale";
        return count == 0 ? "empty" : "ok";
    }
    internal static JsonObject Coverage(List<JsonObject> sources) => Obj(new { domains = sources.Select(s => new { domain_id = s.Int("domain_id"), domain_name = s.Text("fqdn"), state = s.Text("source_state") ?? "not_collected", observed_at_utc = s.Text("observed_at_utc") }), observed_at_utc = sources.Select(s => s.Text("observed_at_utc")).Where(s => s is not null).Order().FirstOrDefault(), freshness_threshold_seconds = 86400,
        stale_domain_count = sources.Count(s => AdInventoryRows.Date(s["observed_at_utc"]) is {} at && at < DateTimeOffset.UtcNow.AddDays(-1)) });
    internal static void Page(JsonObject result, AdV2Request request, List<JsonObject> rows)
    {
        bool computer=request.Key=="ad.computers.v6"&&request.Tab=="computers";string? sort=request.Sort??(computer?"display_name":null);string direction=request.Descending?"desc":"asc";
        if (sort is not null)
        {
            string path = AdV2Endpoints.Definitions[request.Key]!["declaration"]!["columns"]!.AsArray().First(c => c!.Text("key") == sort)!.Text("path") ?? sort;
            JsonNode? Value(JsonObject r) => computer&&sort=="enabled"?AdInventoryRows.Bool(r["enabled"]) is {} enabled?JsonValue.Create(enabled?0:1):null:path.Split('.').Aggregate((JsonNode?)r, (n, p) => n?[p]);
            var present = rows.Where(r => Value(r) is not null).ToArray();
            int Compare(JsonNode? left,JsonNode? right)
            {if(left is JsonValue a&&right is JsonValue b&&a.TryGetValue<decimal>(out var x)&&b.TryGetValue<decimal>(out var y))return x.CompareTo(y);return StringComparer.OrdinalIgnoreCase.Compare(left?.ToString(),right?.ToString());}
            var comparer=Comparer<JsonNode?>.Create(Compare);IOrderedEnumerable<JsonObject> ordered=request.Descending?present.OrderByDescending(Value,comparer):present.OrderBy(Value,comparer);
            if(computer)ordered=request.Descending?ordered.ThenByDescending(r=>r.Text("display_name"),StringComparer.OrdinalIgnoreCase).ThenByDescending(r=>r.Int("entity_id")):ordered.ThenBy(r=>r.Text("display_name"),StringComparer.OrdinalIgnoreCase).ThenBy(r=>r.Int("entity_id"));
            rows=ordered.Concat(rows.Where(r=>Value(r) is null).OrderBy(r=>computer?r.Text("display_name"):null,StringComparer.OrdinalIgnoreCase).ThenBy(r=>computer?r.Int("entity_id"):0)).ToList();
        }
        int offset=0;if(request.Cursor is {} cursor){if(computer){long entity=AdCursors.ComputerDecode(cursor,sort!,direction);int index=rows.FindIndex(r=>r.Int("entity_id")==entity);if(index<0)throw new AdInputException("invalid_computers_v6_cursor");offset=index+1;}else if(!int.TryParse(cursor,out offset)||offset<0)throw new AdInputException("report_cursor_invalid");}
        var page = rows.Skip(offset).Take(request.Limit).ToArray(); bool more = offset + page.Length < rows.Count;
        result["items"] = Array(page); result["filtered_count"] = rows.Count; result["has_more"] = more; result["next_cursor"] = more ? computer?AdCursors.ComputerEncode(sort!,direction,page[^1].Int("entity_id")):(offset + page.Length).ToString(CultureInfo.InvariantCulture) : null;
    }
    internal const string AdUsersSemanticSql = """
        select linked.entity_id,count(distinct finding.id) as finding_count from findings_active finding
        join finding_entities linked on linked.finding_id=finding.id where linked.entity_id=any($1)
        and finding.status in ('new','repeated','confirmed','active','review') and is_semantic_finding_published_v1(finding.id)
        and not semantic_finding_suppressed_v160(finding.id,finding.rule_code) group by linked.entity_id
        """;
    static async Task<JsonObject> Infrastructure(NpgsqlConnection db, AdV2Request request, CancellationToken ct)
    {
        var rows = await AdJson.ReadAsync(db, """
            select e.id as entity_id,e.domain_id,d.fqdn as domain_name,e.display_name,t.value as entity_type,
            v.source_section,v.last_observed_at_utc as observed_at_utc,v.attributes_json::text as record
            from ad_context_entity_versions v join entities_v2 e on e.id=v.entity_id
            join storage_v2_entity_type t on t.id=e.entity_type_id join domains d on d.id=e.domain_id
            join ad_context_runs r on r.run_id=v.source_run_id
            where e.domain_id=any($1) and v.valid_to_utc is null and v.source_section in ('domain_posture','domain_health')
            and r.status='completed' and entity_v2_is_active(e.id) order by e.id limit 5001
            """, ct, request.Domains);
        if(request.QualifyNames)foreach(var row in rows)row["display_name"]=row.Text("domain_name")+"\\"+row.Text("display_name");
        var controls = AdInfrastructure.Compose(rows.Take(5000).ToArray(), request.Params);
        var allControls=AdInfrastructure.Compose(rows.Take(5000).ToArray(),Obj(new{view=request.Params.Text("view")??"overview"}));
        if (request.Tab == "controls" && request.Action == "view" && request.Params.Text("include_previous") == "true")
            await AdParameterHistory.AddPreviousAsync(db, request, controls, ct);
        var coverageRows=await AdJson.ReadAsync(db,"""
            with expected_domains as(select id as domain_id,fqdn as domain_name from domains where id=any($1)),required_sections(section_name) as(values('domain_posture'),('domain_health')),
            latest_section as(select distinct on(run.domain_id,section.section_name)run.domain_id,section.section_name,run.status as run_status,section.status as section_status,section.record_count,run.observed_at_utc
                from ad_context_runs run join expected_domains expected on expected.domain_id=run.domain_id join ad_context_sections section on section.run_id=run.run_id
                where section.section_name in ('domain_posture','domain_health') order by run.domain_id,section.section_name,run.observed_at_utc desc,run.created_at desc,run.run_id desc)
            select expected.domain_id,expected.domain_name,required.section_name,latest.run_status,latest.section_status,latest.record_count,latest.observed_at_utc
            from expected_domains expected cross join required_sections required left join latest_section latest on latest.domain_id=expected.domain_id and latest.section_name=required.section_name order by expected.domain_id,required.section_name
            """,ct,request.Domains);
        string Id(JsonObject r)=>r.Int("domain_id")+":"+r.Text("section_name");
        var missing=coverageRows.Where(r=>r["observed_at_utc"] is null).Select(Id).Order(StringComparer.Ordinal).ToArray();var stale=coverageRows.Where(r=>AdInventoryRows.Date(r["observed_at_utc"]) is not {} at||at<DateTimeOffset.UtcNow.AddDays(-1)).Select(Id).Order(StringComparer.Ordinal).ToArray();var failed=coverageRows.Where(r=>r.Text("run_status") is "failed" or "cancelled"||r.Text("section_status")=="failed").Select(Id).Order(StringComparer.Ordinal).ToArray();var partial=coverageRows.Where(r=>r.Text("run_status")=="partial"||r.Text("section_status")=="partial").Select(Id).Order(StringComparer.Ordinal).ToArray();
        string state=coverageRows.Count==0?"not_collected":failed.Length+partial.Length+missing.Length>0||rows.Count>5000?"partial":stale.Length>0?"stale":controls.Count==0?"empty":"ok";
        var coverage=Obj(new{expected_sections=new[]{"domain_posture","domain_health"},missing,stale,failed,partial,domains=coverageRows,state=state=="ok"?"available":state,freshness_threshold_seconds=86400,observed_at_utc=coverageRows.Select(r=>r.Text("observed_at_utc")).Where(t=>t is not null).Order().FirstOrDefault(),missing_sources=missing.Concat(failed).Concat(partial)});
        var result = Result(request.Key,state,controls,coverage);
        result["filtered_count"]=controls.Count;
        result["metrics"]=Array(new[]{("failed","Не пройдено","danger"),("not_evaluated","Не оценено","warning"),("policy_not_defined","Требование не задано","neutral"),("passed","Пройдено","success")}.Select(p=>Obj(new{key=p.Item1,label=p.Item2,value=allControls.Count(r=>r.Text("qualification")==p.Item1),tone=allControls.Any(r=>r.Text("qualification")==p.Item1)?p.Item3:"neutral",filter=new{qualification=p.Item1}})));
        result["limitations"]=AdInfrastructure.Limitations(coverage);
        if(request.Tab=="semantic")
        {
            var semanticEntities=rows.Take(5000).ToArray();long[] semanticIds=AdInfrastructure.SemanticEntityIds(semanticEntities,request.Params);
            var semantic=await AdJson.ReadAsync(db,"""
                select distinct finding.id as finding_id,linked.entity_id,finding.title,finding.severity,finding.status,finding.summary,finding.why_it_matters,finding.recommended_action,finding.last_seen_utc
                from findings finding join finding_entities linked on linked.finding_id=finding.id where linked.entity_id=any($1) and is_semantic_finding_published_v1(finding.id)
                order by finding.last_seen_utc desc,finding.id desc limit 201
                """,ct,semanticIds);
            result["collections"]!["semantic"]=AdInfrastructure.SemanticRows(semantic,semanticEntities,request.Params);
        }
        return result;
    }
}
