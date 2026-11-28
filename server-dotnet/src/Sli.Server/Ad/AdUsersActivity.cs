using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

// Observed sequences are evidence for review, never proof of use of a granted right.
internal static class AdUsersActivity
{
    internal const string Chain = "investigation.group.membership.removed-after-add";
    static readonly Dictionary<int,int> Pairs = new() { [4728]=4729, [4732]=4733, [4756]=4757 };
    static readonly int[] MembershipIds = [4728,4729,4732,4733,4756,4757];
    internal static (AdPeriod Period,int Minutes,int Repeats) Window(JsonObject parameters)
    {
        DateTimeOffset Instant(JsonNode? node,DateTimeOffset fallback) => node is null ? fallback : DateTimeOffset.Parse(node.ToString(),CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal).ToUniversalTime();
        var end=Instant(parameters["period"]?["to_utc"],DateTimeOffset.UtcNow);
        var start=Instant(parameters["period"]?["from_utc"],end.AddDays(-7));
        long minutes=parameters.Int("max_minutes"),repeats=parameters.Int("min_repeats");
        if(minutes==0)minutes=60;if(repeats==0)repeats=1;
        if(end<=start||end-start>TimeSpan.FromDays(31))throw new AdInputException("users_activity_period_invalid");
        if(minutes is <1 or >1440||repeats is <1 or >100)throw new AdInputException("users_activity_threshold_invalid");
        return (new(start,end),(int)minutes,(int)repeats);
    }
    internal static (string Sql,object?[] Args) EventSql(long[]? domains,int[] codes,AdPeriod period,IConfiguration? config=null)
    {
        string scope=domains is null?"":" and h.domain_id=any($4)";
        return (AdAccountEvents.Source(config, scope: scope)+" select e.* from account_events e where e.time_created_utc>=$2 and e.time_created_utc<$3 order by e.time_created_utc,e.id,e.summary_key",
            domains is null?[codes,period.Start,period.End]:[codes,period.Start,period.End,domains]);
    }

    private static async Task<long> UnknownLogonsAsync(NpgsqlConnection db, long[] domains, AdPeriod period,
        IEnumerable<(long Domain, string Sid)> identities, IConfiguration? config, CancellationToken ct)
    {
        const string accounts = "unnest($5::bigint[], $6::text[]) account(domain_id,sid)";
        string cold = AdAccountEvents.Source(config, scope: " and h.domain_id=any($4)", hot: false);
        var rows = await Read(db, cold + $"""
            select (select count(*) from event_hot h
                join servers recorder on recorder.id=h.ad_user_logon_recorder435
                    and recorder.domain_id=h.domain_id and recorder.role='domain_controller'
                where h.ad_user_logon_recorder435 is not null and h.domain_id=any($4)
                    and h.time_created_utc >= {AdAccountEvents.Boundary(config)}
                    and h.time_created_utc >= $2 and h.time_created_utc < $3
                    and not exists (select 1 from {accounts} where account.domain_id=h.domain_id
                        and account.sid=case when h.actor ilike 'S-1-%' then {AdAccountEvents.ExactSid} end))
                + (select count(*) from account_events e where e.time_created_utc >= $2 and e.time_created_utc < $3
                    and not exists (select 1 from {accounts} where account.domain_id=e.domain_id
                        and account.sid=btrim(e.target_user_sid,{AdAccountEvents.Whitespace}) collate "C")) as total
            """, ct, new[] { 4624 }, period.Start, period.End, domains,
            identities.Select(key => key.Domain).ToArray(), identities.Select(key => key.Sid).ToArray());
        return rows[0].Int("total");
    }
    // Q500 forbids elapsed-time cutoffs and arbitrary source scan caps.
    static async Task<List<JsonObject>> Read(NpgsqlConnection db,string sql,CancellationToken ct,params object?[] args)
    {
        await using var command=new NpgsqlCommand(sql,db){CommandTimeout=0};
        foreach(var arg in args)command.Parameters.Add(new(){Value=arg??DBNull.Value});
        await using var reader=await command.ExecuteReaderAsync(ct);var rows=new List<JsonObject>();
        while(await reader.ReadAsync(ct))
        {
            var row=new JsonObject();
            for(int i=0;i<reader.FieldCount;i++)row[reader.GetName(i)]=reader.IsDBNull(i)?null:JsonSerializer.SerializeToNode(reader.GetValue(i));
            rows.Add(row);
        }
        return rows;
    }
    static JsonObject Facts(JsonObject e) => e["facts_json"] is JsonObject facts?facts:JsonNode.Parse(e.Text("facts_json")??"{}")!.AsObject();
    internal static JsonObject Shape(IEnumerable<JsonObject> events,Dictionary<(long,string),JsonObject> identities,Dictionary<(long,string),JsonObject> groups,Dictionary<long,JsonObject> candidates,int maxMinutes,int minRepeats)
    {
        bool Interpreted(JsonObject row)=>row.Text("processing_status")=="normalized"||row.Text("read_representation") is "short_event" or "daily_summary";
        var ordered=events.GroupBy(AdAccountEvents.Identity).Select(g=>g.Last()).OrderBy(e=>e.Time("time_created_utc")).ThenBy(e=>e.Int("id")).ToArray();
        var auth=new Dictionary<(long,string),List<JsonObject>>();var lifecycle=new Dictionary<(long,string),List<JsonObject>>();var membership=new Dictionary<(long,string,string),List<JsonObject>>();int unknown=0;
        foreach(var e in ordered.Where(Interpreted))
        {
            int code=(int)e.Int("event_id");string? sid=e.Text(code==6272?"subject_user_sid":"target_user_sid");long domain=e.Int("domain_id");
            string? expected=code switch{4624=>"authentication.session.created",6272=>"remote_access.authentication.allowed",4722=>"directory.account.enabled",4725=>"directory.account.disabled",_=>Pairs.ContainsKey(code)?"group.member.added":MembershipIds.Contains(code)?"group.member.removed":null};
            if(expected is null||e.Text("semantic_type")!=expected)continue;
            if(MembershipIds.Contains(code))
            {
                var facts=Facts(e);string? member=facts.Text("relation_member_sid")??e.Text("membership_member_sid"),group=facts.Text("relation_group_sid")??sid;
                if(member is null||!identities.ContainsKey((domain,member))||group is null){unknown++;continue;}
                if(!groups.ContainsKey((domain,group)))continue;
                var key=(domain,member,group);if(!membership.TryGetValue(key,out var changes))membership[key]=changes=[];changes.Add(e);
            }
            else
            {
                if(sid is null||!identities.ContainsKey((domain,sid))){unknown++;continue;}
                var target=code is 4624 or 6272?auth:lifecycle;var key=(domain,sid);
                if(!target.TryGetValue(key,out var list))target[key]=list=[];list.Add(e);
            }
        }
        var disabled=new List<JsonObject>();var temporary=new List<(JsonObject Row,(long,string,string) Key)>();
        foreach(var(key,changes)in lifecycle)
        {
            var user=identities[key];var last=changes[^1];if(AdInventoryRows.Bool(user["enabled"])!=false||last.Int("event_id")!=4725)continue;
            var at=last.Time("time_created_utc");
            foreach(var e in auth.GetValueOrDefault(key,[]).Where(e=>(e["day"] is null?e.Time("time_created_utc"):e.Time("last_seen_utc"))>at)) {
                var stamp=e.Time("time_created_utc");if(stamp<=at)stamp=e.Time("last_seen_utc");
                var row=Obj(new{id=e["id"] is null?null:e.Int("id").ToString(CultureInfo.InvariantCulture),entity_id=user.Int("entityId"),display_name=user.Text("displayName"),disabled_at=AdInventoryRows.PythonIso(at),activity_at=AdInventoryRows.PythonIso(stamp),activity_type=e.Int("event_id").ToString(CultureInfo.InvariantCulture),delay_minutes=Math.Round((stamp-at).TotalMinutes,2),source_id=e.Int("server_id"),logon_type=e.Text("logon_type"),evidence=e["id"] is null?new[]{last.Int("id")}:new[]{last.Int("id"),e.Int("id")},quality="exact_sid"});
                if(e["day"] is not null)foreach(string field in new[]{"day","event_count","first_seen_utc","last_seen_utc"})row[field]=field=="event_count"&&e.Time("first_seen_utc")<=at?null:e[field]?.DeepClone();
                disabled.Add(row);
            }
        }
        foreach(var(key,changes)in membership)
        {
            var user=identities[(key.Item1,key.Item2)];var group=groups[(key.Item1,key.Item3)];
            for(int i=0;i<changes.Count;i++)
            {
                var add=changes[i];if(!Pairs.TryGetValue((int)add.Int("event_id"),out int remove))continue;var at=add.Time("time_created_utc");var removals=new List<JsonObject>();
                foreach(var follow in changes.Skip(i+1))
                {
                    double elapsed=(follow.Time("time_created_utc")-at).TotalMinutes;
                    if(elapsed>maxMinutes||Pairs.ContainsKey((int)follow.Int("event_id")))break;
                    if(elapsed>0&&follow.Int("event_id")==remove)removals.Add(follow);
                }
                if(removals.Count==0)continue;var candidate=candidates.GetValueOrDefault(add.Int("id"));bool ambiguous=removals.Count>1||candidate.Int("evidence_count")>2;var end=removals[0].Time("time_created_utc");
                var observations=auth.GetValueOrDefault((key.Item1,key.Item2),[]);
                bool uncertain=observations.Any(e=>e["day"] is not null&&(e["event_count"] is null||e.Time("first_seen_utc")<end&&e.Time("last_seen_utc")>at&&!(e.Time("first_seen_utc")>at&&e.Time("last_seen_utc")<end)));
                var duringRows=observations.Where(e=>e.Time("time_created_utc")>at&&(e["day"] is null?e.Time("time_created_utc"):e.Time("last_seen_utc"))<end).ToArray();
                var during=duringRows.Where(e=>e["id"] is not null).Select(e=>e.Int("id")).ToArray();
                temporary.Add((Obj(new{id=add.Int("id").ToString(CultureInfo.InvariantCulture),entity_id=user.Int("entityId"),display_name=user.Text("displayName"),group_id=group.Text("id"),group=group.Text("name"),added_at=AdInventoryRows.PythonIso(at),removed_at=ambiguous?null:AdInventoryRows.PythonIso(end),interval_minutes=ambiguous?(double?)null:Math.Round((end-at).TotalMinutes,2),added_by=add.Text("subject_user_sid"),removed_by=removals.Select(e=>e.Text("subject_user_sid")),activity_count=ambiguous||uncertain?(long?)null:duringRows.Sum(e=>e["event_count"] is null?1:e.Int("event_count")),activity_evidence=ambiguous?System.Array.Empty<long>():during,evidence=new[]{add.Int("id")}.Concat(removals.Select(e=>e.Int("id"))),candidate_id=candidate.Text("candidate_id"),quality=ambiguous?"ambiguous":"observed_pair"}),key));
            }
        }
        var counts=temporary.GroupBy(t=>t.Key).ToDictionary(g=>g.Key,g=>g.Count());foreach(var(row,key)in temporary)row["repeats"]=counts[key];
        return Obj(new{disabled_active=disabled,temporary_memberships=temporary.Where(t=>counts[t.Key]>=minRepeats).Select(t=>t.Row),unknown_identity_events=unknown,unprocessed_events=ordered.Count(e=>!Interpreted(e))});
    }
    internal static IEnumerable<JsonObject> Users(IEnumerable<JsonObject> sources) =>
        sources.SelectMany(source => (source["snapshot"]?["users"] as JsonArray ?? []).OfType<JsonObject>());
    internal static IEnumerable<JsonObject> WatchGroups(IEnumerable<JsonObject> sources) =>
        sources.SelectMany(source => (source["snapshot"]?["metadata"]?["watch_groups"] as JsonArray ?? []).OfType<JsonObject>());
    internal static JsonObject Current(IEnumerable<JsonObject> sources) =>
        Obj(new { users = Users(sources), metadata = new { observed_at = sources.FirstOrDefault().Text("observed_at_utc"), watch_groups = WatchGroups(sources) } });
    internal static Task<JsonObject> LoadAsync(NpgsqlConnection db,JsonObject current,long[] domains,JsonObject parameters,bool disabled,CancellationToken ct,IConfiguration? config=null) =>
        LoadAsync(db, (current["users"] as JsonArray ?? []).OfType<JsonObject>(),
            (current["metadata"]?["watch_groups"] as JsonArray ?? []).OfType<JsonObject>(), domains, parameters, disabled, ct, config);
    internal static async Task<JsonObject> LoadAsync(NpgsqlConnection db, IEnumerable<JsonObject> accounts,
        IEnumerable<JsonObject> watchGroups, long[] domains, JsonObject parameters, bool disabled, CancellationToken ct, IConfiguration? config = null,
        bool includeUnmatchedLogonCount = true)
    {
        var(period,minutes,repeats)=Window(parameters);
        var empty=Obj(new{disabled_active=new object[0],temporary_memberships=new object[0],unknown_identity_events=0,unprocessed_events=0,state="partial",truncated=false,window=period.Bounds});
        if(domains.Length==0)return empty;
        var users=accounts.Where(u=>u.Int("entityId")>0).ToDictionary(u=>u.Int("entityId"));
        var groups=watchGroups.Where(g=>g.Text("id")?.StartsWith("group:")==true&&AdInventoryRows.Bool(g["watchGroup"])==true).GroupBy(g=>long.Parse(g.Text("id")![6..],CultureInfo.InvariantCulture)).ToDictionary(g=>g.Key,g=>g.First());
        if(users.Count==0||!disabled&&groups.Count==0)return empty;
        await Read(db,"savepoint ad_users_activity",ct);
        try
        {
            var aliases=await Read(db,"""
                select a.entity_id,e.domain_id,a.alias_value as sid from ad_context_entity_aliases a join entities_v2 e on e.id=a.entity_id
                where a.entity_id=any($1) and a.alias_type='object_sid' and e.domain_id=any($2) order by a.entity_id,a.alias_value
                """,ct,users.Keys.Concat(groups.Keys).Distinct().ToArray(),domains);
            var exact=aliases.Where(a=>a.Text("sid") is not null).GroupBy(a=>(a.Int("domain_id"),a.Text("sid")!)).Where(g=>g.Select(a=>a.Int("entity_id")).Distinct().Count()==1).ToDictionary(g=>g.Key,g=>g.First().Int("entity_id"));
            var identities=exact.Where(p=>users.ContainsKey(p.Value)).ToDictionary(p=>p.Key,p=>users[p.Value]);var watched=exact.Where(p=>groups.ContainsKey(p.Value)).ToDictionary(p=>p.Key,p=>groups[p.Value]);
            if(identities.Count==0||!disabled&&watched.Count==0)return empty;
            var (eventSql, eventArgs) = EventSql(domains, disabled ? [4722, 4725] : MembershipIds, period, config);
            var events = await Read(db, eventSql, ct, eventArgs);
            // Only these exact accounts can contribute logon evidence. Count unresolved
            // logons independently so narrowing the evidence read preserves coverage.
            var relevant = events.Where(e => disabled
                    ? e.Int("event_id") == 4725
                    : Pairs.ContainsKey((int)e.Int("event_id")) && watched.ContainsKey((e.Int("domain_id"), e.Text("target") ?? "")))
                .Select(e => (e.Int("domain_id"), Sid: e.Text(disabled ? "target_user_sid" : "membership_member_sid") ?? ""))
                .Where(key => identities.TryGetValue(key, out var user) && (!disabled || AdInventoryRows.Bool(user["enabled"]) == false))
                .ToHashSet();
            if (relevant.Count > 0)
            {
                var logons = await AdAccountEvents.ReadUserLogonsAsync(db, domains, relevant.Select(key => key.Sid).Distinct().ToArray(),
                    period, ct, config, ignoreCase: false);
                events.AddRange(logons.Where(e => relevant.Contains((e.Int("domain_id"), e.Text("target_user_sid") ?? ""))));
            }
            long? unknownLogons = includeUnmatchedLogonCount
                ? await UnknownLogonsAsync(db, domains, period, identities.Keys, config, ct) : null;
            var anchors=events.Where(e=>Pairs.ContainsKey((int)e.Int("event_id"))&&e.Text("normalized_event_id") is not null).Select(e=>Guid.Parse(e.Text("normalized_event_id")!)).ToArray();
            var candidates=new Dictionary<long,JsonObject>();if(!disabled&&anchors.Length>0)
            {
                var rows=await Read(db,"""
                    select distinct on(anchor.source_event_id) anchor.source_event_id as add_id,c.candidate_id,c.evidence_count,c.confidence
                    from semantic_correlation_candidate_evidence ae join normalized_events anchor on anchor.normalized_event_id=ae.normalized_event_id
                    join semantic_correlation_candidates c on c.candidate_id=ae.candidate_id
                    where ae.normalized_event_id=any($1::uuid[]) and ae.evidence_order=0 and c.rule_id=$2 and c.candidate_status='matched'
                      and c.window_start_utc>=$3 and c.window_start_utc<$4
                      and not exists(select 1 from semantic_correlation_rules r where r.rule_id=c.rule_id and r.rule_version>c.rule_version and r.lifecycle_status in ('shadow','enabled'))
                      and not exists(select 1 from semantic_correlation_candidate_evidence ce join normalized_events old on old.normalized_event_id=ce.normalized_event_id
                        where ce.candidate_id=c.candidate_id and old.normalized_event_id<>(select latest.normalized_event_id from normalized_events latest
                          where latest.source_event_id=old.source_event_id order by latest.semantic_contract_version desc,latest.normalized_at desc,latest.normalized_event_id desc limit 1))
                    order by anchor.source_event_id,c.rule_version desc,c.last_matched_at desc,c.candidate_id
                    """,ct,anchors,Chain,period.Start,period.End);candidates=rows.ToDictionary(r=>r.Int("add_id"));
            }
            var shaped=Shape(events,identities,watched,candidates,minutes,repeats);
            shaped["unknown_identity_events"] = unknownLogons is long count ? JsonValue.Create(shaped.Int("unknown_identity_events") + count) : null;
            foreach(var(key,value)in shaped)empty[key]=value?.DeepClone();return empty;
        }
        catch(PostgresException error)when(error.SqlState is "42P01" or "42703" or "42501")
        {await Read(db,"rollback to savepoint ad_users_activity",ct);empty["state"]="unavailable";return empty;}
        finally {await Read(db,"release savepoint ad_users_activity",ct);}
    }
    internal static void Enrich(JsonObject user, ILookup<long, JsonObject> episodes)
    {
        var memberships = episodes[user.Int("entityId")];
        user.Remove("temporaryMemberships");
        if (memberships.Any()) user["temporaryMemberships"] = Array(memberships);
    }
    internal static void ApplyCoverage(JsonObject result,JsonObject data,bool tab)
    {
        result["coverage"]!["completeness"]="not_proven";result["coverage"]!["activity"]=Obj(new{state=data.Text("state"),truncated=false,window=data["window"],unknown_identity_events=data["unknown_identity_events"]?.DeepClone(),unprocessed_events=data.Int("unprocessed_events")});
        var limitations=result["limitations"]!.AsArray();limitations.Add(Obj(new{code="activity_not_proof",text="Наблюдаемая последовательность не доказывает злоупотребление или использование выданного права. 6272 — разрешение NPS, а не подтверждённая VPN-сессия; 4624 на DC не доказывает интерактивный вход на рабочую станцию."}));
        limitations.Add(Obj(new{code="activity_coverage",text="Полнота источников не подтверждена. Время отключения известно только при наблюдаемом 4725; события без точного SID и домена учитываются отдельно."}));
        if(data.Text("state")=="unavailable")limitations.Add(Obj(new{code="activity_unavailable",text="Хранилище событий или корреляций недоступно для чтения; отсутствие строк не означает отсутствие активности."}));
        if(tab||result.Text("state") is "ok" or "empty")result["state"]=tab&&data.Text("state")=="unavailable"?"error":"partial";
        result["state_message"]=AdPresentation.Message("reports.state."+result.Text("state"));
    }
    internal static async Task<JsonObject> QueryAsync(NpgsqlConnection db,AdV2Request request,List<JsonObject> sources,Func<IEnumerable<string>,bool> fields,CancellationToken ct,IConfiguration? config=null)
    {
        string[] required=request.Tab=="disabled_active"?["technical","security"]:["technical","security","privilege"];
        if(!fields(required))return AdV2Store.Result(request.Key,"denied");
        if(!sources.Any(s=>s["snapshot"] is not null))return AdV2Store.Result(request.Key,"not_collected");
        var current=Current(sources);var data=await LoadAsync(db,current,request.Domains,request.Params,request.Tab=="disabled_active",ct,config);
        var result=AdV2Store.Result(request.Key,"partial",coverage:AdV2Store.Coverage(sources));ApplyCoverage(result,data,true);result["window"]=data["window"]!.DeepClone();
        foreach(string key in new[]{"state","truncated","unknown_identity_events","unprocessed_events"})result["coverage"]![key]=data[key]!.DeepClone();
        if(data.Text("state")=="unavailable")return result;
        var users=current["users"]!.AsArray().OfType<JsonObject>().ToDictionary(u=>u.Int("entityId"));var selected=new List<JsonObject>();
        var filters=new JsonObject();foreach(string key in new[]{"q","department","company","ou"})if(request.Params[key] is {} value)filters[key]=value.DeepClone();
        foreach(var row in data[request.Tab]!.AsArray().OfType<JsonObject>())
        {
            var safe=(JsonObject)users[row.Int("entity_id")].DeepClone();AdInventoryRows.RedactUser(safe,fields);
            if(!AdInventoryRows.Matches(request with{Tab="users",Params=filters},safe,AdInventoryRows.User(safe,current["metadata"]!.Text("observed_at")??Iso(DateTimeOffset.UtcNow)),true))continue;
            if(request.Params.Text("group") is {} group&&row.Text("group_id")!=group||request.Params.Text("activity_type") is {} type&&row.Text("activity_type")!=type)continue;
            row["domain_id"]=safe["domainId"]?.DeepClone();
            row["domain_name"]=safe["domainName"]?.DeepClone();
            row["sam"]=safe["samAccountName"]?.DeepClone();
            row["enabled"]=safe["enabled"]?.DeepClone();
            selected.Add(row);
        }
        selected=selected.OrderByDescending(r=>r.Text("added_at")??r.Text("activity_at"),StringComparer.Ordinal).ThenByDescending(r=>r.Text("id"),StringComparer.Ordinal).ToList();
        AdV2Store.Page(result,request,selected);
        var page = result["items"]!;
        result["items"] = new JsonArray();
        result["collections"]![request.Tab] = page;
        result["metrics"]=Array(new[]{Obj(new{key="activity_observations",label="Наблюдения в выборке",value=selected.Count}),Obj(new{key="activity_accounts",label="Сопоставленные аккаунты",value=selected.Select(r=>r.Int("entity_id")).Distinct().Count()}),Obj(new{key="activity_repeated",label="Повторные краткие включения",value=selected.Count(r=>r.Int("repeats")>1)}),Obj(new{key="activity_ambiguous",label="Неоднозначные продолжения",value=selected.Count(r=>r.Text("quality")=="ambiguous")}),Obj(new{key="activity_unknown",label="События без точной идентичности",value=data.Int("unknown_identity_events")})});
        result["filter_options"]!["group"]=Array(current["metadata"]!["watch_groups"]!.AsArray().Select(g=>new{value=g!.Text("id"),label=g.Text("name")}));return result;
    }
}
