using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdReviewChecks
{
    static readonly JsonObject Templates=AdV2Store.Resource("review-templates");
    static bool? And(bool? a,bool? b)=>a==false||b==false?false:a==true&&b==true?true:null;
    static bool? Over(double? age,int threshold)=>age.HasValue?age>threshold:null;
    static double? Age(JsonNode? value,DateTimeOffset at)=>AdInventoryRows.Date(value) is {} stamp&&stamp<=at?(at-stamp).TotalDays:null;
    public static Dictionary<string,bool?> Evaluate(bool users,JsonObject raw,DateTimeOffset at,JsonObject? previous=null,bool previousComplete=false,IReadOnlyList<JsonObject>? events=null,JsonObject? exceptions=null)
    {
        if(users)
        {
            bool spnKnown=raw["servicePrincipalNames"] is JsonArray;
            AdInventoryRows.SecurityFacts(raw);bool? privilege=Privilege(raw);var activity=AdInventoryRows.Activity(raw);bool? inactive=Over(Age(activity.Value,at),90);bool? enabled=AdInventoryRows.Bool(raw["enabled"]);
            bool? old=previous is null?previousComplete?false:null:Privilege(previous);
            var related=(events??[]).Where(e=>
                raw.Text("sid") is {} sid&&string.Equals(e.Text("membership_member_sid")??e["facts_json"]?.Text("relation_member_sid")??e.Text("target_user_sid"),sid,StringComparison.OrdinalIgnoreCase)
                ||raw.Text("objectGuid") is {} guid&&e.Int("event_id")==5136&&string.Equals(e["facts_json"]?.Text("object")?.Trim('{','}'),guid.Trim('{','}'),StringComparison.OrdinalIgnoreCase)).ToArray();
            var lifecycle=related.Where(e=>e.Int("event_id") is 4722 or 4725).OrderBy(e=>e.Time("time_created_utc")).ThenBy(e=>e.Int("id")).LastOrDefault();
            var disabled=lifecycle?.Int("event_id")==4725?AdInventoryRows.Date(lifecycle["time_created_utc"]):null;
            bool disabledLogon=disabled is not null&&related.Any(e=>e.Int("event_id")==4624&&(e["day"] is null?e.Time("time_created_utc"):e.Time("last_seen_utc"))>disabled);
            bool interactive=related.Any(e=>e.Int("event_id")==4624&&e.Text("logon_type") is "2" or "10");
            var checks=new Dictionary<string,bool?>(){["disabled_logon"]=enabled==true?false:disabledLogon&&enabled==false?true:null,["new_privileged"]=And(privilege,old is null?null:!old.Value),["reversible_password"]=AdInventoryRows.Bool(raw["allowReversiblePasswordEncryption"]),["inactive_privileged"]=And(privilege,enabled==false||inactive==true?true:enabled is null||inactive is null?null:false),["spn_privileged"]=And(privilege,spnKnown?raw["servicePrincipalNames"]!.AsArray().Count>0:null),["privileged_password_never_expires"]=And(privilege,AdInventoryRows.Bool(raw["passwordNeverExpires"])),["locked_out"]=AdInventoryRows.Bool(raw["lockedOut"]),["service_interactive_logon"]=raw.Text("serviceAccountType") is not null&&interactive?true:raw.Text("serviceAccountType") is null&&spnKnown&&raw["objectClasses"] is JsonArray?false:null,["kerberos_no_preauth"]=AdInventoryRows.Bool(raw["doesNotRequirePreAuth"]),["inactive_enabled"]=And(enabled,inactive),["old_password"]=Over(Age(raw["passwordLastSet"],at),365),["password_never_expires"]=AdInventoryRows.Bool(raw["passwordNeverExpires"]),["password_not_required"]=AdInventoryRows.Bool(raw["passwordNotRequired"])}; if(raw.Text("serviceAccountType") is not null&&exceptions?[raw.Text("sid")?.ToUpperInvariant()??""] is not null){checks["old_password"]=false;checks["inactive_enabled"]=false;}return checks;
        }
        var expiration=AdInventoryRows.Date(raw["lapsPasswordExpiration"])??AdInventoryRows.Date(raw["legacyLapsPasswordExpiration"]);
        bool? delegation=raw["userAccountControl"] is not null?(raw.Int("userAccountControl")&524288)!=0:AdInventoryRows.Bool(raw["trustedForDelegation"]);
        var support=AdComputerPosture.SupportEnd(raw.Text("osName"),raw.Text("osVersion"));
        string? agentState=raw["sli_agent"]?.Text("state");
        return new(){["unconstrained_delegation"]=delegation,["unsupported_os"]=support is null?null:at.Date>support.Value.Date,["new_computer"]=Age(raw["whenCreated"],at) is {} created?created<1:null,["laps"]=expiration is null?null:expiration<at,["rbcd"]=AdInventoryRows.Bool(raw["resourceBasedDelegationPresent"]),["no_sli_agent"]=agentState=="absent"?true:agentState is "installed" or "silent"?false:null,["inactive_enabled"]=And(AdInventoryRows.Bool(raw["enabled"]),Over(Age(raw["lastLogonTimestamp"],at),90)),["old_machine_password"]=Over(Age(raw["passwordLastSet"],at),60)};
    }
    static bool? Privilege(JsonObject raw)=>AdInventoryRows.Privileged(raw)?true:raw["memberships"]?.Text("status") is "observed" or "complete"?false:null;
    internal static bool UsesAccountRows(AdV2Request request) =>
        request.Key == "ad.users.v2" && request.Tab == "checks" && request.Params.Text("account_rows") == "yes";

    internal static int SeverityOrder(string? severity) => severity switch
    {
        "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4
    };

    internal static string? UserSeverity(string key, bool privileged) => key == "locked_out" && privileged
        ? "high" : Templates["users"]!.AsObject().TryGetPropertyValue(key, out var template) ? template.Text("severity") : null;

    static string? CheckTitle(string? key, bool english)
    {
        var templates = Templates["users"]!.AsObject();
        if (key is null || !templates.TryGetPropertyValue(key, out var template)) return null;
        var code = template?["presentation_messages"]?["title"].Text("code");
        return code is null ? template.Text("title") : Sli.Server.Reporting.V2.ReportResult.Message(code, english).Text("text");
    }

    internal static void Localize(JsonObject result,bool english)
    {
        void Fields(JsonObject row,params string[] fields)
        {
            foreach(string field in fields)
            {
                if(row["presentation_messages"]?[field] is not JsonObject envelope||envelope.Text("code") is not {} code||!code.StartsWith("reports.ad.checks.",StringComparison.Ordinal))continue;
                string text=Sli.Server.Reporting.V2.ReportResult.Message(code,english).Text("text")!;
                foreach(var (name,value) in envelope["params"] as JsonObject??new())text=text.Replace("{"+name+"}",value?.ToString()??"",StringComparison.Ordinal);
                envelope["text"]=text;row[field]=text;
            }
        }
        foreach(var rows in new[]{result["items"],result["collections"]?["checks"]})
            foreach(var row in rows as JsonArray??[])
                if(row is JsonObject obj&&obj.Text("section") is "review" or "hygiene")Fields(obj,"title","why","action","remediation","status_text","severity_text","section_text");
        foreach (var row in (result["items"] as JsonArray ?? []).OfType<JsonObject>())
            if (row["review_reasons"] is JsonArray reasons)
            {
                foreach (var reason in reasons.OfType<JsonObject>()) reason["label"] = CheckTitle(reason.Text("key"), english);
                row["reason_text"] = string.Join(" · ", reasons.Select(reason => reason.Text("label")));
            }
        foreach (var option in (result["filter_options"]?["check"] as JsonArray ?? []).OfType<JsonObject>())
            option["label"] = CheckTitle(option.Text("value"), english);
    }
    public static async Task<JsonObject> ReadAsync(NpgsqlConnection db,AdV2Request request,List<JsonObject> sources,CancellationToken ct,IConfiguration? config=null, bool fieldsPrivilege = false)
    {
        bool users=request.Key=="ad.users.v2";string kind=users?"users":"computers";
        bool accountRows = UsesAccountRows(request);
        var accounts = new List<JsonObject>();
        var accountCounts = new Dictionary<string, int>();
        if(request.Params.Text("check") is {} requested&&!Templates[kind]!.AsObject().ContainsKey(requested))throw new AdInputException("report_check_invalid");
        var matched=Templates[kind]!.AsObject().ToDictionary(p=>p.Key,_=>new List<JsonObject>());var unknown=matched.Keys.ToDictionary(k=>k,_=>0);int population=0;
        var oldCounts=matched.Keys.ToDictionary(k=>k,_=>0);var baseCounts=matched.Keys.ToDictionary(k=>k,_=>0);
        var matchedIdentities=matched.Keys.ToDictionary(k=>k,_=>new HashSet<(long,string)>());var baseIdentities=matched.Keys.ToDictionary(k=>k,_=>new HashSet<(long,string)>());
        var oldKnown=matched.Keys.ToDictionary(k=>k,_=>true);var baseKnown=matched.Keys.ToDictionary(k=>k,_=>true);
        DateTimeOffset? since=null;
        if(!accountRows && request.Principal is {Type:"session",Id:>0} principal)
        {
            var login=await AdJson.ReadAsync(db,"select previous_login_at from auth_users where id=$1",ct,principal.Id);
            if(login.Count>0)since=AdInventoryRows.Date(login[0]["previous_login_at"]);
        }
        var eventRead=await EventsAsync(db,request.Domains,users,ct,config,accountRows ? sources : null);var events=eventRead.Rows;
        var eventIndex=new EventIndex(events);
        var exceptions=new JsonObject();if(users)
        {
            var configured=await AdJson.ReadAsync(db,"select value from platform_settings where key='ad.service_account_exceptions'",ct);
            foreach(var entry in JsonNode.Parse(configured.FirstOrDefault()?.Text("value")??"[]")!.AsArray())
            {var value=entry is JsonObject obj?obj:new JsonObject{["sid"]=entry?.DeepClone()};if(value.Text("sid") is {} sid)exceptions[sid.ToUpperInvariant()]=value.DeepClone();}
        }
        var agents=new AdComputerPosture.AgentIndex(users?null:await AdComputerPosture.AgentsAsync(db,request.Domains,ct));
        var unassessed=new HashSet<(long,string)>();var affected=new HashSet<(long,string)>();var domainCoverage=new List<JsonObject>();
        bool allComplete=true;
        foreach(var source in sources)
        {
            string family=users?"users_v2":"computers_v6",collection=users?"users":"objects";
            bool complete=Complete(source,users);allComplete&=complete;
            domainCoverage.Add(Obj(new{domain_id=source.Int("domain_id"),domain_name=source.Text("fqdn"),state=complete?"complete":source.Text("source_state")??"not_collected",snapshot_state=source.Text("source_state")??"not_collected",observed_at_utc=source.Text("observed_at_utc")}));
            var previous=await AdV2Store.PreviousSnapshot(db,source,family,ct);
            var baseline=since.HasValue?await AdV2Store.PreviousSnapshot(db,source,family,ct,since):null;
            var predecessor=accountRows||previous is null?null:await AdV2Store.PreviousSnapshot(db,previous,family,ct);
            var baselinePredecessor=baseline is null?null:await AdV2Store.PreviousSnapshot(db,baseline,family,ct);
            string Identity(JsonObject r)=>(r.Text("objectGuid")??r.Text("sid")??r.Text("entityId")??"").ToLowerInvariant();
            bool Matches(JsonObject r)=>request.Params.Text("q") is not {} q||new[]{r.Text(users?"samAccountName":"name"),r.Text(users?"displayName":"name"),r.Text("ou")}.Any(s=>s?.Contains(q,StringComparison.OrdinalIgnoreCase)==true);
            JsonObject[] Objects(JsonObject? s)=>s?["snapshot"]?[collection] is JsonArray array?array.OfType<JsonObject>().Where(r=>Identity(r).Length>0).GroupBy(Identity).Select(g=>(JsonObject)g.Last().DeepClone()).ToArray():[];
            var currentObjects=Objects(source);var previousObjects=Objects(previous);var baseObjects=Objects(baseline);
            var before=previousObjects.ToDictionary(Identity);var beforeOld=Objects(predecessor).ToDictionary(Identity);var beforeBase=Objects(baselinePredecessor).ToDictionary(Identity);
            foreach(string key in matched.Keys){oldKnown[key]&=complete&&Complete(previous,users);baseKnown[key]&=since.HasValue&&complete&&Complete(baseline,users);}
            JsonObject Prepare(JsonObject raw,JsonObject role,bool historical)
            {
                if(!users){var row=AdInventoryRows.Computer(raw,source,role.Text("observed_at_utc")!,new());raw["sli_agent"]=AdComputerPosture.Agent(row,source.Int("domain_id"),agents,historical?role.Time("observed_at_utc"):null);}
                return raw;
            }
            foreach(var (objects,role,older,olderSource,counts,known) in accountRows ? [] : new[]{(previousObjects,previous,beforeOld,predecessor,oldCounts,oldKnown),(baseObjects,baseline,beforeBase,baselinePredecessor,baseCounts,baseKnown)})
                if(role is not null)foreach(var raw in objects.Where(Matches))foreach(var (key,value) in Evaluate(users,Prepare(raw,role,true),role.Time("observed_at_utc"),older.GetValueOrDefault(Identity(raw)),Complete(olderSource,users),Related(raw,users,source.Int("domain_id"),eventIndex).Where(e=>e.Time("time_created_utc")<=role.Time("observed_at_utc")).ToArray(),exceptions))
                    if(value is null)known[key]=false;else if(value==true){counts[key]++;if(ReferenceEquals(counts,baseCounts))baseIdentities[key].Add((source.Int("domain_id"),Identity(raw)));}
            foreach(var raw in currentObjects.Where(Matches))
            {
                if (accountRows && request.Params.Text("account_state") is {} stateFilter &&
                    stateFilter != (AdInventoryRows.Bool(raw["enabled"]) switch { true => "enabled", false => "disabled", _ => "unknown" }))
                    continue;
                population++;var at=source.Time("observed_at_utc");string identity=Identity(raw);var related=Related(raw,users,source.Int("domain_id"),eventIndex);
                var assessments=Evaluate(users,Prepare(raw,source,false),at,before.GetValueOrDefault(identity),Complete(previous,users),related,exceptions);
                if (accountRows)
                {
                    var privileged = fieldsPrivilege && AdInventoryRows.Privileged(raw);
                    var reasons = assessments.Where(pair => pair.Value == true &&
                        (pair.Key != "password_never_expires" || assessments["privileged_password_never_expires"] != true)).Select(pair =>
                        new { key = pair.Key, severity = UserSeverity(pair.Key, privileged), label = Templates[kind]![pair.Key].Text("title") })
                        .OrderBy(reason => SeverityOrder(reason.severity)).ToArray();
                    foreach (var (key, value) in assessments.Where(pair => pair.Value is null))
                    {
                        unknown[key]++;
                        unassessed.Add((source.Int("domain_id"), identity));
                    }
                    if (reasons.Length == 0) continue;
                    affected.Add((source.Int("domain_id"), identity));
                    foreach (var reason in reasons) accountCounts[reason.key] = accountCounts.GetValueOrDefault(reason.key) + 1;
                    if (request.Params.Text("check") is not {} filter || reasons.Any(reason => reason.key == filter))
                    {
                        var account = ReviewAccount(raw, source, request.QualifyNames, identity, at);
                        account["review_reasons"] = Array(reasons);
                        account["severity"] = reasons[0].severity;
                        account["reason_text"] = string.Join(" · ", reasons.Select(reason => reason.label));
                        accounts.Add(account);
                    }
                    continue;
                }
                foreach(var (key,value) in assessments)
                {
                    if(value is null){unknown[key]++;unassessed.Add((source.Int("domain_id"),identity));continue;}if(value!=true)continue;
                    affected.Add((source.Int("domain_id"),identity));
                    matchedIdentities[key].Add((source.Int("domain_id"),identity));
                    var item=Obj(new{entity_id=users?(long?)raw.Int("entityId"):source["entity_ids"]?[raw.Text("objectGuid")??""]?.GetValue<long>(),name=users?raw.Text("samAccountName")??raw.Text("displayName"):raw.Text("name"),observed_at_utc=Iso(at),domain_id=source.Int("domain_id"),domain_name=source.Text("fqdn"),computer_type=users?null:raw.Text("deviceType")});
                    item["change"]=Change(related,key,raw);
                    if(users){var activity=AdInventoryRows.Activity(raw);item["enabled"]=raw["enabled"]?.DeepClone();item["sam"]=raw["samAccountName"]?.DeepClone();item["activity_at"]=activity.Value?.DeepClone();item["ou"]=raw["ou"]?.DeepClone();item["password_last_set"]=raw["passwordLastSet"]?.DeepClone();item["membership_paths"]=raw["memberships"]?["paths"]?.DeepClone();}
                    else{var computer=AdInventoryRows.Computer(raw,source,Iso(at),new());foreach(string field in new[]{"operating_system","last_logon_utc","ou_path","laps_state","enabled"})item[field]=computer[field]?.DeepClone();item["sli_agent"]=raw["sli_agent"]?.DeepClone();item["dns_ip"]=AdComputerPosture.Dns(raw);}
                    matched[key].Add(item);
                }
            }
        }
        var rows=new List<JsonObject>();bool missing=sources.Count==0||sources.Any(s=>s["snapshot"] is null);
        foreach(var (key,template) in accountRows ? new JsonObject() : Templates[kind]!.AsObject())
        {
            var row=(JsonObject)template!.DeepClone();row["id"]=kind+":"+key;row["key"]=key;row["section"]=row.Text("severity")=="low"?"hygiene":"review";
            bool uncertain=missing||unknown[key]>0;
            int? total=population-unknown[key]>0||matched[key].Count>0||allComplete&&!uncertain?matched[key].Count:null;
            int? old=oldKnown[key]&&!uncertain?oldCounts[key]:null;int? delta=old.HasValue?matched[key].Count-old.Value:null;
            string status=delta is null?total is null?"not_evaluated":"no_comparison":delta>0?"new":delta<0?"decreased":"unchanged";
            row["total"]=total;row["new_count"]=baseKnown[key]&&!uncertain?JsonValue.Create(matchedIdentities[key].Except(baseIdentities[key]).Count()):null;row["previous_total"]=old;row["delta"]=delta;row["status"]=status;
            var envelope=Message("status."+status,Math.Abs(delta??0));row["status_text"]=envelope["text"]!.DeepClone();row["presentation_messages"]!["status_text"]=envelope;
            foreach(var (field,code) in new[]{("severity_text","severity."+row.Text("severity")),("section_text",row.Text("severity")=="low"?"hygiene":"tab")}){var msg=Message(code);row[field]=msg["text"]!.DeepClone();row["presentation_messages"]![field]=msg;}
            row["not_evaluated_count"]=missing?null:JsonValue.Create(unknown[key]);row["assessed_count"]=population-unknown[key];row["is_lower_bound"]=!allComplete||uncertain;row["objects"]=Array(request.Params.Text("check")==key?matched[key]:matched[key].Take(3));row["remaining_objects"]=Math.Max(0,matched[key].Count-3);row["last_seen_utc"]=matched[key].Select(o=>o.Text("observed_at_utc")).Order().LastOrDefault();row["change"]=matched[key].Select(o=>o["change"]).Where(o=>o is not null).OrderBy(o=>o!.Text("at_utc")).LastOrDefault()?.DeepClone();rows.Add(row);
        }
        if(!accountRows && request.Params.Text("check") is {} check)rows=matched[check];
        rows=rows.OrderBy(r=>r.Text("severity") switch{"high"=>0,"medium"=>1,_=>2}).ThenByDescending(r=>r.Int("new_count")).ThenByDescending(r=>r.Int("total")).ThenBy(r=>r.Text("id"),StringComparer.Ordinal).ToList();
        var coverage=AdV2Store.Coverage(sources);coverage["domains"]=Array(domainCoverage);coverage["contract_id"]="sli.ad-review-checks.v1";coverage["population"]=missing?null:JsonValue.Create(population);coverage["affected_objects"]=missing&&affected.Count==0?null:JsonValue.Create(affected.Count);coverage["not_evaluated_count"]=missing?null:JsonValue.Create(unassessed.Count);coverage["previous_login_at"]=since.HasValue?Iso(since.Value):null;coverage["event_coverage"]=events is null?"unavailable":"unconfirmed";coverage["counts_are_unique_per_check"]=true;coverage["new_computer_window_days"]=1;
        string state=sources.All(s=>s["snapshot"] is null)?"not_collected":unknown.Values.Any(v=>v>0)||missing||!allComplete||eventRead.Truncated?"partial":sources.Any(s=>s.Time("observed_at_utc")<DateTimeOffset.UtcNow.AddDays(-1))?"stale":"ok";
        coverage["events_truncated"]=eventRead.Truncated;coverage["os_support_policy_version"]="microsoft-lifecycle-2026-10-16";
        if (accountRows)
        {
            var resultAccounts = AdV2Store.Result(request.Key, state == "ok" && accounts.Count == 0 ? "empty" : state, coverage: coverage);
            resultAccounts["filter_options"]!["check"] = Array(Templates[kind]!.AsObject()
                .Where(pair => accountCounts.ContainsKey(pair.Key)).OrderBy(pair => SeverityOrder(pair.Value.Text("severity")))
                .Select(pair => new { value = pair.Key, label = pair.Value.Text("title"), count = accountCounts[pair.Key] }));
            AdV2Store.Page(resultAccounts, request, accounts.OrderBy(row => SeverityOrder(row.Text("severity")))
                .ThenBy(row => row.Text("sam"), StringComparer.OrdinalIgnoreCase).ThenBy(row => row.Text("id"), StringComparer.Ordinal).ToList());
            return resultAccounts;
        }
        var result=AdV2Store.Result(request.Key,state,rows,coverage);AdV2Store.Page(result,request,rows);result["collections"]!["checks"]=result["items"]!.DeepClone();
        return result;
    }

    static JsonObject ReviewAccount(JsonObject raw, JsonObject source, bool qualifyNames, string identity, DateTimeOffset at)
    {
        long domain = source.Int("domain_id");
        string? domainName = source.Text("fqdn");
        string? sam = raw.Text("samAccountName") ?? raw.Text("displayName");
        string? displayName = raw.Text("displayName") ?? sam;
        string? account = qualifyNames && sam is not null ? UseDomain(domainName, domain, sam) : sam;
        var activity = AdInventoryRows.Activity(raw);
        var row = Obj(new
        {
            id = $"{domain}:{identity}", entity_id = raw.Int("entityId"), domain_id = domain, domain_name = domainName,
            sam = account, display_name = displayName, account_label = sam == displayName ? account : $"{account} / {displayName}",
            enabled = AdInventoryRows.Bool(raw["enabled"]), ou = raw.Text("ou"), password_last_set = raw.Text("passwordLastSet"),
            observed_at_utc = Iso(at), activity_at = AdInventoryRows.Date(activity.Value) is {} timestamp ? Iso(timestamp) : null,
            activity_source = activity.Source
        });
        AdUsersTabs.SetPrivileges(row, raw, includePaths: false);
        row["review_privileges"] = Array(new[] { "privilege_basis", "nested_privilege_groups" }.SelectMany(key => row[key]!.AsArray())
            .Select(group => group?.ToString()).Where(group => !string.IsNullOrWhiteSpace(group)).Distinct(StringComparer.OrdinalIgnoreCase));
        return row;

        static string UseDomain(string? name, long id, string login) => $"{name ?? id.ToString(System.Globalization.CultureInfo.InvariantCulture)}\\{login}";
    }
    static bool Complete(JsonObject? source,bool users)
    {
        if(source?["snapshot"] is not JsonObject snapshot)return false;var m=snapshot["metadata"]!;if(m["coverage"]?["truncated"]?.GetValue<bool>()==true)return false;
        return source.Text("source_state")=="complete"||source.Text("source_state")=="partial"&&m.Int(users?"user_count":"object_count")==snapshot[users?"users":"objects"]!.AsArray().Count&&(m["sources"] as JsonArray??[]).Any(s=>s!.Text("name")== (users?"directory":"ad")&&s.Text("status")=="observed");
    }
    static readonly JsonObject Messages=JsonNode.Parse(new StreamReader(typeof(AdReviewChecks).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server.ru.json")!).ReadToEnd())!.AsObject();
    static JsonObject Message(string suffix,int? count=null)
    {string code="reports.ad.checks."+suffix;string text=Messages[code]!.ToString();var parameters=new JsonObject();if(count.HasValue){parameters["count"]=count.Value;text=text.Replace("{count}",count.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));}return new JsonObject{["code"]=code,["params"]=parameters,["text"]=text};}
    sealed class EventIndex
    {
        readonly Dictionary<(long,string),List<JsonObject>> bySid=[];
        readonly Dictionary<(long,string),List<JsonObject>> byGuid=[];
        internal EventIndex(List<JsonObject>? events)
        {
            foreach(var row in events??[])
            {long domain=row.Int("domain_id");string? sid=row.Text("membership_member_sid")??row["facts_json"]?.Text("relation_member_sid")??row.Text("target_user_sid");if(sid is not null){var key=(domain,sid.ToLowerInvariant());if(!bySid.TryGetValue(key,out var values))bySid[key]=values=[];values.Add(row);}if(row.Int("event_id")==5136&&row["facts_json"]?.Text("object") is {} guid){var key=(domain,guid.Trim('{','}').ToLowerInvariant());if(!byGuid.TryGetValue(key,out var values))byGuid[key]=values=[];values.Add(row);}}
        }
        internal JsonObject[] Related(JsonObject raw,long domain)=>bySid.GetValueOrDefault((domain,raw.Text("sid")?.ToLowerInvariant()??""),[]).Concat(byGuid.GetValueOrDefault((domain,raw.Text("objectGuid")?.ToLowerInvariant()??""),[])).Distinct(ReferenceEqualityComparer.Instance).Cast<JsonObject>().ToArray();
    }
    static JsonObject[] Related(JsonObject raw,bool users,long domain,EventIndex events)
    {
        string? sid=raw.Text(users?"sid":"sid"),guid=raw.Text("objectGuid");
        return events.Related(raw,domain);
    }
    internal static async Task<(List<JsonObject>? Rows,bool Truncated)> EventsAsync(NpgsqlConnection db,long[] domains,bool users,CancellationToken ct,IConfiguration? config=null,List<JsonObject>? accountSources=null)
    {
        await using(var save=new NpgsqlCommand("savepoint ad_review_events",db))await save.ExecuteNonQueryAsync(ct);
        try
        {
            int[] codes = accountSources is not null ? [4722, 4725]
                : users ? [4720,4722,4723,4724,4725,4728,4732,4738,4741,4742,4756,5136,4624]
                : [4720,4722,4723,4724,4725,4728,4732,4738,4741,4742,4756,5136];
            var now = DateTimeOffset.UtcNow;
            var period = new AdPeriod(now.AddDays(-365), now);
            var events = await AdAccountEvents.ReadAsync(db, domains, codes, period, ct, config);
            if (accountSources is not null)
            {
                var lifecycle = events.Where(e => e.Int("event_id") == 4725 && e.Text("target_user_sid") is not null)
                    .Select(e => (e.Int("domain_id"), e.Text("target_user_sid")!.ToLowerInvariant())).ToHashSet();
                var sids = accountSources.SelectMany(source => (source["snapshot"]?["users"] as JsonArray ?? [])
                    .Where(user => user.Text("sid") is {} sid && (user.Text("serviceAccountType") is not null
                        || AdInventoryRows.Bool(user!["enabled"]) == false && lifecycle.Contains((source.Int("domain_id"), sid.ToLowerInvariant()))))
                    .Select(user => user.Text("sid")!)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                if (sids.Length > 0)
                    events.AddRange(await AdAccountEvents.ReadUserLogonsAsync(db, domains, sids, period, ct, config, ignoreCase: true));
            }
            return (events, false);
        }
        catch(PostgresException error) when(error.SqlState==PostgresErrorCodes.InsufficientPrivilege){throw;}
        catch(NpgsqlException){await using var rollback=new NpgsqlCommand("rollback to savepoint ad_review_events",db);await rollback.ExecuteNonQueryAsync(ct);return (null,false);}
    }
    static JsonObject? Change(JsonObject[] related,string key,JsonObject raw)
    {
        long[] allowed=key switch{"new_computer"=>[4741],"old_password"=>[4723,4724],"disabled_logon" or "inactive_privileged"=>[4725],"new_privileged"=>[4728,4732,4756],_=>[]};
        string? attribute=key switch{"unconstrained_delegation" or "reversible_password" or "kerberos_no_preauth" or "password_never_expires" or "privileged_password_never_expires"=>"useraccountcontrol","old_machine_password"=>"pwdlastset","rbcd"=>"msds-allowedtoactonbehalfofotheridentity","spn_privileged"=>"serviceprincipalname",_=>null};
        bool TargetAllowed(JsonObject e)
        {
            if(key!="new_privileged")return true;string? sid=e.Text("target_user_sid");if(sid is null)return false;
            return System.Text.RegularExpressions.Regex.IsMatch(sid,@"\AS-1-5-(?:21-\d+-\d+-\d+-(?:512|518|519|520)|32-(?:544|548|549|550|551))\z",System.Text.RegularExpressions.RegexOptions.IgnoreCase)||(raw["memberships"]?["effective"] as JsonArray??[]).Any(g=>AdInventoryRows.Bool(g?["watchGroup"])==true&&string.Equals(g.Text("sid"),sid,StringComparison.OrdinalIgnoreCase));
        }
        var e=related.Where(e=>TargetAllowed(e)&&(allowed.Contains(e.Int("event_id"))||e.Int("event_id")==5136&&attribute is not null&&string.Equals(e["facts_json"]?.Text("attribute"),attribute,StringComparison.OrdinalIgnoreCase))).OrderBy(e=>e.Time("time_created_utc")).ThenBy(e=>e.Int("id")).LastOrDefault();
        if(e is null)return null;string? name=e.Text("subject_user_name"),domain=e.Text("subject_domain_name");
        return Obj(new{event_db_id=e.Int("id"),event_id=e.Int("event_id"),at_utc=e.Text("time_created_utc"),actor=domain is not null&&name is not null?domain+"\\"+name:name});
    }
}
