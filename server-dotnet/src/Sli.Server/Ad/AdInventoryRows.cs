using System.Globalization;
using System.Text.Json.Nodes;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdInventoryRows
{
    static readonly JsonObject ExportContract=AdV2Store.Resource("computer-export");
    internal static string ComputerCsv(JsonArray rows)
    {
        var columns=ExportContract["COMPUTERS_V6_EXPORT_COLUMNS"]!.AsArray().Select(n=>n!.ToString()).ToArray();var output=new System.Text.StringBuilder();void Write(IEnumerable<string> cells)=>output.AppendJoin(';',cells.Select(c=>AdV2Endpoints.CsvCell(c,';'))).Append("\r\n");
        Write(columns.Select(key=>ExportContract["COMPUTERS_V6_EXPORT_LABELS"]!.Text(key)!));
        foreach(var row in rows)Write(columns.Select(key=>key switch{"ip_addresses"=>string.Join(" | ",(row?[key] as JsonArray??[]).Select(n=>n!.ToString())),"ad_site"=>row?["network"]?["ad_site"]?.Text("value")??"","reasons" or "quality_issues"=>string.Join(" | ",(row?[key] as JsonArray??[]).Select(n=>n!.Text("code")??"")),_=>AdV2Endpoints.PythonText(row?[key])}));return output.ToString();
    }
    static readonly JsonObject RawFields = AdV2Store.Resource("user-field-categories");
    internal static bool? Bool(JsonNode? node) => node?.GetValueKind() switch { System.Text.Json.JsonValueKind.True => true, System.Text.Json.JsonValueKind.False => false, _ => null };
    internal static DateTimeOffset? Date(JsonNode? node) => node is not null && System.Text.RegularExpressions.Regex.IsMatch(node.ToString(), @"[Tt ].*(?:Z|[+-]\d{2}:\d{2})\z",System.Text.RegularExpressions.RegexOptions.IgnoreCase) && DateTimeOffset.TryParse(node.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) ? date.ToUniversalTime() : null;
    internal static int? Age(JsonNode? value, DateTimeOffset at) => Date(value) is {} time ? (int)Math.Floor((at - time).TotalDays) : null;
    internal static bool Privileged(JsonObject raw) => (raw["memberships"]?["effective"] as JsonArray ?? []).Any(g => Bool(g?["watchGroup"]) == true) || (raw["privilegedMemberships"] as JsonArray ?? []).Any(g => g!.Text("relation") == "direct");
    public static void RedactUser(JsonObject raw, Func<IEnumerable<string>, bool> fields)
        => UserRedactor(fields)(raw);

    internal static Action<JsonObject> UserRedactor(Func<IEnumerable<string>, bool> fields)
    {
        var hidden = RawFields.Where(category => !fields([category.Key]))
            .SelectMany(category => category.Value!.AsArray()).Select(key => key!.ToString()).ToArray();
        bool allFields = fields(["identity_basic", "technical", "security", "privilege", "contact", "hr"]);
        bool security = !allFields && fields(["security"]);
        return raw =>
        {
            foreach (string key in hidden) raw.Remove(key);
            if (!allFields)
            {
                var states = new JsonObject();
                if (security)
                    foreach (string key in new[] { "directory", "exact_last_logon", "password_last_set", "last_logon_timestamp" })
                        states[key] = new JsonObject { ["status"] = raw["sourceStates"]?[key]?["status"]?.DeepClone(), ["observed_at"] = raw["sourceStates"]?[key]?["observed_at"]?.DeepClone() };
                raw["sourceStates"] = states;
            }
        };
    }
    public static void SecurityFacts(JsonObject user)
    {
        foreach (var (field, bit) in new[] { ("passwordNotRequired", 0x20L), ("allowReversiblePasswordEncryption", 0x80L), ("passwordNeverExpires", 0x10000L), ("smartcardLogonRequired", 0x40000L), ("accountNotDelegated", 0x100000L), ("doesNotRequirePreAuth", 0x400000L) })
            if (user["userAccountControl"]?.ToString() is {} text && text.Length>0 && text.All(c=>c is >= '0' and <= '9') && long.TryParse(text, out long uac)) user[field] = (uac & bit) != 0;
            else user[field]=Bool(user[field]);
        var classes = (user["objectClasses"] as JsonArray ?? []).Select(n => n!.ToString().ToLowerInvariant()).ToHashSet();
        user["servicePrincipalNames"]=Array((user["servicePrincipalNames"] is JsonArray spns?spns:new JsonArray(user["servicePrincipalNames"]?.DeepClone())).Where(s=>s?.GetValueKind()==System.Text.Json.JsonValueKind.String&&!string.IsNullOrWhiteSpace(s.ToString())).Select(s=>s!.ToString()));
        user["serviceAccountType"] = classes.Contains("msds-groupmanagedserviceaccount") ? "gmsa" : classes.Contains("msds-managedserviceaccount") ? "msa" : user["servicePrincipalNames"] is JsonArray { Count: > 0 } ? "spn" : null;
    }
    internal static (JsonNode? Value, string? Source) Activity(JsonObject user)
    {
        string? state = user["sourceStates"]?["exact_last_logon"]?.Text("status"); DateTimeOffset? exact = Date(user["exactLastLogon"]), stamp = Date(user["lastLogonTimestamp"]);
        if (state == "observed" && exact is not null) return (user["exactLastLogon"], "lastLogon across all discovered DCs");
        if (state == "partial" && (exact is not null || stamp is not null)) return (exact > stamp || stamp is null ? user["exactLastLogon"] : user["lastLogonTimestamp"], exact is not null && stamp is not null ? "newest of partial lastLogon and lastLogonTimestamp" : exact is not null ? "partial lastLogon across DCs" : "lastLogonTimestamp");
        return stamp is not null ? (user["lastLogonTimestamp"], "lastLogonTimestamp") : (null, null);
    }
    public static JsonObject User(JsonObject user, string? observed, JsonObject? policy=null, JsonObject? exceptions=null, bool includeDetails = true)
    {
        SecurityFacts(user); DateTimeOffset? time = observed is null ? null : DateTimeOffset.Parse(observed, CultureInfo.InvariantCulture); var row = new JsonObject();
        var map = new Dictionary<string, string> { ["id"] = "id", ["entity_id"] = "entityId", ["display_name"] = "displayName", ["sam"] = "samAccountName", ["upn"] = "userPrincipalName", ["enabled"] = "enabled", ["department"] = "department", ["company"] = "company", ["title"] = "title", ["ou"] = "ou", ["mail"] = "mail", ["admin_count"] = "adminCount", ["password_not_required"] = "passwordNotRequired", ["kerberos_no_preauth"] = "doesNotRequirePreAuth", ["reversible_encryption"] = "allowReversiblePasswordEncryption", ["smartcard_required"] = "smartcardLogonRequired", ["account_not_delegated"] = "accountNotDelegated", ["password_last_set"] = "passwordLastSet", ["password_never_expires"] = "passwordNeverExpires", ["created"] = "whenCreated", ["changed"] = "whenChanged", ["sid"] = "sid", ["guid"] = "objectGuid", ["dn"] = "distinguishedName", ["description"] = "description", ["spn"] = "servicePrincipalNames", ["employee_id"] = "employeeID", ["service_account_type"] = "serviceAccountType" };
        foreach (var (field, source) in map) row[field] = user[source]?.DeepClone();
        row["manager"] = user["manager"]?["name"]?.DeepClone();
        row["display_name"]=user["displayName"]?.DeepClone()??user["name"]?.DeepClone();
        string phones=string.Join(", ", new[] { "telephoneNumber", "mobile", "ipPhone" }.Select(user.Text).Where(s => s is not null));row["phones"]=phones.Length>0?phones:null;
        row["locked"] = Bool(user["lockedOut"]) == true; row["account_expired"] = time is {} at && Date(user["accountExpirationDate"]) is {} expiry && expiry < at;
        row["direct_groups"] = Array((user["memberships"]?["direct"] as JsonArray ?? []).Select(g => g!.Text("name")));
        row["effective_count"] = (user["memberships"]?["effective"] as JsonArray ?? []).Count;
        row["watch_groups"] = Array((user["memberships"]?["effective"] as JsonArray ?? []).Where(g => Bool(g?["watchGroup"]) == true).Select(g => g!.Text("name")));
        var activity = Activity(user); row["activity_at"] = Date(activity.Value) is {} stamp ? PythonIso(stamp):null; row["activity_source"] = activity.Source;
        UserObservations(row, user, observed, policy ?? DefaultHygienePolicy, exceptions, includeDetails);
        return row;
    }
    static readonly JsonObject ReasonTemplates=AdV2Store.Resource("user-reasons");
    static readonly JsonObject DefaultHygienePolicy = new() { ["password_age"] = 365, ["inactivity"] = 90 };
    internal static string PythonIso(DateTimeOffset stamp)=>stamp.UtcDateTime.ToString(stamp.Ticks%TimeSpan.TicksPerSecond==0?"yyyy-MM-dd'T'HH:mm:ss'+00:00'":"yyyy-MM-dd'T'HH:mm:ss.ffffff'+00:00'",CultureInfo.InvariantCulture);
    internal static JsonObject Hygiene(JsonObject user, string? observed, JsonObject policy, bool includeDetails = true)
    {
        var result = new JsonObject();
        var time = Date(JsonValue.Create(user["sourceStates"]?["directory"]?.Text("observed_at") ?? observed));
        foreach(var (kind,field,stateField) in new[]{("password_age","passwordLastSet","password_last_set"),("inactivity","lastLogonTimestamp","last_logon_timestamp")})
            result[kind] = EvaluateHygiene(user, time, field, stateField, policy.Int(kind), includeDetails);
        return result;
    }
    static JsonObject EvaluateHygiene(JsonObject user, DateTimeOffset? time, string field, string stateField, long threshold, bool includeDetails)
    {
        var fact = Date(user[field]);
        string? source = user["sourceStates"]?[stateField]?.Text("status") ?? user["sourceStates"]?["directory"]?.Text("status");
        string? reason = source is not null and not ("observed" or "complete" or "completed") ? "source_untrustworthy"
            : fact is null ? "fact_missing_or_invalid"
            : time is null ? "observation_time_missing_or_invalid"
            : fact > time ? "fact_after_observation" : null;
        string status = reason is not null ? "unknown" : (time!.Value - fact!.Value).TotalDays > threshold ? "exceeded" : "within_policy";
        if (!includeDetails) return new JsonObject { ["status"] = status };
        var evaluation = Obj(new
        {
            status, reason, threshold_days = threshold,
            value = fact is null ? null : PythonIso(fact.Value),
            observed_at = time is null ? null : PythonIso(time.Value)
        });
        if (stateField == "last_logon_timestamp")
            evaluation["limitation"] = "lastLogonTimestamp — приблизительный реплицируемый атрибут; возможна задержка репликации. Это не доказательство отсутствия входов.";
        return evaluation;
    }
    static void UserObservations(JsonObject row, JsonObject user, string? observed, JsonObject policy, JsonObject? exceptions, bool includeDetails)
    {
        string TextValue(JsonNode? value)=>value is null||string.IsNullOrWhiteSpace(value.ToString())?"—":value.ToString();
        var observations=new List<JsonObject>();
        JsonObject Add(string key,string? summary=null,string? evidence=null)
        {
            var template = ReasonTemplates[key]!.AsObject();
            var item = includeDetails ? template.DeepClone().AsObject()
                : new JsonObject { ["key"] = key, ["label"] = template["label"]?.DeepClone(), ["order"] = template["order"]?.DeepClone() };
            if (includeDetails && summary is not null) item["summary"] = summary;
            if (includeDetails && evidence is not null) item["observed"] = evidence;
            observations.Add(item);
            return item;
        }
        var flags=new List<string>();var attention=new List<string>();
        foreach(var (field,label) in new[]{("passwordNeverExpires","Пароль не истекает"),("passwordNotRequired","Пароль не требуется"),("smartcardLogonRequired","Требуется смарт-карта"),("accountNotDelegated","Учётная запись чувствительна, не делегируется"),("doesNotRequirePreAuth","Kerberos pre-authentication не требуется")})if(Bool(user[field])==true)flags.Add(label);
        foreach(var (field,label) in new[]{("allowReversiblePasswordEncryption","Разрешено обратимое шифрование пароля"),("trustedForDelegation","TrustedForDelegation = true"),("trustedToAuthForDelegation","TrustedToAuthForDelegation = true"),("useDesKeyOnly","UseDESKeyOnly = true")})if(Bool(user[field])==true){flags.Add(label);attention.Add(label);}
        if(Bool(user["lockedOut"])==true)Add("locked_out",evidence:$"Заблокирована; снимок: {observed}");
        if(Bool(row["account_expired"])==true)Add("account_expired",$"AccountExpirationDate: {TextValue(user["accountExpirationDate"])}",$"AccountExpirationDate = {TextValue(user["accountExpirationDate"])}; снимок = {observed}");
        if(Bool(user["passwordExpired"])==true||Date(user["passwordExpiry"]) is {} expiry&&expiry<Date(JsonValue.Create(observed)))Add("password_expired",Bool(user["passwordExpired"])==true?"PasswordExpired = true":$"Истечение: {TextValue(user["passwordExpiry"])}",$"PasswordExpired = {(Bool(user["passwordExpired"])==true?"True":"False")}; вычисленная дата = {TextValue(user["passwordExpiry"])}");
        if (attention.Count > 0)
        {
            string? text = includeDetails ? string.Join("; ", attention) : null;
            var item = Add("sensitive_uac_flag", text, text);
            if (includeDetails) item["flags"] = Array(attention);
        }
        var hygiene = Hygiene(user, observed, policy, includeDetails);
        string? snapshot = user["sourceStates"]?["directory"]?.Text("observed_at") ?? observed;
        bool hasSpn = user["servicePrincipalNames"] is JsonArray { Count: > 0 };
        var spnPassword = hasSpn ? policy.Int("password_age") == 365 ? hygiene["password_age"]!
            : EvaluateHygiene(user, Date(JsonValue.Create(snapshot)), "passwordLastSet", "password_last_set", 365, includeDetails) : null;
        foreach(var (key,condition) in new[]{("password_not_required",Bool(user["passwordNotRequired"])==true),("kerberos_no_preauth",Bool(user["doesNotRequirePreAuth"])==true),("spn_privileged",hasSpn&&Privileged(user)),("spn_old_password",spnPassword.Text("status")=="exceeded"),("privileged_password_never_expires",Bool(user["passwordNeverExpires"])==true&&Privileged(user))})
            if(condition)
            {
                var item = Add(key);
                if (!includeDetails) continue;
                item["observed"]=$"{item.Text("condition")}; UAC = {TextValue(user["userAccountControl"])}; SPN = {(user["servicePrincipalNames"] is JsonArray {Count:>0} spns?string.Join("; ",spns.Select(n=>n!.ToString())):"—")}; pwdLastSet = {TextValue(user["passwordLastSet"])}; снимок: {snapshot}";
                item["evidence"]=new JsonObject{["uac"]=user["userAccountControl"]?.DeepClone(),["spn"]=user["servicePrincipalNames"]?.DeepClone(),["password_last_set"]=user["passwordLastSet"]?.DeepClone(),["snapshot_at"]=snapshot};
                if(key=="spn_old_password")item["password_evaluation"]=spnPassword!.DeepClone();
            }
        if(user["temporaryMemberships"] is JsonArray{Count:>0} episodes)
        {
            var item = Add("temporary_membership", includeDetails
                ? string.Join(", ", episodes.Select(e => e.Text("group") ?? "None").Distinct().Order(StringComparer.Ordinal)) : null,
                includeDetails ? episodes.Count.ToString(CultureInfo.InvariantCulture) : null);
            if (includeDetails) item["evidence"] = Array(episodes.Select(e => e!["evidence"]));
        }
        foreach(var (kind,evaluation) in hygiene)
        {
            string status=evaluation!.Text("status")!;if(status=="within_policy"||kind=="inactivity"&&status=="exceeded"&&Bool(user["enabled"])!=true)continue;
            bool unknown=status=="unknown";string key=kind=="password_age"?(unknown?"password_age_unknown":"password_age"):(unknown?"enabled_activity_unknown":"inactive_threshold"),field=kind=="password_age"?"pwdLastSet":"lastLogonTimestamp";
            if (!includeDetails) { Add(key); continue; }
            string detail=evaluation.Text("reason") switch{"source_untrustworthy"=>"Источник неполон или недостоверен","fact_missing_or_invalid"=>"Дата отсутствует или некорректна","observation_time_missing_or_invalid"=>"Момент наблюдения отсутствует или некорректен","fact_after_observation"=>"Дата позже момента наблюдения",_=>"Порог принятой политики превышен"};
            var item=Add(key,unknown?"Неизвестно: "+detail:$"Более {evaluation.Int("threshold_days")} дней",$"{field} = {TextValue(evaluation!["value"])}; снимок = {observed}");
            item["condition"]=$"Возраст наблюдаемого {field} > {evaluation.Int("threshold_days")} дней";item["qualification"]=unknown?"Неизвестно: "+detail:$"Наблюдаемый возраст превышает принятую политику {evaluation.Int("threshold_days")} дней.";item["limitation"]=evaluation.Text("limitation")??"pwdLastSet подтверждает дату установки пароля, а не его стойкость.";item["policy"]=evaluation.DeepClone();
        }
        var missing=new[]{("sAMAccountName","samAccountName"),("userPrincipalName","userPrincipalName")}.Where(p=>user.Text(p.Item2) is null).Select(p=>p.Item1).ToArray();
        if(missing.Length>0)Add("identity_key_missing",string.Join(", ",missing),"Отсутствующие поля: "+string.Join(", ",missing));
        string graph=user["memberships"]?.Text("status")??"not_collected";var unresolved=user["memberships"]?["unresolved"] as JsonArray??[];
        if(graph!="observed"||unresolved.Count>0)Add("group_graph_partial",$"{unresolved.Count} неразрешённых связей",$"groups.status = {graph}; unresolved = {(unresolved.Count>0?string.Join("; ",unresolved.Select(n=>n!.ToString())):"не указано")}");
        JsonNode? serviceException=user.Text("serviceAccountType") is not null?exceptions?[user.Text("sid")?.ToUpperInvariant()??""]:null;
        if(serviceException is not null)observations.RemoveAll(r=>r.Text("key") is "password_age" or "inactive_threshold" or "spn_old_password");
        observations=observations.OrderBy(r=>r.Int("order")).ThenBy(r=>r.Text("summary"),StringComparer.Ordinal).ToList();
        bool Information(JsonObject item)=>item.Text("key") is "password_age_unknown" or "enabled_activity_unknown" or "identity_key_missing" or "group_graph_partial";
        var reasons=observations.Where(r=>!Information(r)).ToArray();var limitations=observations.Where(Information).ToArray();
        row["reasons"] = new JsonArray(reasons);
        row["reason_keys"] = new JsonArray(reasons.Select(r => JsonValue.Create(r.Text("key"))).ToArray());
        row["reason_text"] = reasons.Length == 0 ? null : string.Join(", ", reasons.Select(r => r.Text("label")));
        row["information_limitations"] = new JsonArray(limitations);
        row["information_keys"] = new JsonArray(limitations.Select(r => JsonValue.Create(r.Text("key"))).ToArray());
        row["information_text"] = limitations.Length > 0 ? string.Join(", ", limitations.Select(r => r.Text("label"))) : null;
        foreach (var (kind, evaluation) in hygiene) row[kind + "_policy"] = evaluation!["status"]!.DeepClone();
        if (!includeDetails) return;
        row["hygiene"] = hygiene;
        row["severity"] = reasons.Any(r => r.Text("severity") == "high") ? "high" : reasons.Length > 0 ? "medium" : null;
        row["service_exception"] = serviceException?.DeepClone();
        row["review_details"] = new JsonArray(observations.Select(r =>
        {
            var detail = r.DeepClone().AsObject();
            detail["category"] = Information(r) ? "information" : "confirmed";
            return detail;
        }).ToArray());
        row["flags"] = Array(flags);
    }
    public static JsonObject Computer(JsonObject raw, JsonObject source, string observed, JsonObject parameters)
    {
        var time = DateTimeOffset.Parse(observed, CultureInfo.InvariantCulture); var row = new JsonObject();
        var map = new Dictionary<string, string> { ["display_name"] = "name", ["natural_key"] = "id", ["object_guid"] = "objectGuid", ["object_sid"] = "sid", ["dns_host_name"] = "dnsHostName", ["distinguished_name"] = "distinguishedName", ["canonical_name"] = "canonicalName", ["location"] = "location", ["managed_by"] = "managedBy", ["description"] = "description", ["enabled"] = "enabled", ["operating_system"] = "osName", ["operating_system_version"] = "osVersion", ["operating_system_family"] = "osFamily", ["operating_system_service_pack"] = "servicePack", ["last_logon_utc"] = "lastLogonTimestamp", ["password_last_set_utc"] = "passwordLastSet", ["created_utc"] = "whenCreated", ["when_changed_utc"] = "whenChanged", ["user_account_control"] = "userAccountControl", ["service_principal_names"] = "spns", ["trusted_for_delegation"] = "trustedForDelegation", ["trusted_to_auth_for_delegation"] = "trustedToAuthForDelegation" };
        foreach (var (field, from) in map) row[field] = raw[from]?.DeepClone();
        row["entity_id"] = source["entity_ids"]?[raw.Text("objectGuid") ?? ""]?.DeepClone(); row["domain_id"] = source["domain_id"]!.DeepClone(); row["domain_name"] = source["fqdn"]?.DeepClone();
        row["identity"] = Obj(new { object_guid = raw.Text("objectGuid"), object_sid = raw.Text("sid") }); row["observed_at_utc"] = observed;
        string os = raw.Text("osName") ?? ""; string type = (raw.Int("userAccountControl") & 8192) != 0 ? "domain_controller" : raw["classification"]?.Text("result") is "server" or "domain_controller" or "workstation" ? raw["classification"]!.Text("result")! : os.Contains("server", StringComparison.OrdinalIgnoreCase) ? "server" : os.ToLowerInvariant() is not ("" or "unknown" or "неизвестно") ? "workstation" : "unknown";
        row["computer_type"] = type; row["account_state"] = Bool(raw["enabled"]) switch { true => "enabled", false => "disabled", _ => "unknown" };
        int? age = Age(raw["lastLogonTimestamp"], time) is {} days?Math.Max(0,days):null; int threshold = parameters.Int("threshold_days") > 0 ? (int)parameters.Int("threshold_days") : 90;
        string activity = Bool(raw["enabled"])==false?"not_applicable":Bool(raw["enabled"]) is null||age is null?"not_evaluated":age>60?"inactive":"recent";
        row["activity_state"] = activity; row["activity"] = Obj(new { state = activity, age_days = age, time_semantics = "replicated_lastLogonTimestamp_approximation", source_attribute = "LastLogonDate" }); row["age_days"] = age;
        row["ip_addresses"] = Array((raw["ipv4s"] as JsonArray ?? []).Concat(raw["ipv6s"] as JsonArray ?? []).Select(n => n!.ToString())); row["ip_text"] = string.Join(", ", row["ip_addresses"]!.AsArray().Select(n => n!.ToString()));
        row["ad_site"] = Obj(new { state = raw.Text("adSite") is null ? "not_collected" : "observed", value = raw.Text("adSite") }); row["site_text"] = raw["adSite"]?.DeepClone(); row["ou_path"] = AdUsersSnapshot.Ou(raw.Text("distinguishedName"));
        row["evidence"] = new JsonObject { ["source_states"] = raw["sources"]?.DeepClone(), ["attribute_states"] = new JsonObject() };
        var reasons = new List<JsonObject>();
        void Reason(bool match, string code, string label) { if (match) reasons.Add(Obj(new { code, label })); }
        Reason(type == "unknown", "unknown_type", "Тип объекта не определён"); Reason(Bool(raw["enabled"]) == true && age > threshold, "stale_activity", "Активность старше " + threshold + " дней"); Reason(Bool(raw["enabled"]) == true && age is null, "unavailable_activity", "Нет доступной даты активности"); Reason((raw.Int("userAccountControl") & 524288) != 0 || Bool(raw["trustedForDelegation"]) == true, "unconstrained_delegation", "Неограниченное делегирование");
        row["reasons"] = Array(reasons); row["reason_text"] = string.Join(", ", reasons.Select(r => r.Text("label"))); row["quality_issues"] = new JsonArray(); row["quality_text"] = null; row["semantic_findings"] = new JsonArray();
        row["ad_last_logon_utc"] = raw["lastLogonTimestamp"]?.DeepClone();
        row["last_logon_utc"]=raw["eventLastSeen"]?.DeepClone()??raw["exactLastLogon"]?.DeepClone()??raw["lastLogonTimestamp"]?.DeepClone();
        row["ou_path"]=raw["ou"]?.DeepClone()??row["ou_path"]?.DeepClone();row["operating_system_build"]=raw["osBuild"]?.DeepClone();row["classification"]=raw["classification"]?.DeepClone()??Obj(new{result=type,state=type=="unknown"?"unknown":"observed",rule_id="base_inventory_os_family",evidence=new[]{"OperatingSystem="+(raw.Text("osName")??"не передано")}});
        row["classification"]!["role_hint"]=raw["roleHint"]?.DeepClone();row["classification"]!["role_evidence"]=raw["roleEvidence"]?.DeepClone()??new JsonArray();
        row["collection"]=new JsonObject{["collected_at"]=raw["collectedAt"]?.DeepClone(),["query_dc"]=raw["queryDc"]?.DeepClone()??source["snapshot"]?["metadata"]?["query_dc"]?.DeepClone(),["collector_version"]=raw["collectorVersion"]?.DeepClone()??source["snapshot"]?["metadata"]?["collector_version"]?.DeepClone()};
        foreach(var(field,from)in new[]{("last_logon_timestamp","last_logon_timestamp"),("exact_last_logon","exact_last_logon"),("dc_event","dc_events")})row["activity"]![field]=raw["sources"]?[from]?.DeepClone()??new JsonObject();
        row["network"]=new JsonObject{["addresses"]=row["ip_addresses"]!.DeepClone(),["address_state"]=raw["sources"]?["dns"]?.Text("status")??"not_collected",["ad_site"]=row["ad_site"]!.DeepClone()};row["ad_site"]!["state"]=raw["sources"]?["site"]?.Text("status")??"not_collected";
        row["evidence"]!["collection_errors"]=raw["collectionErrors"]?.DeepClone()??new JsonArray();
        row["evidence"]!["activity_sources"]=new JsonObject{["replicated_last_logon"]=raw["sources"]?["last_logon_timestamp"]?.DeepClone()??new JsonObject(),["exact_last_logon"]=raw["sources"]?["exact_last_logon"]?.DeepClone()??new JsonObject(),["dc_logon_events"]=raw["sources"]?["dc_events"]?.DeepClone()??new JsonObject()};
        row["evidence"]!["network_sources"]=new JsonObject{["dns_addresses"]=raw["sources"]?["dns"]?.DeepClone()??new JsonObject(),["ad_site"]=raw["sources"]?["site"]?.DeepClone()??new JsonObject()};
        AdComputerPosture.Apply(row,raw,time);ComputerQuality(row,raw,source);ComputerReasons(row,raw,threshold,time);
        return row;
    }
    static readonly JsonObject ComputerTemplates=AdV2Store.Resource("computer-reasons");
    static void ComputerQuality(JsonObject row,JsonObject raw,JsonObject source)
    {
        var requested=(source["snapshot"]?["metadata"]?["sources"] as JsonArray??[]).ToDictionary(s=>s!.Text("name")!,s=>Bool(s?["requested"])==true);
        var codes=new HashSet<string>();foreach(var(name,state)in raw["sources"] as JsonObject??new())
        {string? code=state.Text("status") switch{"failed" or "access_denied" or "parse_error"=>"source_error","not_collected" when requested.GetValueOrDefault(name)=>"not_collected","not_evaluated"=>"not_evaluated","no_record" or "missing_in_source"=>"no_record_or_missing_source","partial"=>"partial",_=>null};if(code is not null)codes.Add(code);}
        var issues=new List<JsonObject>();foreach(var(code,label)in new[]{("source_error","Ошибка источника"),("not_collected","Не собиралось"),("not_evaluated","Не оценивалось"),("no_record_or_missing_source","Запись или значение не найдено"),("partial","Частичный результат")})if(codes.Contains(code))issues.Add(Obj(new{code,label}));
        var missing=new[]{("osName",raw.Text("osName")),("dnsHostName",raw.Text("dnsHostName")),("lastObserved",raw.Text("eventLastSeen")??raw.Text("exactLastLogon")??raw.Text("lastLogonTimestamp")),("distinguishedName",raw.Text("distinguishedName"))}.Where(p=>p.Item2 is null).Select(p=>p.Item1).ToArray();if(missing.Length>0)issues.Add(Obj(new{code="missing_field",label="Поле отсутствует",fields=missing}));row["quality_issues"]=Array(issues);row["quality_text"]=issues.Count>0?string.Join(", ",issues.Select(i=>i.Text("label"))):null;
    }
    internal static void ComputerReasons(JsonObject row,JsonObject raw,int threshold,DateTimeOffset at)
    {
        var reasons=new List<JsonObject>();JsonObject Add(string code){var r=(JsonObject)ComputerTemplates[code]!.DeepClone();reasons.Add(r);return r;}
        var end=AdComputerPosture.SupportEnd(row.Text("operating_system"),row.Text("operating_system_version"));
        if(end is not null&&at.Date>end.Value.Date){var r=Add("unsupported_os");string date=end.Value.ToString("yyyy-MM-dd",CultureInfo.InvariantCulture);r["observed"]=$"{row.Text("operating_system")}; окончание расширенной поддержки Microsoft: {date}.";r["support_end_date"]=date;r["operating_system"]=row["operating_system"]?.DeepClone();r["policy_version"]="microsoft-lifecycle-2026-10-16";}
        if(Bool(row["delegation"]?["unconstrained"])==true)Add("unconstrained_delegation");
        if(row["laps"]?.Text("state")=="expired"){var r=Add("laps_expired");r["observed"]=$"Плановый срок: {row["laps"]!.Text("expiration_utc")}.";r["expiration_utc"]=row["laps"]!["expiration_utc"]?.DeepClone();}
        if(row["quality_issues"]!.AsArray().Any(i=>i!.Text("code") is "source_failed" or "source_error"))Add("source_error");
        if(row.Text("computer_type")=="unknown")Add("unknown_type");
        int? age=row["activity"]?["age_days"]?.GetValue<int>();
        if(Bool(row["enabled"])==true&&age>threshold){var r=Add("stale_activity");r["label"]=$"Активность старше {threshold} дней";r["observed"]=$"Последнее приблизительное AD-наблюдение: {row.Text("last_logon_utc")??"нет"}; возраст: {age} дней.";r["condition"]=$"Разница строго больше выбранного порога {threshold} дней, а учётная запись включена в AD.";r["qualification"]=$"Последнее доступное AD-наблюдение старше {threshold} дней.";r["threshold_days"]=threshold;}
        else if(Bool(row["enabled"])==true&&age is null)Add("unavailable_activity");
        if(row.Text("operating_system") is null||raw["sources"]?["os"]?.Text("status") is not ("observed" or "present"))Add("unknown_os");
        foreach(var reason in reasons)
        {
            string code=reason.Text("code")!;
            var parameters=new JsonObject{["threshold_days"]=reason["threshold_days"]?.DeepClone(),["age_days"]=age,["last_logon_utc"]=row.Text("last_logon_utc")??""};
            foreach(string field in new[]{"operating_system","support_end_date","expiration_utc"})if(reason.ContainsKey(field))parameters[field]=reason[field]?.DeepClone();
            var messages=new JsonObject();
            foreach(string field in new[]{"label","observed","condition","qualification","limitation","next_action"})
            {
                string key="reports.v2.ad.computers.v6."+(field=="label"?"reasons."+code:"security."+code+"."+field);
                if(code=="stale_activity"&&field=="observed"&&string.IsNullOrEmpty(row.Text("last_logon_utc")))key+="_missing_date";
                if(AdPresentation.Message(key,parameters) is {} message)messages[field]=message;
            }
            if(messages.Count>0)reason["presentation_messages"]=messages;
        }
        row["reasons"]=Array(reasons);row["reason_text"]=string.Join(", ",reasons.Select(r=>r.Text("label")));
    }
    public static bool Matches(AdV2Request request, JsonObject raw, JsonObject row, bool users)
    {
        string Fold(string value)=>string.Join(' ',value.Normalize(System.Text.NormalizationForm.FormKC).ToLowerInvariant().Replace('ё','е').Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries));
        string? q = request.Params.Text("q"); if(q is not null)
        {
            string text = users
                ? string.Join(' ', new[] { "display_name", "account_display_name", "sam", "upn", "mail", "phones", "department", "company", "title", "manager", "ou", "employee_id", "sid", "guid" }
                    .Select(row.Text).Concat(new[] { "direct_groups", "watch_groups", "privilege_basis" }
                        .SelectMany(key => (row[key] as JsonArray ?? []).Select(group => group?.ToString()))))
                : string.Join(' ',new[]{"display_name","natural_key","dns_host_name","distinguished_name","ou_path","operating_system","operating_system_version","operating_system_build","object_guid","object_sid","canonical_name","location","managed_by","description","site_text"}.Select(row.Text).Concat((row["ip_addresses"] as JsonArray??[]).Select(n=>n?.ToString())).Concat((row["service_principal_names"] as JsonArray??[]).Select(n=>n?.ToString())).Concat((row["reasons"] as JsonArray??[]).SelectMany(r=>new[]{"code","label","observed","condition","qualification","limitation","next_action"}.Select(r!.Text))).Concat((row["quality_issues"] as JsonArray??[]).SelectMany(r=>new[]{r!.Text("code"),r.Text("label")})));
            if(!Fold(text).Contains(Fold(q),StringComparison.Ordinal))return false;
        }
        foreach (string key in users ? new[] { "department", "company", "ou" } : new[] { "os", "os_version", "os_family", "ou", "ad_site", "type", "enabled" })
        {
            string field = key switch { "os" => "operating_system", "os_version" => "operating_system_version", "os_family" => "operating_system_family", "ou" when !users => "ou_path", "ad_site" => "site_text", "type" => "computer_type", "enabled" => "account_state", "activity" => "activity_state", _ => key };
            if (request.Params.Text(key) is {} value && !(users?value==row.Text(field):value=="__missing__"?row.Text(field) is null:string.Equals(value,row.Text(field),StringComparison.OrdinalIgnoreCase))) return false;
        }
        string view = request.Params.Text("view") ?? "all";
        if (users)
        {
            if (request.Tab is "active" or "disabled" && Bool(raw["enabled"]) != (request.Tab == "active")) return false;
            if (request.Tab == "privileged" && !Privileged(raw)) return false;
            if (request.Tab == "risk" && !AdUsersTabs.IsRisk(row)) return false;
            if (view is "enabled" or "disabled" && Bool(raw["enabled"]) != (view == "enabled")) return false;
            if (view == "locked" && Bool(raw["lockedOut"]) != true || view == "expired" && Bool(row["account_expired"]) != true) return false;
            if (request.Tab=="all"&&request.Params.Text("account_state") is {} accountState&&Bool(raw["enabled"])!=(accountState switch{"enabled"=>true,"disabled"=>false,_=>(bool?)null}))return false;
            if (request.Params.Text("group") is {} group && !(raw["memberships"]?[request.Tab != "privileged" && request.Params.Text("relation") == "direct" ? "direct" : "effective"] as JsonArray ?? []).Any(g => request.Tab == "privileged" ? Bool(g?["watchGroup"]) == true && g.Text("id")?.Replace("group:", "") == group.Replace("group:", "") : g.Text("id") == group) && !(request.Tab=="privileged"&&(raw["privilegedMemberships"] as JsonArray??[]).Any(g=>g!.Text("relation")=="direct"&&g.Int("group_id").ToString()==group.Replace("group:","")))) return false;
        }
        else
        {
            if(view is "workstation_enabled" or "workstation_disabled"&&(row.Text("computer_type")!="workstation"||Bool(raw["enabled"])!=(view=="workstation_enabled"))||view is "server_enabled" or "server_disabled"&&(row.Text("computer_type") is not ("server" or "domain_controller")||Bool(raw["enabled"])!=(view=="server_enabled")))return false;
            if(view=="unknown_type"&&row.Text("computer_type")!="unknown"||view=="data_quality"&&row["quality_issues"]!.AsArray().Count==0||view=="semantic"&&row["semantic_findings"]!.AsArray().Count==0)return false;
            if(request.Params.Text("reason_code") is {} code&&!row["reasons"]!.AsArray().Any(r=>r!.Text("code")==code)||request.Params.Text("quality_code") is {} quality&&!row["quality_issues"]!.AsArray().Any(r=>r!.Text("code")==quality))return false;
            if (!MatchesComputerActivity(row, request.Params.Text("activity"), request.Params.Int("threshold_days"))) return false;
        }
        if (view == "attention" && row["reasons"]!.AsArray().Count == 0) return false;
        if (request.Params.Text("reason") is {} reason && !(row["reason_keys"] as JsonArray??[]).Any(n => n!.ToString() == reason)) return false;
        if (request.Params.Text("information") is {} information && !(row["information_keys"] as JsonArray??[]).Any(n=>n!.ToString()==information))return false;
        return true;
    }

    internal static bool MatchesComputerActivity(JsonObject row, string? activity, long configuredThreshold)
    {
        int? days = row["activity"]?["age_days"]?.GetValue<int>();
        long threshold = configuredThreshold > 0 ? configuredThreshold : 90;
        return activity switch
        {
            "missing" => days is null,
            "within_30_days" => days <= 30,
            "days_31_to_90" => days is >= 31 and <= 90,
            "over_60_days" => days > 60,
            "within_threshold" => days <= threshold,
            "over_threshold" => days > threshold,
            _ => true,
        };
    }
}
