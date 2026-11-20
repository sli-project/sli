using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Storage.EventReports;

internal sealed class EventSearchException(string code,int? status=null) : Exception(code)
{
    internal string Code => Message.StartsWith("evsearch.",StringComparison.Ordinal) ? Message : "evsearch."+Message;
    internal int Status => status ?? (Code.EndsWith("snapshot_expired",StringComparison.Ordinal)?410:
        Code.EndsWith("snapshot_invalidated",StringComparison.Ordinal)?409:Code.EndsWith("policy_denied",StringComparison.Ordinal)?403:
        new[]{"unavailable","timeout","integrity"}.Any(Code.Contains)?503:422);
}

internal sealed record SearchCondition(string Field,string Operator,JsonNode[] Values,string? Role=null);
internal sealed record EventSearchInput(DateTimeOffset From,DateTimeOffset To,string Zone,string Sort,int PageSize,
    SearchCondition[] Conditions,string? Q,bool ExcludeMachine,string AccountRole,string? Question,JsonObject Request)
{
    internal static readonly string[] Fields=["action","outcome","reason","account","source_station","server_id","domain_id","channel","provider","ip","related_object","event_id","category","risk","tier","legacy_journal_view","legacy_journal_q","legacy_search_q","file_path","message_sample"];
    internal static readonly string[] IdFields=["account","source_station","server_id","domain_id","related_object"];
    internal static bool Text(JsonNode? node,int max=256) => node is JsonValue v && v.TryGetValue<string>(out var s) && s.Length is >0 && s.EnumerateRunes().Count()<=max && s.Trim()==s && !s.Any(c=>c<32 || c==127);
    internal static string? String(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s)?s:null;
    internal static void Keys(JsonObject obj,params string[] keys)
    { if(obj.Any(p=>!keys.Contains(p.Key))) throw new EventSearchException("invalid_request"); }
    internal static int Size(JsonObject obj,int fallback=50)
    {
        if(!obj.ContainsKey("page_size")) return fallback;
        if(obj["page_size"] is not JsonValue v || !v.TryGetValue<int>(out int n) || n is <1 or >100) throw new EventSearchException("invalid_request");
        return n;
    }
    internal static EventSearchInput Parse(JsonObject raw,DateTimeOffset now)
    {
        // HTTP callers retain the existing default period; legacy links use the
        // wire validator directly so their predicates and dates remain intact.
        var wire=(JsonObject)raw.DeepClone();
        if(!wire.ContainsKey("period")) wire["period"]=new JsonObject { ["preset"]="24h",["timezone"]="UTC" };
        raw=Validate(wire);
        string sort=String(raw["sort"])??"time_desc";
        int size=Size(raw); bool exclude=raw["exclude_machine_system"]?.GetValue<bool>()??false;
        var period=raw["period"]!.AsObject();
        string preset=String(period["preset"])??"",zone=String(period["timezone"])??"";
        DateTimeOffset from,to;
        try
        {
            _=TimeZoneInfo.FindSystemTimeZoneById(zone);
            if(preset=="custom") { from=Instant(String(period["from"]),zone,false); to=Instant(String(period["to"]),zone,true); }
            else { to=now; from=now.AddDays(preset=="24h"?-1:preset=="7d"?-7:-30); }
        }
        catch(Exception e) when(e is TimeZoneNotFoundException or InvalidTimeZoneException or FormatException or ArgumentException) { throw new EventSearchException("invalid_period"); }
        if(from>=to) throw new EventSearchException("invalid_period");
        if(to-from>TimeSpan.FromDays(90)) throw new EventSearchException("period_too_wide");
        var context=raw["entry_context"] as JsonObject; string role="any";
        if(context is not null && String(context["kind"])=="entity" && String(context["role"]) is "actor" or "target" or "any") role=String(context["role"])!;
        var conditions=raw["conditions"] as JsonArray ?? [];
        var selections=new Dictionary<(string,string?),Dictionary<string,JsonNode>>();
        var exclusions=new Dictionary<(string,string?),Dictionary<string,JsonNode>>();
        var presence=new Dictionary<(string,string?),string>();
        foreach(var item in conditions)
        {
            var c=item!.AsObject();
            string field=String(c["field"])??"",op=String(c["operator"])??""; string? cr=String(c["role"]);
            var key=(field,cr);
            if(op is "exists" or "missing")
            { if(presence.TryGetValue(key,out var prev) && prev!=op) throw new EventSearchException("invalid_condition"); presence[key]=op; continue; }
            JsonNode?[] values=op=="eq"?[c["value"]]:(c["value"] as JsonArray)?.ToArray()??[];
            foreach(var value in values)
            {
                JsonNode normalized=value!.DeepClone();
                if(field=="ip") normalized=JsonValue.Create(IPAddress.Parse(String(value)!).ToString())!;
                if(!selections.ContainsKey(key)) { selections[key]=[]; exclusions[key]=[]; }
                string vk=normalized.ToJsonString(); selections[key].Remove(vk); exclusions[key].Remove(vk);
                (op=="not_in"?exclusions:selections)[key][vk]=normalized;
            }
        }
        var result=new List<SearchCondition>();
        foreach(var key in selections.Keys.OrderBy(k=>k.Item1,StringComparer.Ordinal).ThenBy(k=>k.Item2,StringComparer.Ordinal))
        {
            foreach(var (dict,op) in new[]{(selections,"in"),(exclusions,"not_in")})
            { var vals=dict[key].Values.OrderBy(v=>IdFields.Contains(key.Item1) || key.Item1=="event_id"?v.GetValue<long>():0).ThenBy(v=>String(v),StringComparer.Ordinal).ToArray(); if(vals.Length>100 || key.Item1.StartsWith("legacy_",StringComparison.Ordinal) && vals.Length>1) throw new EventSearchException("invalid_condition"); if(vals.Length>0) result.Add(new(key.Item1,key.Item1.StartsWith("legacy_",StringComparison.Ordinal)?"eq":op,vals,key.Item2)); }
        }
        result.AddRange(presence.Select(p=>new SearchCondition(p.Key.Item1,p.Value,[],p.Key.Item2)));
        result=result.OrderBy(c=>c.Field,StringComparer.Ordinal).ThenBy(c=>c.Role,StringComparer.Ordinal).ThenBy(c=>c.Operator is "in" or "eq"?0:c.Operator=="not_in"?1:2).ToList();
        if(result.Any(c=>c.Field=="event_id" && c.Values.Length>0) && !result.Any(c=>c.Field is "provider" or "channel" && c.Operator is "eq" or "in")) throw new EventSearchException("event_context_required");
        string? question=String(raw["question_id"]);
        if(question is not null)
        {
            if(!Questions.ContainsKey(question)) throw new EventSearchException("unsupported_question");
            role=question is "failed_logons" or "lockouts" or "admin_logons" or "new_admins"?"target":"actor";
        }
        var request=new JsonObject { ["contract_version"]="evsearch.v1",["grouping_version"]="evsearch.group.v1",["period"]=Period(from,to,zone),["exclude_machine_system"]=exclude,["sort"]=sort,["page_size"]=size,
            ["conditions"]=new JsonArray(result.Select(c=>
            { var node=new JsonObject { ["field"]=c.Field,["operator"]=c.Operator }; if(c.Role is not null) node["role"]=c.Role; if(c.Values.Length>0) node["value"]=c.Operator=="eq"?c.Values[0].DeepClone():new JsonArray(c.Values.Select(v=>v.DeepClone()).ToArray()); return node as JsonNode; }).ToArray()) };
        if(question is not null) request["question_id"]=question;
        if(raw.ContainsKey("q")) request["q"]=raw["q"]!.DeepClone();
        if(context is not null) request["entry_context"]=context.DeepClone();
        return new(from,to,zone,sort,size,result.ToArray(),String(raw["q"]),exclude,role,question,request);
    }
    internal static string Iso(DateTimeOffset time)=>time.ToUniversalTime().ToString(time.Ticks%TimeSpan.TicksPerSecond==0?"yyyy-MM-dd'T'HH:mm:ss'Z'":"yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'",CultureInfo.InvariantCulture);
    internal static JsonObject Period(DateTimeOffset from,DateTimeOffset to,string zone) => new() { ["preset"]="custom",["from"]=Iso(from),["to"]=Iso(to),["timezone"]=zone };
    internal static bool Integer(JsonNode? n,long min,long max) => n is JsonValue v && v.TryGetValue<long>(out var id) && id>=min && id<=max;
    internal static JsonObject Validate(JsonObject raw)
    {
        Keys(raw,"contract_version","question_id","conditions","period","q","exclude_machine_system","grouping_version","sort","page_size","entry_context");
        if(String(raw["contract_version"])!="evsearch.v1" || raw.ContainsKey("grouping_version") && String(raw["grouping_version"])!="evsearch.group.v1") throw new EventSearchException("unsupported_version");
        if(raw.ContainsKey("sort") && !new[]{"time_desc","time_asc","count_desc"}.Contains(String(raw["sort"]))) throw new EventSearchException("invalid_request");
        _=Size(raw);
        if(raw.ContainsKey("exclude_machine_system") && (raw["exclude_machine_system"] is not JsonValue flag || !flag.TryGetValue<bool>(out _))) throw new EventSearchException("invalid_request");
        foreach(string key in new[]{"q","question_id"}) if(raw.ContainsKey(key) && !Text(raw[key],key=="q"?256:64)) throw new EventSearchException("invalid_request");
        if(raw["period"] is not JsonObject period) throw new EventSearchException("invalid_request");
        Keys(period,"preset","from","to","timezone");
        string? preset=String(period["preset"]);
        if(!new[]{"24h","7d","30d","custom"}.Contains(preset) || !Text(period["timezone"],64) ||
            (preset=="custom" ? !Text(period["from"],64) || !Text(period["to"],64) : period.ContainsKey("from") || period.ContainsKey("to"))) throw new EventSearchException("invalid_period");
        if(raw.ContainsKey("entry_context"))
        {
            if(raw["entry_context"] is not JsonObject context) throw new EventSearchException("invalid_request");
            Keys(context,"kind","finding_id","entity_id","role","return_to");
            if(!new[]{"question","finding","entity"}.Contains(String(context["kind"]))) throw new EventSearchException("invalid_request");
            foreach(string key in new[]{"finding_id","entity_id"}) if(context.ContainsKey(key) && !Integer(context[key],1,long.MaxValue)) throw new EventSearchException("invalid_request");
            if(context.ContainsKey("role") && !new[]{"actor","target","any","source_station","related_object"}.Contains(String(context["role"])) || context.ContainsKey("return_to") && !SafeReturn(context["return_to"])) throw new EventSearchException("invalid_request");
        }
        if(raw.ContainsKey("conditions") && raw["conditions"] is not JsonArray) throw new EventSearchException("invalid_condition");
        var conditions=raw["conditions"] as JsonArray ?? [];
        if(conditions.Count>32) throw new EventSearchException("invalid_condition");
        foreach(var item in conditions)
        {
            if(item is not JsonObject c) throw new EventSearchException("invalid_request");
            Keys(c,"field","operator","value","role");
            string field=String(c["field"])??"",op=String(c["operator"])??"";
            if(!Fields.Contains(field)) throw new EventSearchException("unsupported_field");
            if(!new[]{"eq","in","not_in","exists","missing"}.Contains(op) || field.StartsWith("legacy_",StringComparison.Ordinal) && op!="eq") throw new EventSearchException("unsupported_operator");
            if(field=="account" ? !new[]{"actor","target","any"}.Contains(String(c["role"])) : c.ContainsKey("role")) throw new EventSearchException("invalid_condition");
            if(op is "exists" or "missing") { if(c.ContainsKey("value")) throw new EventSearchException("invalid_condition"); continue; }
            JsonNode?[] values=op=="eq"?[c["value"]]:(c["value"] as JsonArray)?.ToArray()??[];
            if(values.Length is <1 or >100) throw new EventSearchException("invalid_condition");
            foreach(var value in values)
            {
                if(IdFields.Contains(field)?!Integer(value,1,long.MaxValue):field=="event_id"?!Integer(value,0,int.MaxValue):!Text(value)) throw new EventSearchException("invalid_condition");
                if(field=="ip" && (!IPAddress.TryParse(String(value),out _) || String(value)!.Contains('%'))) throw new EventSearchException("invalid_condition");
                if(field=="legacy_journal_view" && !new[]{"attention","authentication","accounts","tasks"}.Contains(String(value))) throw new EventSearchException("invalid_condition");
            }
        }
        if(conditions.Any(c=>String(c!["field"])=="event_id" && String(c["operator"]) is not ("exists" or "missing")) &&
            !conditions.Any(c=>String(c!["field"]) is "provider" or "channel" && String(c["operator"]) is "eq" or "in")) throw new EventSearchException("event_context_required");
        return (JsonObject)raw.DeepClone();
    }
    internal static DateTimeOffset Instant(string? raw,string zone,bool end)
    {
        if(string.IsNullOrWhiteSpace(raw)) throw new FormatException("invalid_datetime");
        var tz=TimeZoneInfo.FindSystemTimeZoneById(zone);
        if(Regex.IsMatch(raw,@"[T ].*(Z|[+-]\d{2}:?\d{2})$",RegexOptions.CultureInvariant)) return DateTimeOffset.Parse(raw,CultureInfo.InvariantCulture).ToUniversalTime();
        var local=DateTime.SpecifyKind(DateTime.Parse(raw,CultureInfo.InvariantCulture),DateTimeKind.Unspecified);
        if(raw.Length==10 && end) local=local.AddDays(1);
        if(tz.IsInvalidTime(local)) throw new FormatException("nonexistent_local_datetime");
        if(tz.IsAmbiguousTime(local)) throw new FormatException("ambiguous_local_datetime_requires_offset");
        return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(local,tz));
    }
    static bool SafeReturn(JsonNode? n)
    {
        if(!Text(n,2048)) return false;
        string s=Uri.UnescapeDataString(String(n)!);
        return !s.Any(c=>c<32 || c==127 || c=='\\') && Regex.IsMatch(s.Split('?', '#')[0],@"^/app/(event-search|security-events-report|report/[a-z0-9][a-z0-9_.-]{1,79}|events(/\d+)?|entities(/\d+)?|objects|investigations(/\d+)?)$",RegexOptions.CultureInvariant);
    }
    internal static readonly Dictionary<string,int[]> Questions=new()
    {
        ["failed_logons"]=[4625,4771,6273,4776], ["lockouts"]=[4740], ["admin_logons"]=[4624], ["new_admins"]=[4728,4732,4756],
        ["group_changes"]=[4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4754,4755,4756,4757,4758,4764], ["log_cleared"]=[1102]
    };
}
