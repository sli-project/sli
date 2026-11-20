using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Agents.Ingress;

// Correlation and minute folding are performed by the collector before signing.
// A delete right alone is deliberately absent from this action contract.
internal static class AgentFileAuditAction
{
    internal static void Validate(JsonObject row,FileAuditPolicy policy,string source)
    {
        static void Require(bool value) { if(!value) throw new ArgumentException(); }
        string Text(string key)=>row[key]!.GetValue<string>();
        Require(!policy.Workstation && JsonRead.HasExactly(row,"contract","record_id","event_id","computer_name","channel","provider_name",
            "collection_scope_id","path","old_path","operation","subject_user_sid","client_ip","minute_utc","time_created",
            "first_seen_utc","last_seen_utc","count","outcome"));
        Require(Text("contract")==FileAuditPolicy.ActionContract && Text("computer_name")==source
            && Text("channel")=="Security" && Text("provider_name")==FileAuditPolicy.Provider);
        Require(JsonRead.TryInteger(row["event_id"],out var id) && id>0 && id<=int.MaxValue);
        Require(JsonRead.TryInteger(row["record_id"],out var record) && record>0 && record<=long.MaxValue);
        string operation=Text("operation");
        var meaning=EventStorageMeaning.Current.Events.SingleOrDefault(e=>e.EventId==(int)id && e.Channel=="Security" && e.Provider==FileAuditPolicy.Provider);
        Require(meaning?.Operations.ContainsKey(operation)==true);
        Require(JsonRead.TryInteger(row["count"],out var count) && row["count"] is JsonValue value && !value.TryGetValue<bool>(out _)
            && count>0 && count<=long.MaxValue);
        var minute=AgentAdDcUtc.Parse(Text("minute_utc")); var first=AgentAdDcUtc.Parse(Text("first_seen_utc")); var last=AgentAdDcUtc.Parse(Text("last_seen_utc"));
        Require(minute.Ticks%TimeSpan.TicksPerMinute==0 && first>=minute && last>=first && last<minute.AddMinutes(1)
            && AgentAdDcUtc.Parse(Text("time_created"))==first && (count!=1 || first==last));
        string sid=Text("subject_user_sid");
        Require(sid.Length<=184 && Regex.IsMatch(sid,"\\AS-1-(?:[0-9]+-)*[0-9]+\\z"));
        if(row["client_ip"] is not null) Require(Text("client_ip").Length<=45 && IPAddress.TryParse(Text("client_ip"),out _));
        Require(Text("outcome")== (operation=="access_denied" ? "failure" : "success"));
        var root=policy.Roots.OfType<JsonObject>().SingleOrDefault(r=>r["collection_scope_id"]!.GetValue<string>()==Text("collection_scope_id"));
        Require(root is not null);
        void Path(string path) {
            Require(AgentFileAuditPolicy.NormalizePath(path)==path);
            string boundary=UnicodeLower.Lower(root!["path"]!.GetValue<string>()), candidate=UnicodeLower.Lower(path);
            Require(candidate==boundary || candidate.StartsWith(boundary.TrimEnd('\\')+"\\",StringComparison.Ordinal));
        }
        Path(Text("path"));
        Require((operation=="rename")== (row["old_path"] is not null));
        if(operation=="rename") { Path(Text("old_path")); Require(UnicodeLower.Lower(Text("old_path"))!=UnicodeLower.Lower(Text("path"))); }
    }
}
