using System.Text.Json.Nodes;
using System.Globalization;
using System.Text.Json;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.FileAudit;
namespace Sli.Server.Agents.ClientControl;
internal sealed record ClientPolicyReport(JsonObject Output, JsonObject Probe, long? AppliedRevision, string? AppliedState,
    bool Acknowledged, JsonObject? ProbeResult);
internal static class AgentClientPolicy
{
    internal static JsonObject CheckIn(JsonObject agent, bool fileAuditHook)
    {
        var control=JsonNode.Parse(AgentPolicyStore.NormalizeCollectionPolicy(JsonSerializer.SerializeToElement(agent["collection_policy"] ?? new JsonObject())).GetRawText())!.AsObject();
        if(!control["manage_windows_audit"]!.GetValue<bool>()) { control.Remove("manage_windows_audit");control.Remove("audit_process_command_line"); }
        var result=new JsonObject { ["agent_id"]=agent["id"]!.DeepClone(),["assigned_modules"]=agent["assigned_modules"]!.DeepClone(),
            ["policy_revision"]=agent["policy_revision"]!.DeepClone(),["rights_probe_request"]=agent["rights_probe"]?["pending"]?.DeepClone(),
            ["collection_policy"]=control,["eventlog_diagnostics_supported"]=true,["delivery_diagnostics_supported"]=true };
        if(agent["source_host_id"] is JsonValue host && JsonRead.TryString(host,out var source) && source.Length>0)
            result["runtime_handoff"]=new JsonObject { ["source_host_id"]=source,["cursors"]=agent["runtime_resume"]?.DeepClone() ?? new JsonObject() };
        if (fileAuditHook && agent["file_audit"] is JsonObject audit && audit["request"] is JsonObject { Count: > 0 } request
            && (request["command"]?["action"]?.ToString() != "check" || request["config"]?["source_kind"]?.ToString() == "workstation"
                || FileAuditResult.OfferCheck(agent, audit)))
        {
            result["file_audit"] = request.DeepClone();
            if (request["command"]?["action"]?.ToString() == "check" && request["config"]?["source_kind"]?.ToString() != "workstation"
                && FileAuditResult.RetryVersion(agent, audit) is { } retryVersion)
                result["file_audit_retry_version"] = retryVersion.ToString();
        }
        return result;
    }
    internal static ClientPolicyReport Report(JsonObject agent, JsonNode? body, DateTimeOffset now)
    {
        var probe=(JsonObject)agent["rights_probe"]!.DeepClone();
        if(body is JsonObject independent && independent.Count==1 && independent.ContainsKey("delivery_diagnostics")) {
            AgentClientDiagnostics.ValidateDelivery(independent["delivery_diagnostics"]);
            var diagnostics=new JsonObject { ["reported_at"]=Timestamp(now),["items"]=independent["delivery_diagnostics"]!.DeepClone() };
            probe["delivery_diagnostics"]=diagnostics;
            return new(new JsonObject { ["delivery_diagnostics"]=diagnostics.DeepClone() },probe,null,null,false,null);
        }
        string[] allowed=["applied_policy_revision","rights_probe","collection_state","eventlog_diagnostics","runtime_handoff_supported","agent_version"];
        if(body is not JsonObject report || report.Any(x=>!allowed.Contains(x.Key)) ||
            report.ContainsKey("runtime_handoff_supported") && !IsTrue(report["runtime_handoff_supported"])) throw Error("invalid_agent_policy_report");
        long current=agent["policy_revision"]!.GetValue<long>(),previous=agent["applied_policy_revision"]!.GetValue<long>();
        if(!JsonRead.TryInteger(report["applied_policy_revision"],out var number) || number<0 || number>current)throw Error("invalid_agent_policy_revision");
        long revision=(long)number;var stateNode=report["collection_state"];
        string? state=JsonRead.TryString(stateNode,out var text)?text:null;
        string desired=agent["collection_policy"]?["state"]?.GetValue<string>() ?? "active";
        if(agent.ContainsKey("collection_policy") && stateNode is null || stateNode is not null &&
            (state is not ("active" or "paused") || revision==current && state!=(desired=="active"?"active":"paused"))) throw Error("invalid_agent_collection_state");
        if(IsTrue(report["runtime_handoff_supported"]))probe["runtime_handoff_supported"]=true;
        if(report.ContainsKey("agent_version"))
        {
            if(!JsonRead.TryString(report["agent_version"],out var version) || !Version.TryParse(version,out var parsed) || parsed.Build<0 || parsed.Revision>=0 || version.Length>32)
                throw Error("invalid_agent_policy_report");
            probe["agent_version"]=version;
        }
        if(report.ContainsKey("eventlog_diagnostics")) {
            AgentClientDiagnostics.ValidateEventLog(report["eventlog_diagnostics"],revision);
            probe["eventlog_diagnostics"]=new JsonObject { ["reported_at"]=Timestamp(now),["items"]=report["eventlog_diagnostics"]!.DeepClone() };
        }
        JsonObject? probeResult=null;
        if(report["rights_probe"] is not null) {
            if(report["rights_probe"] is not JsonObject result || !Keys(result,"request_id","status") ||
                !JsonRead.TryString(result["status"],out var status) || status is not ("allowed" or "denied" or "unavailable") ||
                probe["pending"] is not JsonObject pending || pending.Count==0 || !JsonNode.DeepEquals(result["request_id"],pending["request_id"]))throw Error("invalid_agent_probe_report");
            probeResult=(JsonObject)result.DeepClone();probe.Remove("pending");
            var last=(JsonObject)result.DeepClone();last["policy_revision"]=revision;last["reported_at"]=Timestamp(now);probe["last_result"]=last;
        }
        long applied=Math.Max(revision,previous);string? updatedState=null;
        string appliedState=agent["applied_collection_state"]?.GetValue<string>() ?? "unknown";
        if(revision>=previous && (state is not null || revision>previous)){updatedState=state ?? "unknown";appliedState=updatedState;}
        return new(new JsonObject { ["applied_policy_revision"]=applied,["rights_probe"]=probe.DeepClone(),["applied_collection_state"]=appliedState },
            probe,applied,updatedState,applied!=previous,probeResult);
    }
    internal static bool Keys(JsonObject value,params string[] names)=>value.Count==names.Length && names.All(value.ContainsKey);
    private static bool IsTrue(JsonNode? node)=>node is JsonValue value && value.TryGetValue<bool>(out bool flag) && flag;
    private static AgentControlException Error(string code)=>new(code);
    private static string Timestamp(DateTimeOffset value) {
        var utc=value.UtcDateTime;long micros=utc.Ticks%TimeSpan.TicksPerSecond/10;
        return utc.ToString("yyyy-MM-dd'T'HH:mm:ss",CultureInfo.InvariantCulture)+(micros==0?"":"."+micros.ToString("D6",CultureInfo.InvariantCulture))+"+00:00";
    }
}
