using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Control;
namespace Sli.Server.Agents.ClientControl;

// Source allowlists only: no event, bookmark, token or exception text is accepted.
internal static class AgentClientDiagnostics
{
    private static readonly HashSet<string> Channels=["Security","System","Directory Service","Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-TaskScheduler/Operational","Microsoft-Windows-DriverFrameworks-UserMode/Operational","Microsoft-Windows-Kernel-PnP/Configuration"];
    private static readonly HashSet<string> Stages=["query","bookmark","seek","anchor","read","render","collect"];
    private static readonly HashSet<string> Errors=BuildErrors();
    private static HashSet<string> BuildErrors() {
        HashSet<string> values=["agent_delivery_rejected","agent_receipt_invalid","agent_transport_failed","agent_packet_invalid",
            "agent_sequence_gap","agent_sequence_replayed","agent_sequence_conflict","agent_packet_id_conflict","agent_cursor_mismatch",
            "agent_identity_mismatch","agent_stream_identity_changed","agent_reset_invalid","agent_replay_window","agent_packet_expired","agent_history_pending",
            "agent_source_not_bound","agent_module_not_assigned","agent_module_unsupported","agent_heartbeat_invalid","agent_collection_packet_invalid",
            "agent_workstations_packet_invalid","agent_workstations_rate_limit","agent_file_audit_packet_invalid","agent_nps_packet_invalid",
            "agent_snapshot_chunk_invalid","agent_snapshot_cycle_conflict","agent_snapshot_chunk_conflict"];
        foreach(var kind in new[]{"inbox_","snapshot_"})foreach(var name in new[]{"agent_count","agent_bytes","module_count","module_bytes","global_count","global_bytes","storage_bytes"}) values.Add("agent_"+kind+name+"_limit");
        return values;
    }
    private static bool Number(JsonNode? n,long min,long max)=>JsonRead.TryInteger(n,out var number) && number>=min && number<=max;
    private static bool Text(JsonNode? n,out string value)=>JsonRead.TryString(n,out value);
    private static bool Match(string s,string pattern)=>Regex.IsMatch(s,"\\A(?:"+pattern+")\\z",RegexOptions.CultureInvariant,TimeSpan.FromSeconds(1));
    private static bool ShortTime(JsonNode? n,out string text)=>Text(n,out text) && text.EnumerateRunes().Count()<=40;
    internal static void ValidateEventLog(JsonNode? node,long revision)
    {
        var seen=new HashSet<string>();bool valid=node is JsonArray array && array.Count<=Channels.Count;
        if(valid)foreach(var item in (JsonArray)node!) {
            if(item is not JsonObject row || !AgentClientPolicy.Keys(row,"channel","observed_at_utc","policy_revision","error") ||
                !Text(row["channel"],out var channel)||!Channels.Contains(channel)||!seen.Add(channel)||!Number(row["policy_revision"],1,revision)||
                !ShortTime(row["observed_at_utc"],out var time)||!PythonIsoDateTime.TryParse(time,out var parsed)||!parsed.IsAware){valid=false;break;}
            if(row["error"] is null)continue;
            if(row["error"] is not JsonObject error || !AgentClientPolicy.Keys(error,"exception_class","winerror","hresult","channel","record_id","bookmark_present","stage") ||
                !Text(error["exception_class"],out var name)||!Match(name,"[A-Za-z_][A-Za-z0-9_]{0,63}") ||
                !Text(error["channel"],out var errorChannel)||errorChannel!=channel||!Text(error["stage"],out var stage)||!Stages.Contains(stage)||
                error["bookmark_present"] is not JsonValue flag||!flag.TryGetValue<bool>(out _)||
                error["record_id"] is not null&&!Number(error["record_id"],0,long.MaxValue)||
                error["winerror"] is not null&&!Number(error["winerror"],0,uint.MaxValue)||
                error["hresult"] is not null&&!Number(error["hresult"],int.MinValue,uint.MaxValue)){valid=false;break;}
        }
        if(!valid)throw new AgentControlException("invalid_agent_eventlog_diagnostics");
    }
    internal static void ValidateDelivery(JsonNode? node)
    {
        var seen=new HashSet<string>();bool valid=node is JsonArray array && array.Count<=16;
        if(valid)foreach(var item in (JsonArray)node!) {
            if(item is not JsonObject row || !AgentClientPolicy.Keys(row,"module_id","packet_id","sequence","error_code","receipt_status","http_status","observed_at_utc","resolved_at_utc") ||
                !Text(row["module_id"],out var module)||!Match(module,"[a-z][a-z0-9_.-]{0,127}")||!seen.Add(module)||
                !Text(row["packet_id"],out var packet)||!Guid.TryParseExact(packet,"D",out var id)||id.ToString("D")!=packet||
                !Text(row["sequence"],out var sequence)||!Match(sequence,"0|[1-9][0-9]{0,18}")||!long.TryParse(sequence,NumberStyles.None,CultureInfo.InvariantCulture,out _)||
                !Text(row["error_code"],out var code)||!Errors.Contains(code)||!Text(row["receipt_status"],out var status)||status is not ("rejected" or "retry_later" or "invalid" or "unavailable")||
                row["http_status"] is not null&&!Number(row["http_status"],100,599)||
                !ShortTime(row["observed_at_utc"],out var observed)||!PythonIsoDateTime.TryParseUtc(observed,out var at)){valid=false;break;}
            if(row["resolved_at_utc"] is not null && (!ShortTime(row["resolved_at_utc"],out var resolved)||!PythonIsoDateTime.TryParseUtc(resolved,out var end)||end<at)){valid=false;break;}
        }
        if(!valid)throw new AgentControlException("invalid_agent_delivery_diagnostics");
    }
}
