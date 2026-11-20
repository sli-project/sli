using System.Text.Json.Nodes;
using Sli.Agent.Core;

namespace Sli.Server.Semantic.Detections;

// The packet-stale branch of collection_health_view, including its grace,
// applied-policy and import-backlog precedence. No network probes are used.
public static class DetectionHealth
{
    public static JsonObject Project(JsonObject context,DateTimeOffset now)
    {
        var agent=context["agent"]!;var streams=context["streams"]!.AsArray();var collection=agent["collection_policy"];int interval=collection?["interval_seconds"]?.GetValue<int>()??60;
        DateTimeOffset? Time(JsonNode? n)=>n==null?null:D.Time(n);double? Age(JsonNode? n)=>Time(n) is {} t?Math.Max(0,(now-t).TotalSeconds):null;
        bool online=Age(agent["last_seen"]) is {} age&&age<=Math.Max(300,interval*3),enabled=D.Text(agent["status"])=="active"&&(D.Text(collection?["state"]) is "" or "active"),applied=JsonNode.DeepEquals(agent["policy_revision"],agent["applied_policy_revision"])&&D.Text(agent["applied_collection_state"])=="active";
        var modules=new JsonArray();foreach(var assignment in agent["assigned_modules"]!.AsArray()){
            if(assignment?["enabled"]?.GetValue<bool>()!=true)continue;string module=D.Text(assignment["module_id"]);var config=assignment["config"] as JsonObject??new();string[] channels=module switch{
                "sli.windows.ad-dc"=>new[]{"Security","System","Directory Service"}.Where(c=>config["channels"]?[c]?.GetValue<bool>()??true).ToArray(),
                "sli.workstations"=>Enumerable.Range(0,WorkstationPolicy.Channels.Length).Where(i=>new WorkstationPolicy(config,1,1).ChannelEnabled(i)).Select(i=>WorkstationPolicy.Channels[i]).ToArray(),
                "sli.file-audit" or "sli.vpn-nps"=>["Security"],"sli.radius-accounting"=>["radius-accounting"],"sli.windows-eventlog" when config["channel"]!=null=>[D.Text(config["channel"])],_=>[]};
            int budget=Math.Max(900,interval*Math.Max(1,channels.Length)*3);var checks=new JsonArray();var graceStart=Time(agent["policy_applied_at"]??agent["created_at"]);var grace=graceStart.HasValue?(now-graceStart.Value).TotalSeconds:(double?)null;
            foreach(string channel in channels){var stream=streams.FirstOrDefault(s=>D.Text(s?["agent_id"])==D.Text(agent["id"])&&D.Text(s?["module_id"])==module&&D.Text(s?["revision"])==(D.Text(config["policy_revision"]) is {Length:>0} revision?revision:"1")&&D.Text(s?["channel"])==channel);string state="waiting",reason="";DateTimeOffset? since=null;
                if(enabled&&config["paused"]?.GetValue<bool>()!=true&&(applied||!online&&grace>budget)){
                    double? packetAge=Age(stream?["last_packet_at"]),pending=Age(stream?["pending_since"]);
                    if(stream?["read_error"] is {} error&&error.ToJsonString()!="false"&&error.ToJsonString()!="{}") {state="error";reason="read_error";}
                    else if(pending>900){state="error";reason="import_overdue";}
                    else if(packetAge==null){if(grace>budget){state="error";reason="packet_missing";}}
                    else if(packetAge>budget&&!(grace<=budget)){state="error";reason="packet_stale";since=Time(stream?["last_packet_at"])!.Value.AddSeconds(budget);if(graceStart.HasValue&&graceStart.Value.AddSeconds(budget)>since)since=graceStart.Value.AddSeconds(budget);}
                }
                checks.Add(new JsonObject{["state"]=state,["failure_reason"]=reason,["last_packet_at"]=stream?["last_packet_at"]?.DeepClone(),["issue_since_utc"]=since.HasValue?D.Stamp(since.Value):null});
            }modules.Add(new JsonObject{["channels"]=checks});
        }
        return new(){["connection"]=online?"online":"offline",["state"]=modules.SelectMany(m=>m!["channels"]!.AsArray()).Any(c=>D.Text(c?["state"])=="error")?"error":"waiting",["modules"]=modules};
    }
}
