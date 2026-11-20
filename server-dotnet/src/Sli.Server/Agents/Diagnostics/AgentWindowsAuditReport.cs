using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Agents.Diagnostics;

public sealed record AgentWindowsAuditChange(JsonObject State,bool Write);

public static class AgentWindowsAuditReport
{
    private static AgentControlException Invalid()=>new("invalid_agent_windows_audit_report");
    private static bool BooleanOrNull(JsonNode? n)=>n is null||n is JsonValue v&&v.GetValueKind() is JsonValueKind.True or JsonValueKind.False;
    private static bool Truthy(JsonNode? n)=>n is not null&&AuthJsonBody.Truthy(JsonSerializer.SerializeToElement(n));
    private static HashSet<string> Required(JsonNode? assignments)
    {
        var result=new HashSet<string>(StringComparer.Ordinal);
        foreach(var item in assignments!.AsArray())
        {
            if(item is not JsonObject o||o["enabled"] is not JsonValue enabled||enabled.GetValueKind()!=JsonValueKind.True)continue;
            if(AgentDiagnosticRules.Text(o["module_id"])=="sli.windows.ad-dc") { result.Add("domain_controller");continue; }
            if(AgentDiagnosticRules.Text(o["module_id"])!="sli.workstations")continue;
            var config=o["config"]?.AsObject();var families=config?["families"]?.AsObject();
            foreach(string key in WindowsAuditManager.Families.Keys)
                if(key!="domain_controller"&&(families is null||!families.ContainsKey(key)||Truthy(families[key])))result.Add(key);
        }
        return result;
    }
    public static AgentWindowsAuditChange Prepare(JsonObject agent,JsonNode? body,DateTimeOffset now)
    {
        if(body is not JsonObject o||!AgentDiagnosticRules.Keys(o,"windows_audit")||o["windows_audit"] is not JsonObject value)throw Invalid();
        if(!JsonRead.TryInteger(value["policy_revision"],out var revision)||revision<1||revision>agent["policy_revision"]!.GetValue<long>())throw Invalid();
        var requiredKeys=value.Select(p=>p.Key).Where(k=>k is not ("powershell_logging" or "checked_at")).ToHashSet(StringComparer.Ordinal);
        string? management=AgentDiagnosticRules.Text(value["management_state"]);
        if(!requiredKeys.SetEquals(["policy_revision","management_state","command_line_enabled","families"])
            ||management is not("disabled" or "applied" or "restored" or "blocked" or "unknown")||!BooleanOrNull(value["command_line_enabled"])
            ||value["families"] is not JsonObject families||families.Any(p=>!WindowsAuditManager.Families.ContainsKey(p.Key)))throw Invalid();
        if(families.ContainsKey("domain_controller")&&(!Iso8601.TryParseUtc(AgentDiagnosticRules.Text(value["checked_at"]),out var checkedAt)||checkedAt>now)
            ||value.ContainsKey("checked_at")&&!families.ContainsKey("domain_controller"))throw Invalid();
        if(value.ContainsKey("powershell_logging")&&(value["powershell_logging"] is not JsonObject ps
            ||!AgentDiagnosticRules.Keys(ps,"channel_enabled","script_block_logging_enabled")||ps.Any(p=>!BooleanOrNull(p.Value))||!families.ContainsKey("protection")))throw Invalid();
        long current=agent["policy_revision"]!.GetValue<long>();
        if(revision==current&&!Required(agent["assigned_modules"]).SetEquals(families.Select(p=>p.Key)))throw Invalid();
        var normalized=new JsonObject();
        foreach(var family in families)
        {
            // Keep accepting reports from the previous agent while packages are updated.
            bool rootReported=family.Key=="domain_controller" && family.Value is JsonObject candidate && candidate["required"] is JsonArray reported
                && reported.Any(r=>r is JsonObject row && AgentDiagnosticRules.Text(row["subcategory"])==WindowsAuditManager.DomainRootRequirement.Name);
            var specs=WindowsAuditManager.Families[family.Key];
            if(family.Key=="domain_controller" && family.Value is JsonObject dcResult && dcResult["required"] is JsonArray dcRows
                && !dcRows.Any(r=>WindowsAuditManager.AdditionalDcRequirements.Any(s=>AgentDiagnosticRules.Text(r?["subcategory"])==s.Name)))
                specs=specs.Except(WindowsAuditManager.AdditionalDcRequirements).ToArray();
            if(rootReported) specs=specs.Append(WindowsAuditManager.DomainRootRequirement).ToArray();
            if(family.Value is not JsonObject result||!AgentDiagnosticRules.Keys(result,"state","required","non_security_channels")
                ||AgentDiagnosticRules.Text(result["state"]) is not("ok" or "missing" or "managed_by_gpo" or "unknown")
                ||result["required"] is not JsonArray rows||rows.Count!=specs.Length)throw Invalid();
            var normalizedRows=new JsonArray();bool missing=false,unknown=false;
            for(int i=0;i<specs.Length;i++)
            {
                var spec=specs[i];
                string[] keys = family.Key=="domain_controller" ? ["subcategory","guid","success","failure","actual_success","actual_failure","state","detections","domain_changes","enabled_at","policy_name"]
                    : ["subcategory","guid","success","failure","actual_success","actual_failure"];
                if(rows[i] is not JsonObject row||!AgentDiagnosticRules.Keys(row,keys)
                    ||AgentDiagnosticRules.Text(row["subcategory"])!=spec.Name||AgentDiagnosticRules.Text(row["guid"])!=spec.Guid
                    ||row["success"] is not JsonValue success||success.GetValueKind() is not(JsonValueKind.True or JsonValueKind.False)||success.GetValue<bool>()!=((spec.Mask&1)!=0)
                    ||row["failure"] is not JsonValue failure||failure.GetValueKind() is not(JsonValueKind.True or JsonValueKind.False)||failure.GetValue<bool>()!=((spec.Mask&2)!=0)
                    ||!BooleanOrNull(row["actual_success"])||!BooleanOrNull(row["actual_failure"])||(row["actual_success"] is null)!=(row["actual_failure"] is null))throw Invalid();
                if(family.Key=="domain_controller")
                {
                    var detections=new JsonArray((spec.Detections??[]).Select(n=>(JsonNode?)JsonValue.Create(n)).ToArray());
                    string? rowState=AgentDiagnosticRules.Text(row["state"]);
                    bool satisfied=((spec.Mask&1)==0||row["actual_success"]?.GetValue<bool>()==true)&&((spec.Mask&2)==0||row["actual_failure"]?.GetValue<bool>()==true);
                    bool root=spec.Name==WindowsAuditManager.DomainRootRequirement.Name;
                    if(rowState is not("ok" or "missing" or "managed_by_gpo" or "unknown" or "restored")
                        ||rowState=="restored"&&(!root||satisfied||row["actual_success"] is null)
                        ||root&&(rowState=="managed_by_gpo"||row["policy_name"] is not null||row["actual_failure"]?.GetValue<bool>()==true)
                        ||rowState=="ok"&&!satisfied||rowState=="missing"&&(satisfied||row["actual_success"] is null)
                        ||!JsonNode.DeepEquals(row["detections"],detections)||row["domain_changes"] is not JsonValue dc||!dc.TryGetValue<bool>(out var domainChanges)||domainChanges!=spec.DomainChanges
                        ||row["enabled_at"] is not null&&(rowState!="ok"||!Iso8601.TryParseUtc(AgentDiagnosticRules.Text(row["enabled_at"]),out var at)||at>Iso8601.ParseUtc(AgentDiagnosticRules.Text(value["checked_at"])))
                        ||row["policy_name"] is not null&&(AgentDiagnosticRules.Text(row["policy_name"]) is not string name||name.Length is <1 or >200||name.Any(char.IsControl)))throw Invalid();
                }
                unknown|=row["actual_success"] is null;
                missing|=(spec.Mask&1)!=0&&row["actual_success"]?.GetValue<bool>()==false||(spec.Mask&2)!=0&&row["actual_failure"]?.GetValue<bool>()==false;
                normalizedRows.Add(row.DeepClone());
            }
            string ownership=AgentDiagnosticRules.Text(result["state"])!;
            string state=family.Key=="domain_controller"
                ?normalizedRows.Any(r=>AgentDiagnosticRules.Text(r?["state"])=="managed_by_gpo")?"managed_by_gpo":normalizedRows.Any(r=>AgentDiagnosticRules.Text(r?["state"])=="unknown")?"unknown":missing?"missing":"ok"
                :ownership is "unknown" or "managed_by_gpo"?ownership:unknown?"unknown":missing?"missing":"ok";
            string[] channels=family.Key=="protection"?[WorkstationPolicy.Channels[1],WorkstationPolicy.Channels[2],WorkstationPolicy.Channels[3]]
                :family.Key=="usb"?[WorkstationPolicy.Channels[4],WorkstationPolicy.Channels[5]]:[];
            var expected=new JsonObject{["state"]=state,["required"]=normalizedRows,["non_security_channels"]=new JsonArray(channels.Select(s=>(JsonNode?)JsonValue.Create(s)).ToArray())};
            if(!PythonMetadataEquality.Equal(result,expected))throw Invalid();normalized[family.Key]=expected;
        }
        var policy=agent["collection_policy"]!.AsObject();
        if(management=="applied"&&(normalized.Any(p=>AgentDiagnosticRules.Text(p.Value!["state"])!="ok")
            ||revision==current&&(!Truthy(policy["manage_windows_audit"])||Truthy(policy["audit_process_command_line"])&&families.ContainsKey("processes")&&value["command_line_enabled"]?.GetValue<bool>()!=true)))throw Invalid();
        var observation=(JsonObject)value.DeepClone();observation["families"]=normalized;observation["reported_at"]=AgentControlJson.Stamp(now,true);
        var previous=agent.ContainsKey("windows_audit")?agent["windows_audit"]!.AsObject():new JsonObject();
        BigInteger previousRevision=JsonRead.TryInteger(previous["policy_revision"],out var old)?old:BigInteger.Zero;
        bool write=revision>=previousRevision;
        if(revision==previousRevision&&Iso8601.TryParseUtc(AgentDiagnosticRules.Text(previous["checked_at"]),out var previousCheck)
            &&Iso8601.TryParseUtc(AgentDiagnosticRules.Text(value["checked_at"]),out var incomingCheck)&&incomingCheck<previousCheck)write=false;
        return new(write?observation:(JsonObject)previous.DeepClone(),write);
    }
}
