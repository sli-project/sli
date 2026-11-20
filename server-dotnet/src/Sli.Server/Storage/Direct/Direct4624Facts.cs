using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.FileAudit;

namespace Sli.Server.Storage.Direct;

internal static class Direct4624Facts
{
    private static readonly string[] Fields = [
        "process_name", "process_id", "target_server_name", "service_name", "task_name", "task_action",
        "task_author", "run_as", "logon_type", "result_code", "object_name", "share_name", "message_sample",
        "powershell_user_name", "powershell_command_name", "powershell_script_block_text", "powershell_process_id",
        "process_parent_id", "process_command_line", "process_user_sid", "process_user_name", "process_user_domain",
        "process_logon_id", "service_file", "service_account", "service_start_type", "task_content", "task_change", "native_process_id"
    ];
    internal static JsonObject Document(long eventId, Direct4624Projection projection)
    {
        var facts = new JsonObject { ["event_id"] = eventId };
        if(projection.Normalizer.Length==0)return facts;
        foreach (var field in Fields) facts[field] = null;
        facts["message_sample"] = MessageSample(projection);
        if(projection.Normalizer=="file_audit_event_catalog") {
            foreach(string field in new[]{"account_target_sid","account_target_name","account_name_before","account_name_after","membership_member_sid","membership_member_name"})facts[field]=null;
            var data=new JsonObject();foreach(var (key,value) in projection.Data)data[key]=value;
            var row=new JsonObject{["event_id"]=projection.EventKind,["channel"]="Security",["provider_name"]="Microsoft-Windows-Security-Auditing",["keywords"]=projection.Keywords};
            var native=FileAuditEvidence.NativeFacts(row,data);
            foreach(string key in new[]{"object_name","share_name","process_name"})facts[key]=native[key]?.DeepClone();
            facts["process_id"]=native["server_process_id"]?.ToString();
            var document=new JsonObject{["contract_id"]="file-audit.facts.v1"};foreach(var (key,value) in native)document[key]=value?.DeepClone();
            facts["file_audit_facts_json"]=CanonicalJson.Serialize(document);
            return facts;
        }
        facts["logon_type"] = projection.LogonType;
        string? Raw(params string[] keys) => keys.Select(k=>projection.Data.GetValueOrDefault(k)).FirstOrDefault(v=>!string.IsNullOrEmpty(v));
        var process=Raw("ProcessName","NewProcessName","Application");
        if(process is not null)process=Sli.Server.Compatibility.PythonText.Strip(process);
        facts["process_name"] = !string.IsNullOrEmpty(process) && Encoding.UTF8.GetByteCount(process)<=512 ? process : null;
        facts["process_id"] = WorkstationLogonProjection.ProcessId(Raw("ProcessId","NewProcessId"));
        string? Pick(int limit,params string[] keys) {
            var value=Raw(keys);
            if(value is null)return null;
            value=Sli.Server.Compatibility.PythonText.Strip(value);
            return value.Length==0 ? null : string.Concat(value.EnumerateRunes().Take(limit).Select(r=>r.ToString()));
        }
        string? result=Pick(128,"ResultCode","Status","SubStatus");
        if(projection.EventKind==4625) {
            var explicitResult=Pick(128,"ResultCode");var status=Pick(128,"Status");var sub=Pick(128,"SubStatus");
            result=explicitResult ?? (sub is not null && WorkstationLogonProjection.PositiveHexStatus(sub) ? sub : status ?? sub);
        }
        facts["result_code"]=result;
        if(projection.Normalizer=="event_catalog") {
            facts["target_server_name"]=Pick(512,"TargetServerName","TargetServer");
            facts["service_name"]=Pick(512,"ServiceName");
            facts["task_name"]=Pick(512,"TaskName","TaskNamePath");
            facts["task_action"]=Pick(1024,"Action","ActionName","TaskAction","TaskContentNew","TaskContent");
            facts["task_author"]=Pick(512,"Author","TaskAuthor");
            facts["run_as"]=Pick(512,"RunAs","UserContext","TaskUserName");
            facts["object_name"]=Pick(512,"ObjectName");
            facts["share_name"]=Pick(512,"ShareName");
        }
        if(projection.Normalizer=="event_catalog") {
            string? Exact(int limit,params string[] keys) {
                var value=Raw(keys);if(value is null)return null;value=Sli.Server.Compatibility.PythonText.Strip(value);
                return value.Length>0 && value.EnumerateRunes().Count()<=limit?value:null;
            }
            string? Bounded(int limit,params string[] keys) {
                var value=Raw(keys);if(value is null)return null;value=Sli.Server.Compatibility.PythonText.Strip(value);
                return value.Length>0 && Encoding.UTF8.GetByteCount(value)<=limit?value:null;
            }
            string? Pid(params string[] keys)=>WorkstationLogonProjection.ProcessId(Raw(keys));
            int kind=projection.EventKind;
            bool security=projection.Channel.Equals("Security",StringComparison.OrdinalIgnoreCase) && projection.Provider.Equals("Microsoft-Windows-Security-Auditing",StringComparison.OrdinalIgnoreCase);
            bool ps=projection.Channel.Equals("Microsoft-Windows-PowerShell/Operational",StringComparison.OrdinalIgnoreCase) && projection.Provider.Equals("Microsoft-Windows-PowerShell",StringComparison.OrdinalIgnoreCase);
            if(security && kind is 4688 or 4689) {
                facts["process_name"]=Bounded(512,kind==4688?"NewProcessName":"ProcessName");
                facts["process_id"]=Pid(kind==4688?"NewProcessId":"ProcessId");
            }
            bool scoped=security && kind is 4688 or 4689 or 4697 or 4698 or 4699 or 4700 or 4701 or 4702;
            if(ps && kind is 4103 or 4104) {
                facts["powershell_user_name"]=Pick(512,"User","ConnectedUser");
                facts["powershell_process_id"]=Pid("SystemExecutionProcessId");
                if(kind==4103)facts["powershell_command_name"]=Pick(512,"CommandName");
                if(kind==4104)facts["powershell_script_block_text"]=Pick(2048,"ScriptBlockText");
            }
            if(kind==4688) {
                facts["process_parent_id"]=Pid("CreatorProcessId");facts["process_command_line"]=Bounded(4096,"CommandLine");
            }
            if(scoped)foreach(var (field,key,limit) in new[]{("process_user_sid","SubjectUserSid",512),("process_user_name","SubjectUserName",512),("process_user_domain","SubjectDomainName",512),("process_logon_id","SubjectLogonId",128)})facts[field]=Bounded(limit,key);
            if(kind is 4697 or 7045) {
                facts["service_name"]=Exact(512,"ServiceName");facts["service_file"]=Exact(2048,"ServiceFileName","ImagePath");
                facts["service_account"]=Exact(512,"ServiceAccount","AccountName");facts["service_start_type"]=Exact(128,"ServiceStartType");
            }
            if(kind is 4698 or 4699 or 4700 or 4701 or 4702) {
                facts["task_name"]=Exact(512,"TaskName","TaskNamePath");facts["task_content"]=Exact(8192,"TaskContentNew","TaskContent");
                facts["task_change"]=kind switch{4698=>"created",4699=>"deleted",4700=>"enabled",4701=>"disabled",_=>"updated"};
            }
            if(kind is 4697 or 4698 or 4699 or 4700 or 4701 or 4702)facts["native_process_id"]=Pid("ClientProcessId");
            if(security && kind==4781) {
                facts["account_target_sid"]=Pick(512,"TargetSid","TargetUserSid");facts["account_target_name"]=Pick(512,"NewTargetUserName","TargetUserName");
                facts["account_name_before"]=Pick(512,"OldTargetUserName");facts["account_name_after"]=Pick(512,"NewTargetUserName");
            }
            if(security && kind is 4728 or 4729 or 4732 or 4733 or 4756 or 4757) {
                foreach(var (field,key) in new[]{("membership_member_sid","MemberSid"),("membership_member_name","MemberName")}) {
                    string? value=Pick(512,key);facts[field]=value=="-"?null:value;
                }
            }
        }
        if (projection.Normalizer=="radius_event_catalog") {
            facts["process_name"]=null; facts["process_id"]=null;
            string? Nps(string key,int limit=512) {
                var value=projection.Data.GetValueOrDefault(key);
                if(value is null) return null;
                value=Sli.Server.Compatibility.PythonText.Strip(value);
                return value.Length==0 ? null : string.Concat(value.EnumerateRunes().Take(limit).Select(r=>r.ToString()));
            }
            facts["logon_type"]=Nps("AuthenticationType",128);
            facts["target_server_name"]=Nps("AuthenticationServer");
            facts["result_code"]=Nps(projection.EventKind==6273 ? "ReasonCode" : "LoggingResult",128);
            facts["object_name"]=Nps("NetworkPolicyName") ?? Nps("NASIdentifier");
            var npsFields=new HashSet<string>(StringComparer.Ordinal) { "event_id","process_name","process_id","target_server_name","service_name","task_name","task_action","task_author","run_as","logon_type","result_code","object_name","share_name","message_sample" };
            foreach(var key in facts.Select(pair=>pair.Key).Where(key=>!npsFields.Contains(key)).ToArray())facts.Remove(key);
        }
        return facts;
    }
    internal static byte[] Hash(long eventId, Direct4624Projection projection) =>
        SHA256.HashData(new UTF8Encoding(false, true).GetBytes(CanonicalJson.Serialize(Document(eventId, projection), ensureAscii: false)));
    internal static bool HasFacts(JsonObject document)=>document.Any(x=>x.Key!="event_id" && x.Value is not null);
    internal static bool RetainMessageSample(string stream,int id,string providerName)
    {
        string channel=Sli.Server.Compatibility.PythonText.Strip(stream).ToLowerInvariant();
        string provider=Sli.Server.Compatibility.PythonText.Strip(providerName).ToLowerInvariant();
        return (channel,id) switch {
            ("dns server",5504) or ("system",101 or 103 or 108 or 1112) or ("microsoft-windows-taskscheduler/operational",101 or 108)=>true,
            _=>channel=="system" && (provider.Contains("group policy") || provider.Contains("grouppolicy"))
        };
    }
    private static string? MessageSample(Direct4624Projection projection)
    {
        if(!RetainMessageSample(projection.Channel,projection.EventKind,projection.Provider))return null;
        string value=Sli.Server.Compatibility.PythonText.Strip(projection.MessageText??"");
        return value.Length==0?null:string.Concat(value.EnumerateRunes().Take(220).Select(r=>r.ToString()));
    }
}
