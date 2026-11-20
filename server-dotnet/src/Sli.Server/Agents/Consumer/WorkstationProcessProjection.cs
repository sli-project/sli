using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json.Nodes;

namespace Sli.Server.Agents.Consumer;

internal static partial class WorkstationLogonProjection
{
    private static string? ProcessText(IReadOnlyDictionary<string,string?> data,string key,int byteLimit)
    {
        var text=Text(data,key);return text is not null && Encoding.UTF8.GetByteCount(text)<=byteLimit?text:null;
    }
    // windows_process_id: decimal or an unsigned 0x-prefixed hexadecimal number, 1..2^32-1.
    internal static string? ProcessId(string? input)
    {
        if(input is null)return null;string raw=Strip(input);
        if(raw.Length==0||raw=="-"||Encoding.UTF8.GetByteCount(raw)>128)return null;
        bool hex=raw.StartsWith("0x",StringComparison.OrdinalIgnoreCase);int pos=hex?2:0;
        bool negative=false;if(!hex && pos<raw.Length && raw[pos] is '+' or '-')negative=raw[pos++]=='-';
        if(hex && pos<raw.Length && raw[pos]=='_')pos++;
        bool digit=false,underscore=false;BigInteger value=0;
        foreach(var r in raw[pos..].EnumerateRunes()) {
            if(r.Value=='_'){if(!digit||underscore)return null;underscore=true;continue;}
            int n=Rune.GetUnicodeCategory(r)==UnicodeCategory.DecimalDigitNumber?(int)Rune.GetNumericValue(r):
                hex&&r.Value is >= 'a' and <= 'f'?r.Value-'a'+10:hex&&r.Value is >= 'A' and <= 'F'?r.Value-'A'+10:-1;
            if(n<0||n>=(hex?16:10))return null;digit=true;underscore=false;value=value*(hex?16:10)+n;
            if(value>uint.MaxValue)return null;
        }
        return !negative&&digit&&!underscore&&value>0?value.ToString(CultureInfo.InvariantCulture):null;
    }
    private static string PidState(IReadOnlyDictionary<string,string?> data,string key)
    {
        var raw=Text(data,key);return raw is null||raw=="-"?"unknown_missing":ProcessId(raw) is null?"unknown_invalid":"exact";
    }
    private static string BuildProcess(int id,IReadOnlyDictionary<string,string?> data,JsonObject roles,JsonObject facts,JsonObject quality)
    {
        void Put(string key,string? value){if(value is not null)facts[key]=value;}
        if(id==4688){
            Put("process_id",ProcessId(Text(data,"NewProcessId")));Put("process_parent_id",ProcessId(Text(data,"CreatorProcessId")));
            Put("process_name",ProcessText(data,"NewProcessName",512));Put("process_command_line",ProcessText(data,"CommandLine",4096));
            quality["process_id_state"]=PidState(data,"NewProcessId");quality["process_parent_id_state"]=PidState(data,"CreatorProcessId");
            var command=Text(data,"CommandLine");quality["process_command_line_state"]=command is null||command=="-"?"unknown_missing":ProcessText(data,"CommandLine",4096) is null?"unknown_over_limit":"exact";
        } else {
            string? service=Text(data,"ServiceName");Put("service_name",service);Put("service_file",Text(data,"ServiceFileName","ImagePath"));
            Put("service_account",Text(data,"ServiceAccount","AccountName"));Put("service_start_type",Text(data,"ServiceStartType"));
            if(service is not null)roles["target_entity"]=service;if(id==4697)Put("native_process_id",ProcessId(Text(data,"ClientProcessId")));
        }
        if(id is 4688 or 4697){
            Put("process_user_sid",ProcessText(data,"SubjectUserSid",512));Put("process_user_name",ProcessText(data,"SubjectUserName",512));
            Put("process_user_domain",ProcessText(data,"SubjectDomainName",512));Put("process_logon_id",ProcessText(data,"SubjectLogonId",128));
        }
        return id==4688?"process.started.fragment":"service.installed.fragment";
    }
}
