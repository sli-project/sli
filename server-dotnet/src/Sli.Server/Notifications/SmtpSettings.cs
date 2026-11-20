using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace Sli.Server.Notifications;
public sealed record SmtpSettings(string Host,int Port,string User,string Sender,string Recipient,string BaseUrl,string Password,string Proxy)
{
    public override string ToString()=>"SmtpSettings [redacted]";
}
public static class SmtpSettingsReader
{
    private static readonly UTF8Encoding Utf8=new(false,true);
    private static readonly Regex Mailbox=new(@"\A[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\z",RegexOptions.CultureInvariant);
    private static bool Text(string s)=>s.EnumerateRunes().Count() is >0 and <=1024 && !s.Any(c=>c<32 || c==127);
    private static string Quote(string s)=>"\""+s.Replace("\\","\\\\").Replace("\"","\\\"")+"\"";
    private static byte[] Bounded(Func<string,byte[]> read,string path){var b=read(path);if(b.Length>65536)throw new FormatException();return b;}
    public static SmtpSettings Read(long recipient,long revision,Func<string,string?> get,Func<string,byte[]> read)
    {
        try {
            string path=get("SLI_NOTIFICATION_SMTP_CONFIG_FILE") ?? throw new FormatException();
            string prefix=get("SLI_DEPLOYMENT_MODE")=="native" ? "notifications_" : "";
            string dir=Path.GetDirectoryName(path) ?? "";
            if(Path.GetFileName(path)!=prefix+"smtp.json" || !string.IsNullOrEmpty(get("SLI_NOTIFICATION_SMTP_PASSWORD")) || get("SLI_NOTIFICATION_SMTP_PASSWORD_FILE")!=Path.Combine(dir,prefix+"notification_smtp_password"))throw new FormatException();
            using var document=JsonDocument.Parse(Bounded(read,path));var root=document.RootElement;
            if(root.ValueKind!=JsonValueKind.Object || root.EnumerateObject().Select(p=>p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(["host","port","username","sender","recipients","base_url"])==false)throw new FormatException();
            string host=root.GetProperty("host").GetString() ?? throw new FormatException(),user=root.GetProperty("username").GetString() ?? throw new FormatException(),sender=root.GetProperty("sender").GetString() ?? throw new FormatException(),url=root.GetProperty("base_url").GetString() ?? throw new FormatException();
            int port=root.GetProperty("port").GetInt32();
            if(!Text(host) || !Text(user) || !Text(sender) || !Mailbox.IsMatch(sender) || !Text(url) || port is <1 or >65535)throw new FormatException();
            if(!IPAddress.TryParse(host,out _) && (host.Length>253 || host.Split('.').Any(x=>!Regex.IsMatch(x,@"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z",RegexOptions.CultureInvariant))))throw new FormatException();
            if(!Uri.TryCreate(url,UriKind.Absolute,out var uri) || uri.Scheme!="https" || uri.Host.Length==0 || uri.UserInfo.Length>0 || uri.Query.Length>0 || uri.Fragment.Length>0)throw new FormatException();
            var recipients=root.GetProperty("recipients");if(recipients.ValueKind!=JsonValueKind.Object)throw new FormatException();
            var entries=new SortedDictionary<string,string>(StringComparer.Ordinal);
            foreach(var item in recipients.EnumerateObject()) {
                string value=item.Value.GetString() ?? throw new FormatException();
                if(!Regex.IsMatch(item.Name,@"\A[1-9][0-9]{0,18}\z",RegexOptions.CultureInvariant) || !long.TryParse(item.Name,NumberStyles.None,CultureInfo.InvariantCulture,out _) || !Text(value) || !Mailbox.IsMatch(value))throw new FormatException();
                entries[item.Name]=value;
            }
            if(entries.Count>1000 || !entries.TryGetValue(recipient.ToString(CultureInfo.InvariantCulture),out var address))throw new FormatException();
            string password=Utf8.GetString(Bounded(read,Path.Combine(dir,prefix+"notification_smtp_password")));
            if(password.Length==0 || password.IndexOfAny(['\r','\n','\0'])>=0)throw new FormatException();
            string canonical="{\"base_url\":"+Quote(url)+",\"host\":"+Quote(host)+",\"port\":"+port.ToString(CultureInfo.InvariantCulture)+",\"recipients\":{"+string.Join(',',entries.Select(x=>Quote(x.Key)+":"+Quote(x.Value)))+"},\"sender\":"+Quote(sender)+",\"username\":"+Quote(user)+"}";
            // Python validate_config uses json.dumps defaults (ASCII escaping and spaces).
            int dumpedLength=canonical.Length+11+(entries.Count==0?0:2*entries.Count-1)+canonical.Count(c=>c>=128)*5;
            if(dumpedLength>65536)throw new FormatException();
            byte[] body=Utf8.GetBytes(canonical+"\0"+password);string digest=Convert.ToHexStringLower(SHA256.HashData(body));
            using var marker=JsonDocument.Parse(Bounded(read,Path.Combine(dir,prefix+"smtp.ready")));var m=marker.RootElement;
            if(revision<=0 || m.ValueKind!=JsonValueKind.Object || !m.EnumerateObject().Select(x=>x.Name).ToHashSet(StringComparer.Ordinal).SetEquals(["revision","digest"]) || m.GetProperty("revision").GetInt64()!=revision || !CryptographicOperations.FixedTimeEquals(Utf8.GetBytes(m.GetProperty("digest").GetString() ?? ""),Utf8.GetBytes(digest)))throw new FormatException();
            string proxy=get("SLI_DEPLOYMENT_MODE")=="native" ? get("SLI_NOTIFICATION_PROXY") ?? "" : "";
            TelegramSettingsReader.ValidateProxy(proxy);
            return new(host,port,user,sender,address,url,password,proxy);
        } catch(Exception e) when(e is JsonException or DecoderFallbackException or ArgumentException or InvalidOperationException or KeyNotFoundException or OverflowException){throw new FormatException("smtp_not_configured");}
    }
}
public static class SmtpOutcome
{
    public static string Reply(int status,bool auth)=>status is >=400 and <500 ? "smtp_unavailable" : auth ? "smtp_auth_failed" : "smtp_rejected";
    public static string State(string code)=>code switch {"accepted"=>"accepted","smtp_unavailable"=>"retry","smtp_outcome_unknown"=>"delivery_unknown","smtp_rejected"=>"failed",_=>"blocked"};
}
