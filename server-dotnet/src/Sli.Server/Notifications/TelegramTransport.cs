using System.Text.Json;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
namespace Sli.Server.Notifications;
public sealed record TelegramOutcome(string Code,int RetryAfter=0);
public static class TelegramTransport
{
    public static TelegramOutcome ParseResponse(int status,string body,int retryAfter)
    {
        if(status is >=300 and <400)return new("telegram_rejected");
        try
        {
            using var doc=JsonDocument.Parse(body);var p=doc.RootElement;
            if(p.ValueKind!=JsonValueKind.Object)return new("telegram_outcome_unknown");
            if(status==200 && p.TryGetProperty("ok",out var ok) && ok.ValueKind==JsonValueKind.True)
            {
                if(p.TryGetProperty("result",out var result) && result.ValueKind==JsonValueKind.Object && result.TryGetProperty("message_id",out var id) && id.TryGetInt64(out var number) && number>0)return new("accepted");
                return new("telegram_outcome_unknown");
            }
            if(!p.TryGetProperty("ok",out var bad) || bad.ValueKind!=JsonValueKind.False || !p.TryGetProperty("error_code",out var error) || !error.TryGetInt32(out int code) || code!=status)return new("telegram_outcome_unknown");
            if(status is 401 or 404)return new("telegram_auth_failed");
            if(status is 400 or 403)return new("telegram_chat_denied");
            if(status==429)
            {
                int wait=0;
                if(p.TryGetProperty("parameters",out var parameters) && parameters.ValueKind==JsonValueKind.Object && parameters.TryGetProperty("retry_after",out var value) && value.TryGetInt32(out int seconds) && seconds>0)wait=seconds;
                return new("telegram_rate_limited",Math.Max(60,Math.Max(wait,retryAfter)));
            }
            return new(status is >=500 and <600 ? "telegram_unavailable" : "telegram_rejected");
        }
        catch(Exception e) when(e is JsonException or InvalidOperationException or FormatException){return new("telegram_outcome_unknown");}
    }
}

public sealed record TelegramSettings(string BaseUrl,string Chat,string Token,string Proxy)
{
    public override string ToString() => nameof(TelegramSettings);
}
internal sealed record TelegramBotSettings(string BaseUrl, string Token, string Proxy, Dictionary<long, long> Recipients)
{
    public override string ToString() => nameof(TelegramBotSettings);
}
public static class TelegramSettingsReader
{
    public static TelegramSettings Read(long userId,Func<string,string?> get,Func<string,byte[]> read)
    {
        var settings = ReadBot(get, read);
        if (!settings.Recipients.TryGetValue(userId, out long chat)) throw new FormatException();
        return new(settings.BaseUrl, chat.ToString(CultureInfo.InvariantCulture), settings.Token, settings.Proxy);
    }

    internal static TelegramBotSettings ReadBot(Func<string,string?> get,Func<string,byte[]> read)
    {
        var path=get("SLI_NOTIFICATION_TELEGRAM_CONFIG_FILE") ?? throw new FormatException();
        var raw=read(path);if(raw.Length>65536)throw new FormatException();
        using var doc=JsonDocument.Parse(raw);var root=doc.RootElement;
        if(root.ValueKind!=JsonValueKind.Object)throw new FormatException();
        var keys=root.EnumerateObject().Select(x=>x.Name).ToHashSet(StringComparer.Ordinal);
        if(!keys.IsSubsetOf(["base_url","recipients","names","proxy_url"]) || !keys.Contains("base_url") || !keys.Contains("recipients"))throw new FormatException();
        string url=root.GetProperty("base_url").GetString() ?? throw new FormatException();
        if(url.Length is 0 or >1024 || url.Any(c=>c<33 || c==127) || !Uri.TryCreate(url,UriKind.Absolute,out var uri) || uri.Scheme!="https" || string.IsNullOrEmpty(uri.Host) || uri.UserInfo.Length>0 || uri.Query.Length>0 || uri.Fragment.Length>0)throw new FormatException();
        var recipients=root.GetProperty("recipients");
        if(recipients.ValueKind!=JsonValueKind.Object)throw new FormatException();
        var bindings = new Dictionary<long, long>();
        foreach (var entry in recipients.EnumerateObject())
        {
            if (!long.TryParse(entry.Name, NumberStyles.None, CultureInfo.InvariantCulture, out long userId) || userId <= 0 ||
                entry.Name != userId.ToString(CultureInfo.InvariantCulture)) continue;
            if (entry.Value.ValueKind == JsonValueKind.String &&
                System.Text.RegularExpressions.Regex.IsMatch(entry.Value.GetString()!, @"\A-?[1-9][0-9]{0,15}\z",
                    System.Text.RegularExpressions.RegexOptions.CultureInvariant))
                bindings[userId] = long.Parse(entry.Value.GetString()!, CultureInfo.InvariantCulture);
            else
                bindings.Remove(userId);
        }
        string proxy=get("SLI_DEPLOYMENT_MODE")=="native" ? get("SLI_NOTIFICATION_PROXY") ?? "" : root.TryGetProperty("proxy_url",out var pv) ? pv.GetString() ?? throw new FormatException() : "";
        ValidateProxy(proxy);
        if(!string.IsNullOrEmpty(get("SLI_NOTIFICATION_TELEGRAM_TOKEN")))throw new FormatException();
        var tokenPath=get("SLI_NOTIFICATION_TELEGRAM_TOKEN_FILE") ?? throw new FormatException();
        var bytes=read(tokenPath);if(bytes.Length>65536)throw new FormatException();
        string token=new System.Text.UTF8Encoding(false,true).GetString(bytes).TrimEnd('\r','\n');
        if(!System.Text.RegularExpressions.Regex.IsMatch(token,@"\A[1-9][0-9]*:[A-Za-z0-9_-]+\z",System.Text.RegularExpressions.RegexOptions.CultureInvariant))throw new FormatException();
        return new(url.TrimEnd('/'),token,proxy,bindings);
    }
    internal static string BotId(string token) => token[..token.IndexOf(':')];
    internal static string BotGeneration(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    public static void ValidateProxy(string proxy)
    {
        if(proxy=="")return;
        if(proxy.Length>1024 || !proxy.StartsWith("http://",StringComparison.Ordinal) || proxy.Any(c=>c<=32 || c>=127 || "@?#\\".Contains(c)) || !Uri.TryCreate(proxy,UriKind.Absolute,out var p) || p.Scheme!="http" || p.UserInfo.Length>0 || p.AbsolutePath!="/" || p.Port is <1 or >65535 || !System.Text.RegularExpressions.Regex.IsMatch(proxy,@":[0-9]{1,5}\z"))throw new FormatException();
        string authority=proxy[7..];string host=authority[..authority.LastIndexOf(':')];
        if(host.StartsWith('[')) {
            if(!host.EndsWith(']') || !System.Net.IPAddress.TryParse(host[1..^1],out var ip) || ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetworkV6)throw new FormatException();
        } else if(host.All(c=>char.IsAsciiDigit(c) || c=='.')) {
            var parts=host.Split('.');
            if(parts.Length!=4 || parts.Any(part=>part.Length is <1 or >3 || part.Length>1 && part[0]=='0' || !int.TryParse(part,out int n) || n>255))throw new FormatException();
        } else if(host.Length>253 || host.Split('.').Any(label=>!System.Text.RegularExpressions.Regex.IsMatch(label,@"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z")))throw new FormatException();
    }
}
