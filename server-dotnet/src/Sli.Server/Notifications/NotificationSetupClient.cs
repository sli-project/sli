using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Notifications;

public interface INotificationSetupClient
{
    Task<JsonObject> RequestAsync(string action, long user, JsonObject values, CancellationToken ct);
}

public sealed class NotificationSetupClient : INotificationSetupClient
{
    public static readonly IReadOnlySet<string> TelegramCodes = new HashSet<string>(StringComparer.Ordinal)
    {
        "telegram_setup_invalid_token", "telegram_setup_invalid_proxy", "telegram_setup_network", "telegram_setup_tls",
        "telegram_setup_timeout", "telegram_setup_unavailable", "telegram_setup_provider_unavailable", "telegram_setup_rate_limited",
        "telegram_setup_conflict", "telegram_setup_protocol", "telegram_setup_failed"
    };
    public static readonly IReadOnlySet<string> SmtpCodes = new HashSet<string>(StringComparer.Ordinal)
    { "smtp_setup_invalid", "smtp_setup_unavailable", "smtp_setup_conflict", "smtp_setup_needs_save" };
    public static async Task<byte[]> ReadLineAsync(Stream stream, CancellationToken ct)
    {
        using var output = new MemoryStream(); var one = new byte[1];
        while (output.Length <= 65536)
        {
            int n = await stream.ReadAsync(one, ct); if (n == 0) break;
            output.WriteByte(one[0]); if (one[0] == 10) break;
        }
        if (output.Length > 65536) throw new FormatException(); return output.ToArray();
    }
    public static void ValidateStatus(JsonObject result)
    {
        try
        {
            NotificationInput.Boolean(result, "secret_set"); NotificationInput.Boolean(result, "chat_bound");
            if (result.Any(p => p.Key is not ("secret_set" or "chat_bound" or "chat_name" or "proxy_url"))) throw new FormatException();
            if (result["chat_name"] is not null && NotificationInput.Text(result, "chat_name").EnumerateRunes().Count() > 128) throw new FormatException();
            result["proxy_url"] = NotificationInput.Proxy(result.ContainsKey("proxy_url") ? NotificationInput.Text(result, "proxy_url") : "");
        }
        catch { throw NotificationException.Setup("telegram_setup_unavailable"); }
    }
    public static JsonObject ParseResponse(string action, byte[] raw)
    {
        string unavailable = action.StartsWith("smtp_", StringComparison.Ordinal) ? "smtp_setup_unavailable" : "telegram_setup_unavailable";
        try
        {
            if (raw.Length > 65536 || JsonNode.Parse(raw) is not JsonObject result) throw new FormatException();
            if (result.ContainsKey("error"))
            {
                var code = result["error"]?.GetValue<string>();
                if (result.Count != 1 || code is null || !(action.StartsWith("smtp_", StringComparison.Ordinal) ? SmtpCodes : TelegramCodes).Contains(code)) code = unavailable;
                throw NotificationException.Setup(code);
            }
            if (action == "status") ValidateStatus(result);
            return result;
        }
        catch (NotificationException) { throw; }
        catch { throw NotificationException.Setup(unavailable); }
    }
    public async Task<JsonObject> RequestAsync(string action, long user, JsonObject values, CancellationToken ct)
    {
        bool smtp = action.StartsWith("smtp_", StringComparison.Ordinal);
        try
        {
            if (user <= 0) throw new FormatException();
            var body = values.DeepClone().AsObject(); body["action"] = action; body["user_id"] = user;
            if (body.ContainsKey("proxy_url")) body["proxy_url"] = NotificationInput.Proxy(NotificationInput.Text(body, "proxy_url"));
            var raw = JsonSerializer.SerializeToUtf8Bytes(body);
            if (smtp && raw.Length + 1 > 65536) throw NotificationException.Setup("smtp_setup_invalid");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(Environment.GetEnvironmentVariable("SLI_TELEGRAM_SETUP_SOCKET") ?? "/run/notification-setup/control.sock"), deadline.Token);
            using var stream = new NetworkStream(socket, false);
            await stream.WriteAsync(raw, deadline.Token); await stream.WriteAsync(new byte[] { 10 }, deadline.Token);
            return ParseResponse(action, await ReadLineAsync(stream, deadline.Token));
        }
        catch (NotificationException) { throw; }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { throw NotificationException.Setup(smtp ? "smtp_setup_unavailable" : "telegram_setup_timeout"); }
        catch { throw NotificationException.Setup(smtp ? "smtp_setup_unavailable" : "telegram_setup_unavailable"); }
    }
}
