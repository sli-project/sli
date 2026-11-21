using System.Net.Http.Json;
using System.Security.Authentication;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Notifications;

public sealed class NotificationSetupBot : INotificationSetupBot
{
    public static JsonNode Parse(string method, int status, byte[] body)
    {
        if (body.Length > 65536 || status is >= 300 and < 400) throw NotificationException.Setup("telegram_setup_protocol");
        if (status == 429) throw NotificationException.Setup("telegram_setup_rate_limited");
        if (status is >= 500 and < 600) throw NotificationException.Setup("telegram_setup_provider_unavailable");
        try
        {
            var payload = JsonNode.Parse(body)!.AsObject();
            if (status != 200)
            {
                if (NotificationInput.Boolean(payload, "ok") || NotificationInput.Positive(payload, "error_code", 599) != status) throw new FormatException();
                throw NotificationException.Setup(status switch { 401 or 404 => "telegram_setup_invalid_token", 409 => "telegram_setup_conflict", _ => "telegram_setup_failed" });
            }
            if (!NotificationInput.Boolean(payload, "ok") || !payload.ContainsKey("result") ||
                method == "getMe" && (payload["result"] is not JsonObject info || !NotificationInput.Boolean(info, "is_bot")) ||
                method == "getUpdates" && payload["result"] is not JsonArray) throw new FormatException();
            return payload["result"]!.DeepClone();
        }
        catch (NotificationException ex) when (ex.Code.StartsWith("telegram_", StringComparison.Ordinal)) { throw; }
        catch { throw NotificationException.Setup("telegram_setup_protocol"); }
    }
    public async Task<JsonNode> RequestAsync(string token, string method, JsonObject values, string proxy, CancellationToken ct)
    {
        if (method is not ("getMe" or "getUpdates" or "sendMessage" or "answerCallbackQuery"))
            throw NotificationException.Setup("telegram_setup_failed");
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
            var state = new TelegramRequestState(); state.Begin(proxy, deadline);
            using var handler = TelegramWorkerCommand.CreateHandler(state);
            using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            using var request = new HttpRequestMessage(HttpMethod.Post, $"https://api.telegram.org/bot{token}/{method}") { Content = JsonContent.Create(values) };
            request.Headers.ConnectionClose = true;
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            using var stream = await response.Content.ReadAsStreamAsync(deadline.Token); using var buffer = new MemoryStream(); byte[] chunk = new byte[4096];
            while (true) { int read = await stream.ReadAsync(chunk, deadline.Token); if (read == 0) break; if (buffer.Length + read > 65536) throw NotificationException.Setup("telegram_setup_protocol"); buffer.Write(chunk, 0, read); }
            return Parse(method, (int)response.StatusCode, buffer.ToArray());
        }
        catch (NotificationException) { throw; }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { throw NotificationException.Setup("telegram_setup_timeout"); }
        catch (HttpRequestException ex) { throw NotificationException.Setup(ex.InnerException is AuthenticationException ? "telegram_setup_tls" : "telegram_setup_network"); }
        catch { throw NotificationException.Setup("telegram_setup_unavailable"); }
    }
}
