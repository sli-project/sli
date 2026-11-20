using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Notifications;

// Implemented only in the isolated writer. The web API registers the socket client.
public interface INotificationSetupFiles
{
    bool Exists(string name);
    byte[] Read(string name);
    void Publish(string name, byte[] content);
    void Remove(string name);
}
public interface INotificationSetupBot
{
    Task<JsonNode> RequestAsync(string token, string method, JsonObject values, string proxy, CancellationToken ct);
}

public sealed class NotificationSetupService(INotificationSetupFiles files, INotificationSetupBot bot, string publicUrl,
    bool native = false, string nativeProxy = "", TimeProvider? clock = null)
{
    private sealed record Candidate(DateTimeOffset Expires, Dictionary<string, (string Chat, string Name)> Choices);
    private readonly Dictionary<long, Candidate> candidates = new();
    private readonly TimeProvider time = clock ?? TimeProvider.System;
    private static byte[] Bytes(JsonNode node) => JsonSerializer.SerializeToUtf8Bytes(node);
    private string BaseUrl()
    {
        if (!Uri.TryCreate(publicUrl, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Host.Length == 0 || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0)
            throw NotificationException.Setup("telegram_setup_unavailable");
        string authority = publicUrl[(publicUrl.IndexOf("://", StringComparison.Ordinal) + 3)..].Split('/', '?', '#')[0];
        return "https://" + authority + "/app";
    }
    private JsonObject TelegramConfig()
    {
        JsonObject config;
        if (!files.Exists("telegram.json")) config = new JsonObject { ["base_url"] = BaseUrl(), ["recipients"] = new JsonObject(), ["names"] = new JsonObject() };
        else
        {
            try
            {
                config = JsonNode.Parse(files.Read("telegram.json"))!.AsObject();
                if (config["base_url"] is not JsonValue value || !value.TryGetValue<string>(out _) || config["recipients"] is not JsonObject ||
                    config.Any(p => p.Key is not ("base_url" or "recipients" or "names" or "proxy_url"))) throw new FormatException();
                if (!config.ContainsKey("names")) config["names"] = new JsonObject();
                if (config["names"] is not JsonObject names || names.Any(p => p.Value is not JsonValue v || !v.TryGetValue<string>(out var s) || s.EnumerateRunes().Count() > 128)) throw new FormatException();
            }
            catch { throw NotificationException.Setup("telegram_setup_unavailable"); }
        }
        if (native) config["proxy_url"] = nativeProxy;
        try { NotificationInput.Proxy(config.ContainsKey("proxy_url") ? NotificationInput.Text(config, "proxy_url") : ""); }
        catch { throw NotificationException.Setup("telegram_setup_unavailable"); }
        return config;
    }
    private void WriteTelegram(JsonObject config)
    { var bytes = Bytes(config); if (bytes.Length > 65536) throw NotificationException.Setup("telegram_setup_failed"); files.Publish("telegram.json", bytes); }
    private static string Name(JsonObject value) => string.Concat((value["first_name"]?.ToString() is { Length: > 0 } first ? first : value["username"]?.ToString() is { Length: > 0 } username ? username : "Telegram").EnumerateRunes().Take(128).Select(r => r.ToString()));
    public static string Token(JsonObject body)
    {
        try
        {
            string token = NotificationInput.Text(body, "token");
            if (Encoding.UTF8.GetByteCount(token) > 65536 || !Regex.IsMatch(token, @"\A[1-9][0-9]*:[A-Za-z0-9_-]+\z")) throw new FormatException();
            return token;
        }
        catch { throw NotificationException.Setup("telegram_setup_invalid_token"); }
    }

    public async Task<JsonObject> HandleAsync(JsonObject body, CancellationToken ct)
    {
        string action = body["action"]?.ToString() ?? "";
        if (action is "smtp_status" or "smtp_save") return Smtp(body);
        long user;
        try { user = NotificationInput.Positive(body, "user_id", long.MaxValue); }
        catch { throw NotificationException.Setup("telegram_setup_failed"); }
        var config = TelegramConfig(); string key = user.ToString(System.Globalization.CultureInfo.InvariantCulture);
        try
        {
            if (action == "status")
            {
                NotificationInput.Keys(body, "action", "user_id");
                var chat = config["recipients"]![key];
                bool bound = chat is JsonValue v && v.TryGetValue<string>(out var s) && Regex.IsMatch(s, @"\A-?[1-9][0-9]{0,15}\z");
                return new JsonObject { ["secret_set"] = files.Exists("notification_telegram_token"), ["chat_bound"] = bound,
                    ["chat_name"] = config["names"]![key]?.DeepClone(), ["proxy_url"] = config["proxy_url"]?.DeepClone() ?? JsonValue.Create("") };
            }
            if (action is "token" or "verify")
            {
                NotificationInput.Keys(body, body.ContainsKey("proxy_url") ? ["action", "user_id", "token", "proxy_url"] : ["action", "user_id", "token"]);
                string proxy = NotificationInput.Proxy(native ? nativeProxy : body.ContainsKey("proxy_url") ? NotificationInput.Text(body, "proxy_url") : config["proxy_url"]?.GetValue<string>() ?? "");
                string token = Token(body);
                var result = await bot.RequestAsync(token, "getMe", new(), proxy, ct);
                if (result is not JsonObject info || info["is_bot"] is not JsonValue b || !b.TryGetValue<bool>(out var isBot) || !isBot) throw NotificationException.Setup("telegram_setup_protocol");
                string name = Name(info);
                if (action == "verify") return new JsonObject { ["bot_name"] = name };
                WriteTelegram(new JsonObject { ["base_url"] = config["base_url"]!.DeepClone(), ["recipients"] = new JsonObject(), ["names"] = new JsonObject(), ["proxy_url"] = proxy });
                files.Publish("notification_telegram_token", Encoding.UTF8.GetBytes(token)); candidates.Clear();
                return new JsonObject { ["secret_set"] = true, ["bot_name"] = name };
            }
            string saved = new UTF8Encoding(false, true).GetString(files.Read("notification_telegram_token"));
            Token(new JsonObject { ["token"] = saved });
            if (action == "chats")
            {
                NotificationInput.Keys(body, "action", "user_id");
                var updates = await bot.RequestAsync(saved, "getUpdates", new JsonObject { ["timeout"] = 0, ["limit"] = 100, ["allowed_updates"] = new JsonArray("message") }, config["proxy_url"]?.GetValue<string>() ?? "", ct);
                if (updates is not JsonArray rows) throw NotificationException.Setup("telegram_setup_protocol");
                var found = new Dictionary<string, string>();
                foreach (var update in rows.OfType<JsonObject>())
                {
                    if (update["message"] is not JsonObject message || message["chat"] is not JsonObject chat || chat["type"]?.ToString() != "private" ||
                        chat["id"] is not JsonValue id || !id.TryGetValue<long>(out long number) || number is <= 0 or >= 10000000000000000 ||
                        (message["text"]?.ToString() ?? "").Split(' ')[0] != "/start") continue;
                    found[number.ToString(System.Globalization.CultureInfo.InvariantCulture)] = Name(chat);
                }
                var choices = found.ToDictionary(p => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).TrimEnd('=').Replace('+', '-').Replace('/', '_'), p => (p.Key, p.Value));
                candidates[user] = new(time.GetUtcNow().AddMinutes(5), choices);
                return new JsonObject { ["chats"] = new JsonArray(choices.Select(p => (JsonNode)new JsonObject { ["choice"] = p.Key, ["name"] = p.Value.Value }).ToArray()) };
            }
            if (action == "bind")
            {
                NotificationInput.Keys(body, "action", "user_id", "choice");
                string choice = NotificationInput.Text(body, "choice");
                if (!candidates.TryGetValue(user, out var pending) || time.GetUtcNow() >= pending.Expires || !pending.Choices.TryGetValue(choice, out var selected)) throw NotificationException.Setup("telegram_setup_failed");
                config["recipients"]![key] = selected.Chat; config["names"]![key] = selected.Name;
                WriteTelegram(config); candidates.Remove(user);
                return new JsonObject { ["chat_name"] = selected.Name, ["secret_set"] = true };
            }
            throw NotificationException.Setup("telegram_setup_failed");
        }
        catch (NotificationException error) when (error.Code == "invalid_notification_request") { throw NotificationException.Setup("telegram_setup_failed"); }
    }

    private JsonObject Smtp(JsonObject body)
    {
        try
        {
            NotificationInput.Positive(body, "user_id", long.MaxValue); long revision = NotificationInput.Positive(body, "revision", long.MaxValue);
            if (body["action"]!.GetValue<string>() == "smtp_status")
            {
                NotificationInput.Keys(body, "action", "user_id", "revision"); bool exists = files.Exists("smtp.json");
                var empty = new JsonObject { ["host"] = "", ["port"] = 587, ["username"] = "", ["sender"] = "", ["recipients"] = new JsonObject(), ["secret_set"] = false, ["needs_save"] = exists };
                if (!exists) return empty;
                JsonObject config; bool ready;
                try { (config, _) = SetupSmtpSnapshot.Read(files, revision); ready = true; }
                catch (NotificationException)
                {
                    ready = false;
                    try { config = SetupSmtpSnapshot.ValidateConfig(JsonNode.Parse(files.Read("smtp.json"))!.AsObject()); }
                    catch { return empty; }
                }
                var result = new JsonObject(); foreach (var field in new[] { "host", "port", "username", "sender", "recipients" }) result[field] = config[field]!.DeepClone();
                result["secret_set"] = ready; result["needs_save"] = !ready; return result;
            }
            NotificationInput.Keys(body, "action", "user_id", "host", "port", "username", "sender", "recipients", "password", "revision", "previous_revision");
            long previous = NotificationInput.Positive(body, "previous_revision");
            if (revision != previous + 1) throw NotificationException.Setup("smtp_setup_invalid");
            var values = new JsonObject(); foreach (var field in new[] { "host", "port", "username", "sender", "recipients" }) values[field] = body[field]?.DeepClone();
            try { values["base_url"] = BaseUrl(); } catch { throw NotificationException.Setup("smtp_setup_unavailable"); }
            SetupSmtpSnapshot.ValidateConfig(values);
            string password = NotificationInput.Text(body, "password"); if (password == "") password = SetupSmtpSnapshot.Read(files, previous).Password;
            SetupSmtpSnapshot.ValidatePassword(password);
            // Invalidate the marker before replacing either member of the snapshot.
            files.Remove("smtp.ready");
            files.Publish("notification_smtp_password", Encoding.UTF8.GetBytes(password)); files.Publish("smtp.json", Bytes(values));
            files.Publish("smtp.ready", Bytes(new JsonObject { ["revision"] = revision, ["digest"] = SetupSmtpSnapshot.Digest(values, password) }));
            return new JsonObject { ["secret_set"] = true, ["needs_save"] = false };
        }
        catch (NotificationException error) when (error.Code.StartsWith("smtp_setup_", StringComparison.Ordinal)) { throw; }
        catch (NotificationException) { throw NotificationException.Setup("smtp_setup_invalid"); }
        catch { throw NotificationException.Setup("smtp_setup_unavailable"); }
    }
}
