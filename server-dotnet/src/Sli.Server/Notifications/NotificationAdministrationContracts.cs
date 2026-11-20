using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;

namespace Sli.Server.Notifications;

public sealed class NotificationException(string code, int status = 400) : Exception(code)
{
    public string Code { get; } = code;
    public int Status { get; } = status;
    public static NotificationException Setup(string code) => new(code, code switch
    {
        "smtp_setup_invalid" or "telegram_setup_invalid_token" or "telegram_setup_invalid_proxy" or "telegram_setup_failed" => 400,
        "smtp_setup_conflict" or "smtp_setup_needs_save" or "telegram_setup_conflict" => 409,
        "telegram_setup_rate_limited" => 429, "telegram_setup_timeout" => 504, "telegram_setup_protocol" => 502, _ => 503
    });
}

public static class NotificationAccess
{
    public static bool Allowed(AccessDecision access, string report = "notifications.channels", string action = "view") =>
        access.CoarseRole == "admin" && access.Capabilities.Capabilities.Contains("access.manage") &&
        access.Capabilities.Decide("access.manage").Allowed &&
        ResourceAccessDecisions.ReportAction(access, report, action, null, new HashSet<string> { "technical" }).Allowed;
    public static bool Queue(AccessDecision access) => ResourceAccessDecisions.ReportAction(access, "security.queue", "view", null,
        new HashSet<string> { "security" }).Allowed;
}

public static class NotificationInput
{
    public static readonly IReadOnlyDictionary<string, string> SecretRefs = new Dictionary<string, string>
    { ["smtp"] = "SLI_NOTIFY_SMTP_PASSWORD", ["telegram"] = "SLI_NOTIFY_TELEGRAM_TOKEN" };
    public static void Keys(JsonObject body, params string[] keys)
    { if (!body.Select(p => p.Key).ToHashSet(StringComparer.Ordinal).SetEquals(keys)) throw new NotificationException("invalid_notification_request"); }
    public static string Text(JsonObject body, string key) => body[key] is JsonValue v && v.TryGetValue<string>(out var s) ? s : throw new NotificationException("invalid_notification_request");
    public static long Positive(JsonObject body, string key, long max = long.MaxValue - 1)
    {
        if (body[key] is JsonValue v)
        {
            long n;
            if (!v.TryGetValue<long>(out n)) { if (!v.TryGetValue<int>(out var small)) throw new NotificationException("invalid_notification_request"); n = small; }
            if (n > 0 && n <= max) return n;
        }
        throw new NotificationException("invalid_notification_request");
    }
    public static bool Boolean(JsonObject body, string key) => body[key] is JsonValue v && v.TryGetValue<bool>(out var b) ? b : throw new NotificationException("invalid_notification_request");
    public static Guid Id(string value)
    {
        string hex = value.Replace("urn:", "", StringComparison.Ordinal).Replace("uuid:", "", StringComparison.Ordinal).Trim('{', '}').Replace("-", "", StringComparison.Ordinal);
        return hex.Length == 32 && Guid.TryParseExact(hex, "N", out var id) ? id : throw new NotificationException("invalid_notification_request");
    }
    public static void Channel(string kind, JsonObject body)
    {
        if (!SecretRefs.ContainsKey(kind)) throw new NotificationException("notification_channel_not_found", 404);
        try
        {
            Keys(body, "enabled", "tls_mode", "secret_ref", "revision");
            Boolean(body, "enabled"); Positive(body, "revision");
            if (Text(body, "secret_ref") != SecretRefs[kind] || Text(body, "tls_mode") is not ("tls" or "starttls") || kind == "telegram" && Text(body, "tls_mode") != "tls")
                throw new NotificationException("invalid_notification_request");
        }
        catch (NotificationException) { throw new NotificationException("invalid_notification_channel_metadata"); }
    }
    public static void Subscription(string? id, JsonObject body)
    {
        Keys(body, id is null ? ["recipient_user_id", "channel", "enabled"] : ["recipient_user_id", "channel", "enabled", "revision"]);
        Positive(body, "recipient_user_id"); Boolean(body, "enabled");
        if (!SecretRefs.ContainsKey(Text(body, "channel"))) throw new NotificationException("invalid_notification_request");
        if (id is not null) { Id(id); Positive(body, "revision"); }
    }
    public static string Proxy(string value)
    {
        try
        {
            TelegramSettingsReader.ValidateProxy(value);
            if (value.StartsWith("http://[", StringComparison.Ordinal) && !System.Text.RegularExpressions.Regex.IsMatch(value[8..value.IndexOf(']')], @"\A[0-9a-fA-F:.]+\z")) throw new FormatException();
            return value;
        }
        catch { throw NotificationException.Setup("telegram_setup_invalid_proxy"); }
    }
}

public sealed record NotificationWorkspaceQuery(int Days, string? Channel, string? Status, long? Finding, DateTimeOffset? Before, Guid? BeforeId)
{
    public static readonly IReadOnlyDictionary<string, string[]> States = new Dictionary<string, string[]>
    {
        ["accepted"] = ["accepted"], ["errors"] = ["failed", "blocked", "delivery_unknown"],
        ["waiting"] = ["pending", "sending", "retry"], ["other"] = ["dry_run", "cancelled"]
    };
    public static NotificationWorkspaceQuery Parse(IQueryCollection query)
    {
        string? First(string key) => query[key].FirstOrDefault(v => !string.IsNullOrEmpty(v));
        if (!Integer(First("days") ?? "7", out var parsedDays) || parsedDays != 1 && parsedDays != 7 && parsedDays != 30) throw new NotificationException("invalid_notification_request");
        int days = (int)parsedDays;
        var channel = First("channel"); var status = First("status"); long? finding = null;
        if (channel is not (null or "smtp" or "telegram") || status is not null && !States.ContainsKey(status)) throw new NotificationException("invalid_notification_request");
        if (First("finding_id") is { } value)
        {
            if (!Integer(value, out var id) || id <= 0 || id > long.MaxValue) throw new NotificationException("invalid_notification_request");
            finding = (long)id;
        }
        var result = new NotificationWorkspaceQuery(days, channel, status, finding, null, null);
        if (First("cursor") is not { } token) return result;
        try
        {
            if (token.Length > 2048 || token.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '+' or '/' or '='))) throw new FormatException();
            var text = token.Replace('-', '+').Replace('_', '/');
            var root = JsonNode.Parse(Convert.FromBase64String(text.PadRight((text.Length + 3) / 4 * 4, '=')))!.AsObject();
            if (root["binding"]?.GetValue<string>() != result.Binding()) throw new FormatException();
            var stamp = root["position"]!["time"]!.GetValue<string>();
            if (!System.Text.RegularExpressions.Regex.IsMatch(stamp, @"(Z|[+-]\d\d:\d\d)$") || !DateTimeOffset.TryParse(stamp, CultureInfo.InvariantCulture, DateTimeStyles.None, out var before)) throw new FormatException();
            return result with { Before = before, BeforeId = NotificationInput.Id(root["position"]!["id"]!.GetValue<string>()) };
        }
        catch { throw new NotificationException("invalid_notification_request"); }
    }
    private static bool Integer(string value, out BigInteger result)
    {
        string text = Sli.Server.Compatibility.PythonText.Strip(value); var ascii = new StringBuilder(); bool digit = false; int digits = 0;
        foreach (var rune in text.EnumerateRunes())
        {
            if (rune.Value is '+' or '-' && ascii.Length == 0) { ascii.Append((char)rune.Value); continue; }
            if (rune.Value == '_' && digit) { ascii.Append('_'); digit = false; continue; }
            if (Rune.GetUnicodeCategory(rune) != UnicodeCategory.DecimalDigitNumber) { result = default; return false; }
            ascii.Append((char)('0' + (int)Rune.GetNumericValue(rune))); digit = true; digits++;
        }
        result = default;
        return digit && digits <= 4300 && BigInteger.TryParse(ascii.ToString().Replace("_", ""), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out result);
    }
    private string Binding()
    {
        // Python json.dumps(context, sort_keys=True) includes spaces after commas.
        string raw = $"[{Days}, {(Channel is null ? "null" : JsonSerializer.Serialize(Channel))}, {(Status is null ? "null" : JsonSerializer.Serialize(Status))}, {(Finding?.ToString(CultureInfo.InvariantCulture) ?? "null")}]";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    }
    public string Cursor(JsonObject item) => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new
    { binding = Binding(), position = new { time = item["created_at"]!.GetValue<string>(), id = item["id"]!.GetValue<string>() } })).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
