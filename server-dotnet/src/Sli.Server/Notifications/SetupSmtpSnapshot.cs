using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Notifications;

public static class SetupSmtpSnapshot
{
    private static readonly Regex Mailbox = new(@"\A[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\z", RegexOptions.CultureInvariant);
    private static bool Text(string s) => s.EnumerateRunes().Count() is > 0 and <= 1024 && !s.Any(c => c < 32 || c == 127);
    public static void ValidateMailbox(string value) { if (!Text(value) || !Mailbox.IsMatch(value)) throw NotificationException.Setup("smtp_setup_invalid"); }
    public static string ValidatePassword(string value)
    { if (value.Length == 0 || Encoding.UTF8.GetByteCount(value) > 65536 || value.IndexOfAny(['\r', '\n', '\0']) >= 0) throw NotificationException.Setup("smtp_setup_invalid"); return value; }
    public static JsonObject ValidateConfig(JsonObject config)
    {
        try
        {
            NotificationInput.Keys(config, "host", "port", "username", "sender", "recipients", "base_url");
            foreach (var key in new[] { "host", "username", "sender", "base_url" }) if (!Text(NotificationInput.Text(config, key))) throw new FormatException();
            NotificationInput.Positive(config, "port", 65535); ValidateMailbox(NotificationInput.Text(config, "sender"));
            string host = NotificationInput.Text(config, "host");
            bool strictIp = IPAddress.TryParse(host, out _) && (host.Contains(':') || host.Split('.').Length == 4 && host.Split('.').All(p => p.Length == 1 || p[0] != '0'));
            if (!strictIp && (host.Length > 253 || host.Split('.').Any(p => !Regex.IsMatch(p, @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z")))) throw new FormatException();
            string url = NotificationInput.Text(config, "base_url");
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Host.Length == 0 || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0) throw new FormatException();
            if (config["recipients"] is not JsonObject recipients || recipients.Count > 1000) throw new FormatException();
            foreach (var entry in recipients)
            {
                if (!Regex.IsMatch(entry.Key, @"\A[1-9][0-9]{0,18}\z") || !long.TryParse(entry.Key, out _)) throw new FormatException();
                ValidateMailbox(entry.Value!.GetValue<string>());
            }
            // Bound the Python default (ASCII-escaped) serialization as in validate_config.
            string canonical = Canonical(config);
            if (canonical.Length + canonical.Count(c => c >= 128) * 5 + 11 + (recipients.Count == 0 ? 0 : 2 * recipients.Count - 1) > 65536) throw new FormatException();
            return config;
        }
        catch { throw NotificationException.Setup("smtp_setup_invalid"); }
    }
    private static string Quote(string value) => "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    private static string Canonical(JsonObject config)
    {
        var map = config["recipients"]!.AsObject();
        return "{\"base_url\":" + Quote(config["base_url"]!.GetValue<string>()) + ",\"host\":" + Quote(config["host"]!.GetValue<string>()) +
            ",\"port\":" + NotificationInput.Positive(config, "port", 65535).ToString(CultureInfo.InvariantCulture) + ",\"recipients\":{" +
            string.Join(',', map.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => Quote(p.Key) + ":" + Quote(p.Value!.GetValue<string>()))) +
            "},\"sender\":" + Quote(config["sender"]!.GetValue<string>()) + ",\"username\":" + Quote(config["username"]!.GetValue<string>()) + "}";
    }
    public static string Digest(JsonObject config, string password) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(config) + "\0" + password)));

    internal static void RepairMarker(INotificationSetupFiles files, byte[] original, byte[] repaired)
    {
        if (!files.Exists("smtp.ready") || !files.Exists("notification_smtp_password"))
            return;

        JsonObject marker;
        try
        {
            var config = ValidateConfig(JsonNode.Parse(original)!.AsObject());
            var newConfig = ValidateConfig(JsonNode.Parse(repaired)!.AsObject());
            string password = ValidatePassword(new UTF8Encoding(false, true).GetString(files.Read("notification_smtp_password")));
            marker = JsonNode.Parse(files.Read("smtp.ready")) as JsonObject ?? throw new FormatException();
            NotificationInput.Keys(marker, "revision", "digest");
            NotificationInput.Positive(marker, "revision", long.MaxValue);
            if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(NotificationInput.Text(marker, "digest")), Encoding.UTF8.GetBytes(Digest(config, password))))
                return;
            marker["digest"] = Digest(newConfig, password);
        }
        catch (Exception error) when (error is NotificationException or JsonException or FormatException or DecoderFallbackException)
        {
            return;
        }

        // Publish the marker first. If interrupted, the old loopback URL makes
        // the next run retry the config write, using the already updated marker.
        files.Publish("smtp.ready", JsonSerializer.SerializeToUtf8Bytes(marker));
    }

    public static (JsonObject Config, string Password) Read(INotificationSetupFiles files, long revision)
    {
        try
        {
            var config = ValidateConfig(JsonNode.Parse(files.Read("smtp.json"))!.AsObject());
            string password = ValidatePassword(new UTF8Encoding(false, true).GetString(files.Read("notification_smtp_password")));
            var marker = JsonNode.Parse(files.Read("smtp.ready"))!.AsObject(); NotificationInput.Keys(marker, "revision", "digest");
            if (revision <= 0 || NotificationInput.Positive(marker, "revision", long.MaxValue) != revision ||
                !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(NotificationInput.Text(marker, "digest")), Encoding.UTF8.GetBytes(Digest(config, password)))) throw new FormatException();
            return (config, password);
        }
        catch { throw NotificationException.Setup("smtp_setup_needs_save"); }
    }
}
