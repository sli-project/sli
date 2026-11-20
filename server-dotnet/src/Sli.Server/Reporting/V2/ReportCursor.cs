using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
namespace Sli.Server.Reporting.V2;

public static class ReportCursor
{
    private static string Binding(JsonObject context) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ReportScope.Canonical(context))));
    public static string Encode(JsonObject context, string position)
    {
        var json = new JsonObject { ["binding"] = Binding(context), ["position"] = new JsonObject { ["cursor"] = position } };
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json.ToJsonString())).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
    public static string? Decode(string token, JsonObject context)
    {
        try
        {
            if (token.Length is < 1 or > 2048 || !System.Text.RegularExpressions.Regex.IsMatch(token, @"\A[A-Za-z0-9_+/=-]+\z")) throw new FormatException();
            string raw = token.Replace('-', '+').Replace('_', '/'); raw = raw.PadRight((raw.Length + 3) / 4 * 4, '=');
            var json = JsonNode.Parse(Convert.FromBase64String(raw)) as JsonObject;
            if (json?.Text("binding") != Binding(context) || json["position"] is not JsonObject position) throw new FormatException();
            return position["cursor"]?.GetValue<string>();
        }
        catch (Exception e) when (e is FormatException or System.Text.Json.JsonException or InvalidOperationException)
        { throw new ReportRequestException("invalid_cursor"); }
    }
}
