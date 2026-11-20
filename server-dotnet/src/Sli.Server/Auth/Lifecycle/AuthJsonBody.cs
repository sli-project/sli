using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;

namespace Sli.Server.Auth.Lifecycle;

public sealed class AuthInputException(string code, int statusCode = 400) : Exception(code)
{
    public string Code { get; } = code;
    public int StatusCode { get; } = statusCode;
}

public static class AuthJsonBody
{
    public static Task<JsonDocument> ReadAsync(HttpContext context, CancellationToken ct) => ReadAsync(context, ct, 65536);

    internal static async Task<JsonDocument> ReadAsync(HttpContext context, CancellationToken ct, int maxBytes)
    {
        var request = context.Request;
        if (!string.IsNullOrEmpty(request.Headers.TransferEncoding.ToString())) throw new AuthInputException("unsupported_transfer_encoding");
        if (!long.TryParse(request.Headers["Content-Length"].ToString() is { Length: > 0 } raw ? raw : "0", NumberStyles.Integer,
            CultureInfo.InvariantCulture, out long length) || length < 0) throw new AuthInputException("invalid_content_length");
        if (length == 0) return JsonDocument.Parse("{}");
        if (length > maxBytes) throw new AuthInputException("request_body_too_large", 413);
        if ((request.ContentType ?? "").Split(';')[0].Trim().ToLowerInvariant() != "application/json")
            throw new AuthInputException("json_content_type_required", 415);
        byte[] rawBody = new byte[(int)length];
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            int read = 0;
            while (read < length)
            {
                int size = await request.Body.ReadAsync(rawBody.AsMemory(read), deadline.Token);
                if (size == 0) throw new AuthInputException("request_body_incomplete");
                read += size;
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new AuthInputException("request_body_timeout", 408); }
        JsonDocument doc;
        try
        {
            string text = new UTF8Encoding(false, true).GetString(rawBody);
            doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 1000 });
        }
        catch (Exception error) when (error is JsonException or DecoderFallbackException) { throw new AuthInputException("invalid_json"); }
        if (doc.RootElement.ValueKind != JsonValueKind.Object) { doc.Dispose(); throw new AuthInputException("json_object_required"); }
        return doc;
    }

    public static bool Truthy(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Null or JsonValueKind.Undefined or JsonValueKind.False => false,
        JsonValueKind.String => value.GetString()!.Length != 0,
        JsonValueKind.Array => value.GetArrayLength() != 0,
        JsonValueKind.Object => value.EnumerateObject().Any(),
        JsonValueKind.Number => value.GetDouble() != 0,
        _ => true
    };

    public static string CredentialString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var value) && Truthy(value) ? PythonString(value) : "";

    private static string PythonString(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString()!,
        JsonValueKind.True => "True",
        JsonValueKind.False => "False",
        JsonValueKind.Null => "None",
        JsonValueKind.Number => value.TryGetInt64(out long n) ? n.ToString(CultureInfo.InvariantCulture)
            : BigInteger.TryParse(value.GetRawText(), out var big) ? big.ToString(CultureInfo.InvariantCulture)
            : PythonFloat(value.GetDouble()),
        JsonValueKind.Array => "[" + string.Join(", ", value.EnumerateArray().Select(PythonRepr)) + "]",
        JsonValueKind.Object => "{" + string.Join(", ", value.EnumerateObject().Select(p => Quote(p.Name) + ": " + PythonRepr(p.Value))) + "}",
        _ => ""
    };

    private static string PythonRepr(JsonElement value) => value.ValueKind == JsonValueKind.String ? Quote(value.GetString()!) : PythonString(value);
    private static string Quote(string value) => "'" + value.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t") + "'";

    private static string PythonFloat(double value)
    {
        string text = value.ToString("R", CultureInfo.InvariantCulture).Replace('E', 'e');
        return !text.Contains('.') && !text.Contains('e') ? text + ".0" : text;
    }
}
