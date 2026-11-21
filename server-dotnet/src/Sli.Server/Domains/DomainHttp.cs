using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using Sli.Server.Auth;

namespace Sli.Server.Domains;

public static class DomainHttp
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        NewLine = "\n",
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    private static readonly JsonSerializerOptions CompactJsonOptions = new(JsonOptions) { WriteIndented = false };

    public static Task WriteFailureAsync(HttpContext context, AuthenticationFailure failure, CancellationToken ct)
    {
        string? key = failure.MessageKey ?? (failure.Code switch
        {
            "authentication_required" => "login.error.authenticationRequired",
            "secure_transport_required" => "login.error.https",
            _ => null
        });
        if (key is null)
        {
            return WriteAsync(context, new { error = failure.Code }, failure.StatusCode, ct);
        }
        bool english = SelectEnglish(context.Request.Headers.AcceptLanguage.ToString());
        string text = key switch
        {
            "login.error.authenticationRequired" => english ? "Sign in to continue." : "Необходимо войти в систему.",
            "login.error.https" => english ? "Sign-in requires a secure HTTPS connection." : "Вход разрешён только через защищённое HTTPS-соединение.",
            _ => throw new InvalidOperationException("Unsupported authentication message.")
        };
        return WriteAsync(context, new { error = failure.Code, message = new { code = key, @params = new { }, text } },
            failure.StatusCode, ct);
    }

    public static Task WriteUnexpectedAsync(HttpContext context, ILogger logger, Exception error, CancellationToken ct,
        string route = "/api/v1/domains")
    {
        string errorId = Guid.NewGuid().ToString();
        // Exception text and objects may contain SQL parameters or credentials.
        try
        {
            logger.LogError("request_failed internal_error_id={ErrorId} exception_type={ErrorType} route={Route}",
                errorId, error.GetType().Name, route);
        }
        catch (Exception)
        {
            // A broken logging provider must not turn a handled failure into an
            // uncorrelated response. Keep the fallback free of exception text.
            try { Console.Error.WriteLine($"request_failed internal_error_id={errorId} exception_type={error.GetType().Name} route={route}"); }
            catch (Exception) { /* A closed stderr must not hide the HTTP response. */ }
        }
        return WriteAsync(context, new { error = "internal_server_error", internal_error_id = errorId },
            StatusCodes.Status500InternalServerError, ct);
    }

    public static async Task WriteAsync(HttpContext context, object body, int statusCode, CancellationToken ct, bool compact = false)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(body, compact ? CompactJsonOptions : JsonOptions);
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json; charset=utf-8";
        context.Response.ContentLength = bytes.Length;
        ApplyHeaders(context);
        await context.Response.Body.WriteAsync(bytes, ct);
    }

    public static void ApplyHeaders(HttpContext context, string? cache = null, string? nonce = null)
    {
        var headers = context.Response.Headers;
        headers.TryAdd("X-Content-Type-Options", "nosniff");
        headers.TryAdd("X-Frame-Options", "DENY");
        headers.TryAdd("Referrer-Policy", "same-origin");
        headers.TryAdd("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        headers.TryAdd("Cache-Control", cache ?? "no-store, max-age=0");
        string n = nonce is null ? "" : " 'nonce-" + nonce + "'";
        headers.TryAdd("Content-Security-Policy", $"default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self'{n}; style-src-attr 'unsafe-inline'; script-src 'self'{n}; script-src-attr 'none'");
        var transport = context.RequestServices?.GetService<TransportGate>();
        if (transport?.IsSecureTransport(context) ?? context.Request.IsHttps)
        {
            headers.TryAdd("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
        }
    }

    internal static bool SelectEnglish(string acceptLanguage)
    {
        double best = -1;
        bool english = false;
        foreach (string entry in acceptLanguage.Split(','))
        {
            string[] parts = entry.Trim().ToLowerInvariant().Split(';');
            string locale = parts[0].Split('-')[0];
            double quality = 1;
            bool valid = true;
            foreach (string option in parts.Skip(1))
            {
                string[] pair = option.Trim().Split('=', 2);
                if (pair[0] == "q" && (pair.Length != 2 || !double.TryParse(pair[1], NumberStyles.Float,
                    CultureInfo.InvariantCulture, out quality)))
                {
                    valid = false;
                    break;
                }
            }
            if (valid && (locale is "ru" or "en") && quality > 0 && quality <= 1 && quality > best)
            {
                best = quality;
                english = locale == "en";
            }
        }
        return english;
    }
}
