using Sli.Server.Domains;

namespace Sli.Server.Auth.Lifecycle;

public static class AuthResponse
{
    public static Task UnexpectedAsync(HttpContext context, Exception error, CancellationToken ct, bool login = true)
    {
        string id = Guid.NewGuid().ToString();
        try
        {
            context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Sli.Server.Auth")
                .LogError("request_failed internal_error_id={ErrorId} exception_type={ErrorType} route={Route}", id, error.GetType().Name, context.Request.Path.Value);
        }
        catch (Exception) { /* A logging failure must not expose the underlying exception. */ }
        return ErrorAsync(context, "internal_server_error", 500, ct, internalErrorId: id, login: login);
    }

    public static Task ErrorAsync(HttpContext context, string error, int status, CancellationToken ct, int retry = 0, string? internalErrorId = null, bool login = true)
    {
        bool english = DomainHttp.SelectEnglish(context.Request.Headers.AcceptLanguage.ToString());
        string? key = error switch
        {
            "authentication_required" => "authenticationRequired",
            "authentication_not_enabled" => "disabled",
            "secure_transport_required" => "https",
            "cross_origin_request_rejected" => "origin",
            "invalid_credentials" => "credentials",
            "login_temporarily_locked" => retry > 0 ? "retryAfter" : "locked",
            "invalid_content_length" or "request_body_too_large" or "json_content_type_required" or "invalid_json" or "json_object_required" when login => "generic",
            "internal_server_error" or "server_busy" when login => "unavailable",
            _ => null
        };
        var body = new Dictionary<string, object> { ["error"] = error };
        if (internalErrorId is not null) body["internal_error_id"] = internalErrorId;
        if (retry > 0)
        {
            body["retry_after_seconds"] = retry;
            context.Response.Headers.RetryAfter = retry.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        if (key is not null)
        {
            string text = (key, english) switch
            {
                ("authenticationRequired", true) => "Sign in to continue.",
                ("authenticationRequired", false) => "Необходимо войти в систему.",
                ("disabled", true) => "Authentication is disabled on the server.",
                ("disabled", false) => "Авторизация на сервере отключена.",
                ("https", true) => "Sign-in requires a secure HTTPS connection.",
                ("https", false) => "Вход разрешён только через защищённое HTTPS-соединение.",
                ("origin", true) => "Sign-in request rejected. Open the sign-in page from the server address.",
                ("origin", false) => "Запрос входа отклонён. Откройте страницу входа с адреса сервера.",
                ("credentials", true) => "Sign-in failed. Check your username and password.",
                ("credentials", false) => "Не удалось войти. Проверьте логин и пароль.",
                ("retryAfter", true) => $"Too many sign-in attempts. Try again in {retry} seconds.",
                ("retryAfter", false) => $"Слишком много попыток входа. Повторите через {retry} сек.",
                ("locked", true) => "Too many sign-in attempts. Try again later.",
                ("locked", false) => "Слишком много попыток входа. Повторите позже.",
                ("unavailable", true) => "The sign-in service is temporarily unavailable. Try again later.",
                ("unavailable", false) => "Сервис входа временно недоступен. Повторите попытку позже.",
                (_, true) => "Sign-in failed. Try again.",
                _ => "Не удалось выполнить вход. Повторите попытку."
            };
            body["message"] = new { code = "login.error." + key, @params = retry > 0 ? new Dictionary<string, object> { ["seconds"] = retry } : [], text };
        }
        return DomainHttp.WriteAsync(context, body, status, ct);
    }
}
