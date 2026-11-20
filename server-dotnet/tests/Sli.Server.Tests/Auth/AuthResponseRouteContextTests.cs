using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Sli.Server.Auth.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class AuthResponseRouteContextTests
{
    private static DefaultHttpContext Context(string language = "en")
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.AcceptLanguage = language;
        context.Response.Body = new MemoryStream();
        return context;
    }
    private static async Task<JsonDocument> Body(DefaultHttpContext context)
    {
        context.Response.Body.Position = 0;
        return await JsonDocument.ParseAsync(context.Response.Body, cancellationToken: TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("authentication_required", "authenticationRequired", "en", "Sign in to continue.")]
    [InlineData("authentication_not_enabled", "disabled", "ru", "Авторизация на сервере отключена.")]
    [InlineData("secure_transport_required", "https", "en", "Sign-in requires a secure HTTPS connection.")]
    [InlineData("cross_origin_request_rejected", "origin", "ru", "Запрос входа отклонён. Откройте страницу входа с адреса сервера.")]
    [InlineData("invalid_credentials", "credentials", "en", "Sign-in failed. Check your username and password.")]
    [InlineData("login_temporarily_locked", "locked", "ru", "Слишком много попыток входа. Повторите позже.")]
    public async Task GlobalAuthenticationErrorsRemainLocalizedOutsideLogin(string error, string key, string language, string text)
    {
        var context = Context(language);
        await AuthResponse.ErrorAsync(context, error, 403, TestContext.Current.CancellationToken, login: false);
        using var body = await Body(context);
        Assert.Equal(error, body.RootElement.GetProperty("error").GetString());
        var message = body.RootElement.GetProperty("message");
        Assert.Equal("login.error." + key, message.GetProperty("code").GetString());
        Assert.Equal(text, message.GetProperty("text").GetString());
        Assert.Empty(message.GetProperty("params").EnumerateObject());
    }

    [Theory]
    [InlineData("invalid_content_length")]
    [InlineData("request_body_too_large")]
    [InlineData("json_content_type_required")]
    [InlineData("invalid_json")]
    [InlineData("json_object_required")]
    [InlineData("internal_server_error")]
    [InlineData("server_busy")]
    public async Task LoginOnlyMessagesRequireLoginContextAndExistingDefaultIsPreserved(string error)
    {
        var nonLogin = Context();
        await AuthResponse.ErrorAsync(nonLogin, error, 400, TestContext.Current.CancellationToken, login: false);
        using var plain = await Body(nonLogin);
        Assert.Single(plain.RootElement.EnumerateObject());
        Assert.False(plain.RootElement.TryGetProperty("message", out _));
        var login = Context();
        await AuthResponse.ErrorAsync(login, error, 400, TestContext.Current.CancellationToken);
        using var legacy = await Body(login);
        Assert.True(legacy.RootElement.TryGetProperty("message", out _));
    }

    [Fact]
    public async Task BootstrapLockPreservesHeaderWithoutInventingJsonDelay()
    {
        var context = Context();
        context.Response.Headers.RetryAfter = "900";
        await AuthResponse.ErrorAsync(context, "login_temporarily_locked", 429, TestContext.Current.CancellationToken, login: false);
        using var body = await Body(context);
        Assert.Equal("900", context.Response.Headers.RetryAfter.ToString());
        Assert.False(body.RootElement.TryGetProperty("retry_after_seconds", out _));
        Assert.Equal("login.error.locked", body.RootElement.GetProperty("message").GetProperty("code").GetString());
    }

    [Fact]
    public async Task NonLoginUnexpectedFailureRetainsSafeCorrelationWithoutLoginMessage()
    {
        var context = Context();
        await AuthResponse.UnexpectedAsync(context, new InvalidOperationException("synthetic-private-detail"), TestContext.Current.CancellationToken, login: false);
        using var body = await Body(context);
        Assert.Equal("internal_server_error", body.RootElement.GetProperty("error").GetString());
        Assert.True(Guid.TryParse(body.RootElement.GetProperty("internal_error_id").GetString(), out _));
        Assert.False(body.RootElement.TryGetProperty("message", out _));
        Assert.DoesNotContain("synthetic-private-detail", body.RootElement.GetRawText());
    }
}
