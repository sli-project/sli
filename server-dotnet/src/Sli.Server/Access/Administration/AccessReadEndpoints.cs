using System.Globalization;
using System.Numerics;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Domains;

namespace Sli.Server.Access.Administration;

public static class AccessReadEndpoints
{
    public static IServiceCollection AddAccessReadAdministration(this IServiceCollection services)
    {
        services.AddScoped<AccessReadService>();
        return services;
    }

    public static IEndpointRouteBuilder MapAccessReadEndpoints(this IEndpointRouteBuilder endpoints)
    {
        foreach (string leaf in new[] { "effective", "subjects", "grant-options", "audit" })
        {
            string route = "/api/v1/access/" + leaf;
            endpoints.MapGet(route, async (HttpContext context, AccessReadService service, IPrincipalAuthenticator auth,
                TransportGate transport, ILogger<AccessReadService> logger) =>
            {
                var ct = context.RequestAborted;
                try
                {
                    var failure = transport.CheckTransport(context);
                    if (failure is not null) { await DomainHttp.WriteFailureAsync(context, failure, ct); return; }
                    var authenticated = await auth.AuthenticateAsync(context, ct);
                    if (!authenticated.Succeeded)
                    { await DomainHttp.WriteFailureAsync(context, authenticated.Failure ?? new(401, "authentication_required"), ct); return; }
                    var principal = authenticated.Principal!;
                    failure = TransportGate.CheckViewerRole(principal);
                    if (failure is not null) { await DomainHttp.WriteFailureAsync(context, failure, ct); return; }
                    string rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget is { Length: > 0 } target ? target : context.Request.Path.Value ?? "";
                    string rawPath = rawTarget.Split('?', 2)[0];
                    if (!rawPath.StartsWith(route, StringComparison.Ordinal))
                    { await ErrorAsync(context, "route_policy_unclassified", 403, ct); return; }
                    var loaded = await service.LoadAsync(principal, ct);
                    string capability = leaf switch { "effective" => "workspace.view", "grant-options" => "reports.assign", _ => "access.manage" };
                    if (!await RequireAsync(context, loaded.Capabilities, capability, ct)) return;
                    if (rawPath != route) { await ErrorAsync(context, "not_found", 404, ct); return; }
                    object body;
                    if (leaf == "effective")
                    {
                        string? value = Values(context, "user_id").FirstOrDefault();
                        if (value is not null)
                        {
                            if (!TryPythonInteger(value, out var id, out _))
                            { await ErrorAsync(context, "invalid_user_id", 400, ct); return; }
                            if (!await RequireAsync(context, loaded.Capabilities, "access.preview", ct)) return;
                            if (id < long.MinValue || id > long.MaxValue)
                            { await ErrorAsync(context, "access_subject_not_found", 404, ct); return; }
                            var preview = await service.FindUserAsync((long)id, ct);
                            if (preview is null) { await ErrorAsync(context, "access_subject_not_found", 404, ct); return; }
                            loaded = await service.LoadAsync(preview, ct);
                            body = AccessReadProjection.Compose(preview, loaded.Facts, loaded.Capabilities, loaded.Reports, true);
                        }
                        else body = AccessReadProjection.Compose(principal, loaded.Facts, loaded.Capabilities, loaded.Reports, false);
                    }
                    else if (leaf == "subjects")
                    {
                        var values = Values(context, "account_type");
                        if (values.Length == 0) values = ["all"];
                        if (values.Length != 1 || values[0] is not ("all" or "people" or "service"))
                        { await ErrorAsync(context, "invalid_account_type", 400, ct); return; }
                        body = await service.GetSubjectsAsync(values[0], ct);
                    }
                    else if (leaf == "grant-options") body = await service.GetGrantOptionsAsync(ct);
                    else
                    {
                        string value = Values(context, "limit").FirstOrDefault() ?? "100";
                        if (!TryPythonInteger(value, out var limit, out int digits))
                        {
                            string error = digits > 4300 ? $"Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"
                                : "invalid literal for int() with base 10: " + PythonRepr(value);
                            await ErrorAsync(context, error, 400, ct); return;
                        }
                        body = await service.GetAuditAsync((int)BigInteger.Clamp(limit, 1, 500), ct);
                    }
                    await DomainHttp.WriteAsync(context, AccessReadPresentation.Apply(body, leaf, context.Request.Headers.AcceptLanguage.ToString()), 200, ct);
                }
                catch (PostgresException ex) when (ex.SqlState == "57014")
                { await DomainHttp.WriteAsync(context, new { error = "report_read_timeout", state = "unavailable" }, 503, ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
                catch (Exception ex)
                { if (context.Response.HasStarted) throw; await DomainHttp.WriteUnexpectedAsync(context, logger, ex, ct, route); }
            });
        }
        return endpoints;
    }

    // Python parse_qs drops empty values before route handling.
    private static string[] Values(HttpContext context, string key) => (context.Request.QueryString.Value is { Length: > 0 } query ? query[1..] : "")
        .Split('&').Select(part => part.Split('=', 2)).Where(pair => pair.Length == 2 && WebUtility.UrlDecode(pair[0]) == key)
        .Select(pair => WebUtility.UrlDecode(pair[1])).Where(v => v.Length > 0).ToArray();
    internal static bool TryPythonInteger(string value, out BigInteger result, out int digitCount)
    {
        string text = value.Trim();
        var ascii = new StringBuilder(text.Length);
        digitCount = 0;
        bool previousDigit = false;
        foreach (var rune in text.EnumerateRunes())
        {
            if (rune.Value is '+' or '-' && ascii.Length == 0) { ascii.Append((char)rune.Value); continue; }
            if (rune.Value == '_' && previousDigit) { ascii.Append('_'); previousDigit = false; continue; }
            if (Rune.GetUnicodeCategory(rune) != UnicodeCategory.DecimalDigitNumber) { result = default; digitCount = 0; return false; }
            ascii.Append((char)('0' + (int)Rune.GetNumericValue(rune))); digitCount++; previousDigit = true;
        }
        result = default;
        return previousDigit && digitCount <= 4300 && BigInteger.TryParse(ascii.ToString().Replace("_", ""), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out result);
    }
    internal static string PythonRepr(string value)
    {
        char quote = value.Contains('\'') && !value.Contains('"') ? '"' : '\'';
        var result = new StringBuilder().Append(quote);
        foreach (var rune in value.EnumerateRunes())
        {
            int c = rune.Value;
            if (c == quote || c == '\\') result.Append('\\').Append((char)c);
            else if (c is '\n' or '\r' or '\t') result.Append(c == '\n' ? "\\n" : c == '\r' ? "\\r" : "\\t");
            else if (Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate
                or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
                || c != ' ' && Rune.GetUnicodeCategory(rune) == UnicodeCategory.SpaceSeparator)
                result.Append(c < 256 ? "\\x" + c.ToString("x2", CultureInfo.InvariantCulture) : c < 65536
                    ? "\\u" + c.ToString("x4", CultureInfo.InvariantCulture) : "\\U" + c.ToString("x8", CultureInfo.InvariantCulture));
            else result.Append(rune.ToString());
        }
        return string.Concat(result.Append(quote).ToString().EnumerateRunes().Take(200).Select(r => r.ToString()));
    }
    private static Task ErrorAsync(HttpContext context, string code, int status, CancellationToken ct) =>
        DomainHttp.WriteAsync(context, new { error = code }, status, ct);
    private static async Task<bool> RequireAsync(HttpContext context, CapabilityDecisionSet access, string key, CancellationToken ct)
    {
        var decision = access.Decide(key);
        if (decision.Allowed) return true;
        await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = key }, 403, ct);
        return false;
    }
}
