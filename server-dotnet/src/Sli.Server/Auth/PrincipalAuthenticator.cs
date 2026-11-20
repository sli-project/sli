using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Infrastructure;

namespace Sli.Server.Auth;

public sealed class PrincipalAuthenticator(IPostgresConnectionFactory connections) : IPrincipalAuthenticator
{
    private static readonly object CandidateKeyCache = new();
    private sealed record CandidateKeyResult(Principal? Principal);
    private static readonly Regex ReportRoutes = new(
        @"\A(?:/api/v2/reports/(?:events\.journal|ad\.infrastructure|ad\.gpo\.v2|ad\.users\.v2|ad\.computers\.v6|security\.events\.chains|security\.problems|workstations\.(?:logons|processes|usb|protection)|file-audit\.(?:overview|actions|mass-operations|permission-changes|access-denials|out-of-hours|permissions|audit-state))(?:/data|/rows/[A-Za-z0-9_.:-]{1,128}/detail)?|/api/v2/reports/vpn\.(?:accounts|connections)/data|/api/v1/events/[0-9]+)\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(100));
    // Source grammar: oracle Python 3.14.6 http.cookies._CookiePattern (ASCII).
    // Request.Cookies URL-decodes opaque tokens and does not preserve this legacy grammar.
    private const string CookieKeyChars = @"A-Za-z0-9_!#%&'~`><@,:/\$\*\+\-\.\^\|\)\(\?\}\{=";
    private const string CookieWhitespace = @"[ \t\n\r\f\v]";
    private static readonly Regex CookieItem = new(
        @"\G" + CookieWhitespace + @"*(?<key>[" + CookieKeyChars + @"]+?)(?:" + CookieWhitespace
        + @"*=" + CookieWhitespace + "*(?<val>\"(?:[^\\\\\"]|\\\\.)*\"|(?:[A-Za-z0-9_]{3,6}day|[A-Za-z0-9_]{3}),"
        + CookieWhitespace + @"[A-Za-z0-9_ \t\n\r\f\v-]{9,11}" + CookieWhitespace
        + @"[0-9:]{8}" + CookieWhitespace + @"GMT|[" + CookieKeyChars + @"\[\]]*))?"
        + CookieWhitespace + @"*(?:" + CookieWhitespace + @"+|;|$)",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex LegalCookieKey = new(@"\A[A-Za-z0-9!#$%&'*+\-.^_`|~:]+\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(100));
    private static readonly HashSet<string> CookieAttributes = new(StringComparer.OrdinalIgnoreCase)
        { "expires", "path", "comment", "domain", "max-age", "secure", "httponly", "version", "samesite", "partitioned" };
    private static readonly HashSet<string> CookieFlags = new(StringComparer.OrdinalIgnoreCase)
        { "secure", "httponly", "partitioned" };

    public async ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct)
    {
        var principal = await FromHeadersAsync(context, ct);
        if (principal is null) return AuthenticationResult.Denied(401, "authentication_required");
        // The Python pre-route gate resolves supplied keys before ordinary auth.
        var restriction = CheckReportKeyRoute(principal, context.Request.Method, context.Request.Path.Value ?? "");
        if (restriction is not null) return new(null, restriction);
        return AuthenticationResult.Success(principal);
    }

    internal static AuthenticationFailure? CheckReportKeyRoute(Principal? principal, string method, string path) =>
        principal?.RestrictedReportKey == true && (!HttpMethods.IsGet(method) || !ReportRoutes.IsMatch(path))
            ? new(403, "report_key_route_denied") : null;

    private async Task<Principal?> FromHeadersAsync(HttpContext context, CancellationToken ct)
    {
        var key = await CandidateKeyAsync(context, ct);
        return key ?? await SessionAsync(SessionTokenFromCookie(context.Request.Headers.Cookie.ToString()), ct);
    }

    internal async ValueTask<Principal?> CandidateKeyAsync(HttpContext context, CancellationToken ct)
    {
        if (context.Items.TryGetValue(CandidateKeyCache, out var cached)) return ((CandidateKeyResult)cached!).Principal;
        var request = context.Request;
        string authorization = request.Headers.Authorization.ToString();
        Principal? principal = null;
        if (authorization.StartsWith("bearer ", StringComparison.OrdinalIgnoreCase))
        {
            principal = await ApiKeyAsync(authorization[7..].Trim(), ct);
        }
        principal ??= await ApiKeyAsync(request.Headers["X-ADLog-API-Key"].ToString(), ct);
        context.Items[CandidateKeyCache] = new CandidateKeyResult(principal);
        return principal;
    }

    internal static bool HasCandidateKey(HttpRequest request)
    {
        string authorization = request.Headers.Authorization.ToString();
        return authorization.StartsWith("bearer ", StringComparison.OrdinalIgnoreCase) && IsApiKeyToken(authorization[7..].Trim())
            || IsApiKeyToken(request.Headers["X-ADLog-API-Key"].ToString());
    }

    private static bool IsApiKeyToken([NotNullWhen(true)] string? token) => !string.IsNullOrEmpty(token) && token.StartsWith("adl_", StringComparison.Ordinal);

    internal static string? SessionTokenFromCookie(string header)
    {
        // Validate the full parsed header before applying its session value. A bare invalid
        // item invalidates all morsels, including an earlier otherwise-valid session pair.
        string? token = null;
        bool morselSeen = false;
        bool invalidApplication = false;
        for (int offset = 0; offset < header.Length;)
        {
            var match = CookieItem.Match(header, offset);
            // SimpleCookie stops at an unmatched suffix; it does not search ahead.
            if (!match.Success) break;
            offset = match.Index + match.Length;
            string key = match.Groups["key"].Value;
            string? value = match.Groups["val"].Success ? match.Groups["val"].Value : null;
            if (key[0] == '$')
            {
                if (morselSeen && (!CookieAttributes.Contains(key[1..]) || HasControl(value))) invalidApplication = true;
                continue;
            }
            if (CookieAttributes.Contains(key))
            {
                if (!morselSeen || value is null && !CookieFlags.Contains(key)) return null;
                if (HasControl(Unquote(value))) invalidApplication = true;
                continue;
            }
            if (value is null) return null;
            morselSeen = true;
            string decoded = Unquote(value)!;
            if (!LegalCookieKey.IsMatch(key) || HasControl(value) || HasControl(decoded)) invalidApplication = true;
            if (key == "adlog_session") token = decoded;
        }
        if (invalidApplication) throw new FormatException("Invalid legacy cookie syntax.");
        return token;
    }

    private static bool HasControl(string? value) => value is not null && value.Any(c => c < 32 || c == 127);

    private static string? Unquote(string? value)
    {
        if (value is null || value.Length < 2 || value[0] != '"' || value[^1] != '"') return value;
        value = value[1..^1];
        var decoded = new StringBuilder(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] != '\\' || i + 1 == value.Length) { decoded.Append(value[i]); continue; }
            if (i + 3 < value.Length && value[i + 1] is >= '0' and <= '3'
                && value[i + 2] is >= '0' and <= '7' && value[i + 3] is >= '0' and <= '7')
            {
                decoded.Append((char)((value[i + 1] - '0') * 64 + (value[i + 2] - '0') * 8 + value[i + 3] - '0'));
                i += 3;
            }
            else decoded.Append(value[++i]);
        }
        return decoded.ToString();
    }

    private static string Digest(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private async Task<Principal?> SessionAsync(string? token, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(token)) return null;
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var command = new NpgsqlCommand("""
            select u.id, u.username, u.role, s.id as session_id
            from auth_sessions s join auth_users u on u.id=s.user_id
            where s.token_hash=@hash and s.revoked_at is null
              and s.expires_at > now() and u.is_active=true
            """, connection, transaction);
        command.Parameters.AddWithValue("hash", Digest(token));
        Principal? principal = null;
        long sessionId = 0;
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            if (await reader.ReadAsync(ct))
            {
                principal = new("session", reader.GetInt64(0), reader.GetString(2), Username: reader.GetString(1));
                sessionId = reader.GetInt64(3);
            }
        }
        if (principal is not null)
        {
            await using var update = new NpgsqlCommand("""
                update auth_sessions set last_used_at=now() where id=@id
                and (last_used_at is null or last_used_at < now()-interval '5 minutes')
                """, connection, transaction);
            update.Parameters.AddWithValue("id", sessionId);
            await update.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
        return principal;
    }

    private async Task<Principal?> ApiKeyAsync(string? token, CancellationToken ct)
    {
        if (!IsApiKeyToken(token)) return null;
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var command = new NpgsqlCommand("""
            select id, label, role, report_subject_id from auth_api_keys k
            where key_hash=@hash and is_active=true and revoked_at is null
              and (expires_at is null or expires_at > now())
              and (report_subject_id is null or exists
                  (select 1 from auth_users u where u.id=k.report_subject_id and u.is_active))
            """, connection, transaction);
        command.Parameters.AddWithValue("hash", Digest(token));
        Principal? principal = null;
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            if (await reader.ReadAsync(ct))
                principal = new("api_key", reader.GetInt64(0), reader.GetString(2), Label: reader.GetString(1),
                    ReportSubjectId: reader.IsDBNull(3) ? null : reader.GetInt64(3));
        }
        if (principal is not null)
        {
            await using var update = new NpgsqlCommand("""
                update auth_api_keys set last_used_at=now() where id=@id
                and (last_used_at is null or last_used_at < now()-interval '5 minutes')
                """, connection, transaction);
            update.Parameters.AddWithValue("id", principal.Id);
            await update.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
        return principal;
    }
}
