using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Npgsql;
using Sli.Server.Hosting;

namespace Sli.Server.Agents.Control;

public sealed partial class AgentManagementService
{
    public async Task<JsonElement> CreateConsoleTokenAsync(NpgsqlConnection db, NpgsqlTransaction tx,
        JsonElement payload, string actor, HttpContext context, CancellationToken ct)
    {
        if (payload.ValueKind != JsonValueKind.Object
            || payload.EnumerateObject().Any(property => property.Name is not ("host_limit" or "manage_windows_audit"))
            || payload.EnumerateObject().Count() != (payload.TryGetProperty("manage_windows_audit", out var auditSetting) ? 2 : 1)
            || !payload.TryGetProperty("host_limit", out var count) || count.ValueKind != JsonValueKind.Number
            || !count.TryGetInt32(out int limit) || limit is < 1 or > 100)
            throw new AgentControlException("invalid_agent_console_host_limit");
        if (auditSetting.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.True or JsonValueKind.False))
            throw new AgentControlException("invalid_agent_collection_policy");
        bool manageWindowsAudit = auditSetting.ValueKind != JsonValueKind.False;

        var package = await AgentConsolePackage.ReadAsync(context, ct);
        var id = Guid.NewGuid();
        string token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
        await using var insert = new NpgsqlCommand("""
            insert into sli_agent_console_tokens(id,token_hash,created_at,expires_at,host_limit,remaining)
            values(@id,@hash,statement_timestamp(),statement_timestamp()+interval '1 hour',@limit,@limit)
            returning expires_at
            """, db, tx);
        insert.Parameters.AddWithValue("id", id);
        insert.Parameters.AddWithValue("hash", hash);
        insert.Parameters.AddWithValue("limit", limit);
        var expires = (DateTime)(await insert.ExecuteScalarAsync(ct))!;
        await audit.AppendAsync(db, tx, "token_create", actor, id.ToString(),
            new { host_limit = limit, ttl_seconds = 3600, manage_windows_audit = manageWindowsAudit }, ct);
        return JsonSerializer.SerializeToElement(new
        {
            id, expires_at = expires, command = package.Command(token), package_url = AgentConsolePackage.DownloadPath,
        });
    }

    public async Task<JsonElement> ListConsoleTokensAsync(NpgsqlConnection db, NpgsqlTransaction tx, string actor, CancellationToken ct)
    {
        var items = await RowsAsync(db, tx, """
            select id,created_at,expires_at,host_limit,remaining from sli_agent_console_tokens
            where revoked_at is null and remaining>0 and expires_at>clock_timestamp()
            order by created_at desc,id limit 100
            """, ct);
        await audit.AppendAsync(db, tx, "token_list", actor, "console-tokens", new { }, ct);
        return JsonSerializer.SerializeToElement(new { items });
    }

    public async Task<JsonElement> RevokeConsoleTokenAsync(NpgsqlConnection db, NpgsqlTransaction tx,
        JsonElement payload, string actor, CancellationToken ct)
    {
        Guid id = AgentControlJson.Id(AgentControlJson.Get(payload, "id"));
        await using var query = new NpgsqlCommand("""
            update sli_agent_console_tokens set revoked_at=clock_timestamp()
            where id=@id and remaining>0 and revoked_at is null and expires_at>clock_timestamp() returning id
            """, db, tx);
        query.Parameters.AddWithValue("id", id);
        if (await query.ExecuteScalarAsync(ct) is null) throw new AgentControlException("enrollment_token_not_found", 404);
        await audit.AppendAsync(db, tx, "token_revoke", actor, id.ToString(), new { }, ct);
        return JsonSerializer.SerializeToElement(new { status = "revoked" });
    }
}

internal sealed record AgentConsolePackage(Uri Origin, string Root, string Pin, string Digest)
{
    public const string DownloadPath = "/api/v1/agent/installer/SliAgent.msi";
    private static string PackagePath(IConfiguration config) =>
        config["Sli:AgentInstallerPath"] ?? "/opt/sli/current/agent/SliAgent.msi";

    private static readonly string Script = ReadScript();
    private static string ReadScript()
    {
        using var stream = typeof(AgentConsolePackage).Assembly.GetManifestResourceStream("Sli.Server.Agents.InstallAgent.ps1")!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Trim();
    }

    public static async Task<IResult> DownloadAsync(HttpContext context, IConfiguration configuration, CancellationToken ct)
    {
        if (!context.Request.IsHttps) return Results.NotFound();
        context.Response.Headers.CacheControl = "no-store";
        FileStream? stream = null;
        try
        {
            stream = File.OpenRead(PackagePath(configuration));
            context.Response.Headers["X-SLI-Package-SHA256"] = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, ct));
            stream.Position = 0;
            var result = Results.File(stream, "application/octet-stream", "SliAgent.msi");
            stream = null; // The file result owns the stream.
            return result;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return Results.NotFound(new { error = "agent_console_package_unavailable", message = "The SLI server has no agent installation package." });
        }
        finally { if (stream is not null) await stream.DisposeAsync(); }
    }

    public static async Task<AgentConsolePackage> ReadAsync(HttpContext context, CancellationToken ct)
    {
        if (!context.Request.IsHttps || !Uri.TryCreate("https://" + context.Request.Host.ToUriComponent() + "/", UriKind.Absolute, out var origin)
            || origin.UserInfo.Length > 0 || origin.AbsolutePath != "/" || origin.Query.Length > 0 || origin.Fragment.Length > 0)
            throw new AgentControlException("agent_console_https_required");
        var config = context.RequestServices.GetRequiredService<IConfiguration>();
        try
        {
            string caPath = config["Sli:AgentServerCaFile"] ?? config["SLI_TLS_CA_FILE"] ?? "/var/lib/sli/tls-ca.crt";
            using var root = X509Certificate2.CreateFromPem(await File.ReadAllTextAsync(
                InstalledConfiguration.CredentialPath(config, caPath, "SLI_TLS_CA_FILE"), ct));
            if (root.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()?.CertificateAuthority != true)
                throw new CryptographicException();
            await using var msi = File.OpenRead(PackagePath(config));
            return new(origin, Convert.ToBase64String(root.RawData), Convert.ToHexStringLower(SHA256.HashData(root.RawData)),
                Convert.ToHexStringLower(await SHA256.HashDataAsync(msi, ct)));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or CryptographicException or ServerConfigurationException)
        {
            throw new AgentControlException("agent_console_package_unavailable", 503);
        }
    }

    public string Command(string token) => "& {\n" + Script + "\n} "
        + string.Join(' ', new[] { Origin.AbsoluteUri, token, Root, Pin, Digest }.Select(QuotePowerShell));

    internal static string QuotePowerShell(string value) => "'" + value
        .Replace("'", "''").Replace("\u2018", "\u2018\u2018").Replace("\u2019", "\u2019\u2019")
        .Replace("\u201a", "\u201a\u201a").Replace("\u201b", "\u201b\u201b") + "'";
}
