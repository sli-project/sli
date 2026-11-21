using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Npgsql;
using Sli.Server.Hosting;

namespace Sli.Server.Agents.Control;

public sealed partial class AgentManagementService
{
    private const string ConsoleServerUrlSetting = "agents.console_server_url";
    internal const int ConsoleHostLimit = 100;

    private static async Task<string?> ReadConsoleServerUrlAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("select value from platform_settings where key=@key", db, tx);
        query.Parameters.AddWithValue("key", ConsoleServerUrlSetting);
        return (string?)await query.ExecuteScalarAsync(ct);
    }

    public async Task<JsonElement> ReadConsoleSettingsAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct) =>
        JsonSerializer.SerializeToElement(new { server_url = await ReadConsoleServerUrlAsync(db, tx, ct) });

    public async Task<JsonElement> CreateConsoleTokenAsync(NpgsqlConnection db, NpgsqlTransaction tx,
        JsonElement payload, string actor, HttpContext context, CancellationToken ct)
    {
        if (payload.ValueKind != JsonValueKind.Object
            || payload.EnumerateObject().Any(property => property.Name is not ("host_limit" or "manage_windows_audit" or "server_url"))
            || payload.EnumerateObject().Count() != payload.EnumerateObject().Select(property => property.Name).Distinct().Count()
            || !payload.TryGetProperty("host_limit", out var count) || count.ValueKind != JsonValueKind.Number
            || !count.TryGetInt32(out int limit) || limit is < 1 or > ConsoleHostLimit)
            throw new AgentControlException("invalid_agent_console_host_limit");
        payload.TryGetProperty("manage_windows_audit", out var auditSetting);
        if (auditSetting.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.True or JsonValueKind.False))
            throw new AgentControlException("invalid_agent_collection_policy");
        bool manageWindowsAudit = auditSetting.ValueKind != JsonValueKind.False;

        bool hasServerUrl = payload.TryGetProperty("server_url", out var serverUrl);
        string? address = hasServerUrl
            ? serverUrl.ValueKind == JsonValueKind.String ? serverUrl.GetString() : ""
            : null;
        if (!context.Request.IsHttps)
            throw new AgentControlException("agent_console_https_required");
        var issued = await IssueConsoleTokenAsync(db, tx, limit, manageWindowsAudit, address, actor,
            context.RequestServices.GetRequiredService<IConfiguration>(), hasServerUrl,
            "https://" + context.Request.Host.ToUriComponent(), ct);
        return JsonSerializer.SerializeToElement(new
        {
            id = issued.Id, expires_at = issued.Expires, command = issued.Command, package_url = AgentConsolePackage.DownloadPath,
        });
    }

    internal async Task<(Guid Id, DateTime Expires, string Command)> IssueConsoleTokenAsync(
        NpgsqlConnection db, NpgsqlTransaction tx, int limit, bool manageWindowsAudit, string? address,
        string actor, IConfiguration config, bool saveAddress, string? fallbackAddress, CancellationToken ct)
    {
        address ??= await ReadConsoleServerUrlAsync(db, tx, ct) ?? fallbackAddress
            ?? throw new AgentControlException("agent_console_server_url_required");
        var package = await AgentConsolePackage.ReadAsync(config, address, ct);
        if (saveAddress)
        {
            await using var save = new NpgsqlCommand("""
                insert into platform_settings(key,value,updated_by) values(@key,@value,@actor)
                on conflict(key) do update set value=excluded.value,updated_by=excluded.updated_by,updated_at=now()
                where platform_settings.value is distinct from excluded.value
                """, db, tx);
            save.Parameters.AddWithValue("key", ConsoleServerUrlSetting);
            save.Parameters.AddWithValue("value", package.Origin.AbsoluteUri);
            save.Parameters.AddWithValue("actor", actor);
            await save.ExecuteNonQueryAsync(ct);
        }
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
            new { host_limit = limit, ttl_seconds = 3600, manage_windows_audit = manageWindowsAudit, server_url = package.Origin.AbsoluteUri }, ct);
        return (id, expires, package.Command(token));
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

internal sealed record AgentConsolePackage(Uri Origin, string Root, string Pin, string Digest, string ProductVersion = "")
{
    public const string DownloadPath = "/api/v1/agent/installer/SliAgent.msi";
    private static string PackagePath(IConfiguration config) =>
        config["Sli:AgentInstallerPath"] ?? "/opt/sli/current/agent/SliAgent.msi";

    private static async Task<string> ReadVersionAsync(string path, string digest, CancellationToken ct)
    {
        FileStream metadata;
        try { metadata = File.OpenRead(path + ".json"); }
        catch (FileNotFoundException) { return ""; } // MSI from a kit predating the version manifest.
        await using (metadata)
        {
            using var document = await JsonDocument.ParseAsync(metadata, cancellationToken: ct);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("product_version", out var version) ||
                version.ValueKind != JsonValueKind.String || !Version.TryParse(version.GetString(), out var parsed) ||
                parsed.Major > 255 || parsed.Minor > 255 || parsed.Build is < 0 or > 65535 || parsed.Revision != -1 ||
                !root.TryGetProperty("sha256", out var hash) || hash.ValueKind != JsonValueKind.String || hash.GetString() != digest)
                throw new InvalidDataException("Invalid agent MSI metadata.");
            return parsed.ToString(3);
        }
    }

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
            string path = PackagePath(configuration);
            stream = File.OpenRead(path);
            string digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, ct));
            string version = await ReadVersionAsync(path, digest, ct);
            context.Response.Headers["X-SLI-Package-SHA256"] = digest;
            if (version.Length > 0) context.Response.Headers["X-SLI-Package-Version"] = version;
            stream.Position = 0;
            var result = Results.File(stream, "application/octet-stream", "SliAgent.msi");
            stream = null; // The file result owns the stream.
            return result;
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            return Results.NotFound(new { error = "agent_console_package_unavailable", message = "The SLI server has no agent installation package." });
        }
        finally { if (stream is not null) await stream.DisposeAsync(); }
    }

    public static async Task<AgentConsolePackage> ReadAsync(IConfiguration config, string address, CancellationToken ct)
    {
        try
        {
            string certificatePath = config["Kestrel:Certificates:Default:Path"]
                ?? throw new ServerConfigurationException("Kestrel:Certificates:Default:Path", "missing");
            using var certificate = X509Certificate2.CreateFromPem(await File.ReadAllTextAsync(certificatePath, ct));
            var origin = ValidateOrigin(address, certificate);
            string caPath = config["Sli:AgentServerCaFile"] ?? config["SLI_TLS_CA_FILE"] ?? "/var/lib/sli/tls-ca.crt";
            using var root = X509Certificate2.CreateFromPem(await File.ReadAllTextAsync(
                InstalledConfiguration.CredentialPath(config, caPath, "SLI_TLS_CA_FILE"), ct));
            if (root.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()?.CertificateAuthority != true)
                throw new CryptographicException();
            string path = PackagePath(config);
            await using var msi = File.OpenRead(path);
            string digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(msi, ct));
            string version = await ReadVersionAsync(path, digest, ct);
            return new(origin, Convert.ToBase64String(root.RawData), Convert.ToHexStringLower(SHA256.HashData(root.RawData)), digest, version);
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or JsonException or CryptographicException or ServerConfigurationException)
        {
            throw new AgentControlException("agent_console_package_unavailable", 503);
        }
    }

    internal static Uri ValidateOrigin(string address, X509Certificate2 certificate)
    {
        address = address.Trim();
        if (address.Length <= 1024 && address.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            && !address.Any(c => char.IsWhiteSpace(c) || char.IsControl(c) || c is '\\' or '"' or '@')
            && Uri.TryCreate(address, UriKind.Absolute, out var origin)
            && origin.HostNameType is UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6
            && origin.Port > 0
            && origin.AbsolutePath == "/" && origin.Query.Length == 0 && origin.Fragment.Length == 0
            && address.IndexOf('/', "https://".Length) is var pathStart
            && (pathStart < 0 || pathStart == address.Length - 1)
            && origin.AbsoluteUri.Length <= 1024
            && certificate.MatchesHostname(origin.IdnHost, allowWildcards: true, allowCommonName: false))
            return origin;

        var san = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().SingleOrDefault();
        string[] hosts = san is null ? [] : san.EnumerateDnsNames()
            .Concat(san.EnumerateIPAddresses().Select(ip => ip.ToString())).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        throw new AgentControlException("invalid_agent_console_server_url", allowedHosts: hosts);
    }

    public string Command(string token) => "& {\n" + Script + "\n} "
        + string.Join(' ', new[] { Origin.AbsoluteUri, token, Root, Pin, Digest, ProductVersion }.Select(QuotePowerShell));

    internal static string QuotePowerShell(string value) => "'" + value
        .Replace("'", "''").Replace("\u2018", "\u2018\u2018").Replace("\u2019", "\u2019\u2019")
        .Replace("\u201a", "\u201a\u201a").Replace("\u201b", "\u201b\u201b") + "'";
}
