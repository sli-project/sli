using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http.HttpResults;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using Sli.Server.Operations;

namespace Sli.Server.Agents.Control;

internal sealed class AgentInstallPackages(IConfiguration config, IAgentControlAudit audit)
{
    public const string SettingsPath = "/api/v1/admin/agent-install-package";
    public const string DownloadPath = SettingsPath + "/download";
    private readonly string directoryPath = Path.Combine(new OperationsFiles(config).DataRoot, "agent-installers");
    private string SourcePath => AgentConsolePackage.PackagePath(config);
    private bool SourceAvailable => File.Exists(SourcePath) && (config["SLI_DEPLOYMENT_MODE"] != "native"
        || config["SLI_AGENT_CA_ROOT_CERT_FILE"] is not null);

    private sealed record Installer(Guid Revision, string Url, string Pin, string ReleaseSha256, string Sha256, string Version, string FileName);
    private sealed record Grant(Guid Id, string Hash, DateTime? Expiry, int? Limit, int Used, Installer Package);

    // Files are immutable once published. The transaction selects one revision; an interrupted
    // build cannot expose a partial MSI or commit a revocation without its replacement.
    public async Task PrepareOnStartupAsync(IPostgresConnectionFactory factory, CancellationToken ct)
    {
        if (config["SLI_DEPLOYMENT_MODE"] != "native" || !SourceAvailable) return;
        await using var db = await factory.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        var prepared = await PrepareAsync(db, tx, default, null, "system:agent-installer", ct);
        await tx.CommitAsync(ct);
        DeleteRetiredFiles(prepared.RetiredMsi, prepared.RetiredKey);
    }

    public async Task<JsonElement> ReadSettingsAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct)
    {
        await LockAsync(db, tx, ct, shared: true);
        if (SourceAvailable && await ReadGrantAsync(db, tx, ct) is { } current && File.Exists(PackagePath(current.Package))) return Response(current);
        return JsonSerializer.SerializeToElement(new { server_url = (string?)null, package_url = (string?)null });
    }

    public async Task<JsonElement> PreferRequestOriginAsync(JsonElement settings, AuthRequestIdentity request,
        IPAddress? localAddress, CancellationToken ct)
    {
        if (settings.GetProperty("server_url").GetString() is not { } address
            || config["Kestrel:Certificates:Default:Path"] is not { } path) return settings;
        try
        {
            using var certificate = X509Certificate2.CreateFromPem(await File.ReadAllTextAsync(path, ct));
            var preferred = await PreferredOriginAsync(request, new Uri(address), localAddress, certificate, Dns.GetHostAddressesAsync, ct);
            if (preferred is null) return settings;
            var response = JsonObject.Create(settings)!;
            response["preferred_server_url"] = preferred;
            return JsonSerializer.SerializeToElement(response);
        }
        catch (Exception error) when (error is IOException or CryptographicException or UnauthorizedAccessException)
        {
            return settings;
        }
    }

    internal static async Task<string?> PreferredOriginAsync(AuthRequestIdentity request, Uri current, IPAddress? localAddress,
        X509Certificate2 certificate, Func<string, CancellationToken, Task<IPAddress[]>> resolve, CancellationToken ct)
    {
        var candidate = ExistingOrigin(AuthRequestPolicy.CanonicalOrigin(request.Scheme, request.Host), certificate);
        if (candidate is null || candidate.HostNameType != UriHostNameType.Dns || candidate == current) return null;

        try
        {
            var addresses = await resolve(candidate.IdnHost, ct);
            if (addresses.Length == 0 || addresses.Any(ip => !AgentConsolePackage.IsRemoteHost(ip.ToString()))) return null;
            // A certificate name can be valid without DNS taking agents to this installation.
            var endpointAddresses = IPAddress.TryParse(current.IdnHost, out var currentIp)
                ? [currentIp] : await resolve(current.IdnHost, ct);
            var known = endpointAddresses.Select(ip => ip.MapToIPv6()).ToHashSet();
            if (localAddress is not null) known.Add(localAddress.MapToIPv6());
            return addresses.All(ip => known.Contains(ip.MapToIPv6())) ? candidate.AbsoluteUri : null;
        }
        catch (SocketException)
        {
            return null;
        }
    }

    public async Task<FileStreamHttpResult> OpenDownloadAsync(NpgsqlConnection db, NpgsqlTransaction tx, string revision, CancellationToken ct)
    {
        await LockAsync(db, tx, ct, shared: true);
        var current = await ReadGrantAsync(db, tx, ct);
        if (current is null || !SourceAvailable) throw Unavailable();
        var package = current.Package;
        if (revision != package.Revision.ToString("N")) throw new AgentControlException("agent_install_package_changed", 409);
        try
        {
            var stream = new FileStream(PackagePath(package), FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            return TypedResults.File(stream, "application/octet-stream", package.FileName);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { throw Unavailable(); }
    }

    public async Task<(JsonElement Body, string? RetiredMsi, string? RetiredKey)> PrepareAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement input, Guid? revoke,
        string actor, CancellationToken ct)
    {
        await LockAsync(db, tx, ct);
        var current = await ReadGrantAsync(db, tx, ct, forUpdate: true);
        if (revoke is { } id && id != current?.Id) throw new AgentControlException("enrollment_token_not_found", 404);

        string? address = null;
        DateTime? expiry = current?.Expiry;
        int? limit = current?.Limit;
        if (input.ValueKind != JsonValueKind.Undefined)
        {
            if (input.ValueKind != JsonValueKind.Object) throw InvalidSettings();
            var fields = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in input.EnumerateObject())
            {
                if (!fields.Add(property.Name)) throw InvalidSettings();
                var value = property.Value;
                switch (property.Name)
                {
                    case "server_url" when value.ValueKind == JsonValueKind.String:
                        address = value.GetString(); break;
                    case "host_limit" when value.ValueKind == JsonValueKind.Null:
                        limit = null; break;
                    case "host_limit" when value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int count) && count > 0:
                        limit = count; break;
                    case "expires_at" when value.ValueKind == JsonValueKind.Null:
                        expiry = null; break;
                    case "expires_at" when value.ValueKind == JsonValueKind.String && value.TryGetDateTimeOffset(out var date)
                        && date.UtcDateTime > DateTime.UtcNow:
                        expiry = date.UtcDateTime; break;
                    default: throw InvalidSettings();
                }
            }
        }

        try
        {
            if (!OperatingSystem.IsLinux() || !SourceAvailable) throw Unavailable();
            using var certificate = X509Certificate2.CreateFromPem(await File.ReadAllTextAsync(
                config["Kestrel:Certificates:Default:Path"] ?? throw Unavailable(), ct));
            string? saved = current?.Package.Url ?? await AgentManagementService.ReadConsoleServerUrlAsync(db, tx, ct);
            var origin = address is not null ? AgentConsolePackage.ValidateOrigin(address, certificate, requireRemote: true)
                : ExistingOrigin(saved, certificate) ?? DefaultOrigin(certificate);
            var settings = await AgentConsolePackage.ReadAsync(config, origin.AbsoluteUri, ct);
            if (settings.ProductVersion.Length == 0) throw Unavailable(); // A release manifest must authenticate the source digest.
            if (current is not null && revoke is null && current.Expiry == expiry && current.Limit == limit
                && current.Package.Url == origin.AbsoluteUri && current.Package.Pin == settings.Pin
                && current.Package.ReleaseSha256 == settings.Digest && await MatchesFileAsync(current.Package, ct))
                return (Response(current), null, null);

            Directory.CreateDirectory(directoryPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var token = revoke is not null || current is null ? null : await ReadKeyAsync(current, ct);
            var rotate = token is null;
            token ??= Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            Guid keyId = rotate ? Guid.NewGuid() : current!.Id;
            var host = Regex.Replace(origin.IdnHost, "[^a-zA-Z0-9.-]", "-");
            var fileName = $"SLI-Agent-{host[..Math.Min(host.Length, 63)]}-{settings.ProductVersion}.msi";
            var package = new Installer(Guid.NewGuid(), origin.AbsoluteUri, settings.Pin, settings.Digest, "", settings.ProductVersion, fileName);
            RemoveOldFiles(current?.Package.Revision, current?.Id);
            if (rotate)
            {
                // Retain the key across upgrades and rollback of the package pointer. The
                // API service exclusively owns this directory, which is excluded from backups.
                using var key = new FileStream(KeyPath(keyId), new FileStreamOptions {
                    Mode = FileMode.CreateNew, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
                });
                await key.WriteAsync(Encoding.ASCII.GetBytes(token), ct);
                key.Flush(flushToDisk: true);
            }
            string output = PackagePath(package);
            Directory.CreateDirectory(Path.GetDirectoryName(output)!, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            await AgentInstallPackage.BuildAsync(SourcePath, output, settings, token, ct);
            package = package with { Sha256 = await AgentInstallPackage.DigestAsync(output, ct) };
            // A replacement carries forward current limits. An elapsed expiration remains
            // visible and can be cleared explicitly without reviving the previous key.
            var grant = new Grant(keyId, KeyDigest(token), expiry, limit,
                rotate ? 0 : current!.Used, package);
            if (rotate && current is not null)
            {
                await using var retire = new NpgsqlCommand("update sli_agent_console_tokens set revoked_at=clock_timestamp() where id=@id", db, tx);
                retire.Parameters.AddWithValue("id", current.Id);
                await retire.ExecuteNonQueryAsync(ct);
                await audit.AppendAsync(db, tx, "token_revoke", actor, current.Id.ToString(), new { package = true }, ct);
            }
            await SaveAsync(db, tx, grant, rotate, ct);
            if (rotate) await audit.AppendAsync(db, tx, "token_create", actor, grant.Id.ToString(), new { package = true }, ct);
            return (Response(grant), current is null ? null : PackagePath(current.Package),
                rotate && current is not null ? KeyPath(current.Id) : null);
        }
        catch (Exception error) when (error is IOException or JsonException or CryptographicException or UnauthorizedAccessException or InvalidDataException)
        { throw Unavailable(); }
    }

    private Uri DefaultOrigin(X509Certificate2 certificate)
    {
        if (ExistingOrigin(config["SLI_AGENT_INSTALLER_ORIGIN"], certificate) is { } configured) return configured;
        int port = Uri.TryCreate(config["SLI_HEALTH_URL"], UriKind.Absolute, out var health) ? health.Port : 443;
        foreach (var host in new[] { config["SLI_BIND"] }.OfType<string>().Concat(AgentConsolePackage.CertificateHosts(certificate)))
            if (AgentConsolePackage.IsRemoteHost(host) && ExistingOrigin(new UriBuilder("https", host, port).Uri.AbsoluteUri, certificate) is { } origin)
                return origin;
        throw new AgentControlException("invalid_agent_console_server_url", allowedHosts: AgentConsolePackage.CertificateHosts(certificate));
    }

    private static Uri? ExistingOrigin(string? address, X509Certificate2 certificate)
    {
        if (address is null) return null;
        try { return AgentConsolePackage.ValidateOrigin(address, certificate, requireRemote: true); }
        catch (AgentControlException) { return null; }
    }

    private string PackagePath(Installer value) => Path.Combine(directoryPath, value.Revision.ToString("N"), value.FileName);
    private string KeyPath(Guid id) => Path.Combine(directoryPath, id.ToString("N") + ".enrollment");
    private async Task<bool> MatchesFileAsync(Installer package, CancellationToken ct)
    {
        string path = PackagePath(package);
        return File.Exists(path) && await AgentInstallPackage.DigestAsync(path, ct) == package.Sha256;
    }
    private static string KeyDigest(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
    private async Task<string?> ReadKeyAsync(Grant grant, CancellationToken ct)
    {
        try
        {
            await using var key = File.OpenRead(KeyPath(grant.Id));
            byte[] bytes = new byte[43];
            if (key.Length != bytes.Length) return null;
            await key.ReadExactlyAsync(bytes, ct);
            return Convert.ToHexStringLower(SHA256.HashData(bytes)) == grant.Hash ? Encoding.ASCII.GetString(bytes) : null;
        }
        catch (FileNotFoundException) { return null; }
    }

    private void RemoveOldFiles(Guid? current, Guid? currentKey)
    {
        foreach (string directory in Directory.EnumerateDirectories(directoryPath))
            if (Guid.TryParseExact(Path.GetFileName(directory), "N", out var revision) && revision != current)
            {
                // Only files created by this builder are removed, and no symlink is followed.
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) continue;
                foreach (string file in Directory.EnumerateFiles(directory, "SLI-Agent-*.msi")) File.Delete(file);
                File.Delete(Path.Combine(directory, "Property.idt"));
                Directory.Delete(directory);
            }
        foreach (string key in Directory.EnumerateFiles(directoryPath, "*.enrollment"))
            if (Guid.TryParseExact(Path.GetFileNameWithoutExtension(key), "N", out var id) && id != currentKey)
                File.Delete(key);
    }

    internal static void DeleteRetiredFiles(string? msi, string? key)
    {
        try
        {
            if (key is not null) File.Delete(key);
            if (msi is not null)
            {
                File.Delete(msi);
                Directory.Delete(Path.GetDirectoryName(msi)!);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { /* The next rebuild can clean up the unreferenced revision. */ }
    }

    private static async Task<Grant?> ReadGrantAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct, bool forUpdate = false)
    {
        await using var query = new NpgsqlCommand("""
            select id,token_hash,expires_at,host_limit,installer,
                (select count(*)::int from sli_agent_enrollment_tokens e where e.console_token_id=t.id and e.used_at is not null)
            from sli_agent_console_tokens t where installer is not null and revoked_at is null
            """ + (forUpdate ? " for update" : ""), db, tx);
        await using var row = await query.ExecuteReaderAsync(ct);
        return !await row.ReadAsync(ct) ? null : new(row.GetGuid(0), row.GetString(1),
            row.IsDBNull(2) ? null : row.GetDateTime(2), row.IsDBNull(3) ? null : row.GetInt32(3), row.GetInt32(5),
            JsonSerializer.Deserialize<Installer>(row.GetString(4)) ?? throw Unavailable());
    }

    private static async Task LockAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct, bool shared = false)
    {
        string function = shared ? "pg_advisory_xact_lock_shared" : "pg_advisory_xact_lock";
        await using var query = new NpgsqlCommand($"select {function}(hashtext('sli-agent-install-package'))", db, tx);
        await query.ExecuteNonQueryAsync(ct);
    }

    private static async Task SaveAsync(NpgsqlConnection db, NpgsqlTransaction tx, Grant grant, bool insert, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand(insert ? """
            insert into sli_agent_console_tokens(id, token_hash, created_at, expires_at, host_limit, remaining, installer)
            values(@id,@hash,statement_timestamp(),@expiry,@limit,@remaining,@package)
            """ : """
            update sli_agent_console_tokens set expires_at=@expiry, host_limit=@limit, remaining=@remaining, installer=@package where id=@id
            """, db, tx);
        query.Parameters.AddWithValue("id", grant.Id);
        if (insert) query.Parameters.AddWithValue("hash", grant.Hash);
        query.Parameters.Add("expiry", NpgsqlDbType.TimestampTz).Value = (object?)grant.Expiry ?? DBNull.Value;
        query.Parameters.Add("limit", NpgsqlDbType.Integer).Value = (object?)grant.Limit ?? DBNull.Value;
        query.Parameters.Add("remaining", NpgsqlDbType.Integer).Value = grant.Limit is int cap ? Math.Max(0, cap - grant.Used) : DBNull.Value;
        query.Parameters.AddWithValue("package", NpgsqlDbType.Jsonb, JsonSerializer.Serialize(grant.Package));
        await query.ExecuteNonQueryAsync(ct);
    }

    private static JsonElement Response(Grant grant) => JsonSerializer.SerializeToElement(new
    {
        server_url = grant.Package.Url, sha256 = grant.Package.Sha256, expires_at = grant.Expiry, host_limit = grant.Limit,
        package_url = DownloadPath + "?revision=" + grant.Package.Revision.ToString("N"),
    });

    private static AgentControlException Unavailable() => new("agent_console_package_unavailable", 503);
    private static AgentControlException InvalidSettings() => new("invalid_agent_install_package_settings");
}
