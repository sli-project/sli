using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;

namespace Sli.Server.Hosting;

// Only setting names and fixed reasons belong in startup errors. Never retain an
// inner parser/IO exception: it can contain credentials or certificate contents.
public sealed class ServerConfigurationException(string setting, string reason = "invalid")
    : InvalidOperationException($"server_configuration_invalid:{setting}:{reason}");

public static class InstalledConfiguration
{
    public static void AddInstalledEnvironment(this ConfigurationManager configuration)
    {
        RequirePostgresBackend(configuration);
        var values = new Dictionary<string, string?>();
        void Alias(string target, string source)
        {
            if (configuration[target] is null && configuration[source] is { } value) values[target] = value;
        }
        Alias("Sli:AuthRequired", "ADLOG_AUTH_REQUIRED");
        Alias("Sli:AllowUnauthenticated", "ADLOG_ALLOW_UNAUTHENTICATED");
        Alias("Sli:AuthAllowInsecureHttp", "ADLOG_AUTH_ALLOW_INSECURE_HTTP");
        Alias("Sli:AuthCookieSecure", "ADLOG_AUTH_COOKIE_SECURE");
        Alias("Sli:OwnerSetup", "SLI_OWNER_SETUP");
        Alias("Sli:TrustedProxies", "ADLOG_TRUSTED_PROXIES");
        Alias("Sli:OperatorToken", "ADLOG_OPERATOR_TOKEN");
        Alias("Sli:ReactRoot", "ADLOG_REACT_WEB_DIR");
        // The accepted release's login page and React bundle live in web/app.
        if (configuration["Sli:WebRoot"] is null && configuration["SLI_DEPLOYMENT_MODE"] == "native")
            values["Sli:WebRoot"] = "/opt/sli/current/web/app";
        Alias("Sli:AgentMtlsCaFile", "SLI_AGENT_MTLS_CA_FILE");
        Alias("Sli:AgentUpdateTrustFile", "SLI_AGENT_UPDATE_TRUST_FILE");
        foreach (string name in new[] { "HttpMaxConnections", "HttpMaxConcurrentRequests", "HttpRatePerMinute" })
        {
            string legacy = name switch {
                "HttpMaxConnections" => "ADLOG_HTTP_MAX_CONNECTIONS",
                "HttpMaxConcurrentRequests" => "ADLOG_HTTP_MAX_CONCURRENT_REQUESTS",
                _ => "ADLOG_HTTP_RATE_PER_MINUTE"
            };
            Alias("Sli:" + name, legacy);
        }
        foreach (string name in new[] { "Sli:AgentMtlsCaFile", "Sli:AgentUpdateTrustFile" })
            if (values.TryGetValue(name, out var path)) values[name] = CredentialPath(configuration, path!, name);

        // An explicitly supplied new connection string wins as a whole, including
        // its authentication method. Do not even read legacy secret files then.
        if (configuration.GetConnectionString("Sli") is null && configuration["Sli:PostgresConnectionString"] is null
            && (configuration["SLI_DEPLOYMENT_MODE"] == "native" || configuration["ADLOG_PG_DSN"] is not null || configuration["ADLOG_PG_DSN_FILE"] is not null))
            values["ConnectionStrings:Sli"] = Postgres(configuration);

        bool explicitCertificate = configuration.GetSection("Kestrel:Certificates:Default").Exists()
            || configuration.GetSection("Kestrel:Endpoints").GetChildren().Any(e => e.GetSection("Certificate").Exists());
        if (!explicitCertificate)
        {
            string cert = TlsPath(configuration, "ADLOG_TLS_CERT");
            string key = TlsPath(configuration, "ADLOG_TLS_KEY");
            if (cert.Length > 0 || key.Length > 0)
            {
                if (string.IsNullOrWhiteSpace(cert)) throw new ServerConfigurationException("ADLOG_TLS_CERT_FILE", "missing");
                if (string.IsNullOrWhiteSpace(key)) throw new ServerConfigurationException("ADLOG_TLS_KEY_FILE", "missing");
                cert = CredentialPath(configuration, cert, "ADLOG_TLS_CERT_FILE");
                key = CredentialPath(configuration, key, "ADLOG_TLS_KEY_FILE");
                ValidateCertificate(cert, key);
                values["Kestrel:Certificates:Default:Path"] = cert;
                values["Kestrel:Certificates:Default:KeyPath"] = key;
            }
        }
        // native_runtime supplies its bind address/port through the health URL.
        // Explicit ASP.NET listener configuration always takes precedence.
        if (configuration["urls"] is null && configuration["HTTP_PORTS"] is null && configuration["HTTPS_PORTS"] is null
            && !configuration.GetSection("Kestrel:Endpoints").Exists() && configuration["SLI_HEALTH_URL"] is { } health)
        {
            if (!Uri.TryCreate(health, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")
                || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
                throw new ServerConfigurationException("SLI_HEALTH_URL");
            // The health URL is a probe address: a wildcard bind appears there as loopback.
            // SLI_BIND carries the real listener address.
            if (configuration["SLI_BIND"] is { } bind)
            {
                if (!System.Net.IPAddress.TryParse(bind, out var address) || address.ToString() != bind)
                    throw new ServerConfigurationException("SLI_BIND");
                string host = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "[" + bind + "]" : bind;
                values["urls"] = uri.Scheme + "://" + host + ":" + uri.Port.ToString(CultureInfo.InvariantCulture);
            }
            else values["urls"] = uri.GetLeftPart(UriPartial.Authority);
        }
        configuration.AddInMemoryCollection(values);
    }

    internal static void RequirePostgresBackend(IConfiguration configuration)
    {
        // An absent selector uses PostgreSQL. An explicit unsupported selector
        // must fail before reading credentials or attempting database access.
        string backend = configuration["ADLOG_DB_BACKEND"] ?? "postgres";
        if (!backend.Trim().Equals("postgres", StringComparison.OrdinalIgnoreCase))
            throw new ServerConfigurationException("ADLOG_DB_BACKEND", "postgres_required");
    }

    private static string Postgres(IConfiguration configuration)
    {
        string dsn = Secret(configuration, "ADLOG_PG_DSN") ?? throw new ServerConfigurationException("ADLOG_PG_DSN", "missing");
        string password = Secret(configuration, "ADLOG_PG_PASSWORD") ?? throw new ServerConfigurationException("ADLOG_PG_PASSWORD", "missing");
        try
        {
            var b = new NpgsqlConnectionStringBuilder();
            foreach (var (key, value) in GpoWorkerConfiguration.Parse(dsn))
                switch (key)
                {
                    case "host": b.Host = value; break;
                    case "port": b.Port = int.Parse(value, CultureInfo.InvariantCulture); break;
                    case "dbname": b.Database = value; break;
                    case "user": b.Username = value; break;
                    case "connect_timeout": b.Timeout = int.Parse(value, CultureInfo.InvariantCulture); break;
                    case "application_name": b.ApplicationName = value; break;
                    case "sslmode": b.SslMode = value switch {
                        "disable" => SslMode.Disable, "prefer" => SslMode.Prefer, "require" => SslMode.Require,
                        "verify-ca" => SslMode.VerifyCA, "verify-full" => SslMode.VerifyFull, _ => throw new ArgumentException()
                    }; break;
                    default: throw new ArgumentException();
                }
            if (string.IsNullOrWhiteSpace(b.Host) || string.IsNullOrWhiteSpace(b.Database) || string.IsNullOrWhiteSpace(b.Username))
                throw new ArgumentException();
            b.Password = password;
            b.IncludeErrorDetail = false;
            return b.ConnectionString;
        }
        catch (Exception e) when (e is ArgumentException or FormatException or OverflowException)
        { throw new ServerConfigurationException("ADLOG_PG_DSN"); }
    }

    internal static string? Secret(IConfiguration configuration, string name)
    {
        string? file = configuration[name + "_FILE"], value = configuration[name];
        if (file is null) return string.IsNullOrEmpty(value) ? null : value;
        string setting = name + "_FILE";
        if (!string.IsNullOrEmpty(value)) throw new ServerConfigurationException(setting, "conflict");
        if (string.IsNullOrWhiteSpace(file)) throw new ServerConfigurationException(setting);
        file = CredentialPath(configuration, file, setting);
        try
        {
            using var stream = File.OpenRead(file);
            byte[] bytes = new byte[65537];
            int count = 0, n;
            while (count < bytes.Length && (n = stream.Read(bytes, count, bytes.Length - count)) != 0) count += n;
            if (count > 65536) throw new ServerConfigurationException(setting);
            string result = new UTF8Encoding(false, true).GetString(bytes, 0, count).TrimEnd('\r', '\n');
            if (result.Length == 0 || result.Contains('\0')) throw new ServerConfigurationException(setting);
            return result;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        { throw new ServerConfigurationException(setting, "unavailable"); }
        catch (Exception e) when (e is ArgumentException)
        { throw new ServerConfigurationException(setting); }
    }

    internal static string CredentialPath(IConfiguration configuration, string path, string setting)
    {
        // systemd normally expands %d itself; also accept it with its standard
        // CREDENTIALS_DIRECTORY for launchers and process-level acceptance tests.
        if (!path.StartsWith("%d/", StringComparison.Ordinal)) return path;
        string tail=path[3..];
        if (tail.Length==0 || Path.IsPathRooted(tail) || tail[0]=='/' || tail[0]==(char)92
            || tail.Contains(':') || tail.Split('/', (char)92).Contains("..",StringComparer.Ordinal))
            throw new ServerConfigurationException(setting);
        string? directory = configuration["CREDENTIALS_DIRECTORY"];
        if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory))
            throw new ServerConfigurationException(setting, "credential_directory_missing");
        return Path.Combine(directory, tail);
    }

    private static void ValidateCertificate(string cert, string key)
    {
        if (!File.Exists(cert)) throw new ServerConfigurationException("ADLOG_TLS_CERT_FILE", "unavailable");
        if (!File.Exists(key)) throw new ServerConfigurationException("ADLOG_TLS_KEY_FILE", "unavailable");
        try { using var certificate = X509Certificate2.CreateFromPemFile(cert, key); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException)
        { throw new ServerConfigurationException("ADLOG_TLS_CERT_FILE/ADLOG_TLS_KEY_FILE"); }
    }

    private static string TlsPath(IConfiguration configuration, string name)
    {
        string path = configuration[name + "_PATH"]?.Trim() ?? "";
        if (configuration[name + "_FILE"] is not { } file) return path;
        if (path.Length > 0) throw new ServerConfigurationException(name + "_FILE", "conflict");
        file = file.Trim();
        if (file.Length == 0) throw new ServerConfigurationException(name + "_FILE");
        return file;
    }
}
