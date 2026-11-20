using System.Text;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Infrastructure;
using Sli.Server.Hosting;

namespace Sli.Server.Vpn;

internal static class RadiusHostConfiguration
{
    internal static (NpgsqlConnectionStringBuilder Core, NpgsqlConnectionStringBuilder Broker) Settings(IConfiguration configuration, Func<string, string?> get, Func<string, byte[]> read)
    {
        bool explicitCore = configuration.GetConnectionString("Sli") is not null || configuration["Sli:PostgresConnectionString"] is not null;
        string? Source(string key) => key switch {
            "ADLOG_PG_DSN" => configuration.GetConnectionString("Sli") ?? configuration["Sli:PostgresConnectionString"] ?? get(key),
            "ADLOG_PG_PASSWORD" or "ADLOG_PG_PASSWORD_FILE" when explicitCore => null,
            _ => get(key)
        };
        string dsn = GpoWorkerConfiguration.CreateNamed(Source, read, "ADLOG_PG_DSN", "ADLOG_PG_PASSWORD", "sli_radius_observation_host", 0);
        string user = get("ADLOG_PG_ADMIN_USER")?.Trim() ?? "";
        string? password = get("ADLOG_PG_ADMIN_PASSWORD"), file = get("ADLOG_PG_ADMIN_PASSWORD_FILE");
        if (file is not null) {
            if (!string.IsNullOrEmpty(password) || string.IsNullOrEmpty(file)) throw new ServerConfigurationException("ADLOG_PG_ADMIN_PASSWORD_FILE", "conflict");
            try {
                byte[] bytes = read(file); if (bytes.Length > 65536) throw new ServerConfigurationException("ADLOG_PG_ADMIN_PASSWORD_FILE");
                password = new UTF8Encoding(false, true).GetString(bytes).TrimEnd('\r', '\n');
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { throw new ServerConfigurationException("ADLOG_PG_ADMIN_PASSWORD_FILE", "unavailable"); }
            catch (DecoderFallbackException) { throw new ServerConfigurationException("ADLOG_PG_ADMIN_PASSWORD_FILE"); }
        }
        if (user.Length == 0) throw new ServerConfigurationException("ADLOG_PG_ADMIN_USER", "missing");
        if (string.IsNullOrEmpty(password) || password.Contains('\0')) throw new ServerConfigurationException(file is null ? "ADLOG_PG_ADMIN_PASSWORD" : "ADLOG_PG_ADMIN_PASSWORD_FILE");
        var core = new NpgsqlConnectionStringBuilder(dsn!) { Pooling = false, Multiplexing = false, Timeout = 5, Options = "-c statement_timeout=0 -c lock_timeout=0" };
        var broker = new NpgsqlConnectionStringBuilder(core.ConnectionString) { Username = user, Password = password, ApplicationName = "sli_radius_consumer_control", CommandTimeout = 0 };
        return (core, broker);
    }
    internal static IPostgresConnectionFactory Factory(NpgsqlConnectionStringBuilder settings) => new PostgresConnectionFactory(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:PostgresConnectionString"] = settings.ConnectionString }).Build());
}
