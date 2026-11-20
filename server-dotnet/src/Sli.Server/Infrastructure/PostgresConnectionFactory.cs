using Npgsql;
using Sli.Server.Hosting;

namespace Sli.Server.Infrastructure;

public interface IPostgresConnectionFactory
{
    Task<NpgsqlConnection> OpenAsync(CancellationToken ct);
}

public sealed class PostgresConnectionFactory : IPostgresConnectionFactory
{
    private readonly string connectionString;

    public PostgresConnectionFactory(IConfiguration configuration)
    {
        InstalledConfiguration.RequirePostgresBackend(configuration);
        var explicitValue = configuration.GetConnectionString("Sli")
            ?? configuration["Sli:PostgresConnectionString"];
        if (string.IsNullOrWhiteSpace(explicitValue))
            throw new ServerConfigurationException("ConnectionStrings:Sli", "missing");
        NpgsqlConnectionStringBuilder builder;
        try { builder = new NpgsqlConnectionStringBuilder(explicitValue); }
        catch (Exception error) when (error is ArgumentException or FormatException or OverflowException)
        { throw new ServerConfigurationException(configuration.GetConnectionString("Sli") is null ? "Sli:PostgresConnectionString" : "ConnectionStrings:Sli"); }
        // Reject implicit libpq/Npgsql defaults for the database identity.
        if (string.IsNullOrWhiteSpace(builder.Host) || string.IsNullOrWhiteSpace(builder.Database)
            || string.IsNullOrWhiteSpace(builder.Username))
            throw new ServerConfigurationException("ConnectionStrings:Sli", "host_database_user_required");
        // SQL follows request cancellation rather than a connection-string
        // timer or the driver's implicit command deadline.
        builder.CommandTimeout = 0;
        if (!builder.ContainsKey("Timeout")) builder.Timeout = 8;
        builder.IncludeErrorDetail = false;
        connectionString = builder.ConnectionString;
    }

    public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
    {
        var connection = new NpgsqlConnection(connectionString);
        try
        {
            await connection.OpenAsync(ct);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }
}
