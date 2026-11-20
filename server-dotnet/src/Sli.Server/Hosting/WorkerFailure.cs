using Npgsql;

namespace Sli.Server.Hosting;

// Only fixed step/reason identifiers cross the process boundary. Exception
// messages, SQL details, paths and configuration values may contain secrets.
internal sealed class WorkerFailure(string step, string reason, Exception? inner = null) : InvalidOperationException(step + ":" + reason, inner)
{
    internal string Step { get; } = step;
    internal string Diagnostic { get; } = step + ":" + reason;
    internal static string Describe(Exception error, string step) => error switch {
        ServerConfigurationException configuration => configuration.Message,
        WorkerFailure failure => failure.Diagnostic,
        PostgresException postgres => step + ":postgres_" + postgres.SqlState,
        NpgsqlException => step + ":postgres_unavailable",
        UnauthorizedAccessException => step + ":permission_denied",
        IOException io when io.Message is "notification_setup_path_invalid" or "notification_setup_acl_invalid"
            or "notification_setup_sync_failed" or "notification_setup_size_invalid" => step + ":" + io.Message,
        InvalidOperationException invalid when invalid.Message == "notification_setup_root_required" => step + ":notification_setup_root_required",
        IOException => step + ":io_unavailable",
        _ => step + ":operation_failed"
    };
}
