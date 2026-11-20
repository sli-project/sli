using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace Sli.Server.Tests.Domains;

// Test-runner counterpart of scripts.maintenance.bundle_common.sanitized_pytest_env.
// Keep OS/runtime discovery, but never inherit an operator's server configuration.
internal static class SafeTestEnvironment
{
    // Endpoint tests own their listener and repository reads. Cache warmup has
    // separate tests and must not race authentication or touch external services.
    internal static void ConfigureApiHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
            Microsoft.Extensions.Configuration.MemoryConfigurationBuilderExtensions.AddInMemoryCollection(config,
                new Dictionary<string, string?> { ["urls"] = "http://127.0.0.1:0", ["HTTP_PORTS"] = "", ["HTTPS_PORTS"] = "" }));
        builder.ConfigureServices(services =>
        {
            var warmup = services.Where(s => s.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                && s.ImplementationType == typeof(Sli.Server.Workspace.DashboardWarmupService)).ToArray();
            foreach (var service in warmup) services.Remove(service);
        });
        builder.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddConsole();
        });
    }

    internal const string UnreachablePgDsn = "host=sli-tests.invalid port=5432 dbname=sli_test_unreachable user=sli_test";
    internal const string UnreachableConnectionString = "Host=sli-tests.invalid;Port=5432;Database=sli_test_unreachable;Username=sli_test";

    private static readonly HashSet<string> Blocked = new(StringComparer.OrdinalIgnoreCase)
    {
        "DATABASE_URL", "PGDATABASE", "PGHOST", "PGHOSTADDR", "PGOPTIONS", "PGPASSFILE",
        "PGPASSWORD", "PGPORT", "PGSERVICE", "PGSERVICEFILE", "PGSSLMODE", "PGUSER",
        "POSTGRES_DB", "POSTGRES_HOST", "POSTGRES_PASSWORD", "POSTGRES_PORT", "POSTGRES_USER",
        "PYTHONHOME", "PYTHONINSPECT", "PYTHONPATH", "PYTHONSTARTUP", "PYTEST_ADDOPTS", "PYTEST_PLUGINS",
        "URLS", "HTTP_PORTS", "HTTPS_PORTS", "CREDENTIALS_DIRECTORY", "DOTNET_ENVIRONMENT",
        "DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS", "DOTNET_SHARED_STORE"
    };

    internal static Dictionary<string, string?> Create(IEnumerable<KeyValuePair<string, string?>> source)
    {
        string[] prefixes = ["ADLOG_", "SLI_", "SLI:", "ConnectionStrings__", "ConnectionStrings:",
            "Kestrel__", "Kestrel:", "ASPNETCORE_"];
        var clean = source.Where(pair => !Blocked.Contains(pair.Key)
            && !prefixes.Any(prefix => pair.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
        clean["ADLOG_DB_BACKEND"] = "postgres";
        clean["ADLOG_PG_DSN"] = UnreachablePgDsn;
        clean["ConnectionStrings__Sli"] = UnreachableConnectionString;
        clean["ADLOG_DISABLE_SCHEDULER"] = "1";
        clean["ADLOG_CONTINUOUS_RECOVERY"] = "false";
        clean["ADLOG_ENABLE_POSTGRES_COLLECTION"] = "";
        clean["ADLOG_SCHEDULER_CANARY"] = "";
        clean["ADLOG_CANARY_ARCHIVE"] = "";
        clean["DOTNET_ENVIRONMENT"] = "Testing";
        clean["ASPNETCORE_ENVIRONMENT"] = "Testing";
        return clean;
    }

    internal static void Apply(ProcessStartInfo start)
    {
        var clean = Create(start.Environment);
        start.Environment.Clear();
        foreach (var pair in clean) start.Environment[pair.Key] = pair.Value;
    }
}
