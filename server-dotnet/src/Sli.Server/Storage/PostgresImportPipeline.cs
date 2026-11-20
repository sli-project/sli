using System.Diagnostics;
using System.Text.RegularExpressions;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Storage;

// run_dc_log_pilot's PostgreSQL dispatch boundary. The importer owns publication
// and Storage V2 admission; dispatch must never substitute a source identity.
internal static class PostgresImportPipeline
{
    private static readonly SemaphoreSlim Queue = new(1, 1);

    internal static string NormalizeFqdn(string value, string field)
    {
        string normalized = UnicodeCaseFold.TrimAndFold(value).TrimEnd('.');
        if (normalized is "example" or "example.invalid")
            throw new ArgumentException(field + "_placeholder_forbidden");
        string[] labels = normalized.Split('.');
        if (normalized.Length > 253 || labels.Length < 2 || labels.Any(label =>
            !Regex.IsMatch(label, @"\A(?!-)[a-z0-9-]{1,63}(?<!-)\z", RegexOptions.CultureInvariant)))
            throw new ArgumentException(field + "_must_be_fqdn");
        return normalized;
    }

    internal static (string Domain, string Forest) ResolveSourceIdentity(
        string connectAddress, string? domainOverride = null, string? forestOverride = null)
    {
        string domain;
        if (!string.IsNullOrEmpty(domainOverride)) domain = NormalizeFqdn(domainOverride, "domain");
        else
        {
            string address = NormalizeFqdn(connectAddress, "connect_address");
            domain = NormalizeFqdn(address[(address.IndexOf('.') + 1)..], "domain");
        }
        return (domain, NormalizeFqdn(string.IsNullOrEmpty(forestOverride) ? domain : forestOverride, "forest"));
    }

    internal static async Task<(int ExitCode, string Stdout, string Stderr, long QueueWaitMs, int Retries, string Backend)> RunAsync(
        string targetBackend, string? domain, string? forest,
        Func<string, string, CancellationToken, Task<(int ExitCode, string Stdout, string Stderr)>> import,
        CancellationToken ct)
    {
        if (targetBackend != "postgres") throw new ArgumentException("non_postgres_backend_forbidden: " + targetBackend);
        if (domain is null || forest is null) throw new ArgumentException("postgres_source_identity_required");
        domain = NormalizeFqdn(domain, "domain");
        forest = NormalizeFqdn(forest, "forest");
        var waiting = Stopwatch.StartNew();
        await Queue.WaitAsync(ct);
        long waitMs = waiting.ElapsedMilliseconds;
        try
        {
            var result = await import(domain, forest, ct);
            return (result.ExitCode, result.Stdout, result.Stderr, waitMs, 0, "postgres");
        }
        finally { Queue.Release(); }
    }
}
