using System.Text;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Operations;
using Sli.Server.Storage.Direct;
using System.Text.Json.Nodes;
using Sli.Server.Semantic;

namespace Sli.Server.Legacy;

public sealed record LegacyReportFile(string Name, string Content);
public sealed record LegacyReport(string Url, IReadOnlyList<LegacyReportFile> Files);
public interface ILegacyAnalysis
{
    Task<LegacyReport> RenderAsync(long jobId, string[] servers, CancellationToken ct);
}

// Retired analysis cannot read event storage.
public sealed class LegacyAnalysis : ILegacyAnalysis
{
    public LegacyAnalysis(IPostgresConnectionFactory connections, OperationsService operations) { }

    public Task<LegacyReport> RenderAsync(long jobId, string[] servers, CancellationToken ct)
    {
        throw new InvalidOperationException("module_disabled");
    }

    internal static string SafeName(string server)
    {
        // Same alphabet as analysis_render._safe_name; no path components survive.
        return string.Concat(server.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_'));
    }


    private static Task<string> RenderScopeAsync(NpgsqlConnection db, NpgsqlTransaction tx,
        long jobId, string[] servers, bool overview, CancellationToken ct) =>
        RenderScopeAsync(jobId,servers,overview,new SemanticSession(db,tx).QueryAsync,ct);

    internal static Task<string> RenderScopeAsync(long jobId,string[] servers,bool overview,
        Func<string,CancellationToken,object?[],Task<JsonArray>> query,CancellationToken ct)
    {
        throw new InvalidOperationException("module_disabled");
    }
}

public static class LegacyReportPublication
{
    public static async Task PublishAsync(LegacyReport report, string directory,
        Func<Func<Task>, CancellationToken, Task>? fence, CancellationToken ct)
    {
        Directory.CreateDirectory(directory);
        var staged = new List<(string Temporary, string Target)>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try {
            foreach (var file in report.Files) {
                if (!names.Add(file.Name) || file.Name != Path.GetFileName(file.Name) || file.Name is "." or ".." || !file.Name.EndsWith(".html", StringComparison.Ordinal))
                    throw new InvalidDataException("invalid_report_name");
                string target = Path.Combine(directory, file.Name);
                string temporary = Path.Combine(directory, "." + file.Name + "." + Guid.NewGuid().ToString("N") + ".tmp");
                staged.Add((temporary, target));
                await File.WriteAllTextAsync(temporary, file.Content, new UTF8Encoding(false), ct);
            }
            foreach (var file in staged) {
                Task Promote() {
                    ct.ThrowIfCancellationRequested();
                    File.Move(file.Temporary, file.Target, true);
                    return Task.CompletedTask;
                }
                // Recheck the exact live claim under its row lock for every
                // atomic replacement, including after a previous publication.
                if (fence is null) await Promote(); else await fence(Promote, ct);
            }
        }
        finally { foreach (var file in staged) File.Delete(file.Temporary); }
    }
}
