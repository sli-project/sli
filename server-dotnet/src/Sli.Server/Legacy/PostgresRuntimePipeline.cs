using Npgsql;

namespace Sli.Server.Legacy;

internal static class PostgresRuntimePipeline
{
    internal static Task<string?> ReadArchiveStartCandidateAsync(
        NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct) =>
        throw new InvalidOperationException("module_disabled");
}
