using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

// Request-scoped event projection. The caller owns the PostgreSQL snapshot;
// semantic interpretations remain in PostgreSQL, without an archive fallback.
internal sealed partial class SemanticHistorySession(ISemanticSession inner, IConfiguration? configuration = null) : ISemanticStreamingSession
{
    internal static Task<SemanticHistorySession> CreateAsync(ISemanticSession session, IConfiguration? config, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(new SemanticHistorySession(session,config));
    }
    internal static Task<SemanticHistorySession?> CreateWorkerAsync(ISemanticSession session,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult<SemanticHistorySession?>(null);
    }
    // Kept for report callers outside Semantic. There is no separate history
    // transport to preload: QueryAsync selects the retained PostgreSQL rows.
    internal Task ReportAsync(long domain, DateTimeOffset start, DateTimeOffset end, CancellationToken ct, int[]? eventCodes = null)
    {
        ct.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }
    internal (string Sql,object?[] Values) Rewrite(string sql, object?[] values) => RewriteEvents(sql,values,configuration);
    public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
    {
        var rewritten = Rewrite(sql,values); return inner.QueryAsync(rewritten.Sql,ct,rewritten.Values);
    }
    public IAsyncEnumerable<JsonObject> StreamAsync(string sql, CancellationToken ct, params object?[] values)
    {
        var rewritten = Rewrite(sql,values);
        return (inner as ISemanticStreamingSession ?? throw new InvalidOperationException("semantic_streaming_session_required"))
            .StreamAsync(rewritten.Sql,ct,rewritten.Values);
    }
    public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("semantic_history_is_read_only");
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
