using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Semantic;

internal enum SemanticProcessingStep
{
    Claim, Commit, SourceLock, Context, Identity, RepairScope, Repair, SourceRead, BundleAdmission, Normalize,
    RetainedNormalization, IdentityOverrides, PersistNormalized, IdentityReplay,
    Assemble, PersistAction, EnqueueDispatch, Complete, Dispatch, Risk
}

// Persist only locally defined step names and validated SQLSTATE, never exception
// messages, SQL, constraint names, event data or source identifiers.
internal static class SemanticProcessingFailure
{
    internal static string Describe(Exception error, SemanticProcessingStep step)
    {
        string? state = null;
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is PostgresException pg) { state = pg.SqlState; break; }
        if (state is not null && (state.Length != 5 || state.Any(c => c is not (>= '0' and <= '9' or >= 'A' and <= 'Z')))) state = "unknown";
        return new JsonObject {
            ["code"] = "semantic_processing_failed",
            ["step"] = string.Concat(step.ToString().Select((c, i) => char.IsUpper(c) && i > 0 ? "_" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString())),
            ["sql_state"] = state
        }.ToJsonString();
    }
}
