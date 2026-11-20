using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Legacy;

internal sealed class LegacyAdmittedDatabase(IPostgresConnectionFactory connections) : ISemanticDatabase
{
    public async Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct)
    {
        var db = await connections.OpenAsync(ct);
        NpgsqlTransaction? tx = null;
        try {
            tx = await db.BeginTransactionAsync(ct);
            if (await DirectRuntimeAuthorization.LoadAsync(db,tx,DateTime.UtcNow,ct) is null)
                throw new InvalidOperationException("storage_v2_admission_required");
            return new SemanticSession(db,tx,ownsConnection:true);
        }
        catch { if (tx is not null) await tx.DisposeAsync(); await db.DisposeAsync(); throw; }
    }
}
