using System.Data.Common;

namespace Sli.Server.Vpn;

internal sealed record PluginComponentLease(Guid LeaseUid, string ComponentId, string AdmissionMode, DateTimeOffset ExpiresAtUtc);

// The same calls and transaction boundaries as plugin_runtime_admission_executor.py.
internal static class PluginRuntimeAdmissionExecutor
{
    internal const string Acquisition = "radius-acquisition";
    internal const string Consumer = "radius-session-observation";

    private static string Role(string componentId) => componentId switch {
        Acquisition => "set local role adlog_radius_accounting_worker",
        Consumer => "set local role adlog_radius_session_consumer",
        _ => throw new VpnInputException("component_lease_request_invalid")
    };

    private static DbCommand Command(DbConnection db, DbTransaction? transaction, string sql, params object[] values)
    {
        var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.CommandTimeout = 0;
        foreach (var value in values) {
            var parameter = command.CreateParameter();
            parameter.Value = value;
            command.Parameters.Add(parameter);
        }
        return command;
    }

    private static async Task ActivateRoleAsync(DbConnection db, DbTransaction? transaction, string componentId, CancellationToken ct)
    {
        await using var command = Command(db, transaction, Role(componentId));
        await command.ExecuteNonQueryAsync(ct);
    }

    internal static async Task<PluginComponentLease> AcquireAsync(DbConnection db, Guid leaseUid, string componentId,
        string holderKey, CancellationToken ct, bool activateRole = true, DbTransaction? transaction = null)
    {
        if (componentId is not (Acquisition or Consumer) || string.IsNullOrWhiteSpace(holderKey))
            throw new VpnInputException("component_lease_request_invalid");
        if (activateRole) await ActivateRoleAsync(db, transaction, componentId, ct);
        await using var command = Command(db, transaction, """
            select lease_uid,component_id,admission_mode,expires_at_utc
            from public.acquire_plugin_component_lease_v1($1,$2,$3,$4,$5)
            """, leaseUid, "sli.remote-access", componentId, componentId == Acquisition ? "source_contact" : "delivery_claim", holderKey);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) throw new VpnInputException("component_lease_result_missing");
        DateTimeOffset? expires = reader.GetValue(3) switch {
            DateTimeOffset at => at,
            DateTime { Kind: DateTimeKind.Utc } at => new DateTimeOffset(at),
            _ => null
        };
        if (reader.GetValue(0) is not Guid uid || uid != leaseUid || reader.GetValue(1) is not string component || component != componentId
            || reader.GetValue(2) is not string mode || (mode != "open" && (componentId != Consumer || mode != "drain_only")) || expires is null)
            throw new VpnInputException("component_lease_result_invalid");
        return new(uid, component, mode, expires.Value);
    }

    internal static async Task<bool> ReleaseAsync(DbConnection db, PluginComponentLease lease, string holderKey,
        string outcome, CancellationToken ct, bool activateRole = true, DbTransaction? transaction = null)
    {
        if (outcome is not ("completed" or "failed" or "cancelled"))
            throw new VpnInputException("component_lease_outcome_invalid");
        if (activateRole) await ActivateRoleAsync(db, transaction, lease.ComponentId, ct);
        await using var command = Command(db, transaction,
            "select public.release_plugin_component_lease_v1($1,$2,$3)", lease.LeaseUid, holderKey, outcome);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct) || reader.GetValue(0) is not bool released)
            throw new VpnInputException("component_lease_release_invalid");
        return released;
    }

    internal static async Task RunAsync(DbConnection db, string componentId, string holderKey,
        Func<PluginComponentLease, DbTransaction, CancellationToken, Task> work, CancellationToken ct, Guid? leaseUid = null)
    {
        PluginComponentLease lease;
        await using (var admission = await db.BeginTransactionAsync(ct)) {
            lease = await AcquireAsync(db, leaseUid ?? Guid.NewGuid(), componentId, holderKey, ct, transaction: admission);
            await admission.CommitAsync(ct);
        }
        await using var transaction = await db.BeginTransactionAsync(ct);
        try { await work(lease, transaction, ct); }
        catch {
            // Publish failure even when cancellation interrupted the work.
            await transaction.RollbackAsync(CancellationToken.None);
            await using var failure = await db.BeginTransactionAsync(CancellationToken.None);
            await ReleaseAsync(db, lease, holderKey, "failed", CancellationToken.None, transaction: failure);
            await failure.CommitAsync(CancellationToken.None);
            throw;
        }
        await ReleaseAsync(db, lease, holderKey, "completed", ct, transaction: transaction);
        await transaction.CommitAsync(ct);
    }
}
