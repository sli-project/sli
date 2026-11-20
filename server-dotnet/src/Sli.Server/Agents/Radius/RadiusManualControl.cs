using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Npgsql;

namespace Sli.Server.Agents.Radius;

public sealed class RadiusManualControlException(string code, Exception? inner = null) : Exception(code, inner);

public sealed record RadiusManualState(string SourceActivation, string SubscriptionActivation,
    long CursorRevision, bool Migration58, bool Migration59);

// Do not serialize credentials into worker results or diagnostics.
public sealed class RadiusManualLease(string loginRole, string password, string sourceId, string subscriptionId)
{
    public string LoginRole { get; } = loginRole;
    public string Password { get; } = password;
    public string SourceInstanceId { get; } = sourceId;
    public string SubscriptionId { get; } = subscriptionId;
}

// Port of accounting_manual_control.py. One caller-owned operation per credential;
// the supervised host owns repetition. Q500 removes record and runtime limits.
public static class RadiusManualControl
{
    public const string SubscriptionId = "vpn-radius-session-observations-radius01-v1";
    internal const string AclLock = "sli.radius.ephemeral_database_connect_acl.v1";

    public static void RequireReadyDisabled(RadiusManualState state)
    {
        if (!state.Migration58 || !state.Migration59) throw new RadiusManualControlException("manual_required_migration_missing");
        if (state.SourceActivation != "disabled" || state.SubscriptionActivation != "disabled")
            throw new RadiusManualControlException("manual_activation_not_disabled");
    }

    public static async Task<RadiusManualState> InspectAsync(NpgsqlConnection db, string sourceId, string subscriptionId, CancellationToken ct)
    {
        await using var tx = await db.BeginTransactionAsync(ct);
        await Execute(db, "set transaction read only", ct);
        await using var cmd = Command(db, """
            select s.desired_activation,sub.desired_activation,c.revision,
              exists(select 1 from schema_migrations where version=58 and name='radius_accounting_transaction_foundation'),
              exists(select 1 from schema_migrations where version=59 and name='radius_identity_spine_resolver')
            from acquisition_source_instances s
            join acquisition_stream_cursors c on c.source_instance_id=s.source_instance_id
            join acquisition_consumer_subscriptions sub on sub.source_instance_id=c.source_instance_id
              and sub.stream_id=c.stream_id and sub.transport_binding=c.transport_binding
            where s.source_instance_id=$1 and sub.subscription_id=$2
            """, sourceId, subscriptionId);
        RadiusManualState state;
        await using (var reader = await cmd.ExecuteReaderAsync(ct)) {
            if (!await reader.ReadAsync(ct)) throw new RadiusManualControlException("manual_registration_not_found");
            state = new(reader.GetString(0), reader.GetString(1), reader.GetInt64(2), reader.GetBoolean(3), reader.GetBoolean(4));
        }
        await tx.CommitAsync(ct);
        return state;
    }

    internal static async Task LockDatabaseConnectAclAsync(NpgsqlConnection db, CancellationToken ct)
        => await Execute(db, "select pg_advisory_xact_lock(hashtext($1))", ct, AclLock);

    internal static async Task<(string Role, string Password)> CreateLoginAsync(NpgsqlConnection db, CancellationToken ct)
    {
        string role = "adlog_radius_manual_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(36));
        using var quote = new NpgsqlCommandBuilder();
        string id = quote.QuoteIdentifier(role), database = DatabaseIdentifier(db);
        await using var tx = await db.BeginTransactionAsync(ct);
        await LockDatabaseConnectAclAsync(db, ct);
        // The password is generated hex, never caller input. PostgreSQL DDL has no bind parameters.
        await Execute(db, $"create role {id} login noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication password '{password}'; grant adlog_radius_accounting_worker to {id}; grant connect on database {database} to {id}", ct);
        await tx.CommitAsync(ct);
        return (role, password);
    }

    private static string DatabaseIdentifier(NpgsqlConnection db)
    {
        if (string.IsNullOrWhiteSpace(db.Database)) throw new RadiusManualControlException("manual_database_identity_required");
        using var quote = new NpgsqlCommandBuilder();
        return quote.QuoteIdentifier(db.Database);
    }

    internal static async Task DropLoginAsync(NpgsqlConnection db, string role, CancellationToken ct)
    {
        if (!Regex.IsMatch(role, @"\Aadlog_radius_manual_[a-z0-9_]{1,40}\z", RegexOptions.CultureInvariant))
            throw new RadiusManualControlException("manual_login_role_name_invalid");
        using var quote = new NpgsqlCommandBuilder();
        string id = quote.QuoteIdentifier(role), database = DatabaseIdentifier(db);
        await using var tx = await db.BeginTransactionAsync(ct);
        await LockDatabaseConnectAclAsync(db, ct);
        await Execute(db, $"revoke connect on database {database} from {id}; drop role if exists {id}", ct);
        await tx.CommitAsync(ct);
    }

    internal static async Task SetActivationAsync(NpgsqlConnection db, string sourceId, string subscriptionId, string target, CancellationToken ct)
    {
        if (target is not ("disabled" or "manual_enabled")) throw new RadiusManualControlException("manual_activation_target_invalid");
        await using var tx = await db.BeginTransactionAsync(ct);
        await Execute(db, "set local role adlog_storage_owner", ct);
        await using (var cmd = Command(db, """
            select s.desired_activation,sub.desired_activation
            from acquisition_source_instances s
            join acquisition_consumer_subscriptions sub on sub.source_instance_id=s.source_instance_id
            where s.source_instance_id=$1 and sub.subscription_id=$2 for update of s,sub
            """, sourceId, subscriptionId)) {
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) throw new RadiusManualControlException("manual_registration_not_found");
            if (target == "manual_enabled" && (reader.GetString(0) != "disabled" || reader.GetString(1) != "disabled"))
                throw new RadiusManualControlException("manual_activation_not_disabled");
        }
        if (await Execute(db, "update acquisition_source_instances set desired_activation=$1,updated_at=now() where source_instance_id=$2", ct, target, sourceId) != 1)
            throw new RadiusManualControlException("manual_source_activation_failed");
        if (await Execute(db, "update acquisition_consumer_subscriptions set desired_activation=$1 where subscription_id=$2 and source_instance_id=$3", ct, target, subscriptionId, sourceId) != 1)
            throw new RadiusManualControlException("manual_subscription_activation_failed");
        await tx.CommitAsync(ct);
    }

    public static async Task<T> RunOnceAsync<T>(NpgsqlConnection db, string sourceId, string subscriptionId,
        Func<RadiusManualLease, CancellationToken, Task<T>> operation, CancellationToken ct)
    {
        RequireReadyDisabled(await InspectAsync(db, sourceId, subscriptionId, ct));
        string? role = null;
        bool activated = false;
        try {
            var login = await CreateLoginAsync(db, ct); role = login.Role;
            await SetActivationAsync(db, sourceId, subscriptionId, "manual_enabled", ct); activated = true;
            return await operation(new RadiusManualLease(role, login.Password, sourceId, subscriptionId), ct);
        }
        finally {
            Exception? cleanupError = null;
            if (activated) {
                try { await SetActivationAsync(db, sourceId, subscriptionId, "disabled", CancellationToken.None); }
                catch (Exception error) { cleanupError = error; }
            }
            if (role is not null) {
                try { await DropLoginAsync(db, role, CancellationToken.None); }
                catch (Exception error) { cleanupError ??= error; }
            }
            if (cleanupError is not null) throw new RadiusManualControlException("manual_cleanup_failed", cleanupError);
        }
    }

    private static NpgsqlCommand Command(NpgsqlConnection db, string sql, params string[] values)
    {
        var cmd = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
        foreach (string value in values) cmd.Parameters.Add(new NpgsqlParameter { Value = value });
        return cmd;
    }

    private static async Task<int> Execute(NpgsqlConnection db, string sql, CancellationToken ct, params string[] values)
    {
        await using var cmd = Command(db, sql, values);
        return await cmd.ExecuteNonQueryAsync(ct);
    }
}
