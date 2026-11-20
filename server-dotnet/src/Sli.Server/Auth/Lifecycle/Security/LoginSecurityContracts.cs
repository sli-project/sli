using Npgsql;

namespace Sli.Server.Auth.Lifecycle.Security;

public sealed record AdmissionResult(bool Allowed, int RetryAfterSeconds);

public interface ISourceAdmission
{
    AdmissionResult TryReserve(string address);
}

public sealed class LoginThrottledException(int retryAfterSeconds) : Exception("login_temporarily_locked")
{
    public int RetryAfterSeconds { get; } = Math.Max(1, retryAfterSeconds);
}

public interface IAccountThrottle
{
    Task<IAccountAttempt> BeginAsync(NpgsqlTransaction transaction, string username, CancellationToken ct);
}

// The caller owns the transaction: failed passwords commit accounting, while errors roll back.
public interface IAccountAttempt : IAsyncDisposable
{
    Task FailAsync(CancellationToken ct);
    Task SucceedAsync(CancellationToken ct);
}

public sealed record AuthAuditEvent(string ActorType, long? ActorId, string Action,
    string Outcome = "ok", string? RemoteAddress = null);

public interface IAuthAudit
{
    Task WriteAsync(AuthAuditEvent auditEvent, CancellationToken ct);
    Task AppendAsync(NpgsqlTransaction transaction, AuthAuditEvent auditEvent, CancellationToken ct);
}
