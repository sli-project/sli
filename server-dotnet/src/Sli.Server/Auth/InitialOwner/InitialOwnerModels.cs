using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Auth.InitialOwner;

public sealed record SetupCommand(string? Code, string? Password);
public sealed class InitialOwnerPasswordException() : Exception("new_password_required");

public interface IInitialOwnerSetup
{
    Task<bool> IsPendingAsync(CancellationToken ct);
    Task<LoginResult> ClaimAsync(SetupCommand command, RequestIdentity identity, CancellationToken ct);
}

public sealed record OwnerCodeCommand(bool NewCode = false, bool CheckOnly = false);
public sealed record OwnerCodeResult(string Status, string? Code = null);

public interface IInitialOwnerCodeConsole
{
    Task<OwnerCodeResult> ExecuteAsync(OwnerCodeCommand command, CancellationToken ct);
    Task<int> RunAsync(string[] args, CancellationToken ct);
}
