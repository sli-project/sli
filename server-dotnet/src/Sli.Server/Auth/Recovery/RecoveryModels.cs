using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Auth.Recovery;

public interface IOwnerRecoveryService
{
    // The caller must retain the normal origin, transport and source admission gates.
    Task<LoginResult> LoginAsync(LoginCommand command, string recoveryCode, RequestIdentity identity, CancellationToken ct);
}

public interface IOwnerRecoveryConsole
{
    Task<int> RunAsync(string[] args, CancellationToken ct);
}
