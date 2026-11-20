namespace Sli.Server.Auth.Lifecycle;

public sealed record LoginCommand(string Username, string Password, bool Remember);
public sealed record RequestIdentity(string RemoteAddress);
public sealed record LoginResult(Principal? Principal, string? SessionToken, int RetryAfterSeconds = 0)
{
    public bool Succeeded => Principal is not null && SessionToken is not null;
}

public interface ILoginService
{
    Task<LoginResult> LoginAsync(LoginCommand command, RequestIdentity identity, CancellationToken ct);
}
