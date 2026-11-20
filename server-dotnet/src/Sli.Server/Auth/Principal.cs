namespace Sli.Server.Auth;

// IDs are PostgreSQL bigint values, not client-provided identity claims.
public sealed record SubjectRef(string SubjectType, long SubjectId);

public sealed record Principal(string Type, long Id, string Role, string? Username = null,
    string? Label = null, long? ReportSubjectId = null)
{
    public long? UserId => Type == "session" ? Id : ReportSubjectId;
    public long? ApiKeyId => Type == "api_key" ? Id : null;
    public bool RestrictedReportKey => ReportSubjectId.HasValue;
    public SubjectRef? Subject => UserId is long id ? new("user", id) : null;
}

public sealed record AuthenticationFailure(int StatusCode, string Code, string? Reason = null,
    string? MessageKey = null);

public sealed record AuthenticationResult(Principal? Principal, AuthenticationFailure? Failure)
{
    public bool Succeeded => Principal is not null && Failure is null;
    public static AuthenticationResult Success(Principal principal) => new(principal, null);
    public static AuthenticationResult Denied(int statusCode, string code) => new(null, new(statusCode, code));
}

public interface IPrincipalAuthenticator
{
    ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct);
}
