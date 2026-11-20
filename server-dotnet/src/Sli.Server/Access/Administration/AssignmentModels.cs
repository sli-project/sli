using System.Numerics;
using System.Text.Json;

namespace Sli.Server.Access.Administration;

public sealed record AssignmentActor(string Type, long? Id);
public sealed record ReportAssignmentCommand(JsonElement Payload);
public sealed record ReportAssignmentResult(JsonElement Item);
public interface IReportAssignmentWriter
{
    Task<ReportAssignmentResult> CreateAsync(ReportAssignmentCommand command, AssignmentActor? actor, string? remoteAddress, CancellationToken ct);
}
public sealed class AssignmentValidationException(string code) : Exception(code);
internal sealed record AssignmentValues(string SubjectType, BigInteger SubjectId, string Key, string Effect, string SourceType,
    string Reason, string? ApprovedBy, DateTimeOffset? ValidFrom, DateTimeOffset? ValidUntil,
    string[] Fields, string[] Actions, JsonElement Scope, string ScopeKind);
