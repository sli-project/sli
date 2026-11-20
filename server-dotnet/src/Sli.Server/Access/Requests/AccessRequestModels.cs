using System.Numerics;
using System.Text.Json;
using Npgsql;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;

namespace Sli.Server.Access.Requests;

public sealed class AccessRequestException(string code, int status = 400) : Exception(code)
{
    public int Status { get; } = status;
}

public sealed record RequestAccessView(CapabilityDecisionSet Capabilities, IReadOnlyList<JsonElement> Reports);
public interface IAccessRequestEvaluator
{
    Task<RequestAccessView> EvaluateAsync(Principal principal, CancellationToken ct);
    Task<JsonElement> PreviewReportAsync(long userId, string reportKey, CancellationToken ct);
}

public sealed record AccessRequestAuditEvent(AssignmentActor Actor, string Action, long UserId, string ReportKey,
    string? Reason, object Details, string? RemoteAddress);
public interface IAccessRequestAudit
{
    Task AppendAsync(NpgsqlTransaction transaction, AccessRequestAuditEvent entry, CancellationToken ct);
}

public interface IAccessRequestService
{
    Task<JsonElement> CreateAsync(JsonElement payload, Principal actor, string? remoteAddress, CancellationToken ct);
    Task<JsonElement> ListAsync(Principal actor, bool includeAll, BigInteger limit, CancellationToken ct);
    Task<JsonElement> DecideAsync(BigInteger requestId, JsonElement payload, Principal actor, string? remoteAddress, CancellationToken ct);
    Task<JsonElement> SetPreferenceAsync(string reportKey, JsonElement payload, Principal actor, string? remoteAddress, CancellationToken ct);
}

public sealed class AccessRequestEvaluator(AccessReadService access) : IAccessRequestEvaluator
{
    public async Task<RequestAccessView> EvaluateAsync(Principal principal, CancellationToken ct)
    {
        var loaded = await access.LoadAsync(principal, ct);
        var full = JsonSerializer.SerializeToElement(AccessReadProjection.Compose(principal, loaded.Facts, loaded.Capabilities, loaded.Reports, false));
        return new(loaded.Capabilities, full.Get("reports").Items().Select(r => r.Clone()).ToArray());
    }

    public async Task<JsonElement> PreviewReportAsync(long userId, string reportKey, CancellationToken ct)
    {
        var principal = await access.FindUserAsync(userId, ct) ?? throw new AccessRequestException("access_subject_not_found");
        var view = await EvaluateAsync(principal, ct);
        var report = view.Reports.FirstOrDefault(r => r.Text("report_key") == reportKey);
        return report.ValueKind == JsonValueKind.Undefined ? JsonSerializer.SerializeToElement(new { }) : RequestJson.RawReport(report);
    }
}

public sealed class AccessRequestAudit : IAccessRequestAudit
{
    public Task AppendAsync(NpgsqlTransaction transaction, AccessRequestAuditEvent entry, CancellationToken ct) =>
        AssignmentAudit.AppendEventAsync(transaction, entry.Actor, entry.Action, "user", entry.UserId,
            "report", entry.ReportKey, entry.Reason, entry.Details, entry.RemoteAddress, ct);
}
