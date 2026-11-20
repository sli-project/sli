using System.ComponentModel;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Sources;

public sealed record CollectionFailure(bool Blocked, string? Code = null, string? Phase = null)
{
    public string? OperatorAction => !Blocked ? null :
        "Проверьте локальную учётную запись и доступ к настроенному DC. Автоматический повтор отключён; требуется явная контрольная проверка.";
    public JsonObject Fields() => !Blocked ? new() : new() {
        ["failure_code"] = Code, ["failure_scope"] = "worker_identity", ["retryable"] = false,
        ["retry_policy"] = "operator_recovery_required", ["pipeline_disposition"] = "blocked_pre_import",
        ["operator_action"] = OperatorAction
    };
}

// Only allowlisted codes survive the native/credential boundary. No inner exception.
public sealed class CollectionSourceException : Exception
{
    public string Code { get; }
    public int? WinError { get; }
    internal CollectionSourceException(string code, int? winError = null)
        : base(code + (winError is null ? "" : $" winerror {winError}")) { Code = code; WinError = winError; }
}

public static class CollectionFailurePolicy
{
    public static readonly string[] CredentialCodes = [
        "ad_source_backend_unsupported", "ad_source_credential_mode_invalid", "ad_source_credential_profile_invalid",
        "ad_source_credentials_unavailable", "ad_source_endpoint_invalid", "windows_event_log_access_denied",
        "windows_event_log_authentication_failed"
    ];
    private static readonly int[] AuthCodes = [1317,1326,1327,1328,1329,1330,1331,1385,1793,1907,1909];
    internal static int? NativeCode(Exception error) => error switch {
        CollectionSourceException e => e.WinError,
        Win32Exception e => e.NativeErrorCode & 0xffff,
        System.Runtime.InteropServices.COMException e => e.HResult & 0xffff,
        _ => null
    };
    public static CollectionFailure Classify(params object?[] errors)
    {
        var values = errors.Where(x => x is not null).ToArray();
        string normalized = string.Join('\n', values.Select(x => x!.ToString())).ToLowerInvariant();
        var numbers = values.OfType<Exception>().Select(NativeCode).Where(x => x.HasValue).Select(x => x!.Value).ToHashSet();
        foreach (Match match in Regex.Matches(normalized, @"(?:winerror\s+|\(\s*)(\d+)(?=\b)"))
            if (int.TryParse(match.Groups[1].Value, out int n)) numbers.Add(n);
        string? code = CredentialCodes.FirstOrDefault(normalized.Contains);
        if (code is not null || AuthCodes.Any(numbers.Contains)) return new(true, code ?? "windows_event_log_authentication_failed", "source_authentication");
        if (numbers.Contains(1749) || new[] { "windows_security_context_invalid", "неправильный контекст безопасности", "контекст безопасности устарел", "the security context is invalid", "the security context has expired" }.Any(normalized.Contains))
            return new(true, "windows_security_context_invalid", "security_context_invalid");
        return new(false);
    }
    public static CollectionSourceException Sanitize(Exception error)
    {
        int? code = NativeCode(error);
        return new(code == 5 ? "windows_event_log_access_denied" : Classify(error).Code ?? "ad_source_rpc_failed", code);
    }
}
