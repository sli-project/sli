using System.ComponentModel;
using System.Text.RegularExpressions;

namespace Sli.Server.Legacy;

public sealed record LegacyCollectionFailure(bool Blocked, string? Code = null, string? Phase = null, string? OperatorAction = null);

public static class LegacyCollectionFailurePolicy
{
    public const string SecurityContext = "windows_security_context_invalid";
    internal static readonly string[] CredentialCodes = ["windows_event_log_authentication_failed", "windows_event_log_access_denied",
        "ad_source_credential_mode_invalid", "ad_source_backend_unsupported", "ad_source_credential_profile_invalid",
        "ad_source_endpoint_invalid", "ad_source_credentials_unavailable"];
    private static readonly int[] AuthErrors = [1317,1326,1327,1328,1329,1330,1331,1385,1793,1907,1909];
    public static LegacyCollectionFailure Classify(IEnumerable<object?> errors)
    {
        var values = errors.Where(x => x is not null).ToArray();
        string text = string.Join('\n', values.Select(x => x is Exception e ? e.Message : x!.ToString())).ToLowerInvariant();
        var codes = values.OfType<Exception>().Select(e => (e is Win32Exception w ? w.NativeErrorCode : e.HResult) & 0xffff).ToHashSet();
        foreach (Match match in Regex.Matches(text, @"(?:winerror\s+|\(\s*)(\d+)(?=\b)"))
            if (int.TryParse(match.Groups[1].Value, out int code)) codes.Add(code);
        string? credential = CredentialCodes.Order(StringComparer.Ordinal).FirstOrDefault(text.Contains);
        if (credential is not null || AuthErrors.Any(codes.Contains))
            return new(true, credential ?? "windows_event_log_authentication_failed", "source_authentication",
                "Исправьте локальный AD credential/режим и доступ к настроенному DC; выполните явную контрольную проверку collection_block_control. Автоматический повтор отключён.");
        string[] markers = [SecurityContext, "winerror 1749", "(1749, 'evtopensession'", "(1749, \"evtopensession\"",
            "неправильный контекст безопасности", "контекст безопасности устарел", "the security context is invalid", "the security context has expired"];
        return codes.Contains(1749) || markers.Any(text.Contains)
            ? new(true, SecurityContext, "security_context_invalid", "Перезапустите процесс сбора в подтверждённой интерактивной Windows-сессии и проверьте учётные данные/доступ EvtOpenSession. Автоматический повтор отключён.")
            : new(false);
    }

    // Called before publishing any part of a batch or advancing a source cursor.
    public static void RequireImportAllowed(IEnumerable<object?> errors)
    {
        var decision = Classify(errors);
        if (decision.Blocked) throw new InvalidOperationException(decision.Code);
    }
}
