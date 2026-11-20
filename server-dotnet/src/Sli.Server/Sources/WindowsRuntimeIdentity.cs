using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json.Nodes;

namespace Sli.Server.Sources;

internal sealed record WindowsCollectionIdentity(string? Principal, string? Sid, int? SessionId,
    bool Interactive, bool Elevated, string? Error = null);

internal static class WindowsRuntimeIdentity
{
    internal static WindowsCollectionIdentity Current()
    {
        if (!OperatingSystem.IsWindows()) return new(null, null, null, false, false, "windows_required");
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            using var process = Process.GetCurrentProcess();
            int session = process.SessionId;
            return new(identity.Name, identity.User?.Value, session, session != 0,
                new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator));
        }
        catch (Exception error)
        {
            return new(null, null, null, false, false, "identity_probe_failed:" + error.GetType().Name);
        }
    }

    internal static JsonObject Verify(Func<string, string?>? get = null,
        Func<WindowsCollectionIdentity>? probe = null, string? expectedPrincipal = null, string? expectedSid = null)
    {
        get ??= Environment.GetEnvironmentVariable;
        // Explicit protected values are a pair: a missing member must never fall back to process env.
        if (expectedPrincipal is null && expectedSid is null)
        {
            expectedPrincipal = get("ADLOG_COLLECTION_PRINCIPAL");
            expectedSid = get("ADLOG_COLLECTION_PRINCIPAL_SID");
        }
        expectedPrincipal = (expectedPrincipal ?? "").Trim();
        expectedSid = (expectedSid ?? "").Trim();
        var current = (probe ?? Current)();
        var reasons = new JsonArray();
        if (expectedPrincipal.Length == 0) reasons.Add("expected_principal_missing");
        if (expectedSid.Length == 0) reasons.Add("expected_sid_missing");
        if (!current.Interactive) reasons.Add("interactive_session_required");
        if (!string.Equals(current.Principal ?? "", expectedPrincipal, StringComparison.OrdinalIgnoreCase)) reasons.Add("principal_mismatch");
        if (!string.Equals(current.Sid ?? "", expectedSid, StringComparison.OrdinalIgnoreCase)) reasons.Add("sid_mismatch");
        if (!string.IsNullOrEmpty(current.Error)) reasons.Add(current.Error);
        return new()
        {
            ["status"] = reasons.Count == 0 ? "ok" : "failed",
            ["reason"] = reasons.Count == 0 ? null : "windows_collection_identity_invalid",
            ["reasons"] = reasons, ["expected_principal"] = expectedPrincipal, ["expected_sid"] = expectedSid,
            ["current_principal"] = current.Principal, ["current_sid"] = current.Sid,
            ["session_id"] = current.SessionId, ["interactive"] = current.Interactive, ["elevated"] = current.Elevated
        };
    }
}
