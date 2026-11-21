using System.ComponentModel;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Agent.Windows;

/// <summary>Capture diagnostics contain only fixed reason text, exception classes and numeric error codes.</summary>
internal sealed class SnapshotCaptureException(string code, string detail) : AgentException(code)
{
    public string Detail { get; } = detail;

    public static SnapshotCaptureException FromCollector(string module, JsonNode? diagnostic)
    {
        if (diagnostic is not JsonObject source) return Describe(module, "decode");
        JsonRead.TryString(source["stage"], out var stage);
        JsonRead.TryString(source["exception_class"], out var exceptionClass);
        if (exceptionClass is null || !Regex.IsMatch(exceptionClass, @"\A[A-Za-z][A-Za-z0-9]{0,63}\z"))
            exceptionClass = "Exception";
        return Describe(module, stage, exceptionClass, Number("hresult"), Number("native_error"));

        int? Number(string key) => source[key] is JsonValue value && value.TryGetValue<int>(out var number) ? number : null;
    }

    public static SnapshotCaptureException Describe(string module, string stage, Exception? error = null)
        => Describe(module, stage, error?.GetType().Name, error?.HResult, (error as Win32Exception)?.NativeErrorCode, (error as AgentException)?.Code);

    private static SnapshotCaptureException Describe(string module, string? stage, string? exceptionClass, int? hresult,
        int? nativeError, string? existingCode = null)
    {
        var (prefix, name) = module == SnapshotPolicy.Ad ? ("agent_ad", "AD") : ("agent_gpo", "GPO");
        var (suffix, reason) = stage switch
        {
            "start" => ("capture_start_failed", "Windows PowerShell could not start"),
            "setup" => ("capture_setup_failed", "the Windows collector could not initialize"),
            "ldap_root_dse" => ("ldap_root_dse_failed", "the LDAP RootDSE bind or naming-context read failed"),
            "ldap_domain" => ("ldap_domain_failed", "the LDAP domain object could not be read"),
            "domain_mismatch" => ("domain_mismatch", "the LDAP domain identity differs from the assigned domain"),
            "scope_mismatch" => ("scope_mismatch", "the configured search base is outside the domain naming context"),
            "ldap_inventory" => ("ldap_inventory_failed", "the LDAP inventory could not be read"),
            "serialize" => ("capture_serialize_failed", "the collector result could not be serialized"),
            "process" => ("capture_process_failed", "Windows PowerShell exited before returning a collector result"),
            "decode" => ("capture_invalid", "Windows PowerShell returned an invalid collector result"),
            "normalize" => ("capture_invalid", "the collector result could not be normalized"),
            "freeze" => ("capture_store_failed", "the snapshot could not be saved for delivery"),
            "timeout" => ("capture_timeout", "the snapshot exceeded the configured capture deadline"),
            "size" => ("size_limit", "the snapshot exceeded the configured size limit"),
            _ => ("capture_failed", "the snapshot collector failed")
        };
        var metadata = exceptionClass is null ? "" : $", {exceptionClass}";
        if (hresult is int hr) metadata += $", HResult 0x{hr:X8}";
        if (nativeError is int native) metadata += $", native error {native}";
        return new(existingCode ?? $"{prefix}_{suffix}", $"{name} snapshot capture failed because {reason}{metadata}.");
    }
}
