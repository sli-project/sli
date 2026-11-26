using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Agent.Windows;

internal sealed class FileAuditNativeReadException(string code, uint nativeStatus) : AgentException(code)
{
    internal uint NativeStatus { get; } = nativeStatus;

    internal static string Reason(string stage, Exception error)
    {
        var step = (error as AgentException)?.Message switch
        {
            "file_audit_share_root_mismatch" => "share_path_mismatch",
            "file_audit_group_sid_unresolved" or "file_audit_group_domain_unavailable" => "local_group_identity_unavailable",
            "file_audit_group_members_unavailable" => "local_group_members_unavailable",
            "file_audit_groups_unavailable" => "local_groups_unavailable",
            "file_audit_security_log_unavailable" => "security_log_unavailable",
            "file_audit_path_unavailable" => "directory_open_unavailable",
            "file_audit_descriptor_unavailable" or "file_audit_descriptor_invalid" when stage != "share" => "acl_read_unavailable",
            "file_audit_reparse_point" => "directory_reparse_point",
            "file_audit_root_invalid" => "directory_root_invalid",
            "agent_audit_privilege_unavailable" => NativeCode(error) is 1300 or 1314 ? "security_privilege_missing" : "security_privilege_unavailable",
            "global_sacl_unknown" => "global_sacl_unknown",
            "file_audit_sacl_plan_failed" => "sacl_plan_failed",
            "file_audit_sacl_write_failed" => "sacl_write_failed",
            "file_audit_readback_failed" => "sacl_readback_failed",
            "file_audit_snapshot_limit" => "inventory_limit",
            _ => stage switch
            {
                "audit_policy" => "audit_policy_read_unavailable",
                "share" => "share_read_unavailable",
                "local_groups" => "local_groups_unavailable",
                "directory" => "directory_read_unavailable",
                "acl" => "acl_read_unavailable",
                _ => "inventory_unavailable"
            }
        };
        return NativeCode(error) is > 0 and var code ? step + ":" + code.ToString(CultureInfo.InvariantCulture) : step;
    }

    private static uint NativeCode(Exception error) => error switch
    {
        FileAuditNativeReadException native => native.NativeStatus,
        Win32Exception windows when windows.NativeErrorCode > 0 => (uint)windows.NativeErrorCode,
        _ when (unchecked((uint)error.HResult) & 0xFFFF0000u) == 0x80070000u => unchecked((uint)error.HResult) & 0xFFFFu,
        _ => 0
    };

    internal static FileAuditReadError Describe(string stage, Exception error) => error switch
    {
        FileAuditNativeReadException native when native.NativeStatus != 0 => new(stage, "win32", native.NativeStatus),
        Win32Exception windows when windows.NativeErrorCode > 0 => new(stage, "win32", (uint)windows.NativeErrorCode),
        COMException or UnauthorizedAccessException => new(stage, "hresult", unchecked((uint)error.HResult)),
        _ => new(stage)
    };
}
