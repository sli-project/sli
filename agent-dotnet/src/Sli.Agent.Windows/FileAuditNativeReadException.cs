using System.ComponentModel;
using System.Runtime.InteropServices;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Agent.Windows;

internal sealed class FileAuditNativeReadException(string code, uint nativeStatus) : AgentException(code)
{
    internal uint NativeStatus { get; } = nativeStatus;

    internal static FileAuditReadError Describe(string stage, Exception error) => error switch
    {
        FileAuditNativeReadException native when native.NativeStatus != 0 => new(stage, "win32", native.NativeStatus),
        Win32Exception windows when windows.NativeErrorCode > 0 => new(stage, "win32", (uint)windows.NativeErrorCode),
        COMException or UnauthorizedAccessException => new(stage, "hresult", unchecked((uint)error.HResult)),
        _ => new(stage)
    };
}
