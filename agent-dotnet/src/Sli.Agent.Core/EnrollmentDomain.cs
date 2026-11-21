using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace Sli.Agent.Core;

[SupportedOSPlatform("windows")]
internal static class EnrollmentDomain
{
    // The local LSA already holds the DC's domain identity. Enrollment does not
    // need to contact DNS or LDAP to identify its own domain.
    internal static (string Dns, string Forest, string Sid)? Read()
    {
        const uint ViewLocalInformation = 1;
        const int DnsDomainInformation = 12;
        var attributes = new ObjectAttributes { Length = Marshal.SizeOf<ObjectAttributes>() };
        if (LsaOpenPolicy(IntPtr.Zero, ref attributes, ViewLocalInformation, out var policy) != 0) return null;
        try
        {
            if (LsaQueryInformationPolicy(policy, DnsDomainInformation, out var buffer) != 0) return null;
            try
            {
                var domain = Marshal.PtrToStructure<DomainInformation>(buffer);
                if (domain.Sid == IntPtr.Zero || domain.Dns.Length == 0 || domain.Forest.Length == 0) return null;
                return (domain.Dns.Read(), domain.Forest.Read(), new SecurityIdentifier(domain.Sid).Value);
            }
            finally { LsaFreeMemory(buffer); }
        }
        finally { LsaClose(policy); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory, ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length, MaximumLength;
        public IntPtr Buffer;
        public readonly string Read() => Marshal.PtrToStringUni(Buffer, Length / sizeof(char))!;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DomainInformation
    {
        public UnicodeString Name, Dns, Forest;
        public Guid DomainGuid;
        public IntPtr Sid;
    }

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint LsaOpenPolicy(IntPtr system, ref ObjectAttributes attributes, uint access, out IntPtr policy);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint LsaQueryInformationPolicy(IntPtr policy, int informationClass, out IntPtr buffer);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint LsaFreeMemory(IntPtr buffer);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint LsaClose(IntPtr policy);
}
