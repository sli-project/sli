using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed partial class VpnSourceAuthTests
{
    [Fact]
    public void CurrentUserStoreValidatesVpnEnvelopeAndPrivateAcl()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal("vpn_source_windows_required", Assert.Throws<VpnSourceAuthException>(() =>
                VpnSourceAuth.Read(Directory, "dpapi_current_user", () => Directory,
                    () => throw new Exception("secret read"), () => 1)).Message);
            return;
        }
        CheckStore();
    }

    [SupportedOSPlatform("windows")]
    private static void CheckStore()
    {
        const string sid = "S-1-5-21-100000001-200000002-300000003-1001";
        const string purpose = "sli.vpn-source-credentials";
        string json = JsonSerializer.Serialize(new { version = 1, purpose, owner_sid = sid, username = @"EXAMPLE\vpn", password = "fixture" });
        byte[] blob = Protect(json, purpose);
        byte[] clear = VpnSourceCredentialStore.Unprotect(blob);
        try
        {
            var credentials = VpnSourceCredentialStore.Decode(clear, sid);
            Assert.Equal(@"EXAMPLE\vpn", credentials.Username); Assert.Equal("fixture", credentials.Password);
            Assert.DoesNotContain("fixture", credentials.ToString()); Assert.DoesNotContain("EXAMPLE", credentials.ToString());
            Assert.Throws<IOException>(() => VpnSourceCredentialStore.Decode(clear, sid + "0"));
        }
        finally { Array.Clear(clear); }
        Assert.Throws<IOException>(() => VpnSourceCredentialStore.Unprotect(Protect(json, "sli.ad-source-credentials")));
        Assert.Throws<IOException>(() => VpnSourceCredentialStore.Unprotect([1, 2, 3]));
        foreach (string invalid in new[] { json.Replace("\"version\":1", "\"version\":true"), json.Replace(purpose, "sli.ad-source-credentials"),
            json.Replace("\"version\":1", "\"version\":1,\"version\":1"), json.Replace("fixture", ""), json.Replace("EXAMPLE", "bad domain") })
            Assert.ThrowsAny<Exception>(() => VpnSourceCredentialStore.Decode(Encoding.UTF8.GetBytes(invalid), sid));

        var owner = new SecurityIdentifier(sid);
        foreach (bool directory in new[] { false, true })
        {
            string flags = directory ? "OICI" : "";
            string sddl = $"O:{sid}D:P(A;{flags};FA;;;{sid})(A;{flags};FA;;;SY)";
            VpnSourceCredentialStore.VerifyAcl(Descriptor(sddl), owner, directory);
            foreach (string invalid in new[] { sddl.Replace("D:P", "D:"), sddl + "(A;;FR;;;WD)", sddl.Replace(";FA;", ";FR;"),
                sddl.Replace("O:" + sid, "O:SY"), sddl.Replace("(A;", "(D;") })
                Assert.Throws<IOException>(() => VpnSourceCredentialStore.VerifyAcl(Descriptor(invalid), owner, directory));
            Assert.Throws<IOException>(() => VpnSourceCredentialStore.VerifyAcl(Descriptor(sddl), owner, !directory));
        }
        static byte[] Descriptor(string sddl)
        {
            var descriptor = new RawSecurityDescriptor(sddl);
            byte[] bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0); return bytes;
        }
    }

    private static byte[] Protect(string json, string purpose)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json); var pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        var input = new Blob { Size = bytes.Length, Data = pin.AddrOfPinnedObject() }; Blob output = default;
        try
        {
            Assert.True(CryptProtectData(ref input, purpose, 0, 0, 0, 1, out output));
            var result = new byte[output.Size]; Marshal.Copy(output.Data, result, 0, result.Length); return result;
        }
        finally { if (output.Data != 0) LocalFree(output.Data); pin.Free(); Array.Clear(bytes); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Size; public nint Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptProtectData(ref Blob input, string description, nint entropy, nint reserved, nint prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern nint LocalFree(nint memory);
}
