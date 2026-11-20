using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed partial class SemanticRetainedFactsControlTests
{
    [StructLayout(LayoutKind.Sequential)] private struct TestBlob { internal int Length; internal IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref TestBlob input, string description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out TestBlob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [Fact]
    public void Existing_dpapi_profile_is_decrypted_without_changing_the_file_or_process_credentials()
    {
        using var f = new Fixture(); string path = Path.Combine(f.DirectoryPath, "synthetic-profile.dpapi");
        if (!OperatingSystem.IsWindows()) { Assert.Throws<InvalidOperationException>(() => SemanticRetainedEnvironment.LoadCore(path, true, _ => null, (_, _) => { })); return; }
        Directory.CreateDirectory(f.DirectoryPath);
        byte[] clear = Encoding.UTF8.GetBytes("{\"version\":1,\"environment\":{\"ADLOG_PG_DSN\":\"synthetic-dsn\",\"ADLOG_SEMANTIC_RUNTIME_MODE\":\"investigation-v1\"}}");
        var pinned = GCHandle.Alloc(clear, GCHandleType.Pinned); TestBlob protectedValue = default; byte[] encrypted;
        try {
            var input = new TestBlob { Length = clear.Length, Data = pinned.AddrOfPinnedObject() };
            Assert.True(CryptProtectData(ref input, "Synthetic SLI test profile", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out protectedValue));
            encrypted = new byte[protectedValue.Length]; Marshal.Copy(protectedValue.Data, encrypted, 0, encrypted.Length);
        } finally { if (protectedValue.Data != IntPtr.Zero) LocalFree(protectedValue.Data); pinned.Free(); CryptographicOperations.ZeroMemory(clear); }
        File.WriteAllBytes(path, encrypted); var env = new Dictionary<string, string?>();
        SemanticRetainedEnvironment.LoadCore(path, true, name => env.GetValueOrDefault(name), (name, value) => env[name] = value);
        Assert.Equal("synthetic-dsn", env["ADLOG_PG_DSN"]); Assert.Equal("investigation-v1", env["ADLOG_SEMANTIC_RUNTIME_MODE"]); Assert.Equal(encrypted, File.ReadAllBytes(path));
        File.WriteAllBytes(path, [1, 2, 3]); var error = Assert.Throws<InvalidOperationException>(() => SemanticRetainedEnvironment.LoadCore(path, true, _ => null, (_, _) => throw new InvalidOperationException("must not apply corrupt profile")));
        Assert.Equal("worker supervisor environment decryption failed", error.Message);
    }
}
