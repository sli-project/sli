using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.Deployment;

internal interface IAdCredentialSecrets
{
    byte[] ReadKey();
}

internal sealed class AdCredentialSecrets : IAdCredentialSecrets
{
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx
    {
        [FieldOffset(16)] public uint Links;
        [FieldOffset(20)] public uint User;
        [FieldOffset(28)] public ushort Mode;
        [FieldOffset(40)] public ulong Size;
    }
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Stat(int fd, string path, int flags, uint mask, out Statx stat);
    [DllImport("libc", EntryPoint = "flistxattr", SetLastError = true)]
    private static extern nint ListAttributes(int fd, byte[]? names, nuint size);
    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint UserId();

    public byte[] ReadKey()
    {
        const string setting = "SLI_AD_CREDENTIALS_MASTER_KEY";
        if (Environment.GetEnvironmentVariable(setting) is not null) throw Error("ad_master_key_plaintext_forbidden");
        string? path = Environment.GetEnvironmentVariable(setting + "_FILE");
        if (string.IsNullOrEmpty(path)) throw Error("ad_master_key_not_configured");
        if (!OperatingSystem.IsLinux()) throw Error("ad_master_key_unavailable");
        try
        {
            // O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC; inspect the pinned inode.
            int fd = Open(path, OpenFlags(RuntimeInformation.ProcessArchitecture));
            if (fd < 0) throw Error("ad_master_key_unavailable");
            using var handle = new SafeFileHandle((nint)fd, ownsHandle: true);
            if (Stat(fd, "", 0x1000, 0x7ff, out var info) != 0) throw Error("ad_master_key_unavailable");
            if ((info.Mode & 0xf000) != 0x8000 || info.Links != 1 || info.User != 0 && info.User != UserId()
                || (info.Mode & 0xfff) is not (0x100 or 0x180) || info.Size != 44)
                throw Error("ad_master_key_unprotected");
            nint size = ListAttributes(fd, null, 0);
            if (size < 0 || size > 65536) throw Error("ad_master_key_unavailable");
            var attributes = new byte[(int)size];
            if (size > 0 && ListAttributes(fd, attributes, (nuint)size) != size) throw Error("ad_master_key_unavailable");
            if (Encoding.UTF8.GetString(attributes).Split('\0').Any(x => x.StartsWith("system.posix_acl_", StringComparison.Ordinal)))
                throw Error("ad_master_key_unprotected");
            using var stream = new FileStream(handle, FileAccess.Read);
            byte[] encoded = new byte[45];
            int read = 0, count;
            while (read < encoded.Length && (count = stream.Read(encoded, read, encoded.Length - read)) > 0) read += count;
            if (read != 44) throw Error("ad_master_key_invalid");
            return Decode(Encoding.ASCII.GetString(encoded, 0, read));
        }
        catch (AgentControlException) { throw; }
        catch { throw Error("ad_master_key_unavailable"); }
    }
    private static AgentControlException Error(string code) => new(code, 409);
    internal static int OpenFlags(Architecture architecture) => (architecture switch
    {
        Architecture.X64 or Architecture.X86 => 0x20000,
        Architecture.Arm64 or Architecture.Arm => 0x8000,
        _ => throw Error("ad_master_key_unavailable")
    }) | 0x800 | 0x80000;
    internal static byte[] Decode(string encoded)
    {
        try
        {
            byte[] key = Convert.FromBase64String(encoded);
            if (key.Length == 32 && Convert.ToBase64String(key) == encoded) return key;
        }
        catch (FormatException) { }
        throw Error("ad_master_key_invalid");
    }
    internal static JsonObject Status(IAdCredentialSecrets secrets)
    {
        try { byte[] key = secrets.ReadKey(); CryptographicOperations.ZeroMemory(key); return new() { ["available"] = true, ["error_code"] = null }; }
        catch (AgentControlException e) { return new() { ["available"] = false, ["error_code"] = e.Message }; }
    }
    internal static JsonObject Encrypt(JsonNode? password, JsonObject context, byte[] key)
    {
        byte[]? clear = null;
        byte[] dek = RandomNumberGenerator.GetBytes(32);
        try
        {
            string? text = AdOperationCredentials.InputText(password);
            if (text is null || text.EnumerateRunes().Count() is < 1 or > 4096 || text.Contains('\0')) throw new AgentControlException("ad_password_invalid");
            try { clear = new UTF8Encoding(false, true).GetBytes(text); }
            catch (EncoderFallbackException) { throw new AgentControlException("ad_password_invalid"); }
            if (key.Length != 32) throw new AgentControlException("ad_master_key_invalid");
            byte[] Aad(string purpose) => CanonicalJson.ToBytes(new JsonObject(context.Select(x => KeyValuePair.Create(x.Key, x.Value?.DeepClone())))
                { ["format_version"] = 1, ["purpose"] = purpose });
            byte[] Seal(byte[] secret, byte[] content, byte[] nonce, byte[] aad)
            {
                byte[] output = new byte[content.Length + 16];
                using var aes = new AesGcm(secret, 16);
                aes.Encrypt(nonce, content, output.AsSpan(0, content.Length), output.AsSpan(content.Length), aad);
                return output;
            }
            byte[] nonce = RandomNumberGenerator.GetBytes(12), wrap = RandomNumberGenerator.GetBytes(12);
            return new() { ["format_version"] = 1, ["key_version"] = 1,
                ["nonce"] = Convert.ToBase64String(nonce), ["wrap_nonce"] = Convert.ToBase64String(wrap),
                ["ciphertext"] = Convert.ToBase64String(Seal(dek, clear, nonce, Aad("password"))),
                ["wrapped_dek"] = Convert.ToBase64String(Seal(key, dek, wrap, Aad("dek").Concat("1"u8.ToArray()).ToArray())) };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(key);
            if (clear is not null) CryptographicOperations.ZeroMemory(clear);
        }
    }
}
