using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;

namespace Sli.Server.InstallationSetup;

public static class PostgresBootstrapCredentials
{
    public const string AdminPurpose = "sli-existing-postgres-admin-v1";
    public const string OwnerPurpose = "sli-platform-owner-password-v1";
    public const string RuntimePurpose = "sli-local-postgres-18-profile-v1";
    public static string CredentialRoot(string root) => Path.Combine(root, "data/runtime/local-postgres-admin");
    public static string CredentialPath(string root, bool owner) => Path.Combine(CredentialRoot(root), owner ? "platform-owner.dpapi.json" : "postgres-admin.dpapi.json");
    private static string Prefix(bool owner) => owner ? "platform_owner_credential" : "admin_credential";

    public static void WriteJson(string path, JsonObject value, bool mustBeNew = false)
    {
        string temporary = Path.Combine(Path.GetDirectoryName(path)!, "." + Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                byte[] bytes = Encoding.UTF8.GetBytes(PostgresBootstrap.Canonical(value) + "\n");
                stream.Write(bytes); stream.Flush(true);
            }
            File.Move(temporary, path, !mustBeNew);
        }
        catch (IOException) when (mustBeNew && Path.Exists(path)) { throw new BootstrapException("target_exists"); }
        catch { throw new BootstrapException("receipt_write_failed"); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public static string WriteCredential(string path, string password, string sid, Func<string, string> protect, bool owner = false)
    {
        string prefix = Prefix(owner);
        if (Path.Exists(path)) throw new BootstrapException(prefix + "_exists");
        ValidatePassword(password, owner);
        string sealedValue = protect(password);
        if (string.IsNullOrEmpty(sealedValue)) throw new BootstrapException(prefix + "_protection_failed");
        var envelope = Metadata(sid, owner); envelope["payload"] = sealedValue;
        try { WriteJson(path, envelope, true); }
        catch (BootstrapException ex) when (ex.Message == "target_exists") { throw new BootstrapException(prefix + "_exists"); }
        return path;
    }

    private static JsonObject Metadata(string sid, bool owner) => new() {
        ["credential_version"] = 1, ["identity_sid"] = sid,
        ["kind"] = owner ? "sli-platform-owner" : "postgresql-administrator",
        ["protection"] = "windows-dpapi-current-user", ["purpose"] = owner ? OwnerPurpose : AdminPurpose,
        ["role"] = owner ? "platform-owner" : "postgres" };

    private static void ValidatePassword(string password, bool owner)
    {
        if (owner) PostgresBootstrap.ValidateOwnerPassword(password);
        else if (string.IsNullOrEmpty(password) || password.EnumerateRunes().Count() > 4096 || password.Contains('\0')) throw new BootstrapException("postgres_admin_password_invalid");
    }

    public static string ReadCredential(string path, string sid, Func<string, string> unprotect, bool owner = false)
    {
        string prefix = Prefix(owner); JsonObject value;
        try { value = JsonNode.Parse(File.ReadAllText(path))!.AsObject(); }
        catch { throw new BootstrapException(prefix + "_unavailable"); }
        var expected = Metadata(sid, owner);
        if (!owner && (value.Count != 7 || expected.Any(p => !value.ContainsKey(p.Key)) || !value.ContainsKey("payload"))) throw new BootstrapException(prefix + "_invalid");
        if (!JsonNode.DeepEquals(value["identity_sid"], expected["identity_sid"])) throw new BootstrapException(prefix + "_owner_mismatch");
        if (value.Count != 7 || expected.Any(p => !JsonNode.DeepEquals(p.Value, value[p.Key]))
            || value["payload"] is not JsonValue payload || !payload.TryGetValue<string>(out var sealedValue) || sealedValue.Length == 0)
            throw new BootstrapException(prefix + "_invalid");
        string password;
        try { password = unprotect(sealedValue); }
        catch { throw new BootstrapException(prefix + "_decryption_failed"); }
        try { ValidatePassword(password, owner); }
        catch { throw new BootstrapException(prefix + "_invalid"); }
        return password;
    }

    public static string WriteRuntimeCandidate(string directory, string database, string host, int port, string password, string sid, Func<string, string> protect)
    {
        if (Path.Exists(directory)) {
            if (!Directory.Exists(directory) || Directory.EnumerateFileSystemEntries(directory).Any()) throw new BootstrapException("profile_target_exists");
        } else Directory.CreateDirectory(directory);
        string dsn = $"postgresql://adlog_user:{Uri.EscapeDataString(password)}@{host}:{port}/{database}";
        string path = Path.Combine(directory, "runtime.candidate.json");
        WriteJson(path, new JsonObject { ["active"] = false, ["candidate_version"] = 1, ["identity_sid"] = sid,
            ["kind"] = "runtime", ["payload"] = protect(dsn), ["protection"] = "windows-dpapi-current-user", ["role"] = "adlog_user" }, true);
        return path;
    }

    public static string IdentitySid()
    {
        if (!OperatingSystem.IsWindows()) throw new BootstrapException("windows_dpapi_required");
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? throw new BootstrapException("invalid_identity");
    }

    private static bool HasReparsePoint(string path)
    {
        for (var item = new DirectoryInfo(Path.GetFullPath(path)); item is not null; item = item.Parent)
            if (item.Exists && (item.Attributes & FileAttributes.ReparsePoint) != 0) return true;
        return false;
    }

    [SupportedOSPlatform("windows")]
    public static void CreatePrivateDirectory(string path, string sid)
    {
        if (Path.Exists(path)) throw new BootstrapException("target_exists");
        if (HasReparsePoint(path)) throw new BootstrapException("unsafe_reparse_point");
        // Create with the protected DACL, before any credential can be written.
        var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false);
        foreach (string identity in new[] { sid, "S-1-5-18" }) security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(identity),
            FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        new DirectoryInfo(path).Create(security);
    }

    [SupportedOSPlatform("windows")]
    public static bool VerifyPrivateDirectory(string path, string sid)
    {
        if (!Directory.Exists(path) || HasReparsePoint(path)) return false;
        var acl = new DirectoryInfo(path).GetAccessControl();
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        return acl.AreAccessRulesProtected && rules.Length == 2 && rules.Select(r => r.IdentityReference.Value).ToHashSet().SetEquals([sid, "S-1-5-18"])
            && rules.All(r => !r.IsInherited && r.AccessControlType == AccessControlType.Allow && r.FileSystemRights == FileSystemRights.FullControl
                && r.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) && r.PropagationFlags == PropagationFlags.None);
    }

    public static string Save(string root, string password, bool owner)
    {
        if (!OperatingSystem.IsWindows()) throw new BootstrapException("windows_dpapi_required");
        string sid = IdentitySid(), directory = CredentialRoot(root);
        if (!owner && !Path.Exists(directory)) CreatePrivateDirectory(directory, sid);
        if (!VerifyPrivateDirectory(directory, sid)) throw new BootstrapException(Prefix(owner) + "_acl_invalid");
        return WriteCredential(CredentialPath(root, owner), password, sid, value => Protect(value, owner ? OwnerPurpose : AdminPurpose), owner);
    }
    public static string Load(string root, bool owner)
    {
        if (!OperatingSystem.IsWindows()) throw new BootstrapException("windows_dpapi_required");
        string sid = IdentitySid();
        if (!VerifyPrivateDirectory(CredentialRoot(root), sid)) throw new BootstrapException(Prefix(owner) + "_acl_invalid");
        return ReadCredential(CredentialPath(root, owner), sid, value => Unprotect(value, owner ? OwnerPurpose : AdminPurpose), owner);
    }

    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptProtectData(ref Blob data, string? description, ref Blob entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptUnprotectData(ref Blob data, out IntPtr description, ref Blob entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);

    private static Blob Allocate(byte[] bytes)
    {
        var blob = new Blob { Length = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) }; Marshal.Copy(bytes, 0, blob.Data, bytes.Length); return blob;
    }
    private static void Free(Blob blob, bool local = false)
    {
        if (blob.Data == IntPtr.Zero) return;
        for (int i = 0; i < blob.Length; i++) Marshal.WriteByte(blob.Data, i, 0);
        if (local) LocalFree(blob.Data); else Marshal.FreeHGlobal(blob.Data);
    }
    public static string Protect(string plaintext, string purpose)
    {
        if (!OperatingSystem.IsWindows()) throw new BootstrapException("windows_dpapi_required");
        byte[] clear = Encoding.UTF8.GetBytes(plaintext); var input = Allocate(clear); CryptographicOperations.ZeroMemory(clear);
        var entropy = Allocate(Encoding.UTF8.GetBytes(purpose)); Blob output = default;
        try {
            if (!CryptProtectData(ref input, purpose == RuntimePurpose ? null : purpose, ref entropy, IntPtr.Zero, IntPtr.Zero, 1, out output)) throw new CryptographicException();
            var bytes = new byte[output.Length]; Marshal.Copy(output.Data, bytes, 0, bytes.Length); return Convert.ToBase64String(bytes);
        }
        catch { throw new BootstrapException(purpose == OwnerPurpose ? "platform_owner_credential_protection_failed" : purpose == RuntimePurpose ? "dpapi_protection_failed" : "admin_credential_protection_failed"); }
        finally { Free(input); Free(entropy); Free(output, true); }
    }
    public static string Unprotect(string payload, string purpose)
    {
        if (!OperatingSystem.IsWindows()) throw new BootstrapException("windows_dpapi_required");
        Blob input = default, entropy = default, output = default; IntPtr description = IntPtr.Zero;
        try {
            input = Allocate(Convert.FromBase64String(payload)); entropy = Allocate(Encoding.UTF8.GetBytes(purpose));
            if (!CryptUnprotectData(ref input, out description, ref entropy, IntPtr.Zero, IntPtr.Zero, 1, out output)) throw new CryptographicException();
            if (purpose != RuntimePurpose && Marshal.PtrToStringUni(description) != purpose) throw new BootstrapException(Prefix(purpose == OwnerPurpose) + "_invalid");
            var bytes = new byte[output.Length]; Marshal.Copy(output.Data, bytes, 0, bytes.Length);
            try { return new UTF8Encoding(false, true).GetString(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        catch (BootstrapException) { throw; }
        catch { throw new BootstrapException(Prefix(purpose == OwnerPurpose) + "_decryption_failed"); }
        finally { Free(input); Free(entropy); Free(output, true); if (description != IntPtr.Zero) LocalFree(description); }
    }
}
