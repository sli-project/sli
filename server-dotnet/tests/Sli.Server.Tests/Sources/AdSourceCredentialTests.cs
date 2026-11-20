using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Sources;
using Xunit;

namespace Sli.Server.Tests.Sources;

public sealed partial class AdSourceCredentialTests
{
    [SupportedOSPlatformGuard("windows")]
    public static bool IsWindows => OperatingSystem.IsWindows();
    private const string Username = "Exact.Test@example.test", Password = " synthetic-disposable-пароль-🔐 ";
    private const string Purpose = "sli.ad-source-credentials";
    private const string SyntheticSid = "S-1-5-21-100000001-200000002-300000003-444";

    private sealed class Fixture : IDisposable
    {
        internal readonly string Parent = Path.Combine(Path.GetTempPath(), "sli-source-credentials-" + Guid.NewGuid().ToString("N"));
        internal string Root => Path.Combine(Parent, "store");
        internal string Blob => Path.Combine(Root, AdSourceCredentials.BlobName);
        internal readonly AdSourceCredentialWindows Windows;
        internal readonly AdSourceCredentials Store;
        internal Fixture(AdSourceCredentialWindows? windows = null)
        {
            Directory.CreateDirectory(Parent); Directory.CreateDirectory(Path.Combine(Parent, "runtime"));
            Windows = windows ?? new(); Store = new(Parent, Windows);
        }
        internal void Provision() => Store.Store(Username, Password, Root);
        public void Dispose() => Directory.Delete(Parent, recursive: true);
    }

    private static void Error(string code, Action action) => Assert.Equal(code, Assert.Throws<AdCredentialStoreException>(action).Message);
    private static void Safe(string output) { Assert.DoesNotContain(Password, output); Assert.DoesNotContain(Username, output); }
    private static string Code(JsonObject value) => value["error_code"]!.GetValue<string>();

    // DPAPI/NTFS have no Linux equivalent: exercise the fail-closed contract there.
    // The same cases execute the real native operations on Windows, with no test skips.
    [SupportedOSPlatformGuard("windows")]
    private static bool WindowsAvailable()
    {
        if (IsWindows) return true;
        using var f = new Fixture();
        Error("windows_required", () => f.Store.Store(Username, Password, f.Root));
        Error("windows_required", () => f.Store.Load(f.Root));
        Assert.Equal("windows_required", Code(f.Store.Status(root: f.Root)));
        Assert.False(Directory.Exists(f.Root));
        return false;
    }

    public static TheoryData<object?> InvalidUsernames => new()
    {
        "", "SYNTHETIC", "SYNTHETIC\\", "\\test", "a@", "@example.test", "SYNTHETIC\\two words", " test@example.test",
        "test@example.test\n", "SYNTHETIC\\test\\extra", "a@@example.test", "SYNTHETIC\\a@b", "SYNTHETIC/test",
        "a\0b@example.test", "a\u200bb@example.test", (object?)null, 7, new string('x', 1025) + "@example.test",
        "a/ b@example.test", "a\ud800@example.test", "a\ue000@example.test", ".@example.test", "test@..", Array.Empty<string>()
    };

    [Theory]
    [MemberData(nameof(InvalidUsernames))]
    public void Malformed_username_fails_before_any_write(object? username)
    {
        using var f = new Fixture();
        Error("invalid_username", () => f.Store.Store(username, Password, f.Root));
        Assert.False(Directory.Exists(f.Root));
        Assert.Equal("invalid_username", Code(f.Store.Status(username ?? 7, f.Root)));
    }

    public static TheoryData<object?> InvalidPasswords => new() { "", (object?)null, 7, "a\0b", "a\ud800b", new string('x', 4097) };

    [Theory]
    [MemberData(nameof(InvalidPasswords))]
    public void Invalid_password_fails_before_any_write(object? password)
    {
        using var f = new Fixture();
        Error("invalid_password", () => f.Store.Store(Username, password, f.Root));
        Assert.False(Directory.Exists(f.Root));
    }

    [Theory]
    [InlineData("SYNTHETIC.example.test\\Exact.User")]
    [InlineData("Exact.User@example.test")]
    public void Username_validator_preserves_input(string username) => Assert.Equal(username, AdSourceCredentials.ValidateUsername(username));

    [Theory]
    [InlineData("VPN")]
    [InlineData("other")]
    [InlineData("../ad")]
    [InlineData(null)]
    public void Invalid_profile_fails_closed_before_storage(string? profile)
    {
        using var f = new Fixture();
        Error("invalid_argument", () => f.Store.Store(Username, Password, f.Root, profile: profile));
        Error("invalid_argument", () => f.Store.Load(f.Root, profile));
        Assert.Equal("invalid_argument", Code(f.Store.Status(root: f.Root, profile: profile)));
        Assert.False(Directory.Exists(f.Root));
    }

    private static byte[] Payload(string sid = SyntheticSid) => Encoding.UTF8.GetBytes(new JsonObject
    {
        ["version"] = 1, ["purpose"] = Purpose, ["owner_sid"] = sid, ["username"] = Username, ["password"] = Password
    }.ToJsonString());

    internal static byte[] MutatedPayload(string mutation, string sid)
    {
        var value = JsonNode.Parse(Payload(sid))!.AsObject();
        switch (mutation)
        {
            case "list": return "[]"u8.ToArray();
            case "version_bool": value["version"] = true; break;
            case "version_wrong": value["version"] = 2; break;
            case "version_float": return Encoding.UTF8.GetBytes(value.ToJsonString().Replace("\"version\":1", "\"version\":1.0"));
            case "purpose_wrong": value["purpose"] = "unrelated-payload"; break;
            case "owner_wrong": value["owner_sid"] = SyntheticSid; break;
            case "owner_type": value["owner_sid"] = 1; break;
            case "username_type": value["username"] = new JsonArray(); break;
            case "password_type": value["password"] = 7; break;
            case "password_empty": value["password"] = ""; break;
            case "username_bare": value["username"] = "SYNTHETIC\\"; break;
            case "extra": value["extra"] = true; break;
            case "missing": value.Remove("username"); break;
            case "duplicate": return Encoding.UTF8.GetBytes(value.ToJsonString()[..^1] + ",\"version\":1}");
            case "invalid_json": return "{broken"u8.ToArray();
            case "invalid_utf8": return [0xff];
            case "invalid_utf8_string":
                byte[] bytes = Payload(sid); bytes[Array.IndexOf(bytes, (byte)'E')] = 0xff; return bytes;
            case "oversized_clear": return new byte[AdSourceCredentials.MaxClearBytes + 1];
        }
        return Encoding.UTF8.GetBytes(value.ToJsonString());
    }

    public static TheoryData<string> EnvelopeMutations => new()
    {
        "list", "version_bool", "version_wrong", "version_float", "purpose_wrong", "owner_wrong", "owner_type", "username_type",
        "password_type", "password_empty", "username_bare", "extra", "missing", "duplicate", "invalid_json", "invalid_utf8", "invalid_utf8_string", "oversized_clear"
    };

    [Theory]
    [MemberData(nameof(EnvelopeMutations))]
    public void Envelope_is_strict_and_bound(string mutation)
    {
        string owner = SyntheticSid + "0";
        Error(mutation == "owner_wrong" ? "owner_mismatch" : "invalid_payload",
            () => AdSourceCredentials.Decode(MutatedPayload(mutation, owner), Purpose, Purpose, owner));
    }

    [Fact]
    public void Unknown_errors_are_sanitized_and_nonwindows_fails_closed()
    {
        Assert.Equal(1u, AdSourceCredentialWindows.DpapiFlags);
        Assert.Equal("storage_failed", new AdCredentialStoreException(Password).Message);
        var loaded = AdSourceCredentials.Decode(Payload(), Purpose, Purpose, SyntheticSid);
        Assert.Equal(Username, loaded.Username); Assert.Equal(Password, loaded.Password); Safe(loaded.ToString());
        Error("invalid_payload", () => AdSourceCredentials.Decode(Payload(), "other", Purpose, SyntheticSid));
        if (!IsWindows)
        {
            using var f = new Fixture();
            Assert.Equal("windows_required", Code(f.Store.Status(root: f.Root)));
            Error("windows_required", () => f.Store.Store(Username, Password, f.Root));
            Assert.False(Directory.Exists(f.Root));
        }
    }

    [Fact]
    public void Exact_input_boundaries_accept_unicode_without_envelope_expansion()
    {
        string username = new string('x', 1024 - "@example.test".Length) + "@example.test";
        string password = string.Concat(Enumerable.Repeat("🔐", 4096));
        Assert.Equal(username, AdSourceCredentials.ValidateUsername(username));
        Assert.Equal(password, AdSourceCredentials.ValidatePassword(password));
        Error("invalid_password", () => AdSourceCredentials.ValidatePassword(password + "🔐"));
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); f.Store.Store(username, password, f.Root);
        Assert.Equal(username, f.Store.Load(f.Root).Username); Assert.Equal(password, f.Store.Load(f.Root).Password);
    }

    [Fact]
    public void Current_user_roundtrip_is_exact_encrypted_private_and_missing_is_readonly()
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture();
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"status":"missing","dpapi_scope":"CurrentUser","owner_matches":null,"account_matches":null,"error_code":"missing","credential_values_exposed":false}"""), f.Store.Status(root: f.Root)));
        Assert.False(Directory.Exists(f.Root));
        var result = f.Store.Store(Username, Password, f.Root);
        var loaded = f.Store.Load(f.Root);
        Assert.Equal(Username, loaded.Username); Assert.Equal(Password, loaded.Password); Safe(loaded.ToString());
        Assert.Equal("ready", result["status"]!.GetValue<string>()); Safe(result.ToJsonString());
        var status = f.Store.Status(Username, f.Root); Safe(status.ToJsonString());
        Assert.True(status["owner_matches"]!.GetValue<bool>()); Assert.True(status["account_matches"]!.GetValue<bool>());
        Assert.False(f.Store.Status("exact.test@example.test", f.Root)["account_matches"]!.GetValue<bool>());
        Assert.Null(f.Store.Status(root: f.Root)["account_matches"]);
        Assert.Single(Directory.GetFiles(f.Root));
        byte[] blob = File.ReadAllBytes(f.Blob);
        Assert.False(blob.AsSpan().IndexOf(Encoding.UTF8.GetBytes(Username)) >= 0);
        Assert.False(blob.AsSpan().IndexOf(Encoding.UTF8.GetBytes(Password)) >= 0);
        AssertAcl(f.Root, true); AssertAcl(f.Blob, false);
    }

    private static void AssertAcl(string path, bool directory)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        FileSystemSecurity security = directory ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
        using var identity = WindowsIdentity.GetCurrent();
        Assert.Equal(identity.User, security.GetOwner(typeof(SecurityIdentifier)));
        Assert.True(security.AreAccessRulesProtected);
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        var expected = new HashSet<string> { identity.User!.Value, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value };
        Assert.Equal(expected.Count, rules.Length);
        var actual = new HashSet<string>();
        foreach (var rule in rules)
        {
            actual.Add(rule.IdentityReference.Value);
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType); Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights);
            Assert.Equal(directory ? InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit : InheritanceFlags.None, rule.InheritanceFlags);
            Assert.Equal(PropagationFlags.None, rule.PropagationFlags); Assert.False(rule.IsInherited);
        }
        Assert.True(expected.SetEquals(actual));
    }

    [Fact]
    public void Profiles_have_separate_default_stores_and_bound_envelopes()
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture();
        f.Store.Store(Username, Password);
        string ad = Path.Combine(f.Parent, "runtime", "ad-source-credentials", AdSourceCredentials.BlobName);
        byte[] before = File.ReadAllBytes(ad);
        f.Store.Store("vpn@example.test", "synthetic-vpn", profile: "vpn");
        Assert.Equal(Username, f.Store.Load().Username); Assert.Equal("vpn@example.test", f.Store.Load(profile: "vpn").Username);
        Assert.True(f.Store.Status("vpn@example.test", profile: "vpn")["account_matches"]!.GetValue<bool>());
        f.Store.Store("vpn@example.test", "synthetic-replaced", replace: true, profile: "vpn");
        Assert.Equal(before, File.ReadAllBytes(ad));
        string vpn = Path.Combine(f.Parent, "runtime", "vpn-source-credentials");
        Assert.Equal("invalid_payload", Code(f.Store.Status(root: vpn)));
        Assert.Equal("invalid_payload", Code(f.Store.Status(root: Path.GetDirectoryName(ad), profile: "vpn")));
        AssertAcl(vpn, true); AssertAcl(Path.Combine(vpn, AdSourceCredentials.BlobName), false);
    }

    [Theory]
    [MemberData(nameof(EnvelopeMutations))]
    public void Encrypted_mutations_are_unreadable_with_safe_metadata(string mutation)
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); f.Provision();
        File.WriteAllBytes(f.Blob, f.Windows.Protect(MutatedPayload(mutation, f.Windows.CurrentSid()), Purpose));
        string code = mutation == "owner_wrong" ? "owner_mismatch" : "invalid_payload";
        Error(code, () => f.Store.Load(f.Root));
        var status = f.Store.Status(Username, f.Root);
        Assert.Equal("unreadable", status["status"]!.GetValue<string>()); Assert.Equal(code, Code(status)); Safe(status.ToJsonString());
        if (mutation == "owner_wrong") Assert.False(status["owner_matches"]!.GetValue<bool>());
    }

    [Fact]
    public void Refuses_overwrite_and_explicit_replacement_is_verified()
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); f.Provision(); byte[] before = File.ReadAllBytes(f.Blob);
        Error("already_exists", () => f.Store.Store("changed@example.test", "synthetic-new", f.Root));
        Assert.Equal(before, File.ReadAllBytes(f.Blob)); Assert.Equal(Password, f.Store.Load(f.Root).Password);
        Assert.Equal("ready", f.Store.Store("changed@example.test", "synthetic-new", f.Root, replace: true)["status"]!.GetValue<string>());
        Assert.Equal("synthetic-new", f.Store.Load(f.Root).Password); Assert.Single(Directory.GetFileSystemEntries(f.Root)); AssertAcl(f.Blob, false);
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("truncated")]
    [InlineData("corrupt")]
    [InlineData("oversized")]
    public void Ciphertext_corruption_is_unreadable(string corruption)
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); f.Provision(); byte[] blob = File.ReadAllBytes(f.Blob);
        if (corruption == "empty") blob = [];
        else if (corruption == "truncated") blob = blob[..16];
        else if (corruption == "corrupt") blob[^1] ^= 0x80;
        else blob = new byte[AdSourceCredentials.MaxBlobBytes + 1];
        File.WriteAllBytes(f.Blob, blob);
        string code = corruption is "empty" or "oversized" ? "invalid_size" : "dpapi_failed";
        Assert.Equal(code, Code(f.Store.Status(root: f.Root))); Error(code, () => f.Store.Load(f.Root));
    }

    private sealed class Faults : AdSourceCredentialWindows
    {
        internal bool FailMove, FailProtect, FailUnprotect, WrongReadback, Remote;
        internal string? Owner;
        internal readonly List<string> Calls = [];
        internal override string CurrentSid() => Owner ?? base.CurrentSid();
        internal override uint DriveType(string root) { Calls.Add("drive"); return Remote ? 4u : base.DriveType(root); }
        internal override byte[] Protect(byte[] clear, string purpose) { Calls.Add("protect"); if (FailProtect) throw new Exception(Password); return base.Protect(clear, purpose); }
        internal override (byte[] Clear, string Description) Unprotect(byte[] blob)
        {
            Calls.Add("unprotect"); if (FailUnprotect) throw new Exception(Password);
            return WrongReadback ? (Payload(base.CurrentSid()), Purpose) : base.Unprotect(blob);
        }
        internal override void Move(string source, string destination, bool replace) { if (FailMove) throw new IOException(Password); base.Move(source, destination, replace); }
    }

    [Fact]
    public void Dpapi_failures_are_sanitized_and_interrupted_replace_preserves_old_blob()
    {
        if (!WindowsAvailable()) return;
        var windows = new Faults(); using var f = new Fixture(windows); f.Provision(); f.Store.Load(f.Root);
        Assert.Equal(1, windows.Calls.Count(c => c == "protect")); Assert.Equal(2, windows.Calls.Count(c => c == "unprotect"));
        windows.FailUnprotect = true;
        Assert.Equal("dpapi_failed", Code(f.Store.Status(root: f.Root)));
        var exception = Assert.Throws<AdCredentialStoreException>(() => f.Store.Load(f.Root));
        Assert.Null(exception.InnerException); Assert.DoesNotContain(Password, exception.ToString());
        windows.FailUnprotect = false; windows.FailMove = true;
        byte[] before = File.ReadAllBytes(f.Blob);
        Error("storage_failed", () => f.Store.Store(Username, "synthetic-replacement", f.Root, replace: true));
        Assert.Equal(before, File.ReadAllBytes(f.Blob)); Assert.Equal(Password, f.Store.Load(f.Root).Password); Assert.Single(Directory.GetFileSystemEntries(f.Root));
        windows.FailMove = false; windows.FailProtect = true;
        Error("dpapi_failed", () => f.Store.Store(Username, Password, Path.Combine(f.Parent, "never-created")));
        Assert.False(Directory.Exists(Path.Combine(f.Parent, "never-created")));
        windows.FailProtect = false; windows.WrongReadback = true;
        Error("verification_failed", () => f.Store.Store(Username, "synthetic-replacement", f.Root, replace: true));
    }

    [Theory]
    [InlineData("directory")]
    [InlineData("file")]
    public void Acl_drift_is_rejected_without_repair(string target)
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); f.Provision();
        string path = target == "directory" ? f.Root : f.Blob;
        FileSystemSecurity acl = target == "directory" ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read, AccessControlType.Allow));
        if (acl is DirectorySecurity directory) new DirectoryInfo(path).SetAccessControl(directory); else new FileInfo(path).SetAccessControl((FileSecurity)acl);
        byte[] Before() => (target == "directory" ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl()).GetSecurityDescriptorBinaryForm();
        byte[] before = Before();
        Assert.Equal("unsafe_acl", Code(f.Store.Status(root: f.Root)));
        Error("unsafe_acl", () => f.Store.Store(Username, Password, f.Root, replace: true));
        Assert.Equal(before, Before());
    }

    [Fact]
    public void Existing_unrelated_directory_is_never_adopted()
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); Directory.CreateDirectory(f.Root);
        string unrelated = Path.Combine(f.Root, "unrelated.txt"); File.WriteAllText(unrelated, "synthetic unrelated data");
        byte[] before = new DirectoryInfo(f.Root).GetAccessControl().GetSecurityDescriptorBinaryForm();
        Error("unsafe_acl", () => f.Store.Store(Username, Password, f.Root));
        Assert.Equal(before, new DirectoryInfo(f.Root).GetAccessControl().GetSecurityDescriptorBinaryForm());
        Assert.Equal(unrelated, Assert.Single(Directory.GetFileSystemEntries(f.Root))); Assert.Equal("synthetic unrelated data", File.ReadAllText(unrelated));
    }

    [Theory]
    [InlineData("root")]
    [InlineData("blob")]
    public void Unexpected_object_type_is_rejected(string target)
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture();
        if (target == "root") File.WriteAllText(f.Root, "synthetic unrelated data");
        else { f.Provision(); File.Delete(f.Blob); Directory.CreateDirectory(f.Blob); }
        Assert.Equal("unsafe_path", Code(f.Store.Status(root: f.Root)));
    }

    [Fact]
    public void Changed_local_owner_and_remote_drive_are_rejected_without_modification()
    {
        if (!WindowsAvailable()) return;
        var windows = new Faults(); using var f = new Fixture(windows); f.Provision(); byte[] before = File.ReadAllBytes(f.Blob);
        windows.Owner = new SecurityIdentifier(WellKnownSidType.BuiltinGuestsSid, null).Value;
        Assert.Equal("owner_mismatch", Code(f.Store.Status(root: f.Root)));
        Error("owner_mismatch", () => f.Store.Store(Username, Password, f.Root, replace: true));
        Assert.Equal(before, File.ReadAllBytes(f.Blob));
        windows.Owner = null; windows.Remote = true; windows.Calls.Clear();
        Assert.Equal("unsafe_path", Code(f.Store.Status(root: f.Root))); Assert.Equal(new[] { "drive" }, windows.Calls);
    }

    [Theory]
    [InlineData("relative")]
    [InlineData("unc")]
    [InlineData("ads")]
    [InlineData("traversal")]
    public void Unsafe_path_syntax_fails_closed(string target)
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture();
        string path = target switch { "relative" => "relative", "unc" => @"\\example.test\share\store", "ads" => f.Root + ":stream", _ => Path.Combine(f.Parent, "..", "store") };
        Assert.Equal("unsafe_path", Code(f.Store.Status(root: path)));
        Assert.False(Directory.Exists(f.Root));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLinkW(string name, string existing, nint security);

    [Fact]
    public void Hard_linked_blob_is_rejected()
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); f.Provision();
        Assert.True(CreateHardLinkW(Path.Combine(f.Root, "extra-link"), f.Blob, 0));
        Assert.Equal("unsafe_path", Code(f.Store.Status(root: f.Root)));
        Error("unsafe_path", () => f.Store.Store(Username, Password, f.Root, replace: true));
    }

    [Theory]
    [InlineData("root")]
    [InlineData("ancestor")]
    public async Task Real_junction_paths_are_rejected(string target)
    {
        if (!WindowsAvailable()) return;
        using var f = new Fixture(); f.Provision(); byte[] before = File.ReadAllBytes(f.Blob);
        string junction = Path.Combine(f.Parent, "junction");
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"))
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add("/c"); start.ArgumentList.Add("mklink"); start.ArgumentList.Add("/J"); start.ArgumentList.Add(junction); start.ArgumentList.Add(target == "root" ? f.Root : f.Parent);
        using var process = Process.Start(start)!;
        await process.WaitForExitAsync(TestContext.Current.CancellationToken); Assert.Equal(0, process.ExitCode);
        try
        {
            string alias = target == "root" ? junction : Path.Combine(junction, "store");
            Assert.Equal("unsafe_path", Code(f.Store.Status(root: alias)));
            Error("unsafe_path", () => f.Store.Store(Username, Password, alias, replace: true));
            Assert.Equal(before, File.ReadAllBytes(f.Blob));
        }
        finally { Directory.Delete(junction); }
    }
}
