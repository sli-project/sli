using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Sources;

internal sealed class AdCredentialStoreException : Exception
{
    private static readonly HashSet<string> Codes = ["missing", "already_exists", "invalid_username", "invalid_password",
        "invalid_argument", "unsafe_path", "unsafe_acl", "owner_mismatch", "invalid_payload", "invalid_size",
        "dpapi_failed", "windows_required", "storage_failed", "verification_failed"];
    internal AdCredentialStoreException(string code) : base(Codes.Contains(code) ? code : "storage_failed") { }
}

// Deliberately not a record: generated diagnostic representations must never expose values.
internal sealed class AdSourceCredential(string username, string password)
{
    internal string Username { get; } = username;
    internal string Password { get; } = password;
    public override string ToString() => nameof(AdSourceCredential);
}

// Explicit local provisioning only; never activates a collector or authenticates to AD.
internal sealed class AdSourceCredentials(string dataRoot, AdSourceCredentialWindows? windows = null)
{
    internal const int MaxClearBytes = 32768, MaxBlobBytes = 65536;
    internal const string BlobName = "credentials.dpapi";
    private readonly AdSourceCredentialWindows windows = windows ?? new();

    private (string Path, string Purpose) Profile(object? profile, string? root)
    {
        if (profile is not string name || name is not ("ad" or "vpn")) throw new AdCredentialStoreException("invalid_argument");
        return (root ?? Path.Combine(dataRoot, "runtime", name + "-source-credentials"), "sli." + name + "-source-credentials");
    }

    internal static string ValidateUsername(object? value)
    {
        if (value is not string text || text.EnumerateRunes().Count() is < 1 or > 1024
            || text.EnumerateRunes().Any(r => Rune.IsWhiteSpace(r) || Rune.GetUnicodeCategory(r) is
                UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned)
            || text.IndexOfAny("/:\"<>|?*;=,[]".ToCharArray()) >= 0 || HasInvalidUtf16(text))
            throw new AdCredentialStoreException("invalid_username");
        string[] parts;
        if (text.Count(c => c == '\\') == 1 && !text.Contains('@')) parts = text.Split('\\');
        else if (text.Count(c => c == '@') == 1 && !text.Contains('\\')) parts = text.Split('@');
        else throw new AdCredentialStoreException("invalid_username");
        if (parts.Any(p => p is "" or "." or "..")) throw new AdCredentialStoreException("invalid_username");
        return text;
    }

    internal static string ValidatePassword(object? value)
    {
        if (value is not string text || text.EnumerateRunes().Count() is < 1 or > 4096 || text.Contains('\0') || HasInvalidUtf16(text))
            throw new AdCredentialStoreException("invalid_password");
        return text;
    }

    private static bool HasInvalidUtf16(string value)
    {
        try { _ = new UTF8Encoding(false, true).GetByteCount(value); return false; }
        catch (EncoderFallbackException) { return true; }
    }

    private static byte[] Encode(string sid, string purpose, string username, string password)
    {
        // Match ensure_ascii=False in the reference. Escaping supplementary runes as
        // surrogate pairs would incorrectly exceed the envelope bound for valid passwords.
        static string Quote(string text)
        {
            var result = new StringBuilder("\"");
            foreach (char ch in text)
                if (ch is '"' or '\\') result.Append('\\').Append(ch);
                else if (ch < 32) result.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                else result.Append(ch);
            return result.Append('"').ToString();
        }
        return new UTF8Encoding(false, true).GetBytes("{\"version\":1,\"purpose\":" + Quote(purpose) + ",\"owner_sid\":" + Quote(sid)
            + ",\"username\":" + Quote(username) + ",\"password\":" + Quote(password) + "}");
    }

    internal JsonObject Store(object? username, object? password, string? root = null, bool replace = false, string? profile = "ad")
    {
        try
        {
            var settings = Profile(profile, root);
            string account = ValidateUsername(username), secret = ValidatePassword(password);
            bool overwrite = replace;
            RequireWindows();
            string sid = windows.CurrentSid(), path = windows.RootPath(settings.Path);
            byte[] clear = Encode(sid, settings.Purpose, account, secret);
            byte[] blob;
            try
            {
                if (clear.Length > MaxClearBytes) throw new AdCredentialStoreException("invalid_size");
                try { blob = windows.Protect(clear, settings.Purpose); }
                catch { throw new AdCredentialStoreException("dpapi_failed"); }
            }
            finally { CryptographicOperations.ZeroMemory(clear); }
            if (blob.Length is < 1 or > MaxBlobBytes) throw new AdCredentialStoreException("invalid_size");
            using (windows.Directory(path, sid, create: true))
            {
                string destination = Path.Combine(path, BlobName);
                try
                {
                    using var existing = windows.BlobHandle(destination, sid);
                    if (!overwrite) throw new AdCredentialStoreException("already_exists");
                }
                catch (AdCredentialStoreException e) when (e.Message == "missing") { }
                string temporary = Path.Combine(path, ".pending-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));
                bool created = false;
                try
                {
                    using (var handle = windows.CreateBlob(temporary, sid))
                    {
                        created = true;
                        windows.Verify(handle, sid, directory: false);
                        using var stream = new FileStream(handle, FileAccess.Write);
                        stream.Write(blob);
                        stream.Flush(flushToDisk: true);
                    }
                    windows.Move(temporary, destination, overwrite);
                    created = false;
                    var loaded = LoadPinned(path, sid, settings.Purpose);
                    if (loaded.Username != account || loaded.Password != secret) throw new AdCredentialStoreException("verification_failed");
                }
                finally { if (created) File.Delete(temporary); }
            }
            return Metadata("ready", matches: true, owner: true);
        }
        catch (AdCredentialStoreException) { throw; }
        catch { throw new AdCredentialStoreException("storage_failed"); }
    }

    internal AdSourceCredential Load(string? root = null, string? profile = "ad")
    {
        try
        {
            var settings = Profile(profile, root);
            RequireWindows();
            string sid = windows.CurrentSid(), path = windows.RootPath(settings.Path);
            using (windows.Directory(path, sid, create: false)) return LoadPinned(path, sid, settings.Purpose);
        }
        catch (AdCredentialStoreException) { throw; }
        catch { throw new AdCredentialStoreException("storage_failed"); }
    }

    private AdSourceCredential LoadPinned(string path, string sid, string purpose)
    {
        byte[] blob;
        using (var handle = windows.BlobHandle(Path.Combine(path, BlobName), sid))
        using (var stream = new FileStream(handle, FileAccess.Read))
        {
            long size = stream.Length;
            if (size is < 1 or > MaxBlobBytes) throw new AdCredentialStoreException("invalid_size");
            blob = new byte[(int)size];
            stream.ReadExactly(blob);
            if (stream.Length != size) throw new AdCredentialStoreException("invalid_size");
        }
        (byte[] Clear, string Description) decoded;
        try { decoded = windows.Unprotect(blob); }
        catch { throw new AdCredentialStoreException("dpapi_failed"); }
        try { return Decode(decoded.Clear, decoded.Description, purpose, sid); }
        finally { CryptographicOperations.ZeroMemory(decoded.Clear); }
    }

    internal static AdSourceCredential Decode(byte[] clear, string description, string purpose, string sid)
    {
        if (description != purpose || clear.Length is < 1 or > MaxClearBytes) throw new AdCredentialStoreException("invalid_payload");
        string owner, username, password;
        try
        {
            // JsonDocument validates UTF-8; explicit enumeration also rejects duplicate and extra fields.
            using var json = JsonDocument.Parse(clear);
            var value = json.RootElement;
            string[] fields = ["version", "purpose", "owner_sid", "username", "password"];
            if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Count() != fields.Length
                || fields.Any(f => value.EnumerateObject().Count(p => p.Name == f) != 1)
                || value.GetProperty("version").ValueKind != JsonValueKind.Number || value.GetProperty("version").GetRawText() != "1"
                || value.GetProperty("purpose").GetString() != purpose) throw new JsonException();
            owner = value.GetProperty("owner_sid").GetString() ?? throw new JsonException();
            username = ValidateUsername(value.GetProperty("username").GetString());
            password = ValidatePassword(value.GetProperty("password").GetString());
        }
        catch { throw new AdCredentialStoreException("invalid_payload"); }
        if (owner != sid) throw new AdCredentialStoreException("owner_mismatch");
        return new(username, password);
    }

    internal JsonObject Status(object? expectedUsername = null, string? root = null, string? profile = "ad")
    {
        try
        {
            if (expectedUsername is not null) ValidateUsername(expectedUsername);
            var value = Load(root, profile);
            return Metadata("ready", expectedUsername is null ? null : value.Username == (string)expectedUsername, true);
        }
        catch (AdCredentialStoreException e)
        {
            return Metadata(e.Message == "missing" ? "missing" : "unreadable", owner: e.Message == "owner_mismatch" ? false : null, code: e.Message);
        }
    }

    private static JsonObject Metadata(string status, bool? matches = null, bool? owner = null, string? code = null) => new()
    {
        ["status"] = status, ["dpapi_scope"] = "CurrentUser", ["owner_matches"] = owner,
        ["account_matches"] = matches, ["error_code"] = code, ["credential_values_exposed"] = false
    };
    private static void RequireWindows() { if (!OperatingSystem.IsWindows()) throw new AdCredentialStoreException("windows_required"); }
}
