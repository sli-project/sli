using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

// Read the explicitly selected existing Windows supervisor profile. Never log its
// payload or rewrite/reseal a shared file from this one-shot control process.
internal static partial class SemanticRetainedEnvironment
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Blob { internal int Length; internal IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref Blob input, out IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    internal static void Load(string path, bool overrideExisting) => LoadCore(path, overrideExisting, Environment.GetEnvironmentVariable, Environment.SetEnvironmentVariable);
    internal static void LoadCore(string path, bool overrideExisting, Func<string, string?> get, Action<string, string?> set)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidOperationException("Windows DPAPI is required");
        if (!File.Exists(path)) throw new InvalidOperationException("worker supervisor environment is not provisioned");
        JsonObject payload; byte[] protectedBytes = File.ReadAllBytes(path); Blob output = default; IntPtr description = IntPtr.Zero;
        var pinned = GCHandle.Alloc(protectedBytes, GCHandleType.Pinned);
        try {
            var input = new Blob { Length = protectedBytes.Length, Data = pinned.AddrOfPinnedObject() };
            if (!CryptUnprotectData(ref input, out description, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)) throw new InvalidOperationException();
            byte[] clear = new byte[output.Length];
            try { Marshal.Copy(output.Data, clear, 0, clear.Length); payload = JsonNode.Parse(clear)!.AsObject(); }
            finally { CryptographicOperations.ZeroMemory(clear); }
        }
        catch { throw new InvalidOperationException("worker supervisor environment decryption failed"); }
        finally {
            if (output.Data != IntPtr.Zero) { for (int i = 0; i < output.Length; i++) Marshal.WriteByte(output.Data, i, 0); LocalFree(output.Data); }
            if (description != IntPtr.Zero) LocalFree(description); pinned.Free(); CryptographicOperations.ZeroMemory(protectedBytes);
        }
        using var identity = WindowsIdentity.GetCurrent();
        Apply(payload, identity.User?.Value ?? "", get, set, overrideExisting);
    }
    internal static void Apply(JsonObject payload, string currentSid, Func<string, string?> get, Action<string, string?> set, bool overrideExisting)
    {
        if (payload.Number("version") is not (1 or 2) || payload["environment"] is not JsonObject values) throw new InvalidOperationException("worker supervisor environment has an unsupported format");
        if (payload.Number("version") == 2 && payload.Text("owner_sid") != currentSid) throw new InvalidOperationException("worker supervisor environment owner mismatch");
        // Validate the necessary credential before changing the inherited environment.
        string? dsn = values.Text("ADLOG_PG_DSN"); if (string.IsNullOrEmpty(dsn) && string.IsNullOrEmpty(get("ADLOG_PG_DSN"))) throw new InvalidOperationException("worker supervisor environment does not contain ADLOG_PG_DSN");
        foreach (var (name, node) in values) {
            if ((!Allowed.Contains(name) && !Enforced.ContainsKey(name)) || node is not JsonValue value || !value.TryGetValue<string>(out var text) || string.IsNullOrEmpty(text)) continue;
            if (Enforced.TryGetValue(name, out string? enforced)) set(name, enforced);
            else if (overrideExisting || name is "ADLOG_COLLECTION_PRINCIPAL" or "ADLOG_COLLECTION_PRINCIPAL_SID" || get(name) is null) set(name, text);
        }
        if (overrideExisting && !values.ContainsKey("ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST")) set("ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST", null);
    }
}
