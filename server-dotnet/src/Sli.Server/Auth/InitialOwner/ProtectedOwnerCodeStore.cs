using System.Runtime.InteropServices;
using System.Text;

namespace Sli.Server.Auth.InitialOwner;

// Linux's stable statx ABI avoids platform-dependent struct stat layouts.
public sealed class ProtectedOwnerCodeStore
{
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx
    {
        [FieldOffset(20)] public uint UserId;
        [FieldOffset(28)] public ushort Mode;
    }
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Stat(int directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out Statx data);
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Sync(int descriptor);
    [DllImport("libc", EntryPoint = "close")]
    private static extern int Close(int descriptor);

    private readonly string codeFile;
    private readonly string receiptFile;
    public ProtectedOwnerCodeStore(IConfiguration configuration)
    {
        codeFile = ExplicitPath(configuration["Sli:InitialOwnerOperator:CodeFile"]);
        receiptFile = ExplicitPath(configuration["Sli:InitialOwnerOperator:ReceiptFile"]);
        if (codeFile == receiptFile) throw new InvalidOperationException("native_setup_configuration_conflict");
    }

    private static string ExplicitPath(string? value) => value is not null && Path.IsPathFullyQualified(value)
        ? Path.GetFullPath(value) : throw new InvalidOperationException("native_setup_configuration_conflict");

    private static void Trusted(string path, bool fileRequired)
    {
        if (!OperatingSystem.IsLinux()) throw new UnauthorizedAccessException("host_root_required");
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            if (Stat(-100, current, 0x100 | 0x800, 0x000b, out var info) != 0 || info.UserId != 0
                || (info.Mode & 0x12) != 0 || (info.Mode & 0xf000) == 0xa000)
                throw new InvalidOperationException("native_install_untrusted_path");
            if (current == path && (info.Mode & 0xf000) != (fileRequired ? 0x8000 : 0x4000))
                throw new InvalidOperationException("native_install_file_required");
        }
    }

    public string ReadCode()
    {
        Trusted(codeFile, true);
        // Decode bytes explicitly: Python's UTF-8 decode preserves a BOM as credential data.
        return new UTF8Encoding(false, true).GetString(File.ReadAllBytes(codeFile)).Trim();
    }

    public bool ReceiptExists()
    {
        Trusted(Path.GetDirectoryName(receiptFile)!, false);
        if (!Exists(receiptFile)) return false;
        Trusted(receiptFile, true);
        return true;
    }

    public void RemoveCodeIfPresent()
    {
        Trusted(Path.GetDirectoryName(codeFile)!, false);
        if (!Exists(codeFile)) return;
        Trusted(codeFile, true);
        File.Delete(codeFile);
    }

    public void ReplaceCode(string code)
    {
        Trusted(codeFile, true); // As in source replace_text: rotation does not invent a missing secret file.
        AtomicWrite(codeFile, code + "\n");
    }

    public void WriteReceipt()
    {
        Trusted(Path.GetDirectoryName(receiptFile)!, false);
        if (Exists(receiptFile)) Trusted(receiptFile, true);
        AtomicWrite(receiptFile, "{\"issued\": true, \"schema_version\": 1}\n");
    }

    private static void AtomicWrite(string path, string text)
    {
        if (!OperatingSystem.IsLinux()) throw new UnauthorizedAccessException("host_root_required");
        string parent = Path.GetDirectoryName(path)!;
        Trusted(parent, false);
        string temporary = Path.Combine(parent, ".owner-code-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var stream = new FileStream(temporary, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            }))
            {
                stream.Write(Encoding.UTF8.GetBytes(text));
                stream.Flush(true);
            }
            if (Exists(path)) Trusted(path, true);
            File.Move(temporary, path, true);
            int descriptor = Open(parent, 0x10000 | 0x80000);
            if (descriptor < 0) throw new IOException("native_setup_secrets_failed");
            try { if (Sync(descriptor) != 0) throw new IOException("native_setup_secrets_failed"); }
            finally { Close(descriptor); }
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static bool Exists(string path)
    {
        if (Stat(-100, path, 0x100 | 0x800, 0x000b, out _) == 0) return true;
        if (Marshal.GetLastPInvokeError() == 2) return false;
        throw new IOException("native_install_untrusted_path");
    }
}
