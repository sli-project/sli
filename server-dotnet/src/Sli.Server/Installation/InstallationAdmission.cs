using System.Runtime.InteropServices;
using Sli.Server.Access;

namespace Sli.Server.InstallationSetup;

// The same pre-existing inode and shared flock as update_runtime.admission.
// Keep it for the entire plugin-owned setup operation, including audit/commit.
public sealed class InstallationAdmission : IDisposable
{
    readonly FileStream? stream;
    InstallationAdmission(FileStream? stream) => this.stream = stream;
    [DllImport("libc", EntryPoint = "flock", SetLastError = true)]
    static extern int Flock(int fd, int operation);
    public static InstallationAdmission Enter(string id, InstallationPackages packages)
    {
        var reader = new PluginGenerationReader(packages.RuntimeRoot);
        void Check() { if (reader.Read(id).Fenced) throw new InstallationException("plugin_update_draining", 503); }
        Check();
        string? path = !string.IsNullOrWhiteSpace(packages.LockRoot) ? Path.Combine(packages.LockRoot, id + ".json")
            : !string.IsNullOrWhiteSpace(packages.RuntimeRoot) ? Path.Combine(packages.RuntimeRoot, id, "admission.lock") : null;
        if (path is null) return new(null);
        if (!OperatingSystem.IsLinux()) throw new InstallationException("plugin_admission_unavailable", 503);
        FileStream? stream = null;
        try
        {
            stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (Flock(checked((int)stream.SafeFileHandle.DangerousGetHandle()), 1) != 0) throw new IOException("plugin_admission_unavailable");
            Check();
            return new(stream);
        }
        catch { stream?.Dispose(); throw; }
    }
    public void Dispose() => stream?.Dispose();
}
