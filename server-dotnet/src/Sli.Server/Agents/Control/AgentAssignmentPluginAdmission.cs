using System.Runtime.InteropServices;

namespace Sli.Server.Agents.Control;

// Admission around a known bundled plugin hook. Flock is the same shared
// inode lock used by the Python updater, not FileStream.Lock (POSIX fcntl).
public sealed class AgentAssignmentPluginAdmission : IDisposable
{
    private readonly FileStream? stream;
    private AgentAssignmentPluginAdmission(FileStream? stream) => this.stream=stream;
    [DllImport("libc", SetLastError=true, EntryPoint="flock")]
    private static extern int Flock(int fd,int operation);

    public static AgentAssignmentPluginAdmission Enter(string pluginId,string? runtimeRoot,string? lockRoot)
    {
        if (pluginId is not ("sli.ad" or "sli.gpo" or "sli.remote-access" or "sli.file-audit")) throw new ArgumentException("invalid plugin",nameof(pluginId));
        runtimeRoot=runtimeRoot is null ? null : AgentControlJson.Strip(runtimeRoot);
        if (runtimeRoot?.Length==0) runtimeRoot=null;
        lockRoot=lockRoot is null ? null : AgentControlJson.Strip(lockRoot);
        if (lockRoot?.Length==0) lockRoot=null;
        string? pluginDir=runtimeRoot is null ? null : Path.Combine(runtimeRoot,pluginId);
        bool Fenced() => pluginDir is not null && File.Exists(Path.Combine(pluginDir,"draining.json"));
        void Check()
        {
            if (Fenced()) throw new InvalidOperationException("plugin_update_draining");
            // External generations require their reviewed native registry and hook.
            if (pluginDir is not null && File.Exists(Path.Combine(pluginDir,"active.json")))
                throw new InvalidOperationException("plugin_generation_unavailable");
        }
        Check();
        string? path=lockRoot is not null ? Path.Combine(lockRoot,pluginId+".json")
            : pluginDir is not null ? Path.Combine(pluginDir,"admission.lock") : null;
        if (path is null) return new(null);
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("plugin admission requires flock");
        FileStream? opened=null;
        try
        {
            // Native units use Linux flock. Windows source acceptance holds a
            // shared read handle which denies replacement/writing until disposal.
            opened=new FileStream(path,FileMode.Open,FileAccess.Read,OperatingSystem.IsLinux() ? FileShare.ReadWrite | FileShare.Delete : FileShare.Read);
            int fd=checked((int)opened.SafeFileHandle.DangerousGetHandle());
            if (OperatingSystem.IsLinux() && Flock(fd,1)!=0) throw new IOException("plugin admission lock failed",new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
            Check();
            return new(opened);
        }
        catch { opened?.Dispose();throw; }
    }
    public void Dispose() => stream?.Dispose();
}
