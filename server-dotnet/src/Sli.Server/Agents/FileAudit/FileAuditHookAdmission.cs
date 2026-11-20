using System.Text.Json;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.FileAudit;

// One reviewed native contribution. This is not a general plugin loader.
internal sealed class FileAuditHookAdmission(IHostEnvironment host)
{
    internal string? PackageRoot()
    {
        for(var dir=new DirectoryInfo(host.ContentRootPath);dir is not null;dir=dir.Parent)
            if(Directory.Exists(Path.Combine(dir.FullName,"config","plugin_packages","v3"))) return dir.FullName;
        var lockRoot=Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR");
        return string.IsNullOrWhiteSpace(lockRoot) ? null : Directory.GetParent(Path.GetFullPath(lockRoot))?.Parent?.Parent?.FullName;
    }
    internal bool Present(string plugin)
    {
        var root=PackageRoot();return root is not null && FileAuditManifestValidator.Installed(root,plugin);
    }
    public IDisposable Enter(string hook)
    {
        if(hook is not ("audit_status" or "enqueue_audit" or "enqueue_audit_batch" or "ingest_audit") || !Present("sli.file-audit")) throw new AgentControlException("file_audit_plugin_unavailable",409);
        AgentAssignmentPluginAdmission guard;
        try { guard=AgentAssignmentPluginAdmission.Enter("sli.file-audit",Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"),Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR")); }
        catch(InvalidOperationException ex) when(ex.Message=="plugin_generation_unavailable") { throw new AgentControlException("file_audit_plugin_unavailable",409); }
        return TransferAfterValidation(guard,()=>Present("sli.file-audit"));
    }
    internal static IDisposable TransferAfterValidation(IDisposable guard,Func<bool> check)
    {
        try { if(!check()) throw new AgentControlException("file_audit_plugin_unavailable",409); return guard; }
        catch { guard.Dispose(); throw; }
    }
}






