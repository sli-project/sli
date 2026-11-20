using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic;

namespace Sli.Server.Legacy;

public interface ILegacyStorageSnapshot
{
    Task RecordAsync(LegacyPostClaim claim, CancellationToken ct);
}
public sealed class LegacyStorageSnapshot : ILegacyStorageSnapshot
{
    public LegacyStorageSnapshot(IPostgresConnectionFactory connections, LegacySettings settings) { }

    public Task RecordAsync(LegacyPostClaim claim, CancellationToken ct)
    {
        throw new InvalidOperationException("module_disabled");
    }
    internal static JsonObject Scan(string path,CancellationToken ct)
    {
        var clock=Stopwatch.StartNew(); long bytes=0; int files=0,dirs=0;
        var pending=new Stack<string>(); if (Directory.Exists(path)) pending.Push(path);
        while (pending.TryPop(out string? directory)) {
            ct.ThrowIfCancellationRequested();
            // Never follow links/junctions out of the requested data root.
            if ((File.GetAttributes(directory)&FileAttributes.ReparsePoint)!=0) continue;
            dirs++;
            foreach (var item in new DirectoryInfo(directory).EnumerateFileSystemInfos()) {
                ct.ThrowIfCancellationRequested();
                if ((item.Attributes&FileAttributes.ReparsePoint)!=0 || item.Name is ".git" or "__pycache__" or ".pytest_cache") continue;
                if (item is DirectoryInfo) pending.Push(item.FullName); else if (item is FileInfo file) { bytes+=file.Length; files++; }
            }
        }
        return new() { ["path"]=path,["exists"]=Directory.Exists(path),["bytes"]=bytes,["files_seen"]=files,["dirs_seen"]=dirs,
            ["truncated"]=false,["reason"]=null,["duration_ms"]=clock.ElapsedMilliseconds };
    }
}
