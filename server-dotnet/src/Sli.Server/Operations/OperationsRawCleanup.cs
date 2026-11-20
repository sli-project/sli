using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

public partial class OperationsFiles
{
    // Port of runtime_storage.build_raw_cleanup_plan/apply_raw_cleanup_plan.
    // Local filesystem maintenance only; this does not authorize PG retention.
    public JsonObject BuildRawCleanupPlan(int olderThanDays = 7, string archiveMode = "move")
    {
        archiveMode = archiveMode.Trim().ToLowerInvariant();
        if (archiveMode is not ("move" or "zip")) throw new ArgumentException("archive_mode must be 'move' or 'zip'");
        string raw = Resolve("data/raw"), archive = Resolve("data/raw_archive");
        string zip = Path.Combine(archive, "raw_archive_" + Guid.NewGuid().ToString("N") + ".zip");
        var cutoff = DateTime.UtcNow.AddDays(-Math.Max(0, olderThanDays));
        var candidates = new JsonArray(); var exclusions = new JsonObject(); int total = 0; long bytes = 0;
        void Exclude(string reason) => exclusions[reason] = N(exclusions[reason]) + 1;
        var pending = new Stack<string>();
        if (Directory.Exists(raw)) pending.Push(raw); else Exclude("raw_dir_missing");
        while (pending.TryPop(out string? directory)) {
            try {
                SafeCleanupPath(raw, directory, allowRoot: true);
                foreach (string path in Directory.EnumerateFileSystemEntries(directory).Order(StringComparer.Ordinal)) {
                    var info = new FileInfo(path);
                    if ((info.Attributes & FileAttributes.ReparsePoint) != 0) { Exclude("not_file"); continue; }
                    if ((info.Attributes & FileAttributes.Directory) != 0) { pending.Push(path); Exclude("not_file"); continue; }
                    total++;
                    if (info.LastWriteTimeUtc > cutoff) { Exclude("recent_file"); continue; }
                    string relative = Path.GetRelativePath(raw, path);
                    candidates.Add(new JsonObject {
                        ["path"] = path, ["relative_path"] = relative, ["target"] = archiveMode == "zip" ? zip : Path.Combine(archive, relative),
                        ["size_bytes"] = info.Length, ["modified_ticks"] = info.LastWriteTimeUtc.Ticks, ["created_ticks"] = info.CreationTimeUtc.Ticks,
                        ["sha256"] = RawDigest(path), ["modified_utc"] = Stamp(info.LastWriteTimeUtc), ["reason"] = $"старше {olderThanDays} дней"
                    });
                    bytes += info.Length;
                }
            } catch (Exception error) when (error is IOException or UnauthorizedAccessException) { Exclude("stat_error"); }
        }
        return new() { ["mode"] = "dry-run", ["archive_mode"] = archiveMode, ["raw_dir"] = raw, ["archive_dir"] = archive,
            ["zip_path"] = archiveMode == "zip" ? zip : null, ["older_than_days"] = olderThanDays, ["cutoff_utc"] = Stamp(cutoff),
            ["total_raw_files"] = total, ["candidates"] = candidates, ["total_candidates"] = candidates.Count,
            ["total_bytes"] = bytes, ["total_human"] = Human(bytes), ["exclusion_summary"] = exclusions };
    }

    public JsonObject ApplyRawCleanupPlan(JsonObject plan, bool apply = false)
    {
        var result = (JsonObject)plan.DeepClone(); result["mode"] = apply ? "apply" : "dry-run";
        var moved = new JsonArray(); var archived = new JsonArray(); var errors = new JsonArray();
        result["moved"] = moved; result["archived"] = archived; result["errors"] = errors;
        string raw = Resolve("data/raw"), archive = Resolve("data/raw_archive"), mode = S(plan["archive_mode"]);
        void Error() => errors.Add(new JsonObject { ["error"] = "raw_cleanup_source_changed_or_path_unsafe" });
        if (apply) {
            try {
                if (mode is not ("move" or "zip") || !SamePath(raw, S(plan["raw_dir"])) || !SamePath(archive, S(plan["archive_dir"]))) throw new IOException();
                var valid = new List<JsonObject>();
                foreach (var item in (plan["candidates"] as JsonArray ?? []).OfType<JsonObject>()) {
                    try {
                        string source = S(item["path"]); SafeCleanupPath(raw, source);
                        string target = mode == "zip" ? S(plan["zip_path"]) : Path.Combine(archive, Path.GetRelativePath(raw, source));
                        SafeCleanupPath(archive, target);
                        if (!SamePath(target, S(item["target"]))) throw new IOException();
                        CheckRawSnapshot(item); valid.Add(item);
                    } catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) { Error(); }
                }
                if (mode == "move") foreach (var item in valid) {
                    try {
                        string source = S(item["path"]), target = S(item["target"]); CheckRawSnapshot(item);
                        Directory.CreateDirectory(Path.GetDirectoryName(target)!); SafeCleanupPath(archive, target);
                        string original = target; int suffix = 0;
                        while (File.Exists(target)) target = Path.Combine(Path.GetDirectoryName(original)!, Path.GetFileNameWithoutExtension(original) + "." + ++suffix + Path.GetExtension(original));
                        File.Move(source, target);
                        moved.Add(new JsonObject { ["from"] = source, ["to"] = target, ["size_bytes"] = N(item["size_bytes"]) });
                    } catch (Exception error) when (error is IOException or UnauthorizedAccessException) { Error(); }
                }
                else if (valid.Count > 0) ArchiveRawZip(valid, raw, archive, S(plan["zip_path"]), archived);
            } catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException) { Error(); }
        }
        var metadata = (JsonObject)result.DeepClone(); metadata.Remove("candidates"); metadata.Remove("moved"); metadata.Remove("archived"); metadata.Remove("errors");
        metadata["recorded_at_utc"] = Stamp(DateTimeOffset.UtcNow); metadata["moved_count"] = moved.Count;
        metadata["archived_count"] = archived.Count; metadata["error_count"] = errors.Count;
        try {
            string path = Resolve("data/maintenance/raw_cleanup_last.json"); SafeCleanupPath(DataRoot, path);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, metadata.ToJsonString());
        } catch (Exception error) when (error is IOException or UnauthorizedAccessException) { /* Metadata must not break cleanup. */ }
        lock (storageLock) storageCache = null;
        return result;
    }

    static void ArchiveRawZip(List<JsonObject> candidates, string raw, string archive, string destination, JsonArray archived)
    {
        SafeCleanupPath(archive, destination); Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        string staged = Path.Combine(Path.GetDirectoryName(destination)!, ".raw-archive-" + Guid.NewGuid().ToString("N") + ".tmp");
        try {
            using (var stream = new FileStream(staged, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
                foreach (var item in candidates) {
                    CheckRawSnapshot(item);
                    using var source = File.OpenRead(S(item["path"]));
                    using var output = zip.CreateEntry(Path.GetRelativePath(raw, S(item["path"])).Replace('\\', '/')).Open(); source.CopyTo(output);
                }
            using (var zip = ZipFile.OpenRead(staged)) foreach (var item in candidates) {
                string name = Path.GetRelativePath(raw, S(item["path"])).Replace('\\', '/');
                using var content = (zip.GetEntry(name) ?? throw new InvalidDataException()).Open();
                if (Convert.ToHexStringLower(SHA256.HashData(content)) != S(item["sha256"])) throw new InvalidDataException();
                CheckRawSnapshot(item);
            }
            SafeCleanupPath(archive, destination); File.Move(staged, destination);
            foreach (var item in candidates) {
                string path = S(item["path"]); SafeCleanupPath(raw, path); CheckRawSnapshot(item); File.Delete(path);
                archived.Add(new JsonObject { ["from"] = path, ["archive_name"] = Path.GetRelativePath(raw, path).Replace('\\', '/'), ["size_bytes"] = N(item["size_bytes"]) });
            }
        } finally { if (File.Exists(staged)) File.Delete(staged); }
    }

    static string RawDigest(string path) { using var stream = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    static void CheckRawSnapshot(JsonObject item)
    {
        var info = new FileInfo(S(item["path"]));
        if (!info.Exists || (info.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 || info.Length != N(item["size_bytes"]) ||
            info.LastWriteTimeUtc.Ticks != N(item["modified_ticks"]) || info.CreationTimeUtc.Ticks != N(item["created_ticks"]) || RawDigest(info.FullName) != S(item["sha256"])) throw new IOException();
    }
    static bool SamePath(string a, string b) => Path.GetFullPath(a).Equals(Path.GetFullPath(b), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    static void SafeCleanupPath(string root, string path, bool allowRoot = false)
    {
        root = Path.GetFullPath(root); path = Path.GetFullPath(path);
        string relative = Path.GetRelativePath(root, path);
        if (Path.IsPathRooted(relative) || relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar) || relative == "." && !allowRoot) throw new IOException();
        // Check all existing ancestors, including the configured root itself.
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current)) {
            try { if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new IOException(); }
            catch (FileNotFoundException) { } catch (DirectoryNotFoundException) { }
        }
    }
}
