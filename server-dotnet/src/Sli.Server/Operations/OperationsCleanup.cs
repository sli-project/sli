using System.IO.Compression;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

public sealed partial class OperationsService
{
    internal async Task<JsonObject> ApplyStorageCleanupPlanAsync(JsonObject plan, bool apply = false, bool confirmApply = false, CancellationToken ct = default)
    {
        var result = (JsonObject)plan.DeepClone(); var applied = new JsonArray(); var errors = new JsonArray();
        result["mode"] = apply ? "apply" : "dry-run"; result["applied"] = applied; result["errors"] = errors;
        if (apply && !confirmApply)
        { result["status"] = "failed"; errors.Add(new JsonObject { ["error"] = "--apply requires --confirm-apply" }); }
        else if (apply)
        {
            // Rebuild eligibility from fixed roots; a stale or edited plan cannot authorize deletion.
            var current = await CleanupPreviewAsync(ct);
            var eligible = (current["actions"] as JsonArray ?? []).OfType<JsonObject>().ToDictionary(a => S(a["path"]), StringComparer.Ordinal);
            foreach (var item in (plan["actions"] as JsonArray ?? []).OfType<JsonObject>())
            {
                ct.ThrowIfCancellationRequested(); string path = S(item["path"]);
                try
                {
                    if (!eligible.TryGetValue(path, out var fresh) || S(item["action"]) != S(fresh["action"]) || N(item["size_bytes"]) != N(fresh["size_bytes"]))
                        throw new IOException("cleanup candidate is no longer eligible");
                    OperationsFiles.RequireNoLinks(path);
                    string action = S(fresh["action"]);
                    if (action is "archive_zip" or "archive_move")
                    {
                        string archiveRoot = files.Resolve("data/raw_archive"); OperationsFiles.RequireNoLinks(archiveRoot);
                        Directory.CreateDirectory(archiveRoot);
                        string relative = Path.GetRelativePath(files.Resolve("data/raw"), path);
                        string target = action == "archive_zip" ? Path.Combine(archiveRoot, "raw_archive_" + Guid.NewGuid().ToString("N") + ".zip") : Path.Combine(archiveRoot, relative);
                        OperationsFiles.RequireNoLinks(target); Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                        if (action == "archive_move") File.Move(path, target);
                        else
                        {
                            // Hold the source against concurrent writers until verification and deletion.
                            using (var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
                            {
                                using (var zip = ZipFile.Open(target, ZipArchiveMode.Create))
                                using (var output = zip.CreateEntry(relative.Replace('\\', '/')).Open()) source.CopyTo(output);
                                using var verify = ZipFile.OpenRead(target);
                                using var archived = verify.Entries.Single().Open();
                                source.Position = 0;
                                if (!System.Security.Cryptography.SHA256.HashData(source).SequenceEqual(System.Security.Cryptography.SHA256.HashData(archived)))
                                    throw new IOException("archive verification failed; source preserved");
                                File.Delete(path);
                            }
                        }
                    }
                    else if (action == "delete_file") File.Delete(path);
                    else throw new IOException("unsupported cleanup action");
                    applied.Add(fresh.DeepClone());
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
                { errors.Add(new JsonObject { ["path"] = path, ["error_type"] = e.GetType().Name }); }
            }
            result["status"] = errors.Count > 0 ? "warn" : "ok";
        }
        string receipt = files.Resolve("data/maintenance/storage_cleanup_last.json"); OperationsFiles.RequireNoLinks(receipt);
        Directory.CreateDirectory(Path.GetDirectoryName(receipt)!); File.WriteAllText(receipt, result.ToJsonString());
        return result;
    }
}

public partial class OperationsFiles
{
    static readonly Regex GeneratedRunName = new(@"\A[\w-]+-\d{8}-\d{6}-\d+-[0-9a-f]{8}\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    internal string PytestRunsRoot => Resolve("data/tmp/pytest-runs");
    internal static bool LinkLike(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
    internal virtual bool CleanupLinkLike(string path) => LinkLike(path);
    internal static void RequireNoLinks(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.Exists(current) || Directory.Exists(current)) && LinkLike(current)) throw new IOException("symbolic links and junctions are not cleanup targets");
    }
    static (long Bytes, DateTime Newest) RunMetrics(string root)
    {
        long bytes = 0; DateTime newest = Directory.GetLastWriteTimeUtc(root);
        var pending = new Stack<string>(); pending.Push(root);
        while (pending.TryPop(out var directory))
        {
            foreach (var path in Directory.EnumerateFileSystemEntries(directory))
            {
                if (LinkLike(path)) continue;
                var info = new FileInfo(path); if (info.LastWriteTimeUtc > newest) newest = info.LastWriteTimeUtc;
                if ((info.Attributes & FileAttributes.Directory) != 0) pending.Push(path); else bytes += info.Length;
            }
        }
        return (bytes, newest);
    }
    internal JsonObject BuildPytestRunCleanupPlan(DateTimeOffset now, double minAgeHours = 24)
    {
        string root = PytestRunsRoot; RequireNoLinks(root);
        double age = Math.Max(1, minAgeHours); var actions = new JsonArray(); var excluded = new JsonObject(); long bytes = 0;
        void Exclude(string key) => excluded[key] = N(excluded[key]) + 1;
        if (Directory.Exists(root)) foreach (string path in Directory.EnumerateDirectories(root).Order(StringComparer.Ordinal))
        {
            try
            {
                if (CleanupLinkLike(path)) { Exclude("top_level_link"); continue; }
                if (!GeneratedRunName.IsMatch(Path.GetFileName(path))) { Exclude("invalid_name"); continue; }
                if (File.Exists(Path.Combine(root, ".active-" + Path.GetFileName(path) + ".json"))) { Exclude("active_marker"); continue; }
                var metrics = RunMetrics(path);
                if ((now - metrics.Newest).TotalHours < age) { Exclude("recent"); continue; }
                actions.Add(new JsonObject { ["action"] = "delete_tree", ["path"] = path, ["size_bytes"] = metrics.Bytes }); bytes += metrics.Bytes;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Exclude("scan_error"); }
        }
        return new() { ["root"] = root, ["status"] = "ok", ["mode"] = "dry-run", ["min_age_hours"] = age, ["actions"] = actions,
            ["total_candidates"] = actions.Count, ["total_bytes"] = bytes, ["scan"] = new JsonObject { ["excluded"] = excluded } };
    }
    internal JsonObject ApplyPytestRunCleanupPlan(JsonObject plan, DateTimeOffset now, bool apply = false, bool confirmApply = false)
    {
        var result = (JsonObject)plan.DeepClone(); var applied = new JsonArray(); var errors = new JsonArray();
        result["mode"] = apply ? "apply" : "dry-run"; result["applied"] = applied; result["errors"] = errors; result["applied_count"] = 0;
        if (!apply) return result;
        if (!confirmApply || S(plan["root"]) != PytestRunsRoot)
        { result["status"] = "failed"; errors.Add(new JsonObject { ["error"] = !confirmApply ? "--apply requires --confirm-apply" : "pytest cleanup root mismatch" }); return result; }
        foreach (var item in (plan["actions"] as JsonArray ?? []).OfType<JsonObject>())
        {
            string path = S(item["path"]);
            try
            {
                path = Path.GetFullPath(path); string name = Path.GetFileName(path);
                if (S(item["action"]) != "delete_tree" || Path.GetDirectoryName(path) != PytestRunsRoot || !GeneratedRunName.IsMatch(name)) throw new IOException("candidate is outside the generated pytest runs");
                RequireNoLinks(path);
                if (File.Exists(Path.Combine(PytestRunsRoot, ".active-" + name + ".json"))) throw new IOException("candidate has an active-run marker");
                var metrics = RunMetrics(path);
                if ((now - metrics.Newest).TotalHours < Math.Max(1, plan["min_age_hours"]!.GetValue<double>())) throw new IOException("candidate became newer than the accepted age boundary");
                Directory.Delete(path, recursive: true);
                applied.Add(new JsonObject { ["action"] = "delete_tree", ["path"] = path, ["size_bytes"] = metrics.Bytes });
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
            { errors.Add(new JsonObject { ["path"] = path, ["error_type"] = e.GetType().Name }); }
        }
        result["applied_count"] = applied.Count; result["status"] = errors.Count > 0 ? "warn" : "ok";
        return result;
    }
}
