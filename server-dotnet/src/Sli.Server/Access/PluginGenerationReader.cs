using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sli.Server.Access;

// Existing host updater format, not an access declaration or a native plugin loader.
// Frozen source: plugins/update_runtime.py and deploy/linux/plugin_update.py.
public sealed record PluginGeneration(string PluginId, string? Generation, bool Fenced);

public sealed class PluginGenerationReader
{
    private readonly string? runtimeDirectory;
    public PluginGenerationReader() : this(Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR")) { }

    public PluginGenerationReader(string? runtimeDirectory)
    {
        this.runtimeDirectory = Normalize(runtimeDirectory);
    }

    public PluginGeneration Read(string pluginId)
    {
        ValidateId(pluginId);
        if (runtimeDirectory is null) return new(pluginId, null, false);
        var directory = Path.Combine(runtimeDirectory, pluginId);
        var pointer = Path.Combine(directory, "active.json");
        string? generation = null;
        if (File.Exists(pointer))
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(pointer));
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("generation", out var value)
                || value.ValueKind != JsonValueKind.String
                || !Regex.IsMatch(value.GetString()!, "\\A[a-f0-9]{64}\\z", RegexOptions.CultureInvariant))
                throw new InvalidOperationException("plugin_update_invalid_generation");
            generation = value.GetString();
            var version = new DirectoryInfo(Path.Combine(directory, "versions", generation!));
            // Path.resolve in the source follows ancestor links as well as the leaf.
            if (version.LinkTarget is not null || !IsWithin(Resolve(version.FullName), Resolve(directory)))
                throw new InvalidOperationException("plugin_update_invalid_generation");
        }
        return new(pluginId, generation, File.Exists(Path.Combine(directory, "draining.json"))
            || Directory.Exists(Path.Combine(directory, "draining.json")));
    }

    private static string? Normalize(string? value)
    {
        // Reuse the existing Python-compatible strip, including U+001C..U+001F.
        var stripped = Administration.AssignmentValidation.Strip(value ?? "");
        return stripped.Length == 0 ? null : Path.GetFullPath(stripped);
    }
    internal static void ValidateId(string value)
    {
        if (!Regex.IsMatch(value, "\\A[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+\\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("plugin_update_invalid_id");
    }

    private static string Resolve(string path)
    {
        var full = Path.GetFullPath(path);
        var current = Path.GetPathRoot(full)!;
        foreach (var part in full[current.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            var next = new DirectoryInfo(Path.Combine(current, part));
            current = next.LinkTarget is not null ? next.ResolveLinkTarget(true)!.FullName : next.FullName;
        }
        return current;
    }

    private static bool IsWithin(string path, string parent)
    {
        var relative = Path.GetRelativePath(parent, path);
        return !Path.IsPathRooted(relative) && relative != ".."
            && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }

}
