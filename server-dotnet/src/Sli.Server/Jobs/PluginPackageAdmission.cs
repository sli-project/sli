using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.InstallationSetup;

namespace Sli.Server.Jobs;

// The host authenticates the signed archive before staging release.json. Runtime
// admission rechecks its payload; it does not grant permission to execute DLLs.
internal static class PluginPackageAdmission
{
    internal static JsonObject Read(string directory, string plugin)
    {
        try
        {
            for (var parent = new DirectoryInfo(directory); parent is not null; parent = parent.Parent)
                Require(parent.LinkTarget is null, "update_invalid_plugin_payload");
            var release = ReadJson(InstallationPackages.LocalFile(directory, "release.json"));
            Require(release["schema_version"]?.ToJsonString() == "2" && release.Text("component") == "plugin"
                && release.Text("plugin_id") == plugin && release.Text("package_id") == plugin
                && release.Text("plugin_version") == release.Text("version"), "update_invalid_plugin_payload");
            foreach (string api in new[] { "core_api", "ui_api" })
                Require(Compatible(release[api]), "update_plugin_api_incompatible");

            var files = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
            Require(release["files"] is JsonArray { Count: > 0 }, "update_invalid_plugin_payload");
            foreach (var node in release["files"]!.AsArray())
            {
                var file = node!.AsObject(); string path = file.Text("path");
                Require((path.StartsWith("backend/", StringComparison.Ordinal) || path.StartsWith("ui/", StringComparison.Ordinal))
                    && SafePath(path) && files.TryAdd(path, file), "update_invalid_plugin_payload");
                string local = InstallationPackages.LocalFile(directory, path);
                using var stream = File.OpenRead(local);
                Require(file["size"]!.Integer() == stream.Length && file["size"]!.Integer() >= 0
                    && InstallationPackages.Match(file.Text("sha256"), "[a-f0-9]{64}")
                    && Convert.ToHexStringLower(SHA256.HashData(stream)) == file.Text("sha256"), "update_plugin_payload_changed");
            }
            Require(files.ContainsKey("backend/jobs-v3.json") && files.ContainsKey("ui/descriptor.json"), "update_invalid_plugin_payload");
            var jobs = ReadJson(InstallationPackages.LocalFile(directory, "backend/jobs-v3.json"));
            new CoreJobRegistry().Register(jobs);
            Require(jobs.Text("plugin_id") == plugin && jobs.Text("plugin_version") == release.Text("plugin_version")
                && JsonNode.DeepEquals(jobs["core_api"], release["core_api"]), "update_plugin_handler_mismatch");
            var handlers = release["handlers"]!.AsArray().Select(x => x!.GetValue<string>()).ToArray();
            Require(handlers.Length > 0 && handlers.Distinct(StringComparer.Ordinal).Count() == handlers.Length
                && handlers.ToHashSet(StringComparer.Ordinal).SetEquals(jobs["handlers"]!.AsArray().Select(x => x!.Text("handler_id"))),
                "update_plugin_handler_mismatch");

            var descriptor = ReadJson(InstallationPackages.LocalFile(directory, "ui/descriptor.json"));
            InstallationPackages.ValidateUi(descriptor, plugin);
            string entry = "ui/" + descriptor["entry"]!.Text("path");
            Require(files.TryGetValue(entry, out var asset) && asset.Text("path") == entry
                && asset.Text("sha256") == descriptor["entry"]!.Text("sha256") && asset["size"]!.Integer() <= 4 * 1024 * 1024
                && descriptor.Text("version") == release.Text("plugin_version")
                && files.Keys.Where(p => p.StartsWith("ui/", StringComparison.Ordinal)).ToHashSet(StringComparer.Ordinal)
                    .SetEquals(["ui/descriptor.json", entry]), "update_plugin_ui_mismatch");
            _ = new UTF8Encoding(false, true).GetString(File.ReadAllBytes(InstallationPackages.LocalFile(directory, entry)));
            return jobs;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException
            or ArgumentException or NullReferenceException or FormatException or OverflowException or InstallationException)
        { throw new CoreJobContractException("update_invalid_plugin_payload"); }
    }

    private static bool Compatible(JsonNode? api)
    {
        static int Compare(string text)
        {
            Require(InstallationPackages.Match(text, @"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"), "update_plugin_api_incompatible");
            var parts = text.Split('.').Select(s => System.Numerics.BigInteger.Parse(s, System.Globalization.CultureInfo.InvariantCulture)).ToArray();
            for (int i = 0; i < 3; i++)
            {
                int compared = parts[i].CompareTo(i == 0 ? System.Numerics.BigInteger.One : System.Numerics.BigInteger.Zero);
                if (compared != 0) return compared;
            }
            return 0;
        }
        return api is JsonObject obj && InstallationPackages.Keys(obj, "minimum", "maximum_exclusive")
            && Compare(obj.Text("minimum")) <= 0 && Compare(obj.Text("maximum_exclusive")) > 0;
    }
    private static bool SafePath(string path) => path.Length <= 220 && path.Split('/').All(part => part.Length is > 0 and <= 120
        && part is not ("." or "..") && !part.EndsWith('.') && InstallationPackages.Match(part, "[a-zA-Z0-9_.-]+")
        && !InstallationPackages.Match(part.Split('.')[0].ToUpperInvariant(), "CON|PRN|AUX|NUL|CLOCK\\$|CONIN\\$|CONOUT\\$|(?:COM|LPT)[1-9]"));
    private static JsonObject ReadJson(string path) => JsonNode.Parse(File.ReadAllText(path, new UTF8Encoding(false, true)))!.AsObject();
    private static void Require(bool condition, string code)
    { if (!condition) throw new CoreJobContractException(code); }
}
