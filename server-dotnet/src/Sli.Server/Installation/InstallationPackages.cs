using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Access;
using Sli.Server.Agents.Radius;

namespace Sli.Server.InstallationSetup;

public sealed record InstallationUiPackage(JsonObject Descriptor, byte[] Payload);

public sealed class InstallationPackages(IConfiguration configuration, IHostEnvironment? host = null)
{
    public static readonly string[] Bundled = ["sli.ad", "sli.gpo", "sli.remote-access", "sli.workstations", "sli.file-audit", "sli.sigma"];
    public string? RuntimeRoot => configuration["Sli:PluginRuntimeDirectory"] ?? Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR");
    public string? LockRoot => configuration["Sli:PluginLockDirectory"] ?? Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR");
    public string ConfigRoot
    {
        get
        {
            if (configuration["Sli:ConfigRoot"] is { Length: > 0 } configured) return Path.GetFullPath(configured);
            for (var directory = new DirectoryInfo(host?.ContentRootPath ?? AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
                if (File.Exists(Path.Combine(directory.FullName, "config", "plugin_architecture_v3.json"))) return Path.Combine(directory.FullName, "config");
            return Path.Combine(AppContext.BaseDirectory, "config");
        }
    }
    public static JsonObject Contract(string name)
    {
        using var stream = typeof(InstallationPackages).Assembly.GetManifestResourceStream("Sli.Installation." + name.Replace('/', '.'))
            ?? throw new InvalidOperationException("installation_contract_unavailable");
        return JsonNode.Parse(stream)!.AsObject();
    }
    public JsonObject Settings(string id)
    {
        if (!Bundled.Contains(id, StringComparer.Ordinal)) throw new InstallationException("plugin_settings_not_found", 404);
        var metadata = Contract("plugin_settings_schema/" + id + ".settings.json");
        var manifest = Contract("plugin_packages/v3/" + id + ".json");
        Shape(metadata, Contract("plugin_settings_schema_v1.json"));
        Shape(manifest, Contract("plugin_architecture_v3.json"));
        if (metadata["plugin_id"]?.GetValue<string>() != id || manifest["plugin_id"]?.GetValue<string>() != id)
            throw new InvalidOperationException("plugin_settings_unavailable");
        foreach (var node in metadata["settings"]!["properties"]!.AsObject())
            if (node.Value?["x-secret"]?.GetValue<bool>() == true || !InstallationSettings.Specs.ContainsKey(node.Key))
                throw new InvalidOperationException("plugin_settings_unavailable");
        return metadata;
    }
    public InstallationUiPackage LoadUi(string id) => LoadUi(id, allowDraining: false);
    internal InstallationUiPackage LoadUi(string id, bool allowDraining)
    {
        const string invalid = "plugin_ui_invalid_descriptor";
        if (!Match(id, "[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+")) throw new InstallationException(invalid, 503);
        try
        {
            var generation = new PluginGenerationReader(RuntimeRoot).Read(id);
            if (generation.Fenced && !allowDraining) throw new InstallationException("plugin_ui_updating", 503);
            string root = configuration["Sli:PluginUiDirectory"] ?? Environment.GetEnvironmentVariable("SLI_PLUGIN_UI_DIR")
                ?? Path.Combine(configuration["Sli:WebRoot"] ?? Path.Combine(AppContext.BaseDirectory, "web", "app"), "plugin-ui");
            string directory = generation.Generation is null ? LocalFile(root, id)
                : Path.Combine(RuntimeRoot!, id, "versions", generation.Generation, "ui");
            string descriptorFile = LocalFile(directory, "descriptor.json");
            if (new FileInfo(descriptorFile).Length > 65536) throw new InstallationException(invalid, 503);
            var descriptor = JsonNode.Parse(File.ReadAllText(descriptorFile, new UTF8Encoding(false, true)))!.AsObject();
            ValidateUi(descriptor, id);
            string asset = LocalFile(directory, descriptor["entry"]!["path"]!.GetValue<string>());
            using var stream = File.OpenRead(asset);
            using var output = new MemoryStream();
            byte[] buffer = new byte[65536];
            int read;
            while ((read = stream.Read(buffer)) > 0)
            {
                if (output.Length + read > 4 * 1024 * 1024) throw new InstallationException(invalid, 503);
                output.Write(buffer, 0, read);
            }
            byte[] payload = output.ToArray();
            _ = new UTF8Encoding(false, true).GetString(payload);
            if (Convert.ToHexStringLower(SHA256.HashData(payload)) != descriptor["entry"]!["sha256"]!.GetValue<string>())
                throw new InstallationException("plugin_ui_integrity_failed", 503);
            return new(descriptor, payload);
        }
        catch (FileNotFoundException) { throw new InstallationException("plugin_ui_not_installed", 404); }
        catch (DirectoryNotFoundException) { throw new InstallationException("plugin_ui_not_installed", 404); }
        catch (Exception e) when (e is IOException or JsonException or InvalidOperationException or ArgumentException or DecoderFallbackException or UnauthorizedAccessException)
        { throw new InstallationException(invalid, 503); }
    }
    public static string LocalFile(string root, string relative)
    {
        string path = Path.GetFullPath(root);
        foreach (string part in relative.Split('/'))
        {
            if (part is "" or "." or ".." || part.Contains('\\') || Path.IsPathRooted(part)) throw new InstallationException("plugin_ui_invalid_descriptor", 503);
            path = Path.Combine(path, part);
            if (new FileInfo(path).LinkTarget is not null || new DirectoryInfo(path).LinkTarget is not null)
                throw new InstallationException("plugin_ui_invalid_descriptor", 503);
        }
        return path;
    }
    public static bool Match(string value, string pattern) => Regex.IsMatch(value, "\\A(?:" + pattern + ")\\z", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    public static bool Keys(JsonObject value, params string[] keys) => value.Select(p => p.Key).ToHashSet(StringComparer.Ordinal).SetEquals(keys);
    public static string Text(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";
    public static void ValidateUi(JsonObject d, string id)
    {
        void Check(bool valid) { if (!valid) throw new InstallationException("plugin_ui_invalid_descriptor", 503); }
        Check(Text(d["plugin_id"]) == id);
        if (Text(d["ui_api"]) != "sli.plugin-ui.v1") throw new InstallationException("plugin_ui_unsupported_api", 503);
        Check(Keys(d, "plugin_id", "ui_api", "version", "routes", "entry", "required_capabilities") && Match(Text(d["version"]), @"\d+\.\d+\.\d+"));
        var routes = d["routes"] as JsonArray;
        Check(routes is { Count: > 0 and <= 32 } && routes.All(r => Text(r).StartsWith("/extensions/" + id + "/", StringComparison.Ordinal)
            && Match(Text(r)[("/extensions/" + id + "/").Length..], "[a-z0-9]+(?:[/-][a-z0-9]+)*"))
            && routes.Select(Text).Distinct().Count() == routes.Count);
        Check(d["entry"] is JsonObject entry && Keys(entry, "path", "sha256") && Match(Text(entry["path"]), "[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*\\.js")
            && Match(Text(entry["sha256"]), "[0-9a-f]{64}"));
        Check(d["required_capabilities"] is JsonArray caps && caps.Count <= 32 && caps.All(c => Match(Text(c), "[a-z][a-z0-9_.-]{0,95}"))
            && caps.Select(Text).Distinct().Count() == caps.Count);
    }

    // The vocabulary used by the bundled settings/manifests, with no executable references.
    public static void Shape(JsonNode? value, JsonObject node, JsonObject? schema = null)
    {
        schema ??= node;
        void Check(bool valid) { if (!valid) throw new InstallationException("invalid_plugin_setting_value"); }
        if (node["$ref"] is { } reference) { Shape(value, schema["$defs"]![Text(reference).Split('/').Last()]!.AsObject(), schema); return; }
        if (node["oneOf"] is JsonArray options)
        {
            int matches = 0;
            foreach (var option in options) { try { Shape(value, option!.AsObject(), schema); matches++; } catch (InstallationException) { } }
            Check(matches == 1);
        }
        if (node["type"] is { } declared)
        {
            string[] types = declared is JsonArray list ? list.Select(Text).ToArray() : [Text(declared)];
            using var doc = JsonDocument.Parse(value?.ToJsonString() ?? "null");
            var kind = doc.RootElement.ValueKind;
            Check(types.Any(t => t switch { "null" => value is null, "object" => value is JsonObject, "array" => value is JsonArray,
                "string" => kind == JsonValueKind.String, "boolean" => kind is JsonValueKind.True or JsonValueKind.False,
                "integer" => kind == JsonValueKind.Number && System.Numerics.BigInteger.TryParse(doc.RootElement.GetRawText(), out _), _ => false }));
        }
        if (node.ContainsKey("const")) Check(JsonNode.DeepEquals(value, node["const"]));
        if (node["enum"] is JsonArray enums) Check(enums.Any(v => JsonNode.DeepEquals(v, value)));
        if (value is null) return;
        if (value is JsonObject obj)
        {
            var props = node["properties"] as JsonObject ?? new();
            if (node["required"] is JsonArray required) Check(required.All(r => obj.ContainsKey(Text(r))));
            if (node["additionalProperties"] is JsonValue additional && additional.TryGetValue<bool>(out bool allow) && !allow) Check(obj.All(p => props.ContainsKey(p.Key)));
            foreach (var pair in obj)
            {
                if (node["propertyNames"] is JsonObject names) Shape(JsonValue.Create(pair.Key), names, schema);
                if (props[pair.Key] is JsonObject property) Shape(pair.Value, property, schema);
                else if (node["additionalProperties"] is JsonObject extra) Shape(pair.Value, extra, schema);
            }
        }
        else if (value is JsonArray array)
        {
            Check(array.Count >= (node["minItems"]?.GetValue<int>() ?? 0) && array.Count <= (node["maxItems"]?.GetValue<int>() ?? int.MaxValue));
            if (node["uniqueItems"]?.GetValue<bool>() == true)
                Check(!array.Select((a, i) => array.Skip(i + 1).Any(b => JsonNode.DeepEquals(a, b))).Any(v => v));
            foreach (var item in array) Shape(item, node["items"] as JsonObject ?? new(), schema);
        }
        else if (value is JsonValue scalar)
        {
            if (scalar.TryGetValue<string>(out var text))
                Check(text.EnumerateRunes().Count() >= (node["minLength"]?.GetValue<int>() ?? 0) && text.EnumerateRunes().Count() <= (node["maxLength"]?.GetValue<int>() ?? int.MaxValue)
                    && (node["pattern"] is null || Regex.IsMatch(text, Text(node["pattern"]), RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1))));
            else if (scalar.TryGetValue<decimal>(out var number))
                Check(number >= (node["minimum"]?.GetValue<decimal>() ?? decimal.MinValue) && number <= (node["maximum"]?.GetValue<decimal>() ?? decimal.MaxValue));
        }
    }

    public JsonObject? RadiusRoute()
    {
        try
        {
            return RadiusCollectionRoute.Load(ConfigRoot, RadiusCollectionRoute.EnvironmentValues());
        }
        catch (Exception e) when (e is IOException or JsonException or InvalidOperationException or ArgumentException) { return null; }
    }
    public long? CollectorInterval()
    {
        long fallback = 600;
        try
        {
            string path = Path.Combine(ConfigRoot, "adlog_config.yaml");
            bool collector = false;
            if (File.Exists(path)) foreach (string line in File.ReadLines(path))
            {
                string stripped = line.Split('#', 2)[0].TrimEnd();
                if (stripped.Length == 0) continue;
                if (!char.IsWhiteSpace(line[0]) && stripped.EndsWith(':')) { collector = stripped[..^1].Trim() == "collector"; continue; }
                if (!collector || !char.IsWhiteSpace(line[0])) continue;
                string[] pair = stripped.Trim().Split(':', 2);
                if (pair.Length != 2 || pair[0].Trim() != "interval_seconds") continue;
                string value = pair[1].Trim().Trim('"').Trim('\'');
                if (value is "" or "null" or "none" || value == "0") fallback = 600;
                else if (!long.TryParse(value, out fallback)) return null;
            }
            return long.TryParse(Environment.GetEnvironmentVariable("ADLOG_COLLECTOR_INTERVAL_SECONDS"), out long interval) ? interval : fallback;
        }
        catch (IOException) { return null; }
    }
}
