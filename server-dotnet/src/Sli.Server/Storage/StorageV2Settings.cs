using System.Globalization;
using System.Text.Json.Nodes;

namespace Sli.Server.Storage;

internal sealed record StorageV2Settings(string ReadMode, string WriteMode, double ShadowSampleRate,
    bool Valid, IReadOnlyList<string> Diagnostics)
{
    internal bool V2ReadEnabled => Valid && ReadMode == "v2";
    internal bool ShadowReadEnabled => Valid && ReadMode == "shadow" && ShadowSampleRate > 0;
    internal bool OutboxEnabled => Valid && WriteMode is "v1_outbox" or "v2_primary_compat" or "v2";
    internal bool V2PrimaryWriteEnabled => Valid && WriteMode is "v2_primary_compat" or "v2";

    internal JsonObject PublicValues() => new()
    {
        ["read_mode"] = ReadMode, ["write_mode"] = WriteMode, ["shadow_sample_rate"] = ShadowSampleRate,
        ["valid"] = Valid, ["diagnostics"] = new JsonArray(Diagnostics.Select(s => JsonValue.Create(s)).ToArray())
    };

    internal static StorageV2Settings Load(Func<string, string, string>? setting = null, bool strict = false)
    {
        setting ??= (key, fallback) => Environment.GetEnvironmentVariable(key) ?? fallback;
        string read = setting("ADLOG_STORAGE_READ_MODE", "v2").Trim().ToLowerInvariant();
        string write = setting("ADLOG_STORAGE_WRITE_MODE", "v1").Trim().ToLowerInvariant();
        List<string> diagnostics = [];
        // Do not reflect untrusted configuration values into diagnostics.
        if (read is not ("v1" or "shadow" or "v2")) diagnostics.Add("invalid ADLOG_STORAGE_READ_MODE");
        if (write is not ("v1" or "v1_outbox" or "v2_primary_compat" or "v2")) diagnostics.Add("invalid ADLOG_STORAGE_WRITE_MODE");
        if (!double.TryParse(setting("ADLOG_STORAGE_V2_SHADOW_SAMPLE_RATE", "0").Trim(), NumberStyles.Float,
                CultureInfo.InvariantCulture, out double rate)) rate = -1;
        if (!(rate is >= 0 and <= 1)) diagnostics.Add("ADLOG_STORAGE_V2_SHADOW_SAMPLE_RATE must be between 0 and 1");
        if (read == "shadow" && rate <= 0) diagnostics.Add("shadow read mode requires a positive sample rate");
        if (write is "v1_outbox" or "v2_primary_compat")
            diagnostics.Add("ADLOG_STORAGE_WRITE_MODE cannot select V2 publication; controller authorization is required");
        if (diagnostics.Count == 0) return new(read, write, rate, true, Array.Empty<string>());
        string message = "Storage V2 configuration rejected; fail-closed V1 routing: " + string.Join("; ", diagnostics);
        if (strict) throw new ArgumentException(message);
        return new("v2", "v1", 0, false, new[] { message });
    }
}
