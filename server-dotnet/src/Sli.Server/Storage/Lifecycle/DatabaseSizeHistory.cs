using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Storage.Lifecycle;

internal static class DatabaseSizeHistory
{
    const string DirectoryName = "storage-database-history";
    const int MaxSampleBytes = 1024;

    static string Slot(DateTime observed)
    {
        int hour = observed.Hour / 6 * 6;
        return string.Create(CultureInfo.InvariantCulture, $"{observed:yyyyMMdd}{hour:00}.json");
    }

    internal static JsonObject Record(LifecycleFiles files, DateTime observed, long bytes)
    {
        var sample = new JsonObject { ["database_bytes"] = bytes, ["observed_at_utc"] = LifecycleJson.Iso(observed) };
        if (bytes <= 0) return sample;

        string slot = Slot(observed);
        string name = Path.Combine(DirectoryName, slot);
        try
        {
            // Keep the first real measurement in each UTC six-hour interval.
            files.Write(name, sample, replace: false);
            return sample;
        }
        catch (IOException)
        {
            if (ReadSample(files, slot) is {} existing) return existing;
            throw;
        }
    }

    static JsonObject? ReadSample(LifecycleFiles files, string slot)
    {
        try
        {
            var sample = files.Read(Path.Combine(DirectoryName, slot), MaxSampleBytes);
            if (sample?["database_bytes"] is not JsonValue size || !size.TryGetValue<long>(out long bytes) || bytes <= 0)
                return null;
            if (!DateTimeOffset.TryParse(LifecycleJson.Text(sample, "observed_at_utc"), CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var observed) || Slot(observed.UtcDateTime) != slot)
                return null;
            return sample;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or LifecycleBlocked)
        {
            return null;
        }
    }

    internal static JsonObject Read(string dataRoot, int limit)
    {
        var files = new LifecycleFiles(dataRoot);
        string directory = Path.Combine(files.Root, "runtime", DirectoryName);
        var samples = new JsonArray();
        try
        {
            foreach (string path in Directory.EnumerateFiles(directory, "*.json").OrderDescending(StringComparer.Ordinal).Take(limit))
            {
                if (ReadSample(files, Path.GetFileName(path)) is not {} sample) continue;
                samples.Add(new JsonObject
                {
                    ["captured_at"] = sample["observed_at_utc"]?.DeepClone(),
                    ["database_bytes"] = sample["database_bytes"]?.DeepClone(),
                });
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // The independent legacy storage summary can still be served.
        }

        return new JsonObject
        {
            ["latest_snapshot"] = samples.FirstOrDefault()?.DeepClone(),
            ["samples"] = samples,
        };
    }
}
