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

    internal static JsonObject Record(LifecycleFiles files, DateTime observed, long bytes, JsonObject? volume = null)
    {
        var sample = new JsonObject { ["database_bytes"] = bytes, ["observed_at_utc"] = LifecycleJson.Iso(observed) };
        if (bytes <= 0) return sample;
        if (volume is not null) sample["postgres_volume"] = volume.DeepClone();

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

    internal static double? VolumeForecastDays(string dataRoot, DateTime now, JsonObject? volume)
    {
        if (volume is null) return null;
        string mount = LifecycleJson.Text(volume, "mount_point");
        if (mount.Length == 0 || !TryBytes(volume, "total_bytes", out long total) || total <= 0
            || !TryBytes(volume, "free_bytes", out long free) || free > total) return null;

        var files = new LifecycleFiles(dataRoot);
        var samples = new List<(DateTime Time, long Used)>();
        for (int offset = 0; offset <= 48; offset += 6)
        {
            var sample = ReadSample(files, Slot(now.AddHours(-offset)));
            if (sample?["postgres_volume"] is not JsonObject disk
                || LifecycleJson.Text(disk, "mount_point") != mount
                || !TryBytes(disk, "total_bytes", out long measuredTotal) || measuredTotal != total
                || !TryBytes(disk, "used_bytes", out long used) || used > total
                || !DateTimeOffset.TryParse(LifecycleJson.Text(sample, "observed_at_utc"), CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var observed) || observed.UtcDateTime > now) continue;
            samples.Add((observed.UtcDateTime, used));
        }
        if (samples.Count < 2 || now - samples[0].Time > TimeSpan.FromHours(12)) return null;
        var latest = samples[0];
        var baseline = samples.Skip(1).Select(sample => (Elapsed: (latest.Time - sample.Time).TotalHours, sample.Used))
            .Where(sample => sample.Elapsed is >= 18 and <= 36)
            .OrderBy(sample => Math.Abs(24 - sample.Elapsed)).FirstOrDefault();
        long growth = latest.Used - baseline.Used;
        return baseline.Elapsed == 0 || growth <= 0 ? null : free * (baseline.Elapsed / 24) / growth;
    }

    static bool TryBytes(JsonObject row, string key, out long bytes)
    {
        bytes = 0;
        return row[key] is JsonValue value && value.TryGetValue(out bytes) && bytes >= 0;
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
