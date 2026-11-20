using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Jobs;

namespace Sli.Server.Vpn;

// One isolated child per cycle. Only its lifetime is unbounded; memory and the
// size of each protocol message remain bounded, as in the original plugin cell.
internal static class RadiusObservationProcess
{
    internal static async Task<JsonObject> RunAsync(ProcessStartInfo start, Func<JsonObject?, Task> heartbeat, CancellationToken ct, JsonObject? input = null)
    {
        using var process = new Process { StartInfo = start };
        using var io = new CancellationTokenSource();
        ct.ThrowIfCancellationRequested(); process.Start();
        Task<JsonObject>? output = null; Task? errors = null;
        JsonObject? progress = null, published = null;
        long peak = 0; var clock = Stopwatch.StartNew(); var nextBeat = TimeSpan.Zero;
        try {
            output = ReadAsync(process.StandardOutput.BaseStream, value => progress = value, io.Token);
            errors = process.StandardError.BaseStream.CopyToAsync(Stream.Null, io.Token);
            if (input is not null) await process.StandardInput.WriteAsync(input.ToJsonString().AsMemory(), ct);
            process.StandardInput.Close();
            while (!process.HasExited) {
                ct.ThrowIfCancellationRequested();
                if (output.IsFaulted) await output;
                if (SamplePeakMemory(process) is not long sample) break;
                peak = Math.Max(peak, sample);
                if (peak > 256L * 1024 * 1024) throw new InvalidOperationException("consumer_child_memory_exceeded");
                if (clock.Elapsed >= nextBeat || !ReferenceEquals(progress, published)) {
                    published = progress; await heartbeat(progress); nextBeat = clock.Elapsed + TimeSpan.FromSeconds(10);
                }
                await Task.Delay(100, ct);
            }
            // Close descendants before awaiting EOF: descendants must not keep protocol pipes alive.
            CoreJobProcess.KillGroup(process);
            var result = await output.WaitAsync(ct); await errors.WaitAsync(ct);
            if (progress is not null && !ReferenceEquals(progress, published)) await heartbeat(progress);
            if (result.Text("status") == "failed") throw new RadiusObservationFailure(result);
            if (process.ExitCode != 0 || result.Text("status") != "completed") throw new InvalidOperationException("consumer_cycle_failed");
            result = SafeProgress(result);
            result["resource_usage"] = new JsonObject { ["peak_memory_bytes"] = peak };
            return result;
        }
        finally {
            CoreJobProcess.KillGroup(process); io.Cancel();
            foreach (var task in new Task?[] { output, errors })
                if (task is not null) try { await task; } catch (Exception) { /* Child output is never logged. */ }
            await process.WaitForExitAsync(CancellationToken.None);
        }
    }

    internal static long? SamplePeakMemory(Process process)
    {
        try
        {
            process.Refresh();
            return process.PeakWorkingSet64;
        }
        catch (InvalidOperationException) when (process.HasExited)
        {
            // A child can exit after the loop's liveness check but before Process reads its metrics.
            return null;
        }
    }

    internal static async Task<JsonObject> ReadAsync(Stream stream, Action<JsonObject> progress, CancellationToken ct)
    {
        using var line = new MemoryStream(); byte[] buffer = new byte[4096]; JsonObject? result = null; int read;
        void Message() {
            if (line.Length == 0) return;
            JsonObject value;
            try { value = JsonNode.Parse(line.ToArray()) as JsonObject ?? throw new InvalidOperationException("cycle_result_invalid"); }
            catch (System.Text.Json.JsonException) { throw new InvalidOperationException("cycle_result_invalid"); }
            line.SetLength(0);
            if (result is not null || value["contains_secret_material"] is not JsonValue marker || !marker.TryGetValue<bool>(out bool secret) || secret)
                throw new InvalidOperationException("cycle_result_invalid");
            if (value.Text("status") == "running") progress(SafeProgress(value));
            else if (value.Text("status") is "completed" or "failed") result = value;
            else throw new InvalidOperationException("cycle_result_invalid");
        }
        while ((read = await stream.ReadAsync(buffer, ct)) > 0)
            for (int i = 0; i < read; i++) {
                if (buffer[i] == (byte)'\n') Message();
                else { if (line.Length >= 65536) throw new InvalidOperationException("cycle_result_invalid"); line.WriteByte(buffer[i]); }
            }
        Message(); return result ?? throw new InvalidOperationException("cycle_result_invalid");
    }

    internal static JsonObject SafeProgress(JsonObject value)
    {
        var result = new JsonObject { ["status"] = value.Text("status") };
        foreach (string key in new[] { "claimed", "processed", "cursor_delivery_id" }) {
            if (value[key] is not JsonValue item || !item.TryGetValue<long>(out long number) || number < 0) throw new InvalidOperationException("cycle_result_invalid");
            result[key] = number;
        }
        return result;
    }
}

internal sealed class RadiusObservationFailure(JsonObject failure) : Exception("consumer_cycle_failed")
{
    internal JsonObject Failure { get; } = failure;
}
