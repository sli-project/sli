using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Compatibility;

namespace Sli.Server.Legacy;

// The pilot's source contract, independent of Python executable/argv and its
// retired event/time budgets. Acquisition must preserve this source identity.
public sealed record NpsCollectionRequest(string Source, string StartTimeUtc, string EndTimeUtc)
{
    public string ConnectAddress => Source;
    public string[] Channels => ["Security"];
    public int[] EventIds => [6272, 6273];
    public bool Archive => true;
    public bool UseRecordIdCursor => true;
    public string AdaptiveStateMode => "observe";
    public bool CollectMessage => false;
    public string CredentialMode => "dpapi_current_user";
    public bool NoTechnicalReport => true;
}

// Like PostCollectionLoop, I/O lives below the loop. A heartbeat tick is an
// observation interval, never a deadline or permission to start another reader.
public sealed class NpsWorkerStage(Func<string?> enabled,
    Func<CancellationToken, Task<string?>> source,
    Func<string, CancellationToken, Task<string?>> cursor,
    Func<NpsCollectionRequest, CancellationToken, Task<JsonObject>> collect,
    Func<CancellationToken, Task>? tick = null)
{
    public async Task<JsonObject> RunAsync(string[] dcServers, Func<JsonObject, Task>? heartbeat, CancellationToken ct)
    {
        string value = PythonText.Strip(enabled() ?? "");
        if (value is "" or "0") return new() { ["status"] = "disabled" };
        if (value != "1") throw new InvalidOperationException("nps_eventlog_enabled_value_invalid");
        ct.ThrowIfCancellationRequested();
        string? name = await source(ct);
        if (name is null) return new() { ["status"] = "not_installed", ["phase"] = "nps", ["reason"] = "plugin_not_installed" };
        if (dcServers.Any(dc => Sli.Server.Agents.Registry.UnicodeCaseFold.Fold(PythonText.Strip(dc ?? ""))
            == Sli.Server.Agents.Registry.UnicodeCaseFold.Fold(name)))
            throw new InvalidOperationException("nps_eventlog_dc_target_overlap");
        string start = PythonText.Strip(await cursor(name, ct) ?? "");
        if (start.Length == 0) throw new InvalidOperationException("nps_eventlog_security_cursor_missing");
        var watch = Stopwatch.StartNew();
        using var observation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        try {
            var pending = collect(new(name, start, DateTimeOffset.UtcNow.ToString("O")), ct);
            while (!pending.IsCompleted) {
                var next = (tick ?? (token => Task.Delay(TimeSpan.FromSeconds(30), token)))(observation.Token);
                if (await Task.WhenAny(pending, next) == pending) break;
                await next;
                ct.ThrowIfCancellationRequested();
                if (heartbeat is not null) await heartbeat(new() { ["status"] = "running", ["phase"] = "nps", ["source"] = name });
            }
            var result = (await pending).DeepClone().AsObject();
            if (result["status"]?.GetValue<string>() is not ("completed" or "partial" or "failed"))
                return new() { ["status"] = "failed", ["phase"] = "nps", ["source"] = name,
                    ["reason"] = "nps_eventlog_collection_failed", ["duration_ms"] = watch.ElapsedMilliseconds };
            result["phase"] = "nps"; result["source"] = name;
            result["duration_ms"] ??= JsonValue.Create(watch.ElapsedMilliseconds);
            return result;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) {
            var failure = NpsFailure.Classify(error); failure["source"] = name;
            failure["duration_ms"] = watch.ElapsedMilliseconds; return failure;
        }
        finally { await observation.CancelAsync(); }
    }
}

public sealed class NpsWorkerCycle(Func<CancellationToken, Task<JsonObject>> runNps,
    Func<JsonObject, CancellationToken, Task> history,
    Func<string, int, string, JsonObject, CancellationToken, Task> block)
{
    public async Task<JsonObject> CompleteAsync(JsonObject dc, string worker, int job, CancellationToken ct)
    {
        var result = dc.DeepClone().AsObject();
        string status = result["status"]!.GetValue<string>();
        if (status is not ("completed" or "partial")) { await history(result, ct); return result; }
        // Collection is still owned by this cycle. Do not expose terminal DC
        // history while its serial supplemental stage is in progress.
        var running = result.DeepClone().AsObject(); running["status"] = "running"; running["phase"] = "collection";
        await history(running, ct);
        JsonObject nps;
        try { nps = await runNps(ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) { nps = NpsFailure.Classify(error); }
        string? npsStatus = nps["status"]?.GetValue<string>();
        if (npsStatus != "disabled") {
            result["nps"] = nps.DeepClone(); result["dc_status"] = status; result["phase"] = "nps";
            result["duration_ms"] = (dc["duration_ms"]?.GetValue<long>() ?? 0) + (nps["duration_ms"]?.GetValue<long>() ?? 0);
        }
        if (npsStatus == "partial") result["status"] = "partial";
        else if (npsStatus == "failed") {
            bool blocked = nps["blocked"]?.GetValue<bool>() == true;
            if (blocked) await block(worker, job, nps["source"]?.GetValue<string>() ?? "nps", nps, ct);
            result["status"] = blocked ? "blocked" : "failed";
            result["reason"] = nps["reason"]?.DeepClone();
            if (blocked) result["operator_action"] = nps["operator_action"]?.DeepClone();
        }
        await history(result, ct);
        return result;
    }
}

internal static class NpsFailure
{
    // Never retain exception text: it can include credentials or event data.
    internal static JsonObject Classify(Exception error)
    {
        string[] terminal = ["ad_source_backend_unsupported", "ad_source_credential_mode_invalid", "ad_source_credential_profile_invalid",
            "ad_source_credentials_unavailable", "ad_source_endpoint_invalid", "windows_event_log_access_denied", "windows_event_log_authentication_failed"];
        string? code = terminal.FirstOrDefault(code => error.Message.Contains(code, StringComparison.OrdinalIgnoreCase));
        var numeric = System.Text.RegularExpressions.Regex.Matches(error.Message, @"(?:winerror\s+|\(\s*)(\d+)\b",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase).Select(match => int.TryParse(match.Groups[1].Value, out int n) ? n : -1).ToHashSet();
        if (error is System.ComponentModel.Win32Exception native) numeric.Add(native.NativeErrorCode & 0xffff);
        if (numeric.Overlaps(new[] { 1317, 1326, 1327, 1328, 1329, 1330, 1331, 1385, 1793, 1907, 1909 }))
            code ??= "windows_event_log_authentication_failed";
        bool context = numeric.Contains(1749) || new[] { "windows_security_context_invalid", "winerror 1749",
            "неправильный контекст безопасности", "контекст безопасности устарел", "the security context is invalid", "the security context has expired" }
            .Any(marker => error.Message.Contains(marker, StringComparison.OrdinalIgnoreCase));
        return new() { ["status"] = "failed", ["phase"] = "nps", ["duration_ms"] = 0L,
            ["reason"] = code ?? (context ? "windows_security_context_invalid" : "nps_eventlog_stage_failed"),
            ["blocked"] = code is not null || context,
            ["operator_action"] = code is not null || context
                ? "Исправьте учётные данные и доступ к источнику; выполните контрольную проверку collection_block_control. Автоматический повтор отключён." : null };
    }
}
