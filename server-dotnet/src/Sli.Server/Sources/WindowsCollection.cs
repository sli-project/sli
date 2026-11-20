using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Sources;

public interface ICollectionBlockStore
{
    Task<string?> ActiveAsync(CancellationToken ct);
    Task ActivateAsync(CollectionFailure failure, string server, string worker, CancellationToken ct);
    Task ClearAsync(string server, string actor, CancellationToken ct);
}
public sealed record CollectionIdentity(string Principal, string Sid, int SessionId, string? Error = null)
{
    public bool Interactive => SessionId != 0;
    public bool Matches(string? principal, string? sid) => Error is null && Interactive && !string.IsNullOrWhiteSpace(principal)
        && !string.IsNullOrWhiteSpace(sid) && string.Equals(Principal,principal.Trim(),StringComparison.OrdinalIgnoreCase)
        && string.Equals(Sid,sid.Trim(),StringComparison.OrdinalIgnoreCase);
}

public sealed class WindowsCollection(AdSourceAuth auth, IWindowsEventLog events, ICollectionBlockStore blocks,
    Func<CollectionIdentity> identity, Func<string,string?> environment)
{
    private static JsonObject Failure(string code) => new() { ["status"]="failed", ["failure_code"]=code, ["reason"]=code };
    public async Task<JsonObject> PreflightAsync(string server, string worker, CancellationToken ct)
    {
        string? active = await blocks.ActiveAsync(ct);
        if (active is not null && CollectionFailurePolicy.CredentialCodes.Contains(active)) return Failure(active);
        try {
            if (!identity().Matches(environment("ADLOG_COLLECTION_PRINCIPAL"),environment("ADLOG_COLLECTION_PRINCIPAL_SID")))
                throw new CollectionSourceException("windows_security_context_invalid");
            string mode = AdSourceAuth.ValidateMode(environment(AdSourceAuth.ModeKey) ?? AdSourceAuth.Process,environment("ADLOG_COLLECTOR_BACKEND") ?? "auto");
            return Probe(server,mode);
        }
        catch (Exception e) {
            var decision = CollectionFailurePolicy.Classify(CollectionFailurePolicy.Sanitize(e));
            if (decision.Blocked) await blocks.ActivateAsync(decision,server,worker,ct);
            return Failure(decision.Code ?? "windows_context_preflight_failed");
        }
    }
    private JsonObject Probe(string server, string mode)
    {
        using var session = auth.Open(server,mode,configuredDc:true);
        var latest = events.Latest(session,"Security");
        return new() { ["status"]="ok", ["server"]=server, ["channel"]="Security", ["query_access"]="verified", ["event_observed"]=latest is not null };
    }
    public async Task<JsonObject> RecoverAsync(string server, string? explicitMode, string actor, CancellationToken ct)
    {
        string? active = await blocks.ActiveAsync(ct);
        if (active is not null && CollectionFailurePolicy.CredentialCodes.Contains(active) && explicitMode is null)
            return Failure("ad_source_recovery_mode_required");
        try {
            string mode = AdSourceAuth.ValidateMode(explicitMode ?? AdSourceAuth.Process,environment("ADLOG_COLLECTOR_BACKEND") ?? "auto");
            // An explicit recovery must use the same local owner guard as the worker.
            if (!identity().Matches(environment("ADLOG_COLLECTION_PRINCIPAL"),environment("ADLOG_COLLECTION_PRINCIPAL_SID")))
                throw new CollectionSourceException("windows_security_context_invalid");
            var result = Probe(server,mode);
            await blocks.ClearAsync(server,actor,ct);
            return result;
        }
        catch (Exception e) { return Failure(CollectionFailurePolicy.Sanitize(e).Code); }
    }
    public async Task<JsonObject> RunCycleAsync(string server, string worker, Func<CancellationToken,Task<JsonObject>> createJob, CancellationToken ct)
    {
        string? active = await blocks.ActiveAsync(ct);
        if (active is not null) return new() { ["status"]="blocked", ["reason"]=active };
        var result = await PreflightAsync(server,worker,ct);
        return result["status"]!.GetValue<string>() == "ok" ? await createJob(ct) : result;
    }

    // Cursor/record query/post-probe share one session and have no retry/fallback.
    public JsonObject CollectChannel(string server, string channel, string mode, string xpath, Action? heartbeat, CancellationToken ct)
    {
        try {
            using var session = auth.Open(server,mode);
            var before = events.Probe(session,channel);
            var rows = events.Read(session,channel,xpath,heartbeat,ct);
            var after = events.Probe(session,channel);
            bool consistent = before.GenerationIdentity == after.GenerationIdentity
                && (before.OldestRecordId is null || after.OldestRecordId <= before.OldestRecordId)
                && (before.LatestRecordId is null || after.LatestRecordId >= before.LatestRecordId);
            return new() { ["channel"]=channel, ["status"]="ok", ["count"]=rows.Count,
                ["cursor_commit_allowed"]=consistent, ["events"]=JsonSerializer.SerializeToNode(rows) };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) {
            Exception safe = mode == AdSourceAuth.Dpapi ? CollectionFailurePolicy.Sanitize(error) : error;
            var decision = CollectionFailurePolicy.Classify(safe);
            var result = decision.Fields(); result["channel"]=channel; result["status"]="failed";
            result["count"]=0; result["cursor_commit_allowed"]=false;
            result["failure_code"]=decision.Code ?? "ad_source_rpc_failed";
            return result;
        }
    }
    public async Task<JsonObject> CollectAsync(IEnumerable<string> servers, IReadOnlyList<string> channels, string mode,
        string worker, Func<string,JsonObject,CancellationToken,Task> import, Action? heartbeat, CancellationToken ct)
    {
        AdSourceAuth.ValidateMode(mode,environment("ADLOG_COLLECTOR_BACKEND") ?? "auto");
        var batches = new JsonArray(); bool failed = false;
        foreach (string server in servers) {
            if (await blocks.ActiveAsync(ct) is { } active) return new() { ["status"]="blocked", ["reason"]=active, ["batches"]=batches };
            var results = new JsonArray(); CollectionFailure? terminal = null;
            foreach (string channel in channels) {
                if (terminal is not null) { results.Add(new JsonObject { ["channel"]=channel, ["status"]="not_attempted" }); continue; }
                var result = CollectChannel(server,channel,mode,"*",heartbeat,ct); results.Add(result);
                var decision = CollectionFailurePolicy.Classify(result["failure_code"]?.ToString());
                if (decision.Blocked) terminal = decision;
            }
            bool allowed = terminal is null && results.OfType<JsonObject>().All(x => x["cursor_commit_allowed"]?.GetValue<bool>() == true);
            failed |= !allowed;
            var batch = new JsonObject { ["server"]=server, ["channels"]=results, ["cursor_advanced"]=false,
                ["terminal_block"]=terminal is not null, ["import_allowed"]=allowed, ["import_attempted"]=false };
            batches.Add(batch);
            if (terminal is not null) {
                // Durable activation completes before any subsequent DC, import or cursor commit.
                await blocks.ActivateAsync(terminal,server,worker,ct);
                return new() { ["status"]="blocked", ["exit_code"]=74, ["batches"]=batches };
            }
            if (allowed) { batch["import_attempted"]=true; await import(server,batch,ct); }
        }
        return new() { ["status"]=failed ? "failed" : "ok", ["batches"]=batches };
    }
    public static async Task WriteBlockMarkerAsync(string directory, JsonObject batch, CancellationToken ct)
    {
        var marker = new JsonObject { ["terminal_block"]=true, ["import_allowed"]=false, ["import_attempted"]=false,
            ["cursor_advanced"]=false, ["server"]=batch["server"]?.DeepClone() };
        string path = Path.Combine(directory,"collection-blocked.json"), temporary = path + "." + Guid.NewGuid().ToString("N");
        try { await File.WriteAllTextAsync(temporary,marker.ToJsonString(),ct); File.Move(temporary,path,true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
