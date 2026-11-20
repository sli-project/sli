using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Semantic;

internal sealed record SigmaHistoryPartition(JsonObject Scope, string StorageKind, DateTimeOffset Start, DateTimeOffset End, string Snapshot, long HighWatermark)
{
    internal JsonObject Document => new() { ["scope"] = Scope.Copy(), ["storage_kind"] = StorageKind, ["start"] = SemanticJson.Stamp(Start), ["end"] = SemanticJson.Stamp(End), ["snapshot"] = Snapshot, ["high_watermark"] = HighWatermark };
    internal string Key => Password.PasswordJson.Hash(Document);
    internal void Validate()
    {
        if (StorageKind is not ("core_event" or "core_history" or "workstation_observation" or "workstation_history" or "file_audit") || Start >= End || End > new DateTimeOffset(Start.UtcDateTime.Date.AddDays(1), TimeSpan.Zero) || Snapshot.Length is < 1 or > 256 || HighWatermark < 0 || new[] { "installation_id", "source_instance_id", "source_generation" }.Any(k => string.IsNullOrWhiteSpace(Scope.Text(k)))) throw new InvalidDataException("sigma_history_partition_invalid");
    }
}
internal sealed record SigmaHistoryRecord(long Position, JsonObject Reference, JsonObject Scope, DateTimeOffset Occurred, SigmaEvent? Event, string[] QualityReasons, int EncodedBytes);
internal interface ISigmaHistoryReader
{
    // Store adapters enforce snapshot, scope and byte limits. An executing
    // read has no deadline; the caller yields between records at its checkpoint.
    Task<SigmaHistoryRecord?> ReadOneAsync(SigmaHistoryPartition partition, long after, int maxBytes, TimeSpan timeout, CancellationToken ct);
}
internal sealed record SigmaHistoryBudget(int Rows = 1000, int Bytes = 16777216, int EventBytes = 1048576, int Evaluations = 25000, int Seconds = 30, int CpuSeconds = 10, int JobRows = 100000, int Samples = 100);
internal sealed record SigmaHistoryResult(string Status, string Reason, JsonObject Checkpoint)
{
    internal string Mode => "test";
}
internal static class SigmaHistory
{
    internal static async Task<SigmaHistoryResult> RunAsync(string job, SigmaRule[] rules, SigmaHistoryPartition[] partitions, string manifestSha, ISigmaHistoryReader reader,
        Func<SigmaHistoryPartition, bool> authorized, Func<JsonObject, CancellationToken, Task> save, JsonObject? checkpoint = null, SigmaHistoryBudget? limits = null, CancellationToken ct = default)
    {
        var budget = limits ?? new();
        if (!Regex.IsMatch(job, @"\A[a-zA-Z0-9_-]{1,128}\z") || !Regex.IsMatch(manifestSha, @"\A[a-f0-9]{64}\z") || rules.Length is < 1 or > 25 || rules.Select(x => x.Id).Distinct().Count() != rules.Length || partitions.Length is < 1 or > 256 || partitions.Select(x => x.Key).Distinct().Count() != partitions.Length || partitions.Max(x => x.End) - partitions.Min(x => x.Start) > TimeSpan.FromDays(7) || budget.Rows is < 1 or > 10000 || budget.Bytes is < 1 or > 67108864 || budget.EventBytes is < 1 or > 4194304 || budget.Evaluations is < 1 or > 250000 || budget.Seconds is < 1 or > 60 || budget.CpuSeconds is < 1 or > 60 || budget.JobRows is < 1 or > 100000 || budget.Samples is < 1 or > 1000) throw new InvalidDataException("sigma_history_request_invalid");
        foreach (var part in partitions) part.Validate();
        for (int i = 0; i < partitions.Length; i++) if (partitions.Take(i).Any(old => JsonNode.DeepEquals(old.Scope, partitions[i].Scope) && partitions[i].Start < old.End && old.Start < partitions[i].End)) throw new InvalidDataException("sigma_history_partition_overlap");
        string request = Password.PasswordJson.Hash(new JsonObject { ["version"] = "sli.sigma.history.v1", ["matcher"] = "sli.sigma.matcher.v1", ["job"] = job, ["manifest"] = manifestSha, ["plans"] = new JsonArray(rules.Select(x => JsonValue.Create(x.PlanSha)).ToArray()), ["partitions"] = new JsonArray(partitions.Select(x => JsonValue.Create(x.Key)).ToArray()), ["match_limits"] = SigmaRule.MatchLimits });
        JsonObject Empty() => new() { ["request_sha256"] = request, ["partition_index"] = 0, ["after"] = 0, ["rows_read"] = 0, ["bytes_read"] = 0, ["deduplicated"] = 0, ["seen"] = new JsonArray(), ["counts"] = new JsonArray(), ["samples"] = new JsonArray() };
        var state = checkpoint is null ? Empty() : checkpoint.DeepClone().AsObject();
        if (state.Text("request_sha256") != request || state.Number("partition_index") < 0 || state.Number("partition_index") > partitions.Length || state.Number("rows_read") < 0 || state.Number("rows_read") > budget.JobRows || state.Number("after") < 0 || state["seen"]!.AsArray().Count > budget.JobRows || state["samples"]!.AsArray().Count > budget.Samples || state.Number("partition_index") < partitions.Length && state.Number("after") > partitions[(int)state.Number("partition_index")].HighWatermark) throw new InvalidDataException("sigma_history_checkpoint_mismatch");
        bool Access() { try { return partitions.All(authorized); } catch { return false; } }
        SigmaHistoryResult Result(string status, string reason) => Access() ? new(status, reason, state) : new("failed", "permission_denied", Empty());
        var wall = Stopwatch.StartNew(); var process = Process.GetCurrentProcess(); var cpu = process.TotalProcessorTime; int rows = 0, bytes = 0, evaluations = 0;
        var seen = state["seen"]!.AsArray().Select(x => x!.GetValue<string>()).ToHashSet();
        var counts = state["counts"]!.AsArray().ToDictionary(x => (x.Text("partition_key")!, x.Text("rule_id")!), x => x!.DeepClone().AsObject());
        async Task<bool> Commit(JsonObject candidate) { if (!Access()) return false; await save(candidate.DeepClone().AsObject(), ct); state = candidate; return true; }
        JsonObject Count(string part, string rule) => counts.TryGetValue((part, rule), out var row) ? row.DeepClone().AsObject() : new JsonObject { ["partition_key"] = part, ["rule_id"] = rule, ["scanned"] = 0, ["evaluable"] = 0, ["matched"] = 0, ["suppressed"] = 0, ["unknown"] = 0, ["skipped"] = 0, ["reasons"] = new JsonArray(), ["unknown_fields"] = new JsonArray(), ["first_occurred_at"] = null, ["last_occurred_at"] = null };
        try
        {
            while (state.Number("partition_index") < partitions.Length)
            {
                if (!Access()) return Result("failed", "permission_denied"); if (ct.IsCancellationRequested) return Result("cancelled", "cancel_requested");
                if (wall.Elapsed.TotalSeconds >= budget.Seconds) return Result("partial", "time_budget"); if ((process.TotalProcessorTime - cpu).TotalSeconds >= budget.CpuSeconds) return Result("partial", "cpu_budget");
                var part = partitions[(int)state.Number("partition_index")]; long after = state.Number("after"); SigmaHistoryRecord? record = null;
                if (after != part.HighWatermark)
                {
                    if (rows >= budget.Rows) return Result("partial", "row_budget"); if (state.Number("rows_read") >= budget.JobRows) return Result("partial", "job_row_budget"); if (evaluations + rules.Length > budget.Evaluations) return Result("partial", "evaluation_budget"); if (bytes >= budget.Bytes) return Result("partial", "byte_budget");
                    record = await reader.ReadOneAsync(part, after, Math.Min(budget.EventBytes, budget.Bytes - bytes), Timeout.InfiniteTimeSpan, ct);
                }
                if (!Access()) return Result("failed", "permission_denied");
                if (record is null)
                {
                    foreach (var rule in rules) counts[(part.Key, rule.Id)] = Count(part.Key, rule.Id);
                    var finished = state.DeepClone().AsObject(); finished["partition_index"] = state.Number("partition_index") + 1; finished["after"] = 0; finished["counts"] = SemanticJson.Array(counts.OrderBy(x => x.Key).Select(x => x.Value)); if (!await Commit(finished)) return Result("failed", "permission_denied"); continue;
                }
                if (!(after < record.Position && record.Position <= part.HighWatermark) || !JsonNode.DeepEquals(record.Scope, part.Scope) || record.Reference.Text("storage_kind") != part.StorageKind || record.Reference.Text("native_id")?.Length is not (> 0 and <= 256) || !Regex.IsMatch(record.Reference.Text("sha256") ?? "", @"\A[a-f0-9]{64}\z") || record.Occurred < part.Start || record.Occurred >= part.End || record.Event is { } mapped && mapped.At != record.Occurred || record.QualityReasons.Length > 32 || record.QualityReasons.Any(x => !Regex.IsMatch(x, @"\A[a-z][a-z0-9_]{0,63}\z"))) return Result("failed", "reader_contract_invalid");
                if (record.EncodedBytes > budget.EventBytes || record.EncodedBytes <= 0) return Result("failed", "event_byte_budget"); if (bytes + record.EncodedBytes > budget.Bytes) return Result("partial", "byte_budget");
                rows++; bytes += record.EncodedBytes; var candidate = state.DeepClone().AsObject(); candidate["after"] = record.Position; candidate["rows_read"] = state.Number("rows_read") + 1; candidate["bytes_read"] = state.Number("bytes_read") + record.EncodedBytes;
                string identity = Password.PasswordJson.Hash(new JsonArray(part.Scope.Copy(), record.Reference.Copy()));
                if (!seen.Add(identity)) { candidate["deduplicated"] = state.Number("deduplicated") + 1; if (!await Commit(candidate)) return Result("failed", "permission_denied"); continue; }
                var samples = candidate["samples"]!.AsArray();
                foreach (var rule in rules)
                {
                    evaluations++; string status; string[] reasons; string replay = "";
                    if (record.Event is null || record.QualityReasons.Length > 0) { status = "not_evaluable"; reasons = record.QualityReasons.Length > 0 ? record.QualityReasons : ["payload_unavailable"]; }
                    else if (rule.LogSource == "process_creation" ? record.Event.Channel != "Security" || record.Event.Id != 4688 : !string.Equals(record.Event.Channel, rule.LogSource, StringComparison.OrdinalIgnoreCase)) { status = "skipped"; reasons = []; }
                    else { var matched = rule.Evaluate(record.Event.Fields, record.Event.Unavailable); status = matched.Status; reasons = matched.Reasons; replay = matched.ReplaySha; }
                    var count = Count(part.Key, rule.Id); count["scanned"] = count.Number("scanned") + 1;
                    string category = status is "matched" or "not_matched" ? "evaluable" : status == "skipped" ? "skipped" : "unknown"; count[category] = count.Number(category) + 1; if (status == "matched") count["matched"] = count.Number("matched") + 1;
                    string stamp = SemanticJson.Stamp(record.Occurred); if (count.Text("first_occurred_at") is null || SigmaProjection.At(count, "first_occurred_at") > record.Occurred) count["first_occurred_at"] = stamp; if (count.Text("last_occurred_at") is null || SigmaProjection.At(count, "last_occurred_at") < record.Occurred) count["last_occurred_at"] = stamp;
                    counts[(part.Key, rule.Id)] = count;
                    var reasonCounts = count["reasons"]!.AsArray().ToDictionary(x => x![0]!.GetValue<string>(), x => x![1]!.GetValue<long>());
                    foreach (string reason in reasons) reasonCounts[reason] = reasonCounts.GetValueOrDefault(reason) + 1;
                    count["reasons"] = new JsonArray(reasonCounts.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => (JsonNode)new JsonArray(x.Key, x.Value)).ToArray());
                    if (status == "not_evaluable" && record.Event is not null)
                    {
                        var unknown = count["unknown_fields"]!.AsArray().ToDictionary(x => (x![0]!.GetValue<string>(), x[1]!.GetValue<string>()), x => x![2]!.GetValue<long>());
                        foreach (string name in rule.Fields)
                        {
                            string? reason = record.Event.Unavailable.Contains(name) ? "field_unavailable" : !record.Event.Fields.ContainsKey(name) ? "field_missing" : record.Event.Fields[name] is null ? "field_null" : null;
                            if (reason is not null) unknown[(name, reason)] = unknown.GetValueOrDefault((name, reason)) + 1;
                        }
                        count["unknown_fields"] = new JsonArray(unknown.OrderBy(x => x.Key).Select(x => (JsonNode)new JsonArray(x.Key.Item1, x.Key.Item2, x.Value)).ToArray());
                    }
                    if (status == "matched" && samples.Count < budget.Samples) samples.Add(new JsonObject { ["partition_key"] = part.Key, ["rule_id"] = rule.Id, ["ref"] = record.Reference.Copy(), ["replay_sha256"] = replay });
                }
                candidate["seen"] = new JsonArray(seen.Order(StringComparer.Ordinal).Select(x => JsonValue.Create(x)).ToArray()); candidate["counts"] = SemanticJson.Array(counts.OrderBy(x => x.Key).Select(x => x.Value)); if (!await Commit(candidate)) return Result("failed", "permission_denied");
            }
            return Result("completed", "snapshot_exhausted");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return Result("cancelled", "cancel_requested"); }
        catch (TimeoutException) { return Result("partial", "read_timeout"); }
        catch { return Result("failed", "history_job_failed"); }
    }
}
