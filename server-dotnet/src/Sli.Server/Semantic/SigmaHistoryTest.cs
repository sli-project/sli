using System.Data;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Semantic;

internal sealed record SigmaHistoryTestSelection(JsonObject Scope, DateTimeOffset Start, DateTimeOffset End, int[] Kinds);

internal sealed class SigmaHistoryTest : ISigmaHistoryReader, IAsyncDisposable
{
    private const string ScopeSql = "select public.sigma_test_scope_allowed411($1,$2)";
    private const string CeilingSql = "select public.sigma_test_ceiling411($1,$2,$3,$4)";
    private const string NextSql = "select * from public.sigma_test_next411($1,$2,$3,$4,$5,$6)";
    private const string PayloadSql = "select * from public.sigma_test_payload411($1,$2,$3,$4,$5,$6,$7)";
    private const string PermissionDenied = "permission_denied";
    private const string SnapshotChanged = "sigma_test_snapshot_changed";
    private readonly string job;
    private readonly string manifestSha;
    private readonly SigmaRule[] rules;
    private readonly Dictionary<string, int> ruleKinds;
    private readonly NpgsqlConnection access;
    private readonly NpgsqlConnection enumerator;
    private readonly NpgsqlTransaction snapshot;
    private readonly SigmaHistoryPartition[] partitions;
    private readonly Dictionary<string, SigmaHistoryTestSelection> selections;
    private readonly SemaphoreSlim pageGate = new(1);
    private JsonObject? checkpoint;
    private string? failure;
    private int eventBytes;

    private sealed record Candidate(long Id, DateTimeOffset At, int Kind, string Channel, string? Provider,
        long? RecordId, string Sha, string? RepresentationSha);

    private SigmaHistoryTest(string job, string manifestSha, SigmaRule[] rules, Dictionary<string, int> ruleKinds,
        NpgsqlConnection access, NpgsqlConnection enumerator, NpgsqlTransaction snapshot,
        SigmaHistoryPartition[] partitions, Dictionary<string, SigmaHistoryTestSelection> selections)
    {
        this.job = job;
        this.manifestSha = manifestSha;
        this.rules = rules;
        this.ruleKinds = ruleKinds;
        this.access = access;
        this.enumerator = enumerator;
        this.snapshot = snapshot;
        this.partitions = partitions;
        this.selections = selections;
    }

    internal static async Task<SigmaHistoryTest> OpenAsync(NpgsqlDataSource source, string job, string manifestSha,
        SigmaRule[] rules, SigmaHistoryTestSelection[] selections, CancellationToken ct)
    {
        if (!Regex.IsMatch(job, @"\A[a-zA-Z0-9_-]{1,128}\z") || !Regex.IsMatch(manifestSha, @"\A[a-f0-9]{64}\z")
            || rules.Length is < 1 or > 25 || rules.Select(rule => rule.Id).Distinct().Count() != rules.Length
            || selections.Length is < 1 or > 256 || selections.Max(s => s.End) - selections.Min(s => s.Start) > TimeSpan.FromDays(7))
            throw new InvalidDataException("sigma_history_request_invalid");

        string snapshotId = Guid.NewGuid().ToString("N");
        var kinds = rules.ToDictionary(rule => rule.Id, PilotKind);
        var inputs = selections.Select(s => s with
        {
            Scope = s.Scope.DeepClone().AsObject(),
            Start = s.Start.ToUniversalTime(),
            End = s.End.ToUniversalTime(),
            Kinds = s.Kinds.Distinct().Order().ToArray()
        }).ToArray();
        var partitions = inputs.Select(s => new SigmaHistoryPartition(s.Scope, "core_event", s.Start, s.End, snapshotId, 0)).ToArray();
        for (int i = 0; i < inputs.Length; i++)
        {
            var s = inputs[i];
            partitions[i].Validate();
            if (s.Start.Ticks % 10 != 0 || s.End.Ticks % 10 != 0 || s.Kinds.Length is < 1 or > 3
                || s.Kinds.Except(kinds.Values).Any())
                throw new InvalidDataException("sigma_history_request_invalid");
            if (inputs.Take(i).Any(prior => JsonNode.DeepEquals(prior.Scope, s.Scope) && s.Start < prior.End && prior.Start < s.End))
                throw new InvalidDataException("sigma_history_partition_overlap");
        }

        var access = await source.OpenConnectionAsync(ct);
        NpgsqlConnection? enumerator = null;
        NpgsqlTransaction? snapshot = null;
        try
        {
            await SetWorkerAsync(access, ct);
            if (!await CheckAccessAsync(access, inputs, ct)) throw new InvalidDataException(PermissionDenied);
            enumerator = await source.OpenConnectionAsync(ct);
            await SetWorkerAsync(enumerator, ct);
            snapshot = await enumerator.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await using (var readOnly = Command("set transaction read only", enumerator, snapshot))
                await readOnly.ExecuteNonQueryAsync(ct);
            for (int i = 0; i < inputs.Length; i++)
            {
                await using var ceiling = SelectionCommand(CeilingSql, enumerator, snapshot, inputs[i]);
                partitions[i] = partitions[i] with { HighWatermark = (long)(await ceiling.ExecuteScalarAsync(ct))! };
            }
            return new(job, manifestSha, rules.ToArray(), kinds, access, enumerator, snapshot, partitions,
                partitions.Select((part, index) => (part.Key, Input: inputs[index])).ToDictionary(x => x.Key, x => x.Input));
        }
        catch (Exception error)
        {
            if (snapshot is not null) await snapshot.DisposeAsync();
            if (enumerator is not null) await enumerator.DisposeAsync();
            await access.DisposeAsync();
            if (error is PostgresException { SqlState: PostgresErrorCodes.InsufficientPrivilege })
                throw new InvalidDataException(PermissionDenied);
            throw;
        }
    }

    internal async Task<SigmaHistoryResult> RunPageAsync(SigmaHistoryBudget budget, CancellationToken ct)
    {
        await pageGate.WaitAsync(ct);
        try
        {
            if (failure is not null) return new("failed", failure, new());
            if (!await CheckAccessAsync(access, selections.Values, ct))
                return Fail(PermissionDenied);

            eventBytes = budget.EventBytes;
            var result = await SigmaHistory.RunAsync(job, rules, partitions, manifestSha, this,
                _ => failure is null, (_, _) => Task.CompletedTask, checkpoint, budget, ct);
            if (failure is not null) return Fail(failure);
            if (result.Status == "cancelled") return new("cancelled", result.Reason, new());
            if (!await CheckAccessAsync(access, selections.Values, ct))
                return Fail(PermissionDenied);

            checkpoint = result.Checkpoint.DeepClone().AsObject();
            return result;
        }
        finally { pageGate.Release(); }
    }

    private SigmaHistoryResult Fail(string reason)
    {
        failure = reason;
        checkpoint = null;
        return new("failed", reason, new());
    }

    bool ISigmaHistoryReader.Applies(SigmaRule rule, SigmaHistoryRecord record) => ruleKinds[rule.Id] == record.NativeKind;

    async Task<SigmaHistoryRecord?> ISigmaHistoryReader.ReadOneAsync(SigmaHistoryPartition part, long after, int maxBytes,
        TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            var selection = selections[part.Key];
            if (!await CheckAccessAsync(access, [selection], ct))
                throw new InvalidDataException(PermissionDenied);
            var candidate = await ReadCandidateAsync(part, selection, after, ct);
            if (candidate is null) return null;

            var reference = new JsonObject { ["storage_kind"] = part.StorageKind,
                ["native_id"] = candidate.Id.ToString(CultureInfo.InvariantCulture), ["sha256"] = candidate.Sha };
            SigmaHistoryRecord Record(int bytes, SigmaEvent? mapped, string[] reasons, bool rejected = false)
                => new(candidate.Id, reference, part.Scope, candidate.At, mapped, reasons, bytes, candidate.Kind, rejected);

            await using var payload = Command(PayloadSql, access);
            payload.Parameters.AddWithValue(NpgsqlDbType.Jsonb, part.Scope.ToJsonString());
            payload.Parameters.AddWithValue(candidate.Id);
            payload.Parameters.AddWithValue(candidate.At);
            payload.Parameters.AddWithValue(candidate.Kind);
            payload.Parameters.AddWithValue(candidate.Sha);
            payload.Parameters.Add(new() { NpgsqlDbType = NpgsqlDbType.Text, Value = (object?)candidate.RepresentationSha ?? DBNull.Value });
            payload.Parameters.AddWithValue(maxBytes);
            await using var row = await payload.ExecuteReaderAsync(ct);
            if (!await row.ReadAsync(ct) || row.GetString(0) == "changed")
                throw new InvalidDataException(SnapshotChanged);
            if (row.GetString(0) == "missing") return Record(1, null, ["payload_unavailable"]);

            int bytes = row.GetInt32(1);
            if (bytes > eventBytes) return Record(1, null, ["source_payload_oversized"], rejected: true);
            // A row that fits a full page but not its remainder stays behind the prior cursor.
            if (bytes > maxBytes) return Record(bytes, null, []);
            if (bytes < 1 || row.IsDBNull(2)) throw new InvalidDataException(SnapshotChanged);

            try
            {
                var representation = JsonNode.Parse(row.GetString(2))!.AsObject();
                if (DirectEventIdentityStore.RepresentationDigest(representation) != candidate.RepresentationSha)
                    return Record(bytes, null, ["source_representation_digest_mismatch"], rejected: true);
                var mapped = SigmaEvent.Map(representation.Text("xml")!);
                if (mapped.Id != candidate.Kind || mapped.Channel != candidate.Channel
                    || mapped.Fields.Text("Provider_Name") != candidate.Provider
                    || candidate.RecordId is not > 0 || !mapped.Fields["EventRecordID"]!.AsValue().TryGetValue<ulong>(out ulong recordId)
                    || recordId != (ulong)candidate.RecordId.Value || mapped.Computer != representation.Text("machine_name")
                    || DirectEventTime.Utc(mapped.Fields.Text("TimeCreated")!) != candidate.At.UtcDateTime)
                    return Record(bytes, null, ["source_event_header_mismatch"], rejected: true);
                return Record(bytes, mapped with { At = candidate.At }, []);
            }
            catch (Exception error) when (error is JsonException or InvalidDataException or InvalidOperationException or ArgumentException)
            {
                return Record(bytes, null, ["source_xml_invalid"], rejected: true);
            }
        }
        catch (Exception error) when (error is PostgresException { SqlState: PostgresErrorCodes.InsufficientPrivilege }
            or InvalidDataException { Message: PermissionDenied or SnapshotChanged })
        {
            failure = error is PostgresException ? PermissionDenied : error.Message;
            throw;
        }
    }

    private async Task<Candidate?> ReadCandidateAsync(SigmaHistoryPartition part, SigmaHistoryTestSelection selection, long after, CancellationToken ct)
    {
        await using var command = SelectionCommand(NextSql, enumerator, snapshot, selection);
        command.Parameters.AddWithValue(after);
        command.Parameters.AddWithValue(part.HighWatermark);
        await using var row = await command.ExecuteReaderAsync(ct);
        return !await row.ReadAsync(ct) ? null : new(row.GetInt64(0), row.GetFieldValue<DateTimeOffset>(1),
            row.GetInt32(2), row.GetString(3), row.IsDBNull(4) ? null : row.GetString(4),
            row.IsDBNull(5) ? null : row.GetInt64(5), row.GetString(6), row.IsDBNull(7) ? null : row.GetString(7));
    }

    private static async Task<bool> CheckAccessAsync(NpgsqlConnection connection, IEnumerable<SigmaHistoryTestSelection> inputs, CancellationToken ct)
    {
        foreach (var selection in inputs)
        {
            await using var check = Command(ScopeSql, connection);
            check.Parameters.AddWithValue(NpgsqlDbType.Jsonb, selection.Scope.ToJsonString());
            check.Parameters.AddWithValue(selection.Kinds);
            if (await check.ExecuteScalarAsync(ct) is not true) return false;
        }
        return true;
    }

    private static NpgsqlCommand SelectionCommand(string sql, NpgsqlConnection connection, NpgsqlTransaction snapshot, SigmaHistoryTestSelection selection)
    {
        var command = Command(sql, connection, snapshot);
        command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, selection.Scope.ToJsonString());
        command.Parameters.AddWithValue(selection.Start);
        command.Parameters.AddWithValue(selection.End);
        command.Parameters.AddWithValue(selection.Kinds);
        return command;
    }

    private static NpgsqlCommand Command(string sql, NpgsqlConnection connection, NpgsqlTransaction? tx = null)
        => new(sql, connection, tx) { CommandTimeout = 15 };

    private static async Task SetWorkerAsync(NpgsqlConnection connection, CancellationToken ct)
    {
        await using var command = Command("set role adlog_semantic_worker", connection);
        await command.ExecuteNonQueryAsync(ct);
    }

    private static int PilotKind(SigmaRule rule)
    {
        static IEnumerable<long> EventKinds(SigmaExpression expr)
            => expr is { Field: "EventID", ValueKind: "number" }
                ? [expr.Value!.GetValue<long>()] : expr.Args.SelectMany(EventKinds);
        static bool RequiresKind(SigmaExpression expr, long kind) => expr.Op switch
        {
            "compare" => expr is { Field: "EventID", ValueKind: "number" } && expr.Value!.GetValue<long>() == kind,
            "and" => expr.Args.Any(child => RequiresKind(child, kind)),
            "or" => expr.Args.Length > 0 && expr.Args.All(child => RequiresKind(child, kind)),
            _ => false
        };
        long[] kinds = EventKinds(rule.Expression).Distinct().ToArray();
        if (kinds.Length != 1 || kinds[0] is not (4698 or 4702 or 7045) || !RequiresKind(rule.Expression, kinds[0])
            || rule.LogSource != (kinds[0] == 7045 ? "system" : "security"))
            throw new InvalidDataException("sigma_test_rule_kind_unsupported");
        return (int)kinds[0];
    }

    public async ValueTask DisposeAsync()
    {
        await snapshot.DisposeAsync();
        await enumerator.DisposeAsync();
        await access.DisposeAsync();
        pageGate.Dispose();
    }
}
