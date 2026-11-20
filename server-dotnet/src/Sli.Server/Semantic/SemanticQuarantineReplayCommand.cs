using System.CommandLine;
using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic;

public static class SemanticQuarantineReplayCommand
{
    internal static NpgsqlConnectionStringBuilder Configuration(Func<string, string?> get, Func<string, byte[]> read) =>
        new(GpoWorkerConfiguration.CreateNamed(get, read, "ADLOG_SEMANTIC_REPLAY_DSN", "ADLOG_SEMANTIC_REPLAY_PASSWORD", "sli_semantic_quarantine_replay", 0)) {
            Pooling = false, Multiplexing = false, Timeout = 0, CommandTimeout = 0, Options = "-c statement_timeout=0 -c lock_timeout=0", IncludeErrorDetail = false
        };
    private sealed class Connections(NpgsqlDataSource source) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => await source.OpenConnectionAsync(ct);
    }
    internal static DateTimeOffset? Time(string? value)
    {
        if (value is null) return null;
        if (!Regex.IsMatch(value, @"(?:Z|[+-]\d{2}:?\d{2})\z")) throw new SemanticInputException("timezone_required");
        if (!DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var time)) throw new SemanticInputException("invalid_time_range");
        return time;
    }
    private static byte[] ReadBounded(string path)
    {
        using var file = File.OpenRead(path); byte[] bytes = new byte[65537]; int n = file.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
        if (n > 65536) throw new ArgumentException(); return bytes[..n];
    }
    public static Task<int> RunAsync(string[] args) => RunAsync(args, async (selection, apply, digest, ct) => {
        await using var source = new NpgsqlDataSourceBuilder(Configuration(Environment.GetEnvironmentVariable, ReadBounded).ConnectionString).Build();
        var database = new SemanticDatabase(new Connections(source));
        var production = new SemanticProduction(new PasswordProducerRuntime(source), new(true, true, false, selection.Dispatch, false, false), SemanticRuntimeSettings.FactsMode, 1);
        // The cursor is safe operational state; source contents and errors never enter output.
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        JsonObject? current = new();
        async Task Pulse() {
            while (!stop.IsCancellationRequested) {
                if (Volatile.Read(ref current) is { } cursor) Console.Error.WriteLine(new JsonObject { ["heartbeat"] = DateTimeOffset.UtcNow, ["cursor"] = cursor["cursor"].Copy() }.ToJsonString());
                await Task.Delay(TimeSpan.FromSeconds(5), stop.Token);
            }
        }
        Task pulse = Pulse();
        try { return await new SemanticQuarantineReplay(database, production.ReplayQuarantined).RunAsync(selection, apply, digest, ct, progress => Volatile.Write(ref current, progress)); }
        finally { stop.Cancel(); try { await pulse; } catch (OperationCanceledException) when (stop.IsCancellationRequested) { } }
    }, Console.Out);

    internal static async Task<int> RunAsync(string[] args,
        Func<QuarantineSelection, bool, string, CancellationToken, Task<JsonObject>> run, TextWriter output)
    {
        var apply = new Option<bool>("--apply"); var dry = new Option<bool>("--dry-run");
        var reasons = new Option<string[]>("--reason") { Required = true, AllowMultipleArgumentsPerToken = true };
        var min = new Option<long?>("--source-id-min"); var max = new Option<long?>("--source-id-max");
        var since = new Option<string?>("--since"); var until = new Option<string?>("--until");
        var limit = new Option<int>("--limit") { DefaultValueFactory = _ => 100 };
        var digest = new Option<string>("--plan-digest") { DefaultValueFactory = _ => "" };
        var close = new Option<string?>("--close-reason"); var dispatch = new Option<bool>("--dispatch");
        var command = new RootCommand("Preview or apply audited quarantine replay without changing the original job.");
        foreach (Option option in new Option[] { apply, dry, reasons, min, max, since, until, limit, digest, close, dispatch }) command.Options.Add(option);
        command.SetAction(async (parse, ct) => {
            if (parse.GetValue(apply) && (parse.GetValue(dry) || !SemanticQuarantineReplay.IsDigest(parse.GetValue(digest)))) {
                await output.WriteLineAsync("{\"status\":\"error\",\"reason\":\"plan_digest_required\"}"); return 2;
            }
            try {
                var selection = new QuarantineSelection(parse.GetValue(reasons)!.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
                    parse.GetValue(min), parse.GetValue(max), Time(parse.GetValue(since)), Time(parse.GetValue(until)), parse.GetValue(limit), parse.GetValue(close), parse.GetValue(dispatch));
                selection.Validate();
                var result = await run(selection, parse.GetValue(apply), parse.GetValue(digest)!, ct);
                await output.WriteLineAsync(result.ToJsonString());
                return result.Number("failed") + result.Number("changed") + result.Number("blocked") > 0 ? 1 : 0;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return 1; }
            catch (Exception error) {
                string reason = error is SemanticInputException { Message: "invalid_reason" or "invalid_limit" or "invalid_source_range"
                    or "timezone_required" or "invalid_time_range" or "invalid_close_reason" or "selection_limit_exceeded"
                    or "plan_changed" or "plan_digest_required" } input ? input.Message : "semantic_quarantine_replay_failed";
                await output.WriteLineAsync(new JsonObject { ["status"] = "error", ["reason"] = reason }.ToJsonString()); return 1;
            }
        });
        return await command.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null }).InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
    }
}
