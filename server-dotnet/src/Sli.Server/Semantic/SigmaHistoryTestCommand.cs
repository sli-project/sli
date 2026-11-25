using System.CommandLine;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Hosting;
using Sli.Server.Storage.Lifecycle;

namespace Sli.Server.Semantic;

internal static class SigmaHistoryTestCommand
{
    internal static Task<int> RunAsync(string[] args) => RunAsync(args,
        () => GpoWorkerConfiguration.CreateNamed(Environment.GetEnvironmentVariable, LifecycleRuntime.ReadSecret,
            "ADLOG_SIGMA_TEST_DSN", "ADLOG_SIGMA_TEST_PASSWORD", "sli_sigma_history_test", 0), Console.Out);

    internal static async Task<int> RunAsync(string[] args, Func<string> connectionString, TextWriter output)
    {
        var plan = new Option<string>("--plan") { Required = true, Description = "JSON document with job and partitions (scope, start, end, event_ids)." };
        var files = new Option<string[]>("--rule") { Required = true, AllowMultipleArgumentsPerToken = true, Description = "Local Sigma rule files to evaluate." };
        var pageRows = new Option<int>("--page-rows") { DefaultValueFactory = _ => 1000 };
        var root = new RootCommand("Run the bounded native Sigma TEST on event_hot for Windows events 4698, 4702 and 7045. Set ADLOG_SIGMA_TEST_DSN explicitly to the test copy database.");
        root.Options.Add(plan);
        root.Options.Add(files);
        root.Options.Add(pageRows);
        root.SetAction(async (parse, ct) =>
        {
            try
            {
                var selection = JsonNode.Parse(ReadBounded(parse.GetValue(plan)!))!.AsObject();
                string jobId = selection.Text("job") ?? "";
                if (parse.GetValue(files) is not { Length: >= 1 and <= 25 } paths
                    || parse.GetValue(pageRows) is not (>= 1 and <= 10000)
                    || selection["partitions"] is not JsonArray { Count: >= 1 and <= 256 } parts)
                    throw new InvalidDataException("sigma_history_request_invalid");

                var rules = paths.Select(path => SigmaRule.Compile(ReadBounded(path))).ToArray();
                var inputs = parts.Select(part => new SigmaHistoryTestSelection(
                    part!["scope"]!.AsObject(), Time(part.Text("start")), Time(part.Text("end")),
                    part["event_ids"]!.AsArray().Select(kind => kind!.GetValue<int>()).ToArray())).ToArray();
                var manifest = Password.PasswordJson.Hash(new JsonArray(rules.Select(rule => JsonValue.Create(rule.Sha)).ToArray()));
                var settings = new NpgsqlConnectionStringBuilder(connectionString()) { Pooling = false, Multiplexing = false, IncludeErrorDetail = false };
                await using var source = NpgsqlDataSource.Create(settings.ConnectionString);
                var budget = new SigmaHistoryBudget(Rows: parse.GetValue(pageRows));
                var wall = Stopwatch.StartNew();
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(TimeSpan.FromSeconds(budget.Seconds));
                await using var job = await SigmaHistoryTest.OpenAsync(source, jobId, manifest, rules, inputs, deadline.Token);

                var result = new SigmaHistoryResult("partial", "time_budget", new());
                long previousRows = -1;
                while (wall.Elapsed.TotalSeconds < budget.Seconds)
                {
                    int remaining = (int)Math.Ceiling(budget.Seconds - wall.Elapsed.TotalSeconds);
                    if (remaining <= 0) break;
                    result = await job.RunPageAsync(budget with { Seconds = remaining }, deadline.Token);
                    long rows = result.Checkpoint.Number("rows_read");
                    if (rows <= previousRows || result.Status != "partial"
                        || result.Reason is not ("row_budget" or "byte_budget" or "time_budget" or "cpu_budget" or "evaluation_budget"))
                        break;
                    previousRows = rows;
                }
                if (result.Status == "cancelled" && deadline.IsCancellationRequested && !ct.IsCancellationRequested)
                    result = new("partial", "time_budget", new());
                if (result.Status == "partial" && wall.Elapsed.TotalSeconds >= budget.Seconds)
                    result = result with { Reason = "time_budget" };

                await output.WriteLineAsync(new JsonObject
                {
                    ["mode"] = result.Mode,
                    ["coverage"] = "event_hot_only",
                    ["status"] = result.Status,
                    ["reason"] = result.Reason,
                    ["result"] = result.Checkpoint.Copy()
                }.ToJsonString());
                return result.Status == "completed" ? 0 : 1;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return 1; }
            catch (OperationCanceledException)
            {
                await output.WriteLineAsync("""{"mode":"test","coverage":"event_hot_only","status":"partial","reason":"time_budget"}""");
                return 1;
            }
            catch (Exception error)
            {
                string reason = error switch
                {
                    PostgresException { SqlState: PostgresErrorCodes.UndefinedFunction } => "sigma_history_test_schema_unavailable",
                    PostgresException { SqlState: PostgresErrorCodes.InsufficientPrivilege } => "permission_denied",
                    NpgsqlException => "sigma_history_test_database_unavailable",
                    ServerConfigurationException => "sigma_history_test_configuration_invalid",
                    InvalidDataException { Message: "permission_denied" or "sigma_history_request_invalid"
                        or "sigma_history_partition_invalid" or "sigma_history_partition_overlap"
                        or "sigma_test_rule_kind_unsupported" } input => input.Message,
                    InvalidDataException or ArgumentException or FormatException or IOException or JsonException
                        or InvalidOperationException or NullReferenceException => "sigma_history_test_input_invalid",
                    _ => "sigma_history_test_failed"
                };
                await output.WriteLineAsync(new JsonObject { ["mode"] = "test", ["coverage"] = "event_hot_only", ["status"] = "failed", ["reason"] = reason }.ToJsonString());
                return 1;
            }
        });
        return await root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null })
            .InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
    }

    private static string ReadBounded(string path)
    {
        using var file = File.OpenRead(path);
        byte[] data = new byte[1048577];
        int count = file.ReadAtLeast(data, data.Length, throwOnEndOfStream: false);
        if (count >= data.Length) throw new InvalidDataException("sigma_history_request_invalid");
        return new UTF8Encoding(false, true).GetString(data, 0, count);
    }

    private static DateTimeOffset Time(string? value)
    {
        if (value?.EndsWith("+00:00", StringComparison.Ordinal) == true) value = value[..^6] + "Z";
        if (value is null || !value.EndsWith('Z') || !DateTimeOffset.TryParseExact(value,
            ["yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFF'Z'"], CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var time))
            throw new InvalidDataException("sigma_history_request_invalid");
        return time;
    }
}
