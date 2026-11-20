using System.CommandLine;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Control;
using Sli.Server.Storage.Lifecycle;

namespace Sli.Server.Agents.Radius;

public static class NpsEventLogCommand
{
    public static Task<int> RunAsync(string[] args) => RunCoreAsync(args, Collect, Console.Out, Console.Error);

    internal static async Task<int> RunCoreAsync(string[] args, Func<NpsEventLogRequest, string, CancellationToken, int> collect,
        TextWriter output, TextWriter error, CancellationToken ct = default)
    {
        var nps = new Option<bool>("--nps-continuous");
        var computer = new Option<string>("--computer-name") { Required = true };
        var source = new Option<string>("--source-name") { Required = true };
        var start = new Option<string>("--start-time-utc") { Required = true };
        var end = new Option<string>("--end-time-utc") { Required = true };
        var destination = new Option<string>("--output-root") { Required = true };
        var channels = new Option<string>("--channels") { DefaultValueFactory = _ => "Security" };
        var mode = new Option<string>("--ad-source-credential-mode") { DefaultValueFactory = _ => "process" };
        var ids = new Option<string>("--event-ids-json") { DefaultValueFactory = _ => "[6272,6273]" };
        var maximum = new Option<int>("--max-events-per-channel") { DefaultValueFactory = _ => 50_000 };
        var timeout = new Option<int>("--channel-timeout-seconds") { DefaultValueFactory = _ => 60 };
        var message = new Option<string>("--collect-message") { DefaultValueFactory = _ => "false" };
        var limits = new Option<string>("--channel-limits-json");
        var timeouts = new Option<string>("--channel-timeouts-json");
        var starts = new Option<string>("--channel-start-times-json");
        var records = new Option<string>("--channel-after-record-ids-json");
        var generations = new Option<string>("--channel-cursor-generations-json");
        var root = new RootCommand("Windows Event Log acquisition with an explicit continuous NPS selector.");
        foreach (Option option in new Option[] { nps, computer, source, start, end, destination, channels, mode, ids, maximum, timeout, message, limits, timeouts, starts, records, generations }) root.Options.Add(option);
        root.SetAction((parse, token) =>
        {
            static Dictionary<string, T> Map<T>(string? text) => text is null ? [] : JsonSerializer.Deserialize<Dictionary<string, T>>(text) ?? throw new JsonException();
            NpsEventLogRequest request;
            try
            {
                request = new(parse.GetValue(computer)!, parse.GetValue(source)!, parse.GetValue(start)!, parse.GetValue(end)!) {
                    NpsContinuous = parse.GetValue(nps), CredentialMode = parse.GetValue(mode)!,
                    Channels = parse.GetValue(channels)!.Split(',').Select(x => x.Trim()).ToArray(),
                    EventIds = JsonSerializer.Deserialize<int[]>(parse.GetValue(ids)!) ?? throw new JsonException(),
                    CollectMessage = bool.Parse(parse.GetValue(message)!), MaxEvents = parse.GetValue(maximum), ChannelTimeoutSeconds = parse.GetValue(timeout),
                    ChannelLimits = Map<int>(parse.GetValue(limits)), ChannelTimeouts = Map<int>(parse.GetValue(timeouts)),
                    ChannelStarts = Map<string>(parse.GetValue(starts)), AfterRecordIds = Map<long>(parse.GetValue(records)), CursorGenerations = Map<string>(parse.GetValue(generations)),
                };
                request.Validate();
            }
            catch (Exception e) when (e is ArgumentException or JsonException or FormatException or OverflowException)
            { error.WriteLine("continuous_nps_admission_failed"); return Task.FromResult(12); }
            return Task.FromResult(collect(request, parse.GetValue(destination)!, token));
        });
        var parsed = root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });
        if (parsed.Errors.Count != 0) { await error.WriteLineAsync("continuous_nps_admission_failed"); return 12; }
        return await parsed.InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false, Output = output, Error = error }, ct);
    }

    internal static JsonObject LoadRoute(string root, IReadOnlyDictionary<string, string?> env)
    {
        string? Env(string name) => env.GetValueOrDefault(name);
        using var document = JsonDocument.Parse(File.ReadAllBytes(Env("ADLOG_RADIUS_COLLECTION_ROUTES_PATH") ?? Path.Combine(root, "config", "stage10_radius_collection_routes_v1.json")));
        string source = RadiusCollectionRoute.Validate(document.RootElement, env);
        var route = document.RootElement;
        string instance = Env("ADLOG_RADIUS_SOURCE_INSTANCE_ID")?.Trim() is { Length: > 0 } id ? id
            : env.ContainsKey("ADLOG_RADIUS_SOURCE_NAME") ? source : route.GetProperty("source_instance_id").GetString()!;
        string ip = Env("ADLOG_RADIUS_OWNER_CONFIRMED_IP")?.Trim() is { Length: > 0 } address ? address
            : route.TryGetProperty("owner_confirmed_ip", out var configured) ? configured.GetString() ?? "" : "";
        return new JsonObject { ["source_name"] = source, ["source_instance_id"] = instance, ["owner_confirmed_ip"] = ip,
            ["event_log_ready"] = true, ["event_log_adapter"] = route.GetProperty("event_log_route").GetProperty("primary_adapter").GetString() };
    }

    private static int Collect(NpsEventLogRequest request, string destination, CancellationToken ct)
    {
        using var admission = request.NpsContinuous ? AgentAssignmentPluginAdmission.Enter("sli.remote-access",
            Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"), Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR")) : null;
        string root = LifecycleConfiguration.FindRoot();
        var env = new[] { "ADLOG_RADIUS_COLLECTION_ROUTES_PATH", "ADLOG_RADIUS_SOURCE_NAME", "ADLOG_RADIUS_SOURCE_INSTANCE_ID", "ADLOG_RADIUS_OWNER_CONFIRMED_IP", "ADLOG_RADIUS_ACCOUNTING_SHARE_UNC" }
            .Where(x => Environment.GetEnvironmentVariable(x) is not null).ToDictionary(x => x, Environment.GetEnvironmentVariable);
        string data = new LifecycleConfiguration(root, Environment.GetEnvironmentVariable).DataRoot(root);
        Directory.CreateDirectory(destination);
        var results = new JsonArray();
        foreach (string channel in request.Channels)
        {
            // Channels become filenames only after rejecting path components.
            string file = Path.Combine(destination, channel.Replace('/', '_').Replace('\\', '_') + ".jsonl");
            if (channel is "." or ".." || channel.IndexOfAny(Path.GetInvalidFileNameChars().Where(x => x != '/' && x != '\\').ToArray()) >= 0)
                throw new ArgumentException("event_log_channel_invalid");
            using var output = new StreamWriter(file, false, new UTF8Encoding(false));
            var result = NpsEventLogTransport.Collect(request, channel, output,
                () => NpsEventLogTransport.OpenSession(request, () => LoadRoute(root, env), profile => NpsSourceCredentials.Load(data, profile), (target, credentials) => new NpsNativeEventLog(target, credentials)),
                code => Console.Error.WriteLine(code), beat => Console.Out.WriteLine(beat.ToJsonString()), ct);
            results.Add(result);
        }
        File.WriteAllText(Path.Combine(destination, "collection-summary.json"), new JsonObject {
            ["computer_name"] = request.SourceName, ["connect_address"] = request.ComputerName,
            ["start_time_utc"] = request.StartTimeUtc, ["end_time_utc"] = request.EndTimeUtc,
            ["collector_backend"] = "dotnet_eventlog", ["channels"] = results,
        }.ToJsonString(), new UTF8Encoding(false));
        return results.OfType<JsonObject>().All(x => x["status"]!.GetValue<string>() == "completed") ? 0 : 3;
    }
}
