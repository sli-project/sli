using System.CommandLine;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Hosting;

namespace Sli.Server.Jobs;

public static class CoreJobCommand
{
    public static Task<int> RunAsync(string[] args) => RunAsync(args, CoreJobPluginCatalog.Compiled(), Console.In, Console.Out, Console.Error);
    internal static async Task<int> RunAsync(string[] args, CoreJobPluginCatalog catalog, TextReader input, TextWriter output, TextWriter error, CancellationToken ct = default)
    {
        var profile = new Option<string>("--profile") { Required = true };
        var child = new Option<string?>("--child"); var once = new Option<bool>("--once");
        var persistent = new Option<bool>("--persistent");
        var quarantine = new Option<bool>("--quarantine-report");
        var retry = new Option<Guid?>("--retry-quarantined");
        var expectedCode = new Option<string?>("--expected-error");
        var root = new RootCommand("Run the bounded core-job light/heavy/long dispatcher.");
        root.Options.Add(profile); root.Options.Add(child); root.Options.Add(once);
        root.Options.Add(persistent);
        root.Options.Add(quarantine); root.Options.Add(retry); root.Options.Add(expectedCode);
        root.SetAction(async (parse, token) =>
        {
            string selected = parse.GetValue(profile)!; string? purpose = parse.GetValue(child);
            try
            {
                if (!CoreJobRegistry.Profiles.ContainsKey(selected)) throw new CoreJobContractException("executor_profile_invalid");
                if (purpose is not null && purpose is not ("handler" or "publisher")) throw new CoreJobContractException("executor_purpose_invalid");
                if (parse.GetValue(persistent) && (purpose is null || selected != "light")) throw new CoreJobContractException("executor_purpose_invalid");
                if (parse.GetValue(quarantine) || parse.GetValue(retry) is not null)
                {
                    if (purpose is not null || (parse.GetValue(quarantine) && parse.GetValue(retry) is not null)) throw new CoreJobContractException("executor_purpose_invalid");
                    var settings = CoreJobIdentity.Settings(selected, "dispatcher", Environment.GetEnvironmentVariable, CoreJobIdentity.ReadSecret);
                    await using var db = new NpgsqlConnection(settings.ConnectionString); await db.OpenAsync(token);
                    bool requeue = parse.GetValue(retry) is not null;
                    await using var command = new NpgsqlCommand(requeue ? "select public.retry_core_job_v322(@job,@code)" : "select public.read_core_job_quarantine_v322(@profile)::text", db);
                    if (requeue)
                    {
                        command.Parameters.AddWithValue("job", parse.GetValue(retry)!.Value);
                        command.Parameters.AddWithValue("code", parse.GetValue(expectedCode) ?? throw new CoreJobContractException("job_expected_error_required"));
                    }
                    else command.Parameters.AddWithValue("profile", selected);
                    var value = await command.ExecuteScalarAsync(token);
                    await output.WriteLineAsync(requeue ? new JsonObject { ["requeued"] = (bool)value! }.ToJsonString() : (string)value!);
                    return requeue && value is not true ? 1 : 0;
                }
                await using var worker = new CoreJobWorker(catalog);
                if (purpose is not null)
                {
                    CoreJobProcess.Isolate();
                    if (parse.GetValue(persistent))
                    {
                        string? line;
                        while ((line = await input.ReadLineAsync(token)) is not null)
                        {
                            JsonObject reply;
                            try
                            {
                                var request = JsonNode.Parse(line) as JsonObject ?? throw new CoreJobContractException("job_input_invalid");
                                reply = await worker.ChildAsync(selected, purpose, request, token);
                            }
                            catch (CoreJobLeaseLost) { reply = new() { ["status"] = "lease_lost" }; }
                            catch (Exception e) when (e is CoreJobContractException or System.Text.Json.JsonException or FormatException)
                            { reply = new() { ["status"] = "permanent_error", ["error_code"] = "job_contract_invalid" }; }
                            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                            catch (Exception e)
                            {
                                // A database/transport error may leave an aborted transaction.
                                // End the sandbox; the parent recreates it on the next attempt.
                                await WriteFrame(output, new() { ["status"] = "retryable_error", ["error_code"] = FailureCode(e) });
                                return 1;
                            }
                            await WriteFrame(output, reply);
                        }
                        return 0;
                    }
                    var job = JsonNode.Parse(await input.ReadToEndAsync(token)) as JsonObject ?? throw new CoreJobContractException("job_input_invalid");
                    var result = await worker.ChildAsync(selected, purpose, job, token);
                    await output.WriteLineAsync(CanonicalJson.Serialize(result));
                    return 0;
                }
                return await WorkerShutdown.RunAsync(stopping => Sli.Server.Operations.OperationsWorkerObservation.RunAsync(
                    "core_job_executor_" + selected, () => worker.RunAsync(selected, parse.GetValue(once), stopping), stopping), token);
            }
            catch (CoreJobLeaseLost) when (purpose is not null) { await output.WriteLineAsync("{\"status\":\"lease_lost\"}"); return 0; }
            catch (Exception e) when (purpose is not null && e is CoreJobContractException or System.Text.Json.JsonException or FormatException)
            { await output.WriteLineAsync("{\"status\":\"permanent_error\",\"error_code\":\"job_contract_invalid\"}"); return 0; }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { return 0; }
            catch (Exception e) when (purpose is not null)
            {
                // Safe protocol result: never forward driver text, SQL or child stderr.
                await output.WriteLineAsync(CanonicalJson.Serialize(new JsonObject { ["status"] = "retryable_error", ["error_code"] = FailureCode(e) }));
                return 0;
            }
            catch (Exception e)
            {
                await error.WriteLineAsync("core_executor_failed " + CanonicalJson.Serialize(Diagnostic(e)));
                return 1;
            }
        });
        var parsed = root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });
        var invocation = new InvocationConfiguration { EnableDefaultExceptionHandler = false, Output = output, Error = error };
        if (parsed.Errors.Count == 0 && parsed.GetValue(child) is null && !parsed.GetValue(quarantine) && parsed.GetValue(retry) is null)
            invocation.ProcessTerminationTimeout = null;
        return await parsed.InvokeAsync(invocation, ct);
    }
    private static async Task WriteFrame(TextWriter output, JsonObject result)
    {
        string json = CanonicalJson.Serialize(result);
        await output.WriteLineAsync(System.Text.Encoding.UTF8.GetByteCount(json).ToString(System.Globalization.CultureInfo.InvariantCulture));
        await output.WriteLineAsync(json);
        await output.FlushAsync();
    }
    internal static JsonObject Diagnostic(Exception error)
    {
        var result = new JsonObject { ["error_type"] = "Exception", ["error_code"] = "unexpected_error" };
        if (error is CoreJobProcess.ExitFailure child)
        {
            result["error_code"] = "job_child_exited";
            result["child_exit_code"] = child.ExitCode;
            // Unix Process.ExitCode uses 128 + signal for signal termination.
            // An explicit exit can have the same value, so label it a candidate.
            if (OperatingSystem.IsLinux() && child.ExitCode is > 128 and <= 192)
                result["child_signal_candidate"] = child.ExitCode - 128;
            result["child_stderr"] = child.Stderr;
        }
        if (error is CoreJobContractException && error.Message is "update_invalid_plugin_payload" or "update_plugin_payload_changed"
            or "update_plugin_api_incompatible" or "update_plugin_handler_mismatch" or "update_plugin_ui_mismatch" or "plugin_version_changed")
            result["error_code"] = error.Message;
        if (error is CoreJobContractException && error.Message is "executor_profile_invalid" or "executor_purpose_invalid" or "executor_secret_missing" or "executor_secret_file_required" or "handler_version_unavailable" or "manifest_shape_invalid" or "handler_not_allowlisted" or "handler_registration_duplicate" or "schedule_reference_invalid" or "schedule_trigger_invalid" or "handler_core_api_incompatible" or "handler_dependency_unavailable" or "radius_pilot_source_required") result["error_code"] = error.Message;
        if (error is PostgresException pg)
        {
            result["error_code"] = "database_error";
            if (System.Text.RegularExpressions.Regex.IsMatch(pg.SqlState, "\\A[0-9A-Z]{5}\\z")) result["sqlstate"] = pg.SqlState;
            if (pg.SqlState == "23514" && pg.SchemaName == "sli_jobs" && pg.TableName == "jobs" && pg.ConstraintName == "jobs_check1") result["error_code"] = "job_deadline_constraint";
        }
        else if (error is NpgsqlException or IOException) result["error_code"] = "job_connection_lost";
        if (error is System.Net.Sockets.SocketException socket)
        { result["error_code"] = "job_connection_lost"; result["native_error_code"] = socket.NativeErrorCode; }
        else if (error is System.ComponentModel.Win32Exception native)
        { result["error_code"] = "job_child_start_failed"; result["native_error_code"] = native.NativeErrorCode; }
        return result;
    }
    internal static string FailureCode(Exception error) => error switch
    {
        PostgresException { SqlState: "57014" } => "job_statement_cancelled",
        PostgresException { SqlState: "55P03" } => "job_lock_unavailable",
        PostgresException p when p.SqlState.StartsWith("08", StringComparison.Ordinal) || p.SqlState is "57P01" or "57P02" or "57P03" => "job_connection_lost",
        PostgresException => "job_database_error",
        NpgsqlException or IOException => "job_connection_lost",
        System.Net.Sockets.SocketException => "job_connection_lost",
        InvalidOperationException { Message: "job_child_failed" } => "job_child_failed",
        System.ComponentModel.Win32Exception => "job_child_start_failed",
        InvalidOperationException { Message: "job_child_host_invalid" } => "job_child_host_invalid",
        InvalidOperationException { Message: "job_child_memory_exceeded" } => "job_child_memory_exceeded",
        InvalidOperationException { Message: "job_child_exited" } => "job_child_exited",
        TimeoutException => "job_deadline_exceeded",
        _ => "job_execution_failed"
    };
}
