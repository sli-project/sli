using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Compatibility;

// The Python record_ai_run equivalent: persist safe execution metadata only.
public sealed class AiRunRepository(IPostgresConnectionFactory connections, TimeProvider clock)
{
    public async Task<long> RecordAsync(JsonObject package, JsonObject result, JsonObject artifacts, CancellationToken ct)
    {
        var draft = LegacyRender.Draft(result);
        bool called = draft["ai_call_performed"]?.GetValue<bool>() == true;
        var summary = new JsonObject {
            ["provenance"] = LegacyHttpReader.Provenance(),
            ["filters"] = package["preview"]?["filters"]?.DeepClone() ?? new JsonObject(),
            ["source"] = package["preview"]?["source"]?.DeepClone() ?? new JsonObject(),
            ["safety"] = package["safety"]?.DeepClone() ?? new JsonObject(),
            ["payload_events"] = (package["payload"]?["events"] as JsonArray)?.Count ?? 0
        };
        string Text(string key, string fallback) => package[key]?.ToString() is { Length: > 0 } text ? text : fallback;
        await using var db = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            insert into ai_api_runs(provider,model,prompt_version,redaction_level,status,query_summary_json,
                prompt_file_path,request_file_path,result_file_path,report_file_path,ai_call_performed,
                validation_errors_json,completed_at)
            values(@provider,@model,@version,@redaction,@status,@summary,@prompt,@request,@result,@html,@called,@errors,@completed)
            returning id
            """, db) { CommandTimeout = 0 };
        command.Parameters.AddWithValue("provider", Text("provider", "openai_api"));
        command.Parameters.AddWithValue("model", Text("model", "unknown"));
        command.Parameters.AddWithValue("version", Text("prompt_version", "unknown"));
        command.Parameters.AddWithValue("redaction", Text("redaction_level", "strict"));
        command.Parameters.AddWithValue("status", draft["status"]!.GetValue<string>());
        command.Parameters.AddWithValue("summary", summary.ToJsonString());
        foreach (string key in new[] { "prompt", "request", "result", "html" })
            command.Parameters.AddWithValue(key, NpgsqlDbType.Text, (object?)artifacts[key]?.ToString() ?? DBNull.Value);
        command.Parameters.AddWithValue("called", called);
        command.Parameters.AddWithValue("errors", (draft["validation_errors"] ?? new JsonArray()).ToJsonString());
        command.Parameters.AddWithValue("completed", NpgsqlDbType.Text, called
            ? clock.GetUtcNow().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture) : DBNull.Value);
        return await command.ExecuteScalarAsync(ct) is long id ? id : throw new InvalidOperationException("PostgreSQL did not return ai_api_runs.id");
    }
}
