using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class FileAuditRetentionTests
{
    internal static JsonObject AgentObservation()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName,"agent-dotnet/tests/vectors/file-audit-scenarios.json"))) directory = directory.Parent;
        Assert.NotNull(directory);
        var vectors = JsonNode.Parse(File.ReadAllText(Path.Combine(directory.FullName,"agent-dotnet/tests/vectors/file-audit-scenarios.json")))!.AsArray();
        var vector = vectors.OfType<JsonObject>().Single(v => v["name"]!.ToString() == "events-restart-filter");
        var packet = JsonNode.Parse(vector["steps"]![0]!["payload_canonical"]!.ToString())!;
        string agent = "11111111-1111-1111-1111-111111111111";
        var policy = vector["config"]!.DeepClone().AsObject(); policy["source_name"] = vector["host_id"]!.DeepClone();
        var normalized = FileAuditObservation.Build(packet["records"]![0]!["payload"]!.AsObject(),FileAuditPolicy.Parse(policy),
            agent,"synthetic","synthetic-generation","1","agent-event:"+agent+":synthetic-generation:1");
        var observation = new JsonObject();
        foreach (string key in new[] { "evidence_key","agent_id","source_instance_id","channel","provider","generation","record_id","event_id","event_version","observed_at","core_evidence_ref","payload_sha256" }) observation[key] = normalized[key]!.DeepClone();
        observation["collection_scope_id"] = "scope:one"; observation["policy_revision"] = 1L; observation["normalized"] = normalized;
        return observation;
    }
    internal static JsonObject Payload(JsonObject? observation = null) => new() {
        ["observation"] = observation ?? AgentObservation(),
        ["links"] = new JsonArray(new JsonObject { ["action_id"] = new string('b',64), ["core_evidence_ref"] = AgentObservation()["core_evidence_ref"]!.DeepClone(),
            ["evidence_key"] = AgentObservation()["evidence_key"]!.DeepClone(), ["role"] = "primary" }) };

    [Theory] [InlineData("incomplete")] [InlineData("corrupt")] [InlineData("duplicate")] [InlineData("ttl")] [InlineData("unavailable")]
    public async Task Exact_copy_rejects_damage_and_retries_without_duplicate_inserts(string failure)
    {
        var ct = TestContext.Current.CancellationToken;
        using var handler = new HistoryHttp { Failure = failure }; using var http = new HttpClient(handler);
        using var history = new FileAuditHistory(new LifecycleClickHouse(http,new Uri("http://192.0.2.1/")));
        var payload = Payload();
        await Assert.ThrowsAsync<LifecycleBlocked>(() => history.PreserveAsync(payload,ct));
        handler.Failure = null;
        if (failure == "corrupt") handler.Records.Clear();
        await history.PreserveAsync(payload,ct); await history.PreserveAsync(payload,ct);
        Assert.Single(handler.Records); Assert.True(JsonNode.DeepEquals(payload,FileAuditHistory.Decode(handler.Records[0])));
        var root = new JsonObject { ["agent_id"] = payload["observation"]!["agent_id"]!.DeepClone(), ["source_instance_id"] = "synthetic", ["collection_scope_id"] = "scope:one" };
        Assert.Single(await history.ReadAsync(root,[payload["observation"]!["evidence_key"]!.ToString()],ct));
    }

    internal sealed class HistoryHttp : HttpMessageHandler
    {
        internal readonly List<JsonObject> Records = [];
        internal string? Failure;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            string sql = await request.Content!.ReadAsStringAsync(ct);
            var p = request.RequestUri!.Query.TrimStart('?').Split('&').Select(v => v.Split('=',2)).ToDictionary(v => Uri.UnescapeDataString(v[0]),v => v.Length == 2 ? Uri.UnescapeDataString(v[1]) : "");
            if (Failure == "unavailable") return new(HttpStatusCode.ServiceUnavailable);
            if (sql.StartsWith("CREATE TABLE",StringComparison.Ordinal)) return Response("");
            if (sql.Contains("system.tables",StringComparison.Ordinal)) return Response(new JsonObject { ["engine"] = "ReplacingMergeTree", ["sorting_key"] = "evidence_key", ["partition_key"] = "",
                ["create_table_query"] = "SETTINGS fsync_after_insert=1,fsync_part_directory=1"+(Failure == "ttl" ? " TTL now()" : "") }.ToJsonString());
            if (sql.StartsWith("INSERT INTO",StringComparison.Ordinal)) {
                Assert.Contains("max_execution_time=0",request.RequestUri.Query);
                foreach (string line in sql[(sql.IndexOf('\n')+1)..].Split('\n',StringSplitOptions.RemoveEmptyEntries)) {
                    if (Failure == "incomplete") continue;
                    var row = JsonNode.Parse(line)!.AsObject(); if (Failure == "corrupt") row["payload_sha256"] = new string('0',64); Records.Add(row);
                }
                return Response("");
            }
            Assert.Contains(" FINAL WHERE ",sql); Assert.Contains("readonly=1",request.RequestUri.Query);
            IEnumerable<JsonObject> found = Records;
            if (p.TryGetValue("param_key",out string? key)) found = found.Where(r => r["evidence_key"]!.ToString() == key);
            else {
                found = found.Where(r => r["agent_id"]!.ToString() == p["param_agent"] && r["source_instance_id"]!.ToString() == p["param_source"] && p["param_keys"].Contains(r["evidence_key"]!.ToString(),StringComparison.Ordinal));
            }
            if (Failure == "duplicate") found = found.Concat(found).ToArray();
            return Response(string.Join('\n',found.Select(LifecycleJson.Canonical)));
        }
        static HttpResponseMessage Response(string text) => new(HttpStatusCode.OK) { Content = new StringContent(text,Encoding.UTF8,"text/plain") };
    }
}
