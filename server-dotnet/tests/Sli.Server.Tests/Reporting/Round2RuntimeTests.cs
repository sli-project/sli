using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Npgsql;
using Sli.Server.Storage.Direct;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class Round2RuntimeTests
{
    static JsonObject Entry(string severity = "high", string provider = "Provider-A", string channel = "Security") => JsonNode.Parse($$"""
        {"event_id":4624,"provider_name":"{{provider}}","channel":"{{channel}}","severity":"{{severity}}",
         "card":{"risk_rules":[{"severity":"critical","all":[{"contains_any":["token"]}]}]},"title":"presentation-only"}
        """)!.AsObject();

    [Theory]
    [InlineData("{}\n{\"event_id\":4624,\"channel\":\"Security\"}\n")]
    [InlineData("\uFEFF{}\r\n \r\n{\"event_id\":4624,\"channel\":\"Security\"}")]
    public void Jsonl_keeps_empty_object_and_hashes_exact_source_in_one_pass(string text)
    {
        byte[] raw = Encoding.UTF8.GetBytes(text);
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var stream = new ForwardOnlyStream(raw);
        var rows = DirectJsonlReader.Read(stream, digest).ToArray();
        Assert.Equal(2, rows.Length);
        Assert.Empty(rows[0]);
        Assert.Equal(4624, (int?)rows[1]["event_id"]);
        Assert.Equal("Security", (string?)rows[1]["channel"]);
        Assert.Equal(SHA256.HashData(raw), digest.GetHashAndReset());
        Assert.Equal(raw.Length, stream.BytesRead);
    }

    [Fact]
    public void Jsonl_file_stays_open_through_enumeration_and_is_released()
    {
        string path = Path.Combine(Path.GetTempPath(), "sli-round2-" + Guid.NewGuid().ToString("N") + ".jsonl");
        try
        {
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes("{}\n{\"event_id\":4624,\"channel\":\"Security\"}\n"));
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using (var rows = DirectJsonlReader.Read(path, digest).GetEnumerator())
            {
                Assert.True(rows.MoveNext());
                Assert.Empty(rows.Current);
                Assert.Throws<IOException>(() => { using var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None); });
                Assert.True(rows.MoveNext());
                Assert.Equal(4624, (int?)rows.Current["event_id"]);
                Assert.False(rows.MoveNext());
            }
            Assert.Equal(SHA256.HashData(File.ReadAllBytes(path)), digest.GetHashAndReset());
            using var reopened = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Semantic_cache_invalidates_for_risk_provider_channel_and_rule_content()
    {
        var current = Entry();
        var cache = new DashboardRiskProjection(() => [current]);
        var first = cache.Get();
        Assert.Same(first, cache.Get());
        current = Entry(severity: "medium");
        var second = cache.Get();
        Assert.NotSame(first, second);
        Assert.Contains("medium", second.Parameters);
        Assert.DoesNotContain("high", second.Parameters);
        current = Entry("medium", "Provider-B");
        var third = cache.Get();
        Assert.NotSame(second, third);
        Assert.Contains("provider-b", third.Parameters);
        current = Entry("medium", "Provider-B", "System");
        var fourth = cache.Get();
        Assert.NotSame(third, fourth);
        Assert.Contains("system", fourth.Parameters);
        current["title"] = "changed presentation";
        Assert.Same(fourth, cache.Get());
        current["card"]!["risk_rules"]![0]!["all"]![0]!["contains_any"]![0] = "changed-token";
        var fifth = cache.Get();
        Assert.NotSame(fourth, fifth);
        Assert.Contains("%changed-token%", fifth.Parameters);
        current["card"]!["risk_rules"]![0]!["severity"] = "high";
        Assert.NotSame(fifth, cache.Get());
    }

    [Fact]
    public void Fingerprint_is_canonical_and_ignores_presentation()
    {
        var first = Entry();
        string expected = DashboardRiskProjection.Fingerprint([first]);
        Assert.Equal("03e652b5058d6f1ae637ff1c97c80bf41d4f82fd6b7fa2774eb569d389d29305", expected);
        Assert.Matches("^[0-9a-f]{64}$", expected);
        var second = Entry();
        second["title"] = "changed presentation";
        Assert.Equal(expected, DashboardRiskProjection.Fingerprint([second]));
        second["provider_name"] = " PROVIDER-A ";
        second["channel"] = " SECURITY ";
        second["severity"] = " HIGH ";
        Assert.Equal(expected, DashboardRiskProjection.Fingerprint([second]));
        Assert.Equal(DashboardRiskProjection.Fingerprint([first, Entry("medium", "Provider-B")]),
            DashboardRiskProjection.Fingerprint([Entry("medium", "Provider-B"), first]));
    }

    [Fact]
    public void Bundled_compiler_matches_frozen_python_sql_parameters_and_exactness()
    {
        var expected = WorkspaceJson.Declarations.GetProperty("risk");
        var actual = DashboardRiskProjection.Bundled.Get();
        Assert.Equal(expected.GetProperty("sql").GetString(), actual.Sql);
        Assert.Equal(expected.GetProperty("exact").GetBoolean(), actual.Exact);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected.GetProperty("params").GetRawText()), JsonSerializer.SerializeToNode(actual.Parameters)));
    }

    [Fact]
    public async Task Overview_binds_recompiled_risk_to_the_activity_query()
    {
        var current = Entry();
        var source = new ActivityRows();
        var overview = Sli.Server.Tests.Workspace.UiWorkspaceParityTests.Overview(source, Sli.Server.Tests.Workspace.UiWorkspaceParityTests.Snapshot(), new(() => [current]));
        await overview.ReadAsync(new QueryCollection(), TestContext.Current.CancellationToken);
        Assert.Contains("high", source.Parameters.Select(p => p.Value));
        Assert.Contains("provider-a", source.Parameters.Select(p => p.Value));
        current = Entry("medium", "Provider-B", "System");
        await overview.ReadAsync(new QueryCollection(), TestContext.Current.CancellationToken);
        Assert.Contains("medium", source.Parameters.Select(p => p.Value));
        Assert.Contains("provider-b", source.Parameters.Select(p => p.Value));
        Assert.Contains("system", source.Parameters.Select(p => p.Value));
        Assert.DoesNotContain("high", source.Parameters.Select(p => p.Value));
        Assert.DoesNotContain("Provider-B", source.Sql);
    }

    sealed class ActivityRows : IWorkspaceRows
    {
        internal NpgsqlParameter[] Parameters = [];
        internal string Sql = "";
        public Task<IReadOnlyList<JsonElement>> ReadAsync(string sql, CancellationToken ct, params NpgsqlParameter[] parameters)
        {
            if (sql.Contains("as final_security_severity", StringComparison.Ordinal)) { Parameters = parameters; Sql = sql; }
            return Task.FromResult<IReadOnlyList<JsonElement>>([]);
        }
    }

    sealed class ForwardOnlyStream(byte[] bytes) : Stream
    {
        internal int BytesRead;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            // Deliberately split UTF-8, CRLF and JSON across reads.
            int length = Math.Min(3, Math.Min(count, bytes.Length - BytesRead));
            Array.Copy(bytes, BytesRead, buffer, offset, length);
            BytesRead += length;
            return length;
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
