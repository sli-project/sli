using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Archive;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class SemanticAgentSourceTests
{
    static readonly DateTimeOffset Now = new(2026, 10, 9, 0, 0, 0, TimeSpan.Zero);
    const string Xml = "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><EventData><Data Name=\"TargetUserName\">fixture-account</Data><Data Name=\"Status\">0xc000006a</Data><Data Name=\"LogonType\">3</Data></EventData></Event>";
    static CancellationToken Token => TestContext.Current.CancellationToken;

    sealed class Fixture : IAsyncDisposable
    {
        internal readonly JsonObject Core, Row, Identity;
        internal readonly Session Db;
        readonly PasswordProducerRuntime runtime = PasswordProducerRuntime.Create(
            n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? "host=192.0.2.1 dbname=synthetic user=semantic password=synthetic" : null, _ => throw new InvalidOperationException());
        internal readonly SemanticProduction Production;
        internal Fixture(int eventId = 4625)
        {
            Row = new() { ["event_id"] = eventId, ["record_id"] = 42, ["time_created"] = "2026-10-09T00:00:00+00:00", ["computer_name"] = "fixture-dc", ["channel"] = "Security", ["xml"] = Xml };
            Core = new() { ["id"] = 7, ["server_id"] = 1, ["domain_id"] = 2, ["log_source_id"] = 3,
                ["event_id"] = eventId, ["event_record_id"] = 42, ["time_created_utc"] = Now.ToString("O"),
                ["normalized_hash"] = Hash(Row), ["migrated_at"] = Now.ToString("O"), ["channel"] = "Security",
                ["computer"] = "fixture-dc", ["provider_name"] = "Microsoft-Windows-Security-Auditing" };
            Core["event_data_json"] = new JsonObject { ["TargetUserName"]="fixture-account",["Status"]="0xc000006a",["LogonType"]="3" };
            Identity = Core.DeepClone().AsObject();
            Db = new(Core);
            Production = new(runtime, new(true, false, false, true, false, false), SemanticRuntimeSettings.FactsMode, 1);
        }
        internal Task<JsonObject> Load() => Production.LoadSource(Db, 7, Identity, Token);
        internal Task<int> Hydrate() => Production.HydrateDispatchContext(Db, ["authentication.session.created"], ["source_host"], new() { ["source_host"] = "1" }, "1", Now, Now, Token);
        public ValueTask DisposeAsync() => runtime.DisposeAsync();
    }
    static string Hash(JsonObject row) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(row))));

    sealed class Session(JsonObject core) : ISemanticSession
    {
        internal JsonArray Blocks = [];
        internal string? ArchiveRoot;
        internal bool Missing;
        internal int ShortReads, SummaryReads;
        internal JsonObject? Persisted;
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            ct.ThrowIfCancellationRequested();
            if (sql.Contains("from public.semantic_event_source355 where")) {
                ShortReads++; Assert.Equal(7L, values[0]);
                return Task.FromResult(Missing ? new JsonArray() : new JsonArray(core.DeepClone()));
            }
            if (sql.Contains("has_table_privilege")) return Task.FromResult(new JsonArray(new JsonObject { ["available"] = true }));
            if (sql.Contains("from public.storage_v2_runtime_authorizations")) return Task.FromResult(new JsonArray(SemanticArchiveFixture.Authorization(ArchiveRoot!)));
            if (sql.Contains("from storage_v2_archive_blocks")) { Assert.Equal(7L, values[0]); return Task.FromResult(Blocks.DeepClone().AsArray()); }
            if (sql.Contains("from public.semantic_event_source355 core")) {
                SummaryReads++;
                Assert.Equal(1L, values[0]); Assert.Equal(Now, values[1]); Assert.Equal(Now, values[2]);
                Assert.Equal(4624, values[3]); Assert.Equal("Security", values[4]); Assert.Equal("Microsoft-Windows-Security-Auditing", values[5]);
                Assert.Contains("not exists(select 1 from normalized_events", sql);
                return Task.FromResult(new JsonArray(core.DeepClone()));
            }
            if (sql.Contains("insert into normalized_events")) {
                Assert.Equal(7L, values[1]); Assert.Equal(Convert.FromHexString(core.Text("normalized_hash")!), (byte[])values[3]!);
                Persisted = new() { ["normalized_event_id"] = values[0]!.ToString(), ["semantic_type"] = (string)values[5]!,
                    ["occurred_at_utc"] = ((DateTimeOffset)values[6]!).ToString("O"), ["roles_json"] = ((JsonObject)values[8]!).DeepClone(),
                    ["facts_json"] = ((JsonObject)values[9]!).DeepClone(), ["quality_json"] = ((JsonObject)values[10]!).DeepClone(),
                    ["semantic_sha256"] = Convert.ToHexStringLower((byte[])values[4]!) };
                return Task.FromResult(new JsonArray(new JsonObject { ["normalized_event_id"] = values[0]!.ToString() }));
            }
            if (sql.Contains("from normalized_events where source_event_id")) return Task.FromResult(new JsonArray(Persisted!.DeepClone()));
            throw new InvalidOperationException("Unexpected semantic source query");
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    [Fact] public async Task Attested_short_event_without_archive_normalizes_named_fields()
    {
        await using var f = new Fixture();
        // Digest generated by the Python reference's json.dumps(sort_keys=True, ensure_ascii=False).
        Assert.Equal("072e22fd1f8c58f39599cfb28433a9066c9668b8a82d00cef39bd1cc4e834e8d", f.Core.Text("normalized_hash"));
        var source = await f.Load(); var normalized = SemanticNormalization.Normalize(source);
        Assert.Equal("authentication.session.failed", normalized.Type);
        Assert.Equal("3", source["event_data_json"].Text("LogonType"));
        Assert.Equal("0xc000006a", normalized.Facts.Text("failure_status"));
        Assert.Equal(f.Core.Text("normalized_hash"), source.Text("source_event_sha256"));
        Assert.Equal(1, f.Db.ShortReads);
    }

    [Theory] [InlineData(-1)] [InlineData(1)]
    public async Task Timestamp_precision_preserves_short_identity_and_attested_hash(int microseconds)
    {
        await using var f = new Fixture(); f.Core["time_created_utc"] = Now.AddTicks(microseconds * 10).ToString("O");
        f.Identity["time_created_utc"] = f.Core["time_created_utc"].Copy();
        var source = await f.Load();
        Assert.Equal(f.Core.Text("time_created_utc"), source.Text("time_created_utc"));
        Assert.Equal(f.Core.Text("normalized_hash"), source.Text("source_event_sha256"));
        Assert.Equal("authentication.session.failed", SemanticNormalization.Normalize(source).Type);
    }

    [Fact] public async Task Database_microsecond_timestamp_keeps_attested_hash()
    {
        await using var f = new Fixture(); f.Row["time_created"] = "2026-10-09T00:00:00.502957500Z";
        f.Core["time_created_utc"] = Now.AddTicks(5029580).ToString("O");
        f.Core["normalized_hash"] = Hash(f.Row);
        f.Identity["time_created_utc"] = f.Core["time_created_utc"].Copy(); f.Identity["normalized_hash"] = f.Core["normalized_hash"].Copy();
        Assert.Equal(f.Core.Text("normalized_hash"), (await f.Load()).Text("source_event_sha256"));
    }

    [Theory] [InlineData(-2)] [InlineData(2)]
    public async Task Timestamp_different_from_retained_identity_fails_closed(int microseconds)
    {
        await using var f = new Fixture(); f.Core["time_created_utc"] = Now.AddTicks(microseconds * 10).ToString("O");
        Assert.Equal("archive_core_timestamp_mismatch", (await Assert.ThrowsAsync<InvalidDataException>(() => f.Load())).Message);
    }

    [Fact] public async Task Timestamp_tolerance_never_admits_changed_payload()
    {
        await using var f = new Fixture(); f.Core["time_created_utc"] = Now.AddTicks(10).ToString("O");
        f.Identity["time_created_utc"] = f.Core["time_created_utc"].Copy(); f.Row["xml"] = Xml.Replace("fixture-account", "other-account");
        f.Core["normalized_hash"]=Hash(f.Row);
        Assert.Equal("semantic_source_hash_mismatch", (await Assert.ThrowsAsync<InvalidDataException>(() => f.Load())).Message);
    }

    [Theory] [InlineData("hash")] [InlineData("event")] [InlineData("time")] [InlineData("job")] [InlineData("domain")]
    public async Task Evidence_mismatch_fails_closed(string mutation)
    {
        await using var f = new Fixture();
        switch (mutation) {
            case "hash": f.Core["normalized_hash"] = new string('b', 64); break;
            case "event": f.Core["event_id"] = 4624; break;
            case "time": f.Core["time_created_utc"] = Now.AddHours(1).ToString("O"); break;
            case "job": f.Identity["normalized_hash"] = new string('a', 64); break;
            case "domain": f.Core["domain_id"] = 3; break;
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Load());
    }

    [Fact] public async Task Missing_short_event_and_archive_fail_without_legacy_fallback()
    {
        await using var f = new Fixture(); f.Db.Missing = true;
        await Assert.ThrowsAsync<SemanticSourceAbsentException>(() => f.Load());
    }

    [Fact] public async Task Agent_context_without_archive_is_normalized_and_persisted()
    {
        await using var f = new Fixture(4624);
        Assert.Equal(1, await f.Hydrate()); Assert.Equal(1, f.Db.SummaryReads); Assert.Equal(1, f.Db.ShortReads);
        Assert.Equal("authentication.session.created", f.Db.Persisted.Text("semantic_type"));
        Assert.Equal("3", f.Db.Persisted!["facts_json"].Text("logon_type"));
    }

    [Theory] [InlineData(false, false)] [InlineData(true, false)] [InlineData(true, true)]
    public async Task Published_archive_corruption_or_missing_row_fails_closed(bool context, bool missingRow)
    {
        await using var f = new Fixture(context ? 4624 : 4625); f.Db.Missing=true;
        string root = Path.Combine(Path.GetTempPath(), "semantic-source-" + Guid.NewGuid().ToString("N"));
        string? previous = Environment.GetEnvironmentVariable("ADLOG_STORAGE_V2_ARCHIVE_ROOT");
        try {
            Environment.SetEnvironmentVariable("ADLOG_STORAGE_V2_ARCHIVE_ROOT", root); f.Db.ArchiveRoot = root;
            // The published range covers 7, but the verified block can lack that exact row.
            var first = f.Core.DeepClone().AsObject(); first["id"] = 6;
            var last = f.Core.DeepClone().AsObject(); last["id"] = 8;
            var encoded = ArchiveCodec.Encode("event", [first, last]); var compressed = ArchiveCodec.Compress(encoded.Raw);
            string path = Path.Combine(root, "published", "fixture.jsonl.gz"); Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllBytes(path, compressed);
            f.Db.Blocks = new(new JsonObject { ["archive_set_id"] = Guid.NewGuid().ToString(), ["format_version"] = 1, ["block_index"] = 0,
                ["first_event_id"] = 6, ["last_event_id"] = 8, ["row_count"] = 2, ["raw_bytes"] = encoded.Raw.Length, ["compressed_bytes"] = compressed.Length,
                ["raw_sha256"] = ArchiveCodec.Hash(encoded.Raw), ["archive_sha256"] = missingRow ? ArchiveCodec.Hash(compressed) : new string('0', 64),
                ["object_location"] = path, ["created_at"] = Now.ToString("O") });
            var error = await Assert.ThrowsAsync<InvalidDataException>(async () => { if (context) await f.Hydrate(); else await f.Load(); });
            Assert.Equal(missingRow ? "archive_event_missing_or_duplicate" : "archive_compressed_hash_mismatch", error.Message);
            Assert.Equal(1, f.Db.ShortReads); Assert.Null(f.Db.Persisted);
        }
        finally { Environment.SetEnvironmentVariable("ADLOG_STORAGE_V2_ARCHIVE_ROOT", previous); if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
}
