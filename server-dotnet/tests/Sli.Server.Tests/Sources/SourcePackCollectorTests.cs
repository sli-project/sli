using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.SourcePacks;
using Xunit;

namespace Sli.Server.Tests.Sources;

public sealed class SourcePackCollectorTests
{
    [Fact]
    public void CollectorDeclarationIsValidatedWithoutStartingIt()
    {
        var spec = CollectorSpec.Parse(JsonNode.Parse("""{"kind":"file","entry":"server.source_packs.examples.linux_auth:auth_log_collector","schedule":"*/5 * * * *"}"""));
        Assert.Equal(new CollectorSpec("file", LinuxAuth.CollectorEntry, "*/5 * * * *"), spec);
        Assert.Null(CollectorSpec.Parse(null));
        Assert.Null(CollectorSpec.Parse(new JsonObject()));
        // A valid namespace declaration need not have a factory installed during validation.
        Assert.Equal("pull", CollectorSpec.Parse(JsonNode.Parse("""{"kind":"pull","entry":"sli_source_packs.example:factory"}"""))!.Kind);
        Assert.Equal("push", CollectorSpec.Parse(JsonNode.Parse("""{"kind":"push","entry":"server.source_packs.absent:factory"}"""))!.Kind);
        Assert.Contains("kind", Assert.Throws<ArgumentException>(() => CollectorSpec.Parse(JsonNode.Parse("""{"kind":"stream","entry":"server.source_packs.x:y"}"""))).Message);
        Assert.Contains("not allowed", Assert.Throws<ArgumentException>(() => CollectorSpec.Parse(JsonNode.Parse("""{"kind":"pull","entry":"subprocess:run"}"""))).Message);
        Assert.Contains("not allowed", Assert.Throws<ArgumentException>(() => CollectorSpec.Parse(JsonNode.Parse("""{"kind":"file","entry":"server.source_packs.x:"}"""))).Message);
        Assert.Contains("object", Assert.Throws<ArgumentException>(() => CollectorSpec.Parse(JsonValue.Create("file"))).Message);
    }

    [Fact]
    public void FileCollectorReadsOnlyCompleteLinesAfterByteOffset()
    {
        WithFile(path =>
        {
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes("one\ntwo\nthree\npartial"));
            var collector = new FileLineCollector(path);
            var first = collector.Collect(null, 2);
            Assert.Equal(["one", "two"], Lines(first));
            Assert.Equal(["0", "4"], first.Events.Select(e => e.Position));
            Assert.Equal("8", first.NextCursor);
            Assert.True(first.HasMore);
            var second = collector.Collect(first.NextCursor, 10);
            Assert.Equal(["three"], Lines(second));
            Assert.Equal("14", second.NextCursor);
            Assert.False(second.HasMore);
            Assert.Empty(collector.Collect(second.NextCursor, 10).Events);
            File.AppendAllText(path, " line\n", new UTF8Encoding(false));
            var third = collector.Collect(second.NextCursor, 10);
            Assert.Equal(["partial line"], Lines(third));
            Assert.Equal("14", third.Events.Single().Position);
            Assert.Equal("27", third.NextCursor);
        });
    }

    [Fact]
    public void FileCollectorUsesBytesAndReplacementDecodingAndAdvancesPastSkippedLines()
    {
        WithFile(path =>
        {
            File.WriteAllBytes(path, [0xc3, 0xa9, 13, 10, 0xff, 10]);
            var collector = new FileLineCollector(path);
            var first = collector.Collect(null, 1);
            Assert.Equal(["é"], Lines(first));
            Assert.Equal("4", first.NextCursor);
            Assert.True(first.HasMore);
            var second = collector.Collect(first.NextCursor, 1);
            Assert.Equal(["�"], Lines(second));
            Assert.Equal("4", second.Events.Single().Position);
            Assert.Equal("6", second.NextCursor);
            Assert.False(second.HasMore);

            File.WriteAllText(path, "skip\nkeep\nskip\n", new UTF8Encoding(false));
            var filtered = new FileLineCollector(path, line => line == "keep" ? new JsonObject { ["line"] = line } : null).Collect(null, 10);
            Assert.Equal(["keep"], Lines(filtered));
            Assert.Equal("5", filtered.Events.Single().Position);
            Assert.Equal("15", filtered.NextCursor);
            Assert.False(filtered.HasMore);
        });
    }

    [Fact]
    public void HostMovesCursorOnlyAfterSinkAcceptsAndDeduplicatesPayloads()
    {
        RawEvent[] events = [new("1", new() { ["a"] = 1 }), new("2", new() { ["a"] = 1 }), new("3", new() { ["a"] = 2 })];
        var collector = new Fixed(events, "3");
        var cursors = new MemoryCursorStore();
        Assert.Throws<InvalidOperationException>(() => CollectorHost.RunOnce("p", collector, cursors,
            (_, _) => throw new InvalidOperationException("storage unavailable")));
        Assert.Null(cursors.Get("p"));
        var stored = new List<RawEvent>();
        var report = CollectorHost.RunOnce("p", collector, cursors, (pack, batch) =>
        {
            Assert.Equal("p", pack);
            Assert.Null(cursors.Get("p"));
            stored.AddRange(batch);
            return batch.Count;
        });
        Assert.Equal(new RunReport("p", 3, 2, 1, null, "3", false), report);
        Assert.Equal(["1", "3"], stored.Select(e => e.Position));
        Assert.Equal("3", cursors.Get("p"));
        Assert.Null(cursors.Get("other-pack"));
        // Fingerprints depend on canonical payloads, including nested keys and Unicode, not positions.
        Assert.Equal(new RawEvent("4", JsonNode.Parse("""{"b":{"z":"é","a":1},"a":2}""")!.AsObject()).Fingerprint(),
            new RawEvent("5", JsonNode.Parse("""{"a":2,"b":{"a":1,"z":"é"}}""")!.AsObject()).Fingerprint());
    }

    [Fact]
    public void HostPreservesCursorOnFailureAndHandlesEmptyOrInvalidBatches()
    {
        var cursors = new MemoryCursorStore();
        cursors.Set("p", "before");
        var one = new RawEvent("1", new() { ["a"] = 1 });
        Assert.Throws<InvalidOperationException>(() => CollectorHost.RunOnce("p", new Fixed([one], "after"), cursors,
            (_, _) => throw new InvalidOperationException()));
        Assert.Equal("before", cursors.Get("p"));
        var empty = new Fixed([], null, true);
        var report = CollectorHost.RunOnce("p", empty, cursors, (_, _) => throw new InvalidOperationException(), limit: 10001);
        Assert.Equal("before", empty.CursorReceived);
        Assert.Equal(new RunReport("p", 0, 0, 0, "before", "before", true), report);
        Assert.Throws<ArgumentException>(() => CollectorHost.RunOnce("p", empty, cursors, (_, _) => 0, limit: 0));
        Assert.Throws<ArgumentException>(() => CollectorHost.RunOnce("p", new Fixed([one, one], "after", obeyLimit: false), cursors, (_, _) => throw new InvalidOperationException(), limit: 1));
        Assert.Equal("before", cursors.Get("p"));
    }

    [Fact]
    public void ReferencePackCollectsAndNormalizesThroughManifest()
    {
        var pack = new SourcePackCollectorManifest(File.ReadAllText(RepoFile("config/source_packs/examples/linux_auth.json")));
        var collector = pack.Collector!.Load(RepoFile("tests/fixtures/linux_auth/auth.log.txt"), 2026, "UTC");
        var stored = new List<RawEvent>();
        var cursors = new MemoryCursorStore();
        var report = CollectorHost.RunOnce(pack.PackId, collector, cursors, (_, batch) => { stored.AddRange(batch); return batch.Count; }, limit: 100);
        Assert.Equal("example.linux-auth", pack.PackId);
        Assert.Equal("example-linux-auth-v1", pack.NormalizerId);
        Assert.Equal(9, report.Received);
        Assert.Equal(9, report.Accepted);
        Assert.Equal(0, report.Duplicates);
        Assert.False(report.HasMore);
        Assert.Equal(File.ReadAllBytes(RepoFile("tests/fixtures/linux_auth/auth.log.txt")).Length.ToString(), report.CursorAfter);
        JsonObject[] expected =
        [
            Event(100, "2026-09-30T10:15:01Z", "sshd", "1201", "alice", "192.0.2.10", "publickey"),
            Event(120, "2026-09-30T10:15:01Z", "sshd", "1201", "alice"),
            Event(110, "2026-09-30T10:16:22Z", "sudo", null, "alice", command: "/usr/bin/apt update"),
            Event(101, "2026-09-30T10:20:47Z", "sshd", "1310", "bob", "198.51.100.7", "password"),
            Event(101, "2026-09-30T10:20:51Z", "sshd", "1310", "admin", "198.51.100.7", "password"),
            Event(100, "2026-09-30T10:21:05Z", "sshd", "1312", "bob", "198.51.100.7", "password"),
            Event(100, "2026-09-01T09:05:09Z", "sshd", "1400", "alice", "192.0.2.11", "password"),
            Event(121, "2026-09-30T10:31:12Z", "sshd", "1201", "alice"),
            Event(121, "2026-09-30T10:35:10Z", "sshd", "1312", "bob")
        ];
        for (int i = 0; i < expected.Length; i++)
        {
            Assert.True(JsonNode.DeepEquals(expected[i], stored[i].Payload), $"event {i}: {stored[i].Payload}");
            var facts = pack.EventFacts(stored[i].Payload, stored[i].Payload);
            var expectedFacts = new JsonObject
            {
                ["process_name"] = expected[i]["program"]!.DeepClone(), ["process_id"] = expected[i]["pid"]?.DeepClone(),
                ["target_server_name"] = "web01.example.test", ["service_name"] = null, ["task_name"] = null,
                ["task_action"] = null, ["task_author"] = null, ["run_as"] = null,
                ["logon_type"] = expected[i]["auth_method"]?.DeepClone(),
                ["result_code"] = i is 0 or 5 or 6 ? "success" : i is 3 or 4 ? "failure" : null,
                ["object_name"] = expected[i]["command"]?.DeepClone(), ["share_name"] = null, ["message_sample"] = null
            };
            Assert.True(JsonNode.DeepEquals(expectedFacts, facts));
        }
        Assert.Equal("file", pack.PublicDict()["collector"]!["kind"]!.GetValue<string>());
        Assert.False(pack.PublicDict()["collector"]!.AsObject().ContainsKey("schedule"));
        Assert.Empty(collector.Collect(report.CursorAfter, 100).Events);
    }

    private static JsonObject Event(int id, string time, string program, string? pid, string user, string? ip = null, string? method = null, string? command = null) => new()
    {
        ["event_id"] = id, ["host"] = "web01.example.test", ["program"] = program, ["pid"] = pid,
        ["user"] = user, ["source_ip"] = ip, ["auth_method"] = method, ["command"] = command, ["time"] = time
    };
    private static IEnumerable<string?> Lines(CollectResult result) => result.Events.Select(e => e.Payload["line"]?.GetValue<string>());
    private static void WithFile(Action<string> test)
    {
        string directory = Path.Combine(Path.GetTempPath(), "sli-source-collector-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try { test(Path.Combine(directory, "log.txt")); }
        finally { Directory.Delete(directory, true); }
    }
    private static string RepoFile(string relative, [System.Runtime.CompilerServices.CallerFilePath] string caller = "")
    {
        for (var directory = new FileInfo(caller).Directory; directory is not null; directory = directory.Parent)
        {
            string path = Path.Combine(directory.FullName, relative);
            if (File.Exists(path)) return path;
        }
        throw new FileNotFoundException(relative);
    }
    private sealed class Fixed(RawEvent[] events, string? cursor, bool hasMore = false, bool obeyLimit = true) : ICollector
    {
        public string? CursorReceived { get; private set; }
        public CollectResult Collect(string? before, int limit)
        {
            CursorReceived = before;
            return new(obeyLimit ? events.Take(limit).ToArray() : events, cursor, hasMore);
        }
    }
}
