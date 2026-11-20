using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Sli.Agent.Windows;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>
/// The parts only a real Windows can prove: DPAPI, ACLs, NTFS durability and the Event Log with bookmarks.
/// They run on the stage-2 Win10 VM; Linux CI excludes Category=WindowsOnly.
/// </summary>
[Trait("Category", "WindowsOnly")]
[SupportedOSPlatform("windows")]
public sealed class WindowsIntegrationTests : IDisposable
{
    private const string LogName = "SliAgentTest";
    private const string SourceName = "SliAgentTestSource";
    private readonly string _directory = Helpers.TempDirectory();

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
        if (EventLog.Exists(LogName)) EventLog.Delete(LogName);
    }

    [WindowsFact]
    public void DpapiRoundTripsAndTheKeyFileUsesIt()
    {
        var protector = new DpapiKeyProtector();
        var secret = "secret"u8.ToArray();
        var wrapped = protector.Protect(secret);
        Assert.NotEqual(secret, wrapped);
        Assert.Equal(secret, protector.Unprotect(wrapped));

        var store = new HostIdentityStore(Path.Combine(_directory, "state"), new PhysicalDurableFiles(new WindowsDirectorySecurity()), protector);
        var first = store.Prepare();
        Assert.Equal(first, store.Prepare());
        var body = JsonNode.Parse(File.ReadAllText(Path.Combine(_directory, "state", "identity-key.json")))!;
        Assert.Equal("dpapi_local_machine", body["protection"]!.GetValue<string>());
        using var key = store.LoadKey();
        Assert.Equal(first.KeyFingerprint, HostIdentityStore.Fingerprint(key));
        // The restricted-file form cannot read a DPAPI key file.
        Assert.Equal("agent_identity_invalid", Assert.Throws<AgentException>(() =>
            new HostIdentityStore(Path.Combine(_directory, "state"), new PhysicalDurableFiles(), new RestrictedFileKeyProtector()).LoadKey()).Code);
    }

    [WindowsFact]
    public void TheStateDirectoryKeepsOnlyTheServiceIdentityAndSystem()
    {
        var path = Path.Combine(_directory, "protected");
        new PhysicalDurableFiles(new WindowsDirectorySecurity()).EnsureDirectory(path);
        var rules = new DirectoryInfo(path).GetAccessControl();
        Assert.True(rules.AreAccessRulesProtected);
        var principals = rules.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            .Select(rule => rule.IdentityReference.Value).Distinct().Order().ToArray();
        var expected = new[] { WindowsIdentity.GetCurrent().User!.Value, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value }.Distinct().Order().ToArray();
        Assert.Equal(expected, principals);
        Assert.All(rules.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(), rule => Assert.Equal(AccessControlType.Allow, rule.AccessControlType));
        File.WriteAllText(Path.Combine(path, "probe.txt"), "ok"); // the service identity itself keeps access
    }

    [WindowsFact]
    public void TheQueueSurvivesARestartOnNtfsWithAProtectedDirectory()
    {
        var files = new PhysicalDurableFiles(new WindowsDirectorySecurity());
        using var key = Helpers.NewKey();
        SignedPacket packet;
        using (var queue = Helpers.Queue(Path.Combine(_directory, "queue"), files))
        {
            packet = queue.Capture(Helpers.Signer(key), Helpers.AgentId, Helpers.Sample("", "1"), Helpers.Now);
            Assert.Equal("agent_state_locked", Assert.Throws<AgentException>(() => Helpers.Queue(Path.Combine(_directory, "queue"), files)).Code);
        }
        using var restarted = Helpers.Queue(Path.Combine(_directory, "queue"), files);
        Assert.Equal(packet.ToCanonical(), restarted.Pending().Single().ToCanonical());
        Assert.True(restarted.Acknowledge(packet, Helpers.Receipt(packet)));
        Assert.Empty(restarted.Pending());
        Assert.Equal(2, restarted.Capture(Helpers.Signer(key), Helpers.AgentId, Helpers.Sample("1", "2"), Helpers.Now).Envelope.Sequence);
    }

    private static long RecordId(string xml) =>
        JsonRead.TryInteger(EventXml.Parse(xml, "host", "address", LogName)["record_id"], out var id) ? (long)id : throw new InvalidOperationException();

    private static void Write(int count, int firstEventId)
    {
        using var log = new EventLog(LogName) { Source = SourceName };
        for (var i = 0; i < count; i++) log.WriteEntry("synthetic entry " + (firstEventId + i), EventLogEntryType.Information, firstEventId + i);
    }

    private static SourceBatch ReadUntil(EventLogBookmarkSource source, ChannelProgress progress, int limit, int expected)
    {
        // The Event Log service publishes new entries asynchronously.
        var deadline = Stopwatch.StartNew();
        SourceBatch batch;
        do
        {
            batch = source.Read(LogName, progress, limit);
            if (batch.Rows.Count >= expected || batch.BookmarkRecovered) return batch;
            Thread.Sleep(250);
        }
        while (deadline.Elapsed < TimeSpan.FromSeconds(20));
        return batch;
    }

    [WindowsAdminFact]
    public void ReadsAChannelResumesFromABookmarkAndNoticesALostAnchor()
    {
        if (EventLog.SourceExists(SourceName)) EventLog.DeleteEventSource(SourceName);
        EventLog.CreateEventSource(new EventSourceCreationData(SourceName, LogName));
        var catalog = EventCatalog.Load();
        var source = new EventLogBookmarkSource(catalog);
        Write(5, 1000);

        var first = ReadUntil(source, ChannelProgress.Start("gen"), 3, 3);
        Assert.False(first.BookmarkRecovered);
        Assert.Equal(3, first.Rows.Count);
        var ids = first.Rows.Select(row => RecordId(row.Xml)).ToArray();
        Assert.Equal(ids.Order(), ids);
        Assert.All(first.Rows, row =>
        {
            Assert.StartsWith("<BookmarkList", row.Bookmark, StringComparison.Ordinal);
            Assert.InRange(row.Bookmark.Length, 1, ChannelProgress.MaxBookmarkCodePoints);
            // Each event is a complete XML the module can parse and the server can re-parse.
            Assert.Equal(LogName, EventXml.NativeChannel(EventXml.ParseBounded(row.Xml)));
        });

        // Resume right after the third event: exactly the remaining two, no overlap, no gap.
        var progress = new ChannelProgress(ids[^1], first.Rows[^1].Bookmark, "gen");
        var second = ReadUntil(source, progress, 10, 2);
        Assert.False(second.BookmarkRecovered);
        Assert.Equal(2, second.Rows.Count);
        Assert.Equal(ids[^1] + 1, RecordId(second.Rows[0].Xml));

        // At the tail there is nothing new, and that is not a lost anchor.
        var tail = new ChannelProgress(RecordId(second.Rows[^1].Xml), second.Rows[^1].Bookmark, "gen");
        var empty = source.Read(LogName, tail, 10);
        Assert.Empty(empty.Rows);
        Assert.False(empty.BookmarkRecovered);

        // New events after the tail are found from the same bookmark.
        Write(2, 2000);
        var later = ReadUntil(source, tail, 10, 2);
        Assert.False(later.BookmarkRecovered);
        Assert.Equal(2, later.Rows.Count);
        Assert.Equal(RecordId(second.Rows[^1].Xml) + 1, RecordId(later.Rows[0].Xml));

        // Clearing the log removes the anchor: the source must say so instead of silently continuing.
        using (var log = new EventLog(LogName)) log.Clear();
        Write(2, 3000);
        var lost = ReadUntil(source, tail, 10, 1);
        Assert.True(lost.BookmarkRecovered);
    }

    [WindowsFact]
    public void ReadsApplicationAndResumesItsBookmarkWithoutRegisteringAServiceOrEventSource()
    {
        var source = new EventLogBookmarkSource(EventCatalog.Load(), filterSecurity: false);
        var first = source.Read("Application", ChannelProgress.Start("synthetic-generation"), 2);
        Assert.NotEmpty(first.Rows);
        var last = first.Rows[^1];
        var row = EventXml.Parse(last.Xml, "synthetic-host", "localhost", "Application");
        Assert.True(JsonRead.TryInteger(row["record_id"], out var id));
        var next = source.Read("Application", new ChannelProgress((long)id, last.Bookmark, "synthetic-generation"), 2);
        Assert.False(next.BookmarkRecovered);
        foreach (var item in next.Rows)
        {
            var parsed = EventXml.Parse(item.Xml, "synthetic-host", "localhost", "Application");
            Assert.True(JsonRead.TryInteger(parsed["record_id"], out var following) && following > id);
        }
    }

    [WindowsFact]
    public void AMissingChannelIsADiagnosticAndNeverExposesContent()
    {
        var source = new EventLogBookmarkSource(EventCatalog.Load());
        var exception = Assert.Throws<EventLogReadException>(() => source.Read("SliNoSuchChannel", ChannelProgress.Start("gen"), 1));
        Assert.Equal("agent_ad_dc_read_failed", exception.Code);
        Assert.Equal("SliNoSuchChannel", exception.Diagnostic!.Channel);
        Assert.False(exception.Diagnostic.BookmarkPresent);
        Assert.DoesNotContain("SliNoSuchChannel", exception.Message, StringComparison.Ordinal);
    }

    [WindowsAdminFact]
    public void TheSecurityChannelIsReadableAndItsEventsParse()
    {
        var source = new EventLogBookmarkSource(EventCatalog.Load());
        var progress = ChannelProgress.Start("gen") with { SinceUtc = Iso8601.Format(DateTimeOffset.UtcNow.AddHours(-1)) };
        SourceBatch batch;
        try
        {
            batch = source.Read("Security", progress, 5);
        }
        catch (EventLogReadException exception) when (exception.Diagnostic?.WinError == 5)
        {
            return; // an account without the right to read Security: the diagnostic says so, which is the contract
        }
        Assert.True(batch.Rows.Count <= 5);
        foreach (var row in batch.Rows)
        {
            Assert.Equal("Security", EventXml.NativeChannel(EventXml.ParseBounded(row.Xml)));
            Assert.NotNull(EventXml.Parse(row.Xml, "host", "address", "Security")["record_id"]);
        }
    }
}
