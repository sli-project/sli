using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Sli.Server.Legacy;
using Xunit;

namespace Sli.Server.Tests.Legacy;

// Vectors from tests/reporting/test_post_collection_publication.py.
public sealed class PostCollectionPublicationTests
{
    private static readonly LegacyReport Report = new("/reports/server-DC1-security-profile.html", [
        new("server-DC1-security-profile.html", "current-report"),
        new("domain-security-overview.html", "current-report"),
        new("collector-health.html", "current-health")]);
    private static readonly LegacyPostClaim Claim = new("job-1", 1, ["DC1"], "worker-a", 2);

    [Fact]
    public async Task LeaseLossDuringRenderCannotOverwriteNewerFiles()
    {
        using var directory = new ReportDirectory();
        directory.Seed("new-owner-report");
        var store = new Store();
        var result = await RunAsync(directory, store, () => store.Owns = false);

        Assert.Equal(new LegacyPostResult(1, 0, 1), result);
        Assert.Equal(0, store.Finishes);
        Assert.Single(store.Guards);
        directory.AssertFiles("new-owner-report");
    }

    [Fact]
    public async Task EachPublicationPromotesOneCompleteStagedFileInsideExactClaimGuard()
    {
        using var directory = new ReportDirectory();
        directory.Seed("previous-report");
        var store = new Store();
        int publications = 0;
        store.OnFence = async publish => {
            var file = Report.Files[publications];
            string temporary = Assert.Single(Directory.GetFiles(directory.Path, "." + file.Name + ".*.tmp"));
            Assert.Equal(file.Content, await File.ReadAllTextAsync(temporary));
            Assert.Equal("previous-report", File.ReadAllText(System.IO.Path.Combine(directory.Path, file.Name)));

            await publish();

            Assert.False(File.Exists(temporary));
            publications++;
            // A guard must publish only its own file, never the remaining batch.
            for (int index = 0; index < Report.Files.Count; index++) {
                var expected = Report.Files[index];
                Assert.Equal(index < publications ? expected.Content : "previous-report",
                    File.ReadAllText(System.IO.Path.Combine(directory.Path, expected.Name)));
            }
        };

        Assert.Equal(new LegacyPostResult(1, 1, 0), await RunAsync(directory, store));
        Assert.Equal(3, publications);
        Assert.Equal(3, store.Guards.Count);
        Assert.All(store.Guards, claim => Assert.Equal(Claim, claim));
        Assert.Equal(1, store.Finishes);
        directory.AssertFiles();
    }

    [Fact]
    public async Task LeaseLossBetweenPublicationsPreservesRemainingNewOwnerFiles()
    {
        using var directory = new ReportDirectory();
        directory.Seed("new-owner-report");
        var store = new Store();
        store.OnFence = async publish => { await publish(); store.Owns = false; };

        Assert.Equal(new LegacyPostResult(1, 0, 1), await RunAsync(directory, store));
        Assert.Equal(2, store.Guards.Count);
        Assert.Equal(0, store.Finishes);
        directory.AssertFiles("new-owner-report", firstPublished: true);
    }

    [Fact]
    public async Task FailedPromotionPropagatesIoErrorPreservesPublishedBytesAndCleansTemporaryFiles()
    {
        using var directory = new ReportDirectory();
        directory.Seed("published-report");
        bool promotionAttempted = false;
        await Assert.ThrowsAnyAsync<IOException>(() => LegacyReportPublication.PublishAsync(Report, directory.Path,
            async (publish, _) => {
                // Fault injection at the filesystem boundary: the real move must fail.
                string temporary = Assert.Single(Directory.GetFiles(directory.Path, "." + Report.Files[0].Name + ".*.tmp"));
                Assert.Equal("current-report", File.ReadAllText(temporary));
                File.Delete(temporary);
                promotionAttempted = true;
                await publish();
            }, TestContext.Current.CancellationToken));

        Assert.True(promotionAttempted);
        directory.AssertFiles("published-report");
    }

    private static Task<LegacyPostResult> RunAsync(ReportDirectory directory, Store store, Action? render = null)
    {
        var settings = new LegacySettings(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:DataDirectory"] = directory.Root,
            ["Sli:Legacy:SLI_LEGACY_COLLECTION_DISABLED"] = "0",
            ["Sli:Legacy:ADLOG_LEGACY_FINDINGS_ENABLED"] = "0"
        }).Build());
        return new LegacyPostCollection(store, new Analysis(render), settings, NullLogger<LegacyPostCollection>.Instance)
            .RunOnceAsync(Claim.Worker, 1, TestContext.Current.CancellationToken);
    }

    private sealed class Analysis(Action? render) : ILegacyAnalysis
    {
        public Task<LegacyReport> RenderAsync(long jobId, string[] servers, CancellationToken ct)
        {
            Assert.Equal(Claim.SourceId, jobId);
            Assert.Equal(Claim.Servers, servers);
            render?.Invoke();
            return Task.FromResult(Report);
        }
    }

    private sealed class Store : ILegacyPostStore
    {
        public bool Owns = true;
        public int Finishes;
        public List<LegacyPostClaim> Guards { get; } = [];
        public Func<Func<Task>, Task>? OnFence;
        public Task QueueAsync(string durableId, int sourceId, string[] servers, CancellationToken ct) => throw new NotSupportedException();
        public Task RecoverAsync(CancellationToken ct) => Task.CompletedTask;
        public Task<IReadOnlyList<LegacyPostClaim>> ClaimAsync(string worker, int limit, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<LegacyPostClaim>>([Claim]);
        public Task HeartbeatAsync(LegacyPostClaim claim, string phase, CancellationToken ct) => Task.CompletedTask;
        public Task FindingsAsync(LegacyPostClaim claim, JsonObject result, string? errorId, CancellationToken ct) => Task.CompletedTask;
        public Task FinishAsync(LegacyPostClaim claim, string? reportPath, string? errorId, CancellationToken ct)
        {
            // A lost lease must never be finished, even as a failed job.
            if (!Owns) throw new LegacyLeaseLost();
            Finishes++;
            return Task.CompletedTask;
        }
        public async Task FenceAsync(LegacyPostClaim claim, Func<Task> publish, CancellationToken ct)
        {
            Guards.Add(claim);
            if (!Owns) throw new LegacyLeaseLost();
            if (OnFence is null) await publish(); else await OnFence(publish);
        }
    }

    private sealed class ReportDirectory : IDisposable
    {
        public string Root { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sli-publication-tests-" + Guid.NewGuid().ToString("N"));
        public string Path => System.IO.Path.Combine(Root, "reports");
        public ReportDirectory() => Directory.CreateDirectory(Path);
        public void Seed(string content)
        {
            foreach (var file in Report.Files) File.WriteAllText(System.IO.Path.Combine(Path, file.Name), content);
        }
        public void AssertFiles(string? content = null, bool firstPublished = false)
        {
            Assert.Equal(Report.Files.Select(file => file.Name).Order(), Directory.GetFiles(Path).Select(System.IO.Path.GetFileName).Order());
            for (int index = 0; index < Report.Files.Count; index++) {
                var file = Report.Files[index];
                Assert.Equal(firstPublished && index == 0 ? file.Content : content ?? file.Content,
                    File.ReadAllText(System.IO.Path.Combine(Path, file.Name)));
            }
        }
        public void Dispose() => Directory.Delete(Root, true);
    }
}
