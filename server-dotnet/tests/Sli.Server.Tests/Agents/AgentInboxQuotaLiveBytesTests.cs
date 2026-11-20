using Sli.Server.Agents.Ingress;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentInboxQuotaLiveBytesTests
{
    private const long Gib = 1024L * 1024 * 1024;
    private const long StorageLimit = 16 * Gib;

    [Fact]
    public void Large_file_with_little_live_data_counts_only_the_live_part()
    {
        // 20 GiB file after retention deleted almost everything: 10k rows of 1 KiB remain.
        long live = AgentInboxQuota.EstimateLiveBytes(20 * Gib, 2 * Gib, 10_000, 1024, 0);
        Assert.True(live < Gib / 10, live.ToString());
        Assert.True(live <= StorageLimit - (2 * 65536 + 65536));
    }

    [Fact]
    public void Large_toasted_payloads_are_counted_through_their_chunks()
    {
        long live = AgentInboxQuota.EstimateLiveBytes(20 * Gib, 2 * Gib, 1000, 60, 2_000_000);
        Assert.InRange(live, 3L * Gib, 5L * Gib);
    }

    [Fact]
    public void Live_data_filling_the_file_keeps_the_full_size_over_the_limit()
    {
        long total = 18 * Gib;
        long live = AgentInboxQuota.EstimateLiveBytes(total, 2 * Gib, 4_500_000, 4096, 0);
        Assert.Equal(total, live);
        Assert.True(live > StorageLimit);
    }

    [Fact]
    public void Missing_statistics_fall_back_to_the_relation_size()
    {
        Assert.Equal(18 * Gib, AgentInboxQuota.EstimateLiveBytes(18 * Gib, 2 * Gib, -1, 0, 0));
        Assert.Equal(18 * Gib, AgentInboxQuota.EstimateLiveBytes(18 * Gib, 2 * Gib, 100, 0, 0));
    }
}
