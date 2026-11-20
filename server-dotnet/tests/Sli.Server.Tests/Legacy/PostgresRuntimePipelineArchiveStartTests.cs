using Sli.Server.Legacy;
using Xunit;

namespace Sli.Server.Tests.Legacy;

public sealed class PostgresRuntimePipelineArchiveStartTests
{
    [Fact]
    public async Task Retired_archive_reader_never_opens_a_database()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresRuntimePipeline.ReadArchiveStartCandidateAsync(null!, null!, TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled", error.Message);
    }
}
