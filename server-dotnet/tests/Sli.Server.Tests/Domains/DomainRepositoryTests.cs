using Npgsql;
using Sli.Server.Access;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class DomainRepositoryTests
{
    [Fact]
    public async Task EmptyGrantNeverOpensDatabaseConnection()
    {
        var factory = new RefusingFactory();
        var repository = new DomainRepository(factory);

        IReadOnlyList<DomainItem> result = await repository.ReadAsync(DomainGrant.None, CancellationToken.None);

        Assert.Empty(result);
        Assert.False(factory.Called);
    }

    private sealed class RefusingFactory : IPostgresConnectionFactory
    {
        public bool Called { get; private set; }

        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            Called = true;
            throw new InvalidOperationException("A denied scope must not access the database.");
        }
    }
}
