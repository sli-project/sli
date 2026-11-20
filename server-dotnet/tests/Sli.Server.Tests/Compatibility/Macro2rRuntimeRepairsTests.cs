using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Server.Compatibility;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Compatibility;

// Behavioral vectors from tests/core/test_macro2r_runtime_repairs.py.
// Npgsql binds @pN directly; psycopg's percent escaping must not be copied.
public sealed class Macro2rRuntimeRepairsTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static IConfiguration Configuration(string dsn) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = dsn }).Build();

    [Fact]
    public async Task Like_literals_and_one_bound_id_execute_without_accidental_bind_markers()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        using var rows = new PostgresLegacyRows(new PostgresConnectionFactory(Configuration(pg.ConnectionString)));
        foreach (int id in new[] { 3, 4 })
        {
            var parameters = new LegacySql();
            string sql = """
                select id from (values (1,'fixture SERVICE account'),(2,'fixture SCHEMA ADMINS'),
                    (3,'ordinary fixture'),(4,'another fixture')) events(id,name)
                where lower(name) like '%service%' or lower(name) like '%schema admins%' or id =
                """ + parameters.Bind(id) + " order by id";
            Assert.Equal(id, Assert.Single(parameters.Parameters));
            var result = await rows.QueryAsync(sql, parameters.Parameters, 8000, Ct);
            Assert.Equal(new long[] { 1, 2, id }, result.Select(row => LegacySemantics.Number(row, "id")));
        }
    }

}
