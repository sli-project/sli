using System.Globalization;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Infrastructure;
using Sli.Server.Operations;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class SecurityLogFullTests
{
    private const string Path = "/api/v1/operations/security-log-full";

    private sealed class Connections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
            await db.OpenAsync(ct);
            return db;
        }
    }

    [Fact]
    public async Task NativeSecurityLogFullReachesStatusOnceAfterReplayAlongsideLogCleared()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var time = DateTimeOffset.UtcNow.AddMinutes(-3);
        time = DateTimeOffset.FromUnixTimeSeconds(time.ToUnixTimeSeconds());
        var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: time,
            eventKinds: [1104, 1102], firstRecordId: 42);
        Assert.Null(rows[0].Actor);
        Assert.Null(rows[0].Target);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);

        using var app = await OperationsEndpointTests.Start(postgresQueries: new OperationsQueries(new Connections(fixture)));
        using var response = await OperationsEndpointTests.Request(app, "GET", Path);
        response.EnsureSuccessStatusCode();
        var line = Assert.Single((await OperationsEndpointTests.Body(response))["items"]!.AsArray())!;
        Assert.Equal("dc.example.test", line["server"]!.GetValue<string>());
        Assert.Equal("42", line["record_id"]!.GetValue<string>());
        Assert.Equal(time, DateTimeOffset.Parse(line["time_created_utc"]!.GetValue<string>(), CultureInfo.InvariantCulture));

        await using var cleared = new NpgsqlCommand("select event_record_id from event_hot where event_kind=1102", owner);
        Assert.Equal(43L, await cleared.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public void SameCodeFromAnotherProviderIsNotCollectedOrProjected()
    {
        const string source = "dc.example.test";
        var row = EventXml.Parse($"""
            <Event xmlns="{EventXml.Namespace}"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>
            <EventID>1104</EventID><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-11-14T01:16:00Z"/>
            <Channel>Security</Channel><Computer>{source}</Computer></System>
            <UserData><FileIsFull xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"/></UserData></Event>
            """, source, source, "Security");
        Assert.False(EventCatalog.Load().AcceptsPayload(row));
        Assert.Null(ShortEventRow.Create(1, 1, row, Direct4624Projection.Create(row), 1));
    }
}
