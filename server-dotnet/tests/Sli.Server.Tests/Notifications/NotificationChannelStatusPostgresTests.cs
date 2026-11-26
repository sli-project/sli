using Microsoft.Extensions.Configuration;
using Sli.Server.Infrastructure;
using Sli.Server.Notifications;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Notifications;

public sealed class NotificationChannelStatusPostgresTests
{
    [Fact]
    public async Task Channel_status_uses_delivery_attempts_and_current_configuration()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            create table notification_channels(kind text primary key, enabled boolean, tls_mode text, secret_ref text,
                revision integer, updated_at timestamptz, state text default 'not_configured' check(state='not_configured'));
            create table notification_outbox(id integer primary key, channel text);
            create table notification_attempts(job_id integer, attempt integer, state text, result_code text, finished_at timestamptz);
            insert into notification_channels(kind,enabled,tls_mode,revision,updated_at) values
                ('telegram',true,'tls',1,'2026-01-01 09:00Z'),('smtp',true,'tls',1,'2026-01-01 09:00Z');
            insert into notification_outbox values (1,'telegram'),(2,'smtp'),(3,'smtp'),(4,'smtp');
            insert into notification_attempts values
                (1,1,'accepted','accepted','2026-01-01 10:00Z'),(2,1,'accepted','accepted','2026-01-01 11:00Z'),
                (3,1,'blocked','smtp_not_configured','2026-01-01 12:00Z'),(4,1,'blocked','recipient_denied','2026-01-01 13:00Z');
            """, ct);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["ConnectionStrings:Sli"] = pg.ConnectionString }).Build();
        await using var harness = new NotificationHarness();
        var repository = new NotificationAdministrationRepository(new PostgresConnectionFactory(configuration), harness.Recipients);

        var channels = await repository.ChannelsAsync(ct);
        var telegram = Assert.Single(channels, row => row!["kind"]!.ToString() == "telegram")!;
        Assert.Equal("configured", telegram["state"]!.ToString());
        Assert.Equal(DateTimeOffset.Parse("2026-01-01T10:00:00Z"), DateTimeOffset.Parse(telegram["last_accepted_at"]!.ToString()));
        var smtp = Assert.Single(channels, row => row!["kind"]!.ToString() == "smtp")!;
        Assert.Equal("not_configured", smtp["state"]!.ToString());
        Assert.Equal(DateTimeOffset.Parse("2026-01-01T11:00:00Z"), DateTimeOffset.Parse(smtp["last_accepted_at"]!.ToString()));

        await PostCollectionPostgres.Sql(db, "update notification_channels set enabled=false where kind='telegram'", ct);
        telegram = Assert.Single(await repository.ChannelsAsync(ct), row => row!["kind"]!.ToString() == "telegram")!;
        Assert.Equal("not_configured", telegram["state"]!.ToString());
        Assert.NotNull(telegram["last_accepted_at"]);
    }
}
