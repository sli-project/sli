using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Ad;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class InstalledStorageS5Fixture
{
    private sealed record Source(Guid Agent, Guid Host, long Id, string Name);

    [Fact]
    public async Task WriteExpiredAndBoundaryEventsThroughShortStorage()
    {
        var ct = TestContext.Current.CancellationToken;
        string root = Environment.GetEnvironmentVariable("S5_PROOF_ROOT")
            ?? throw new InvalidOperationException("S5_PROOF_ROOT");
        var today = new DateTimeOffset(DateTime.UtcNow.Date, TimeSpan.Zero);
        var boundary = today.AddDays(-14);
        var expired = boundary.AddDays(-1);

        await using var owner = new NpgsqlConnection(
            "Host=/var/run/postgresql;Port=5432;Database=sli;Username=postgres;Pooling=false");
        await owner.OpenAsync(ct);
        await using var insertDomain = new NpgsqlCommand("""
            with forest as (insert into public.forests(name) values('example.test') returning id)
            insert into public.domains(forest_id,fqdn)
            select id,'example.test' from forest returning id
            """, owner);
        long domain = Assert.IsType<long>(await insertDomain.ExecuteScalarAsync(ct));
        await NewLogonPairsNativeFixture.ExecuteAsync(owner, """
            insert into platform_settings(key,value,updated_by) values('reports.domain_fqdn','example.test','installed-s5-fixture')
            on conflict(key) do update set value=excluded.value,updated_by=excluded.updated_by
            """, ct);
        var first = new Source(Guid.NewGuid(), Guid.NewGuid(), 930001, "dc-s5-a.example.test");
        var second = new Source(Guid.NewGuid(), Guid.NewGuid(), 930002, "dc-s5-b.example.test");
        foreach (var source in new[] { first, second })
            await ShortEventAdmissionPostgresTests.RegisterDcAsync(owner, source.Agent, source.Host, source.Id,
                domain, source.Name, "Security", ct, "System", completePolicy: true);

        const string userSid = "S-1-5-21-100000001-200000002-300000003-10000";
        var users = new JsonObject { ["users"] = new JsonArray(new JsonObject
            { ["samAccountName"] = "synthetic-user-0", ["sid"] = userSid }) };
        await NewLogonPairsNativeFixture.StoreUsersAsync(owner, domain, boundary, users, 1, ct);
        var inventory = NewLogonPairsNativeFixture.SyntheticSnapshot(boundary, 2);
        await NewLogonPairsNativeFixture.StoreComputersAsync(owner, domain, boundary, inventory, ct);
        var run = await NewLogonPairsNativeFixture.StoreRunAsync(owner, domain, boundary, ct);
        await NewLogonPairsNativeFixture.ExecuteAsync(owner, """
            insert into ad_context_sections(run_id,section_name,status,record_count) values($1,'directory_accounts','complete',2)
            """, ct, run);
        await NewLogonPairsNativeFixture.ExecuteAsync(owner, """
            insert into storage_v2_entity_type(value) values('ad_computer') on conflict do nothing
            """, ct);

        foreach (var item in inventory["objects"]!.AsArray())
        {
            string guid = item!["objectGuid"]!.GetValue<string>();
            string name = item["name"]!.GetValue<string>();
            var attrs = new JsonObject
            {
                ["object_guid"] = guid, ["name"] = name,
                ["dns_host_name"] = item["dnsHostName"]!.DeepClone(), ["enabled"] = true
            };
            var args = new object?[] { guid, name, domain, boundary, AdJobPlugin.Digest(attrs), run };
            await NewLogonPairsNativeFixture.ExecuteAsync(owner, """
                with e as (
                    insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,first_seen_utc,last_seen_utc,source_core_sha256)
                    select id,'ad_computer:'||$1,$2,$3,$4,$4,decode($5,'hex') from storage_v2_entity_type where value='ad_computer'
                    returning id
                )
                insert into ad_context_entity_aliases(entity_id,domain_id,alias_type,alias_value,normalized_value,first_seen_utc,last_seen_utc,source_run_id)
                select id,$3,'object_guid',$1,$1,$4,$4,$6 from e
                """, ct, args);
        }

        await NewLogonPairsNativeFixture.ExecuteAsync(owner,
            "select public.create_event_storage_partitions($1::date,$2::date)", ct,
            DateOnly.FromDateTime(expired.UtcDateTime), DateOnly.FromDateTime(boundary.UtcDateTime));
        string storageSecret = await File.ReadAllTextAsync(Path.Combine(root, "storage.password"), ct);
        var options = new NpgsqlConnectionStringBuilder {
            Host = "127.0.0.1", Port = 5432, Database = "sli", Username = "sli_storage_login",
            Password = storageSecret.TrimEnd('\r','\n'), Pooling = false
        };
        await using var writer = new NpgsqlConnection(options.ConnectionString);
        await writer.OpenAsync(ct);

        async Task WriteAsync(Source source, int record, int kind, DateTimeOffset at, string address,
            Dictionary<string,string>? fields = null)
        {
            var sourceRows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [kind],
                registered: (source.Agent, source.Host, source.Id, domain),
                nativeTimestamp: at.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture),
                nativeAccounts: ["synthetic-user-0"], nativeAddresses: [address], nativeTargetSids: [userSid],
                packetId: Guid.NewGuid(), sequence: record, firstRecordId: record, hostName: source.Name,
                nativeFields: fields, nativeVersion: 0, allocatedAt: [DateTimeOffset.UtcNow]);
            await using var tx = await writer.BeginTransactionAsync(ct);
            await using var setRole = new NpgsqlCommand("set local role adlog_storage_worker", writer, tx);
            await setRole.ExecuteNonQueryAsync(ct);
            await ShortEventWriter.WriteAsync(writer, tx, sourceRows, ct);
            await tx.CommitAsync(ct);
        }

        // At the UTC cutoff, the former pair still suppresses the repeated
        // pair through the cold daily summary. The other pair stays visible.
        await WriteAsync(first, 20, 4624, boundary.AddSeconds(-1), "192.0.2.1");
        await WriteAsync(first, 21, 4720, boundary.AddSeconds(-1), "192.0.2.1",
            new() { ["SamAccountName"] = "synthetic-user-0", ["PrimaryGroupId"] = "513" });
        await WriteAsync(second, 30, 4624, boundary, "192.0.2.1");
        await WriteAsync(second, 31, 4624, boundary.AddSeconds(1), "192.0.2.2");

        var window = new JsonObject
        {
            ["from"] = boundary.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            ["to"] = boundary.AddDays(1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            ["expired_day"] = expired.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            ["survivor_day"] = boundary.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            ["domain_id"] = domain
        };
        await File.WriteAllTextAsync(Path.Combine(root, "window.json"), window.ToJsonString(), ct);
    }
}
