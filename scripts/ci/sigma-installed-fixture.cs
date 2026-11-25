using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class InstalledSigmaGuestFixture
{
    private sealed record Source(Guid Agent, Guid Host, long Server, string Name);

    [Fact]
    public async Task SeedRetainedEventFixture()
    {
        var ct = TestContext.Current.CancellationToken;
        string root = Environment.GetEnvironmentVariable("SIGMA_PROOF_ROOT")
            ?? throw new InvalidOperationException("SIGMA_PROOF_ROOT");
        string storageSecret = await File.ReadAllTextAsync(Path.Combine(root, "storage.password"), ct);
        await using var owner = new NpgsqlConnection(
            "Host=/var/run/postgresql;Port=5432;Database=sli;Username=postgres;Pooling=false");
        await owner.OpenAsync(ct);
        // The stock native installer starts without a configured report domain.
        await using var domainQuery = new NpgsqlCommand("""
            with forest as (insert into public.forests(name) values('sigma-proof.example.test') returning id)
            insert into public.domains(forest_id,fqdn)
            select id,'sigma-proof.example.test' from forest returning id
            """, owner);
        long domain = Assert.IsType<long>(await domainQuery.ExecuteScalarAsync(ct));
        Assert.True(domain > 0);
        await using var installationQuery = new NpgsqlCommand(
            "select installation_id::text from public.semantic_default_installation", owner);
        string installation = Assert.IsType<string>(await installationQuery.ExecuteScalarAsync(ct));

        var allowed = new Source(Guid.NewGuid(), Guid.NewGuid(), 930001, "sigma-proof-a.example.test");
        var denied = new Source(Guid.NewGuid(), Guid.NewGuid(), 930002, "sigma-proof-b.example.test");
        foreach (var source in new[] { allowed, denied })
            await ShortEventAdmissionPostgresTests.RegisterDcAsync(owner, source.Agent, source.Host,
                source.Server, domain, source.Name, "Security", ct, "System", completePolicy: true);

        var date = DateTime.UtcNow.Date.AddDays(-1);
        string stamp = date.ToString("yyyy-MM-dd") + "T01:00:00.1234567Z";
        var storage = new NpgsqlConnectionStringBuilder
        {
            Host = "127.0.0.1", Port = 5432, Database = "sli", Username = "sli_storage_login",
            Password = storageSecret.TrimEnd('\r', '\n'), Pooling = false
        };
        await using var worker = new NpgsqlConnection(storage.ConnectionString);
        await worker.OpenAsync(ct);

        async Task SeedAsync(Source source, int record, int kind, string channel, string field, string? value)
        {
            string? payload = value is null || kind == 7045 ? value
                : "<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'><Description>" +
                    value + "</Description></Task>";
            var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [kind],
                registered: (source.Agent, source.Host, source.Server, domain), nativeTimestamp: stamp,
                packetId: Guid.NewGuid(), sequence: record, firstRecordId: record, hostName: source.Name,
                eventChannel: channel, nativeFields: payload is null ? null
                    : new Dictionary<string, string> { [field] = payload }, nativeVersion: kind == 7045 ? 0 : 1);
            await using var tx = await worker.BeginTransactionAsync(ct);
            await using var setRole = new NpgsqlCommand("set local role adlog_storage_worker", worker, tx);
            await setRole.ExecuteNonQueryAsync(ct);
            await ShortEventWriter.WriteAsync(worker, tx, rows, ct);
            await tx.CommitAsync(ct);
        }

        async Task PlanAsync(Source source, int kind, string name)
        {
            var scope = new JsonObject
            {
                ["installation_id"] = installation, ["plugin_id"] = "sli.windows.ad-dc",
                ["source_instance_id"] = source.Host.ToString(), ["source_generation"] = source.Host.ToString(),
                ["collection_scope_id"] = ""
            };
            var plan = new JsonObject
            {
                ["job"] = name, ["partitions"] = new JsonArray(new JsonObject
                {
                    ["scope"] = scope, ["start"] = date.ToString("yyyy-MM-dd") + "T00:00:00Z",
                    ["end"] = date.AddDays(1).ToString("yyyy-MM-dd") + "T00:00:00Z", ["event_ids"] = new JsonArray(kind)
                })
            };
            await File.WriteAllTextAsync(Path.Combine(root, name + ".json"), plan.ToJsonString(), ct);
        }

        foreach (var (kind, channel, field, first) in new[]
        {
            (4698, "Security", "TaskContent", 10),
            (4702, "Security", "TaskContentNew", 20),
            (7045, "System", "ImagePath", 30)
        })
        {
            await SeedAsync(allowed, first, kind, channel, field, "sigma-qa-only");
            await SeedAsync(allowed, first + 1, kind, channel, field, "ordinary-fixture");
            await SeedAsync(allowed, first + 2, kind, channel, field, null);
            await PlanAsync(allowed, kind, "allowed-" + kind);
            string service = channel.ToLowerInvariant();
            string yaml = $$"""
                title: Synthetic installed Sigma TEST {{kind}}
                id: 00000000-0000-4000-8000-00000000{{kind}}
                author: SLI installation test
                logsource:
                    product: windows
                    service: {{service}}
                detection:
                    selection:
                        EventID: {{kind}}
                        {{field}}|contains: sigma-qa-only
                    condition: selection
                """;
            Assert.Equal(service, SigmaRule.Compile(yaml).LogSource);
            await File.WriteAllTextAsync(Path.Combine(root, kind + ".yml"), yaml, ct);
        }

        await SeedAsync(denied, 40, 4698, "Security", "TaskContent", "sigma-qa-only");
        await using var bind = new NpgsqlCommand("""
            insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select oid,rolname,@installation,'sli.windows.ad-dc',@host,@host,'','core_event',
                (select id from public.log_sources where name='Security'),@agent
            from pg_roles where rolname='sli_semantic_login'
            """, owner);
        bind.Parameters.AddWithValue("installation", NpgsqlDbType.Uuid, Guid.Parse(installation));
        bind.Parameters.AddWithValue("host", allowed.Host.ToString());
        bind.Parameters.AddWithValue("agent", allowed.Agent);
        Assert.Equal(1, await bind.ExecuteNonQueryAsync(ct));

        await PlanAsync(denied, 4698, "denied-4698");
        var allowedPlan = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(root, "allowed-4698.json"), ct))!;
        var deniedPlan = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(root, "denied-4698.json"), ct))!;
        allowedPlan["job"] = "mixed-4698";
        allowedPlan["partitions"]!.AsArray().Add(deniedPlan["partitions"]![0]!.DeepClone());
        await File.WriteAllTextAsync(Path.Combine(root, "mixed-4698.json"), allowedPlan.ToJsonString(), ct);
    }
}
