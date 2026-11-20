using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Registry;
using Sli.Server.Agents.SnapshotPublication;
using Xunit;
using AgentIdentity = Sli.Server.Agents.AgentIdentity;

namespace Sli.Server.Tests.Agents;

public sealed class AdSnapshotScheduleTests
{
    private const string Sid = "S-1-5-21-100000001-200000002-300000003";
    private const string Zone = "Asia/Kathmandu";

    [Fact]
    public async Task First_console_DC_publishes_on_registration_and_is_due_again_at_the_next_local_slot()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 391);
        await fixture.Pg.ApplyFileAsync(Migration(), null, ct);
        await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await app.OpenAsync(ct);

        string token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        await using (var seed = new NpgsqlCommand("""
            insert into platform_settings(key,value,updated_by) values('server.timezone',@zone,'fixture');
            insert into sli_agent_console_tokens(id,token_hash,created_at,expires_at,host_limit,remaining)
            values(gen_random_uuid(),@hash,now(),now()+interval '15 minutes',1,1)
            """, app))
        {
            seed.Parameters.AddWithValue("zone", Zone);
            seed.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(token))));
            await seed.ExecuteNonQueryAsync(ct);
        }

        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = AgentEnrollmentTests.CaRequest("CN=fixture root", rootKey, 1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var publicIssuer = AgentEnrollmentTests.CaRequest("CN=fixture issuer", issuerKey, 0)
            .Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddMonths(1), RandomNumberGenerator.GetBytes(16));
        using var ca = new AgentIssuingCa(new X509Certificate2(root), publicIssuer.CopyWithPrivateKey(issuerKey));
        using var agentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid host = Guid.NewGuid();
        var csr = new CertificateRequest($"CN={host:D}", agentKey, HashAlgorithmName.SHA256);
        var enrollment = new AgentEnrollmentService(ca, new AgentIdentityService(ca));
        var control = new AgentClientControlService(new AgentControlAudit(), TimeProvider.System);
        AgentIdentity identity;
        JsonArray assignments;
        await using (var tx = await app.BeginTransactionAsync(ct))
        {
            var result = await enrollment.EnrollAsync(app, tx, new JsonObject
            {
                ["token"] = token, ["csr_pem"] = csr.CreateSigningRequestPem(), ["reported_hostname"] = "dc",
                ["machine_role"] = "domain_controller", ["domain_dns"] = "example.test", ["forest_dns"] = "example.test", ["domain_sid"] = Sid,
            }, ct);
            identity = new AgentIdentity(Guid.Parse(result["agent_id"]!.GetValue<string>()), host,
                Convert.ToHexStringLower(SHA256.HashData(agentKey.ExportSubjectPublicKeyInfo())), "active");
            assignments = (await control.CheckInAsync(app, tx, identity, ct))["assigned_modules"]!.AsArray();
            await tx.CommitAsync(ct);
        }

        var observed = DateTimeOffset.Parse("2026-10-08T12:00:00Z");
        foreach (var (module, vectorName) in new[] { (SnapshotPolicy.Ad, "ad"), (SnapshotPolicy.Gpo, "gpo") })
        {
            var config = Assert.Single(assignments.OfType<JsonObject>(), row => row["module_id"]!.GetValue<string>() == module)["config"]!.AsObject();
            Assert.Equal(Zone, config["schedule"]!["timezone"]!.GetValue<string>());
            var policy = SnapshotPolicy.Parse(module, config);
            var stream = new SnapshotStream(fixture.Pg.Root, module, new PhysicalDurableFiles());
            var state = Assert.IsType<JsonObject>(stream.Begin(policy, observed));
            Assert.Equal("2026-10-08T00:15:00+00:00", state["slot_start_utc"]!.GetValue<string>());
            stream.Freeze(state, Families(policy, vectorName));
            await using (var tx = await app.BeginTransactionAsync(ct))
            {
                var ledger = new AgentPacketLedger(app, tx);
                CapturedPosition? captured = null;
                long sequence = 0;
                while (stream.NextSample(captured) is { } sample)
                {
                    var envelope = new Envelope(Guid.NewGuid().ToString("D"), identity.Id.ToString("D"), sample.SourceInstanceId,
                        module, sample.ModuleVersion, sample.PolicyRevision, sample.Channel, sample.Generation, ++sequence,
                        sample.CursorBefore, sample.CursorAfter, module + ".chunk.v1", Packets.Digest(sample.Payload), 1,
                        CanonicalJson.Length(sample.Payload), Iso8601.Format(observed), "complete", 0, 0);
                    var plan = await SnapshotIngress.ValidateAsync(app, tx, identity, envelope, sample.Payload, assignments, ct);
                    await ledger.StoreAsync(envelope, sample.Payload, null, AgentReceipt.Make(envelope, "committed", null, observed), ct);
                    await SnapshotIngress.StoreAsync(app, tx, plan, ct);
                    captured = new CapturedPosition(sample.Generation, sample.CursorAfter);
                }
                await tx.CommitAsync(ct);
            }
            Assert.Null(stream.Begin(policy, observed.AddMinutes(14)));
            Assert.Equal("2026-10-08T12:15:00+00:00", stream.Begin(policy, observed.AddMinutes(15))!["slot_start_utc"]!.GetValue<string>());
        }

        var consumer = new SnapshotCycleConsumer();
        var output = await consumer.RunOnceAsync(fixture.Pg.ConnectionString, ct);
        Assert.True(output.PendingReasons.Count == 0, string.Join(", ", output.PendingReasons.Keys) + await fixture.Pg.DiagnosticsAsync(ct));
        await using (var read = new NpgsqlCommand("""
            select m.schedule_timezone,m.scheduled_local_at,(select count(*) from users_report_v2_snapshots where domain_id=m.domain_id),
              (select count(*) from computers_v6_source_snapshots where domain_id=m.domain_id),
              (select count(*) from gpo_report_v2_source_snapshots where domain_id=m.domain_id)
            from ad_snapshot_manifests m where m.domain_sid=@sid
            """, app))
        {
            read.Parameters.AddWithValue("sid", Sid);
            await using var rows = await read.ExecuteReaderAsync(ct);
            Assert.True(await rows.ReadAsync(ct));
            Assert.Equal(Zone, rows.GetString(0));
            Assert.Equal(new DateTime(2026, 10, 8, 6, 0, 0), rows.GetDateTime(1));
            for (int i = 2; i < 5; i++) Assert.Equal(1, rows.GetInt64(i));
            Assert.False(await rows.ReadAsync(ct));
        }

        await PostCollectionPostgres.Sql(app, "update platform_settings set value='Europe/Berlin' where key='server.timezone'", ct);
        await using (var tx = await app.BeginTransactionAsync(ct))
        {
            var updated = await control.CheckInAsync(app, tx, identity, ct);
            Assert.Equal(3, updated["policy_revision"]!.GetValue<long>());
            Assert.All(updated["assigned_modules"]!.AsArray().OfType<JsonObject>().Where(m => m["module_id"]!.GetValue<string>() is SnapshotPolicy.Ad or SnapshotPolicy.Gpo),
                item => Assert.Equal("Europe/Berlin", item["config"]!["schedule"]!["timezone"]!.GetValue<string>()));
            await tx.CommitAsync(ct);
        }
    }

    [Fact]
    public async Task Migration_391_to_392_accepts_IANA_headers_and_preserves_existing_manifests_on_rollback()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 391);
        await using var admin = await fixture.Pg.OpenAsync(ct);
        async Task Insert(string slot, string? zone, string? local = null)
        {
            await using var statement = new NpgsqlCommand("""
                insert into ad_snapshot_manifests(manifest_id,domain_id,domain_sid,domain_dns,slot_start_utc,assembled_at_utc,
                    contract_version,coverage_state,manifest_sha256,schedule_timezone,scheduled_local_at)
                select gen_random_uuid(),id,@sid,fqdn,cast(@slot as timestamptz),cast(@slot as timestamptz),
                    'sli.ad-snapshot-manifest/2.0','complete',decode(repeat('a0',32),'hex'),@zone,cast(@local as timestamp)
                from domains where fqdn='example.test'
                """, admin);
            statement.Parameters.AddWithValue("sid", Sid);
            statement.Parameters.AddWithValue("slot", slot);
            statement.Parameters.AddWithValue("zone", NpgsqlTypes.NpgsqlDbType.Text, (object?)zone ?? DBNull.Value);
            statement.Parameters.AddWithValue("local", NpgsqlTypes.NpgsqlDbType.Text, (object?)local ?? DBNull.Value);
            Assert.Equal(1, await statement.ExecuteNonQueryAsync(ct));
        }

        await Insert("2026-10-07T23:00:00Z", null);
        await fixture.Pg.ApplyFileAsync(Migration(), null, ct);
        await Insert("2026-10-08T00:15:00Z", Zone);
        Assert.Equal("22023", (await Assert.ThrowsAsync<PostgresException>(() => Insert("2026-10-08T06:00:00Z", "+00:00"))).SqlState);
        Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() => Insert("2026-10-08T01:15:00Z", Zone))).SqlState);
        Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() => Insert("2026-10-08T12:15:00Z", Zone, "2026-10-08T06:00:00"))).SqlState);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(Migration(), ".rollback.sql"), null, ct);
        await Assert.ThrowsAsync<PostgresException>(() => Insert("2026-10-08T12:15:00Z", Zone));
        await fixture.Pg.ApplyFileAsync(Migration(), null, ct);
        await using var check = new NpgsqlCommand("select array_agg(schedule_timezone order by slot_start_utc) from ad_snapshot_manifests", admin);
        Assert.Equal(new[] { "Asia/Novosibirsk", Zone }, (string[]?)await check.ExecuteScalarAsync(ct));
    }

    private static string Migration() => MigrationDirectory.Read(392).Single(item => item.Version == 392).Path;

    private static Dictionary<string, SnapshotFamily> Families(SnapshotPolicy policy, string vectorName)
    {
        string path = Path.Combine(PostCollectionPostgres.Repository(), $"server-dotnet/tests/Sli.Server.Tests/Agents/{vectorName}-publication-source-vector.json");
        var vector = JsonNode.Parse(File.ReadAllText(path))!;
        var families = JsonNode.Parse(vector["families"]!.ToJsonString().Replace("directory.invalid", "example.test")
            .Replace("DC=directory,DC=invalid", "DC=example,DC=test").Replace(vector["config"]!["domain_sid"]!.GetValue<string>(), Sid))!;
        return policy.Families.ToDictionary(name => name, name =>
        {
            var family = families[name]!.AsObject();
            family.Remove("bundle_sha256");
            string collection = name == "computers_v6" ? "objects" : name == "gpo_v2" ? "gpos" : "records";
            return new SnapshotFamily(family, family[collection]!.AsArray().Count);
        });
    }
}
