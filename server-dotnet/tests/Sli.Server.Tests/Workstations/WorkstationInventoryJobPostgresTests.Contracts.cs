using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Workstations;
using CoreJobQueue = Sli.Server.Jobs.CoreJobQueue;
using PostgresCoreJobSession = Sli.Server.Jobs.PostgresCoreJobSession;
using Xunit;

namespace Sli.Server.Tests.Workstations;

public sealed partial class WorkstationInventoryJobPostgresTests
{
    [Fact]
    public async Task Real_dispatcher_enqueues_domain_scopes_idempotently_and_claimed_jobs_publish()
    {
        await using var db = await fixture.Open(); var (own, foreign) = await Directory(db); await Install(db);
        string? projection = Environment.GetEnvironmentVariable("SLI_CORE_JOB_WORKSTATIONS_PROJECTION");
        string? retention = Environment.GetEnvironmentVariable("SLI_CORE_JOB_WORKSTATIONS_RETENTION");
        try
        {
            Environment.SetEnvironmentVariable("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "1");
            Environment.SetEnvironmentVariable("SLI_CORE_JOB_WORKSTATIONS_RETENTION", null);
            var queue = new CoreJobQueue(new PostgresCoreJobSession(db));
            await As(db, "sli_job_dispatcher_light", async () => {
                await Catalog.ScheduleAsync("sli.workstations", db, queue, Registry, "light", Ct);
                await Catalog.ScheduleAsync("sli.workstations", db, queue, Registry, "light", Ct);
            });
            var queued = await Rows(db, "select source_instance_id,partition_key,spec->'access_scope' as scope from sli_jobs.jobs where state='queued' order by source_instance_id");
            Assert.Equal(4, queued.Count);
            foreach (var row in queued.Where(r => r.Text("source_instance_id")!.StartsWith("workstations:inventory:", StringComparison.Ordinal)))
            {
                string source = row.Text("source_instance_id")!; Assert.Equal(source, row.Text("partition_key"));
                Equal(new JsonArray("ad-domain:" + source.Split(':')[2]), row["scope"]!["clauses"]![0]!["collection_scope_ids"]);
            }
            for (int i = 0; i < 4; i++)
            {
                JsonObject? job = null;
                await As(db, "sli_job_dispatcher_light", async () => job = await queue.ClaimAsync("light", "synthetic-t031", Registry.Identities("light"), Ct));
                Assert.NotNull(job); Assert.Equal("committed", await Publish(db, job, await Stage(db, job)));
            }
            Assert.Equal(new[] { $"ws:ad:{own}", $"ws:ad:{foreign}" }.Order(), (await InventoryRows(db)).Select(r => r.Text("station_id")).Order());
        }
        finally
        {
            Environment.SetEnvironmentVariable("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", projection);
            Environment.SetEnvironmentVariable("SLI_CORE_JOB_WORKSTATIONS_RETENTION", retention);
        }
    }

    [Fact]
    public async Task Current_agent_scope_cannot_read_a_different_saved_directory_identity()
    {
        await using var db = await fixture.Open(); var (old, current) = await Directory(db); var (agent, device) = await Device(db, current);
        string station = $"ws:ad:{old}", finding = Ws.Sha(station);
        await Exec(db, """
            insert into sli_plugin_workstations.station_inventory(station_id,entity_id,ad_computer_id,agent_key,domain_id,metadata)
            values(@p0,@p1,@p2,@p3,11,'{"display_name":"synthetic-private-A","ou_path":"synthetic-private-OU-A"}');
            insert into sli_plugin_workstations.station_inventory(station_id,ad_computer_id,domain_id) values(@p4,@p5,22);
            insert into sli_plugin_workstations.check_findings(id,station_id,check_id,rule_version,episode_id,condition_sha256,status,severity,first_detected_at,last_observed_at,materially_changed_at,reason_code)
            values(@p6,@p0,'C05',1,repeat('e',64),repeat('c',64),'active','medium',now(),now(),now(),'synthetic_private_A')
            """, station, device, old, agent.ToString(), $"ws:ad:{current}", current, finding);
        foreach (int domain in new[] { 11, 22 })
        {
            var result = await Overview(db, domain: domain);
            Assert.Equal(domain == 22 ? new[] { $"ws:ad:{current}" } : [], result["items"]!.AsArray().Select(r => r.Text("station_id")).ToArray());
            Assert.Empty(result["filter_options"]!["ou"]!.AsArray());
            Assert.Equal(domain == 22 ? 1 : 0, result["metrics"]![0]!.Number("value")); Assert.Equal(0, result["metrics"]![1]!.Number("value"));
            Assert.DoesNotContain("synthetic-private", result.ToJsonString());
            foreach (var parameters in new[] { new JsonObject(), new JsonObject { ["finding_id"] = finding, ["evidence_index"] = 1 } })
            {
                var error = await Assert.ThrowsAsync<WorkstationException>(() => Overview(db, parameters, domain, station));
                Assert.Equal("workstation_access_denied", error.Message); Assert.Equal(403, error.Status);
            }
        }
    }

    static JsonObject Sources(JsonArray directory) => new() { ["directory"] = directory, ["agents"] = new JsonArray(), ["devices"] = new JsonArray(), ["associations"] = new JsonArray(), ["existing"] = new JsonArray(), ["ambiguous_agents"] = new JsonArray() };
    static async Task<JsonObject> Page(NpgsqlConnection db, JsonObject snapshot)
        => JsonNode.Parse((string)(await Scalar(db, "select sli_plugin_workstations.inventory_page_v1(@p0::jsonb)::text", snapshot))!)!.AsObject();

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Canonical_metadata_matches_trusted_builder_controls(int vector)
    {
        await using var db = await fixture.Open();
        // Expected values are the reference builder's outputs, not another .NET normalizer.
        string attributes = vector switch {
            0 => "{}",
            1 => """{"operating_system":" Windows Server 2022 ","operating_system_version":"v1","organizational_unit":"OU=Blue,DC=example,DC=test","ip_addresses":["192.0.2.10","bad","2001:0db8::1","192.0.2.10"]}""",
            2 => """{"operating_system":"Windows","distinguished_name":"CN=Desktop\\,One, OU=Blue, DC=example,DC=test","ip_addresses":["192.0.2.10"]}""",
            _ => """{"operating_system":"Windows","organizational_unit":"OU=Blue","ip_addresses":["fe80::1%Eth0","::ffff:192.0.2.128","::","::192.0.2.1","192.00.2.1","1"]}"""
        };
        var directory = new JsonObject { ["ad_computer_id"] = 123, ["domain_id"] = 11, ["display_name"] = " Synthetic ", ["attributes"] = JsonNode.Parse(attributes), ["metadata_observed_at"] = vector == 0 ? null : "2026-10-27T00:00:00Z" };
        var page = await Page(db, new() { ["sources"] = Sources(new JsonArray(directory)), ["cursor"] = "", ["deferred"] = new JsonArray() });
        string[] ips = vector switch { 0 => [], 1 => ["192.0.2.10", "2001:db8::1"], 2 => ["192.0.2.10"], _ => ["::", "::c000:201", "::ffff:192.0.2.128", "fe80::1%Eth0"] };
        var expected = new JsonObject {
            ["station_id"] = "ws:ad:123", ["entity_id"] = null, ["ad_computer_id"] = 123, ["agent_key"] = null, ["domain_id"] = 11, ["ou_entity_id"] = null,
            ["station_type"] = vector switch { 0 => "unknown", 1 => "server", _ => "workstation" }, ["association_status"] = "unlinked",
            ["metadata"] = new JsonObject { ["display_name"] = "Synthetic", ["ou_path"] = vector switch { 0 => null, 3 => "OU=Blue", _ => "OU=Blue,DC=example,DC=test" }, ["operating_system"] = vector switch { 0 => null, 1 => "Windows Server 2022", _ => "Windows" }, ["operating_system_version"] = vector == 1 ? "v1" : null, ["ip_addresses"] = new JsonArray(ips.Select(ip => (JsonNode?)JsonValue.Create(ip)).ToArray()) },
            ["metadata_observed_at"] = directory["metadata_observed_at"]?.DeepClone(), ["quality"] = new JsonObject { ["status"] = vector == 0 ? "not_collected" : "complete", ["reasons"] = new JsonArray() }
        };
        Equal(new JsonArray(expected), page["rows"]); Assert.Empty(page["deferred"]!.AsArray()); Assert.False(page["more"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Database_retry_quota_and_unattempted_pending_preserve_partial_status()
    {
        await using var db = await fixture.Open();
        var directory = new JsonArray(Enumerable.Range(1000, 81).Select(i => (JsonNode)new JsonObject { ["ad_computer_id"] = i, ["domain_id"] = 11, ["display_name"] = i.ToString() }).ToArray());
        var pending = new JsonArray(Enumerable.Range(1000, 25).Select(i => (JsonNode)new JsonObject { ["station_id"] = $"ws:ad:{i}", ["reason"] = "identity_owner_conflict", ["due"] = true }).ToArray());
        var page = await Page(db, new() { ["sources"] = Sources(directory), ["cursor"] = "", ["deferred"] = pending });
        Assert.Equal(76, page["attempted_ids"]!.AsArray().Count); Assert.Equal(76, page["rows"]!.AsArray().Count);
        Assert.Equal(20, page["attempted_ids"]!.AsArray().Select(n => n!.ToString()).Intersect(pending.Select(n => n.Text("station_id"))).Count());
        Assert.True(page["more"]!.GetValue<bool>()); Assert.Equal("", page.Text("next_cursor"));
    }
}
