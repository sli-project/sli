using System.Text.Json.Nodes;
using Npgsql;
using CoreJobPluginCatalog = Sli.Server.Jobs.CoreJobPluginCatalog;
using CoreJobRegistry = Sli.Server.Jobs.CoreJobRegistry;
using CoreJobHandler = Sli.Server.Jobs.CoreJobHandler;
using CoreJobJson = Sli.Server.Jobs.CoreJobJson;
using CoreJobQueue = Sli.Server.Jobs.CoreJobQueue;
using PostgresCoreJobSession = Sli.Server.Jobs.PostgresCoreJobSession;
using CoreJobLeaseLost = Sli.Server.Jobs.CoreJobLeaseLost;
using ICoreJobSession = Sli.Server.Jobs.ICoreJobSession;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

public sealed partial class WorkstationInventoryJobPostgresTests
{
    [Theory]
    [InlineData("sli_job_executor_light")]
    [InlineData("sli_job_publisher_light")]
    public async Task Job_roles_cannot_read_raw_sources_or_insert_inventory(string role)
    {
        await using var db = await fixture.Open();
        await As(db, role, async () => {
            Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => Scalar(db, "select e.id from public.entities_v2_active e join public.storage_v2_entity_type t on t.id=e.entity_type_id where t.value='ad_computer'"))).SqlState);
            Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => Exec(db, "insert into sli_plugin_workstations.station_inventory(station_id,agent_key) values('ws:synthetic','synthetic-agent')"))).SqlState);
        });
        await Empty(db);
    }

    [Theory]
    [InlineData("adlog_user")]
    [InlineData("sli_job_executor_heavy")]
    public async Task Foreign_role_cannot_read_leased_inputs_and_owner_cannot_read_key_fingerprint(string role)
    {
        await using var db = await fixture.Open(); await Directory(db); var job = await Job(db);
        await As(db, role, async () => Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => Input(db, job))).SqlState));
        Assert.Equal(false, await Scalar(db, "select rolcanlogin or rolsuper or rolbypassrls or rolcreaterole from pg_roles where rolname='sli_workstation_inventory_owner'"));
        Assert.Equal(false, await Scalar(db, "select has_column_privilege('sli_workstation_inventory_owner','public.sli_agents','key_fingerprint','SELECT')"));
    }

    [Theory]
    [InlineData("foreign_domain")]
    [InlineData("operating_system")]
    [InlineData("ou_path")]
    [InlineData("ip_addresses")]
    [InlineData("station_type")]
    [InlineData("quality")]
    [InlineData("subset")]
    [InlineData("cursor")]
    [InlineData("null")]
    [InlineData("object")]
    [InlineData("null_row")]
    [InlineData("empty_row")]
    public async Task Direct_publication_cannot_forge_canonical_facts_or_choose_page(string tamper)
    {
        await using var db = await fixture.Open(); var (own, foreign) = await Directory(db); var job = await Job(db);
        await As(db, "sli_job_publisher_light", async () => {
            var input = await Input(db, job);
            Assert.Equal(own, input["sources"]!["directory"]![0]!.Number("ad_computer_id"));
            Assert.Single(input["sources"]!["directory"]!.AsArray());
            var rows = input["page"]!["rows"]!.DeepClone(); string? cursor = input["page"].Text("next_cursor");
            switch (tamper)
            {
                case "foreign_domain": rows[0]!["station_id"] = $"ws:ad:{foreign}"; rows[0]!["ad_computer_id"] = foreign; rows[0]!["domain_id"] = 22; break;
                case "operating_system": case "ou_path": rows[0]!["metadata"]![tamper] = "fabricated"; break;
                case "ip_addresses": rows[0]!["metadata"]![tamper] = new JsonArray("192.0.2.123"); break;
                case "station_type": rows[0]![tamper] = "server"; break;
                case "quality": rows[0]![tamper] = new JsonObject { ["status"] = "complete", ["reasons"] = new JsonArray() }; break;
                case "subset": rows = new JsonArray(); break;
                case "cursor": cursor = rows[0].Text("station_id"); break;
                case "null": rows = null; break;
                case "object": rows = new JsonObject(); break;
                case "null_row": rows = new JsonArray((JsonNode?)null); break;
                case "empty_row": rows = new JsonArray(new JsonObject()); break;
            }
            Assert.Contains("workstation_inventory_canonical_page_required", (await Assert.ThrowsAsync<PostgresException>(() => Direct(db, job, input, rows, cursor))).MessageText);
        });
        await Empty(db);
    }

    [Fact]
    public async Task Forged_recorded_scope_is_rejected_even_when_source_string_matches()
    {
        await using var db = await fixture.Open(); await Directory(db); var job = await Job(db);
        await Exec(db, "update sli_jobs.jobs set spec=jsonb_set(spec,'{access_scope,clauses,0,collection_scope_ids}','[\"ad-domain:22\"]'::jsonb) where job_id=@p0", Guid.Parse(job.Text("job_id")!));
        Assert.Contains("workstation_inventory_access_denied", (await Assert.ThrowsAsync<PostgresException>(() => Stage(db, job))).MessageText);
        await Empty(db);
    }

    [Fact]
    public async Task Publication_rollback_and_lost_lease_leave_no_effects()
    {
        await using var db = await fixture.Open(); await Directory(db); var job = await Job(db); var staged = await Stage(db, job);
        Assert.Equal("synthetic rollback", (await Assert.ThrowsAsync<InvalidOperationException>(() => Publish(db, job, staged, () => throw new InvalidOperationException("synthetic rollback")))).Message);
        await Empty(db);
        await Exec(db, "update sli_jobs.jobs set lease_generation=lease_generation+1 where job_id=@p0", Guid.Parse(job.Text("job_id")!));
        Assert.Contains("workstation_inventory_access_denied", (await Assert.ThrowsAsync<PostgresException>(() => Stage(db, job))).MessageText);
        await Assert.ThrowsAsync<CoreJobLeaseLost>(() => Publish(db, job, staged));
        await Empty(db);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Direct_sql_requires_exact_core_receipt_and_one_page_per_lease(bool twice)
    {
        await using var db = await fixture.Open(); await Directory(db); var job = await Job(db);
        await As(db, "sli_job_publisher_light", async () => {
            await using var tx = await db.BeginTransactionAsync(Ct);
            var input = await Input(db, job);
            var error = await Assert.ThrowsAsync<PostgresException>(async () => {
                await Direct(db, job, input, input["page"]!["rows"], input["page"].Text("next_cursor"));
                if (twice) await Direct(db, job, input, input["page"]!["rows"], input["page"].Text("next_cursor"));
                else await tx.CommitAsync(Ct);
            });
            Assert.Contains(twice ? "workstation_inventory_page_already_published" : "workstation_inventory_core_receipt_required", error.MessageText);
        });
        await Empty(db);
        Assert.Equal("leased", await Scalar(db, "select state from sli_jobs.jobs where job_id=@p0", Guid.Parse(job.Text("job_id")!)));
    }

    [Theory]
    [InlineData("lease_until")]
    [InlineData("deadline_at")]
    public async Task Final_core_fence_rejects_expiry_after_effects_before_finish(string field)
    {
        await using var db = await fixture.Open(); await Directory(db); var job = await Job(db); var staged = await Stage(db, job);
        var id = Guid.Parse(job.Text("job_id")!);
        await Exec(db, "update sli_jobs.jobs set available_at=clock_timestamp()-interval '1 minute' where job_id=@p0", id);
        bool expiredAfterEffects = false;
        await Assert.ThrowsAsync<CoreJobLeaseLost>(() => Publish(db, job, staged, async () => {
            // Move the clock field after plugin publication, while this transaction owns the job lock.
            await Exec(db, "set local session authorization default");
            Assert.Equal(1, await Exec(db, "update sli_jobs.jobs set " + field + "=clock_timestamp()-interval '1 second' where job_id=@p0", id));
            await Exec(db, "set local session authorization sli_job_publisher_light");
            expiredAfterEffects = true;
        }));
        Assert.True(expiredAfterEffects);
        await Empty(db);
        Assert.Equal("leased", await Scalar(db, "select state from sli_jobs.jobs where job_id=@p0", id));
        Assert.Null(await Scalar(db, "select result_payload from sli_jobs.jobs where job_id=@p0", id));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Atomic_receipt_does_not_require_outer_commit_before_lease_wall_clock(bool immediate)
    {
        await using var db = await fixture.Open(); await Directory(db); var job = await Job(db); var staged = await Stage(db, job);
        // Give SQL publication time to finish under load, then wait for the exact expiry before COMMIT.
        var expires = Assert.IsType<DateTime>(await Scalar(db, "update sli_jobs.jobs set lease_until=clock_timestamp()+interval '15 seconds' where job_id=@p0 returning lease_until", Guid.Parse(job.Text("job_id")!)));
        await As(db, "sli_job_publisher_light", async () => {
            var session = new DelayedCommit(new PostgresCoreJobSession(db), db, expires, immediate);
            Assert.Equal("committed", await new CoreJobQueue(session).PublishAsync(job, staged, ct => Handler(job).Publish(db, job, staged, ct), Ct));
        });
        Assert.Equal(1L, await Scalar(db, "select count(*) from sli_plugin_workstations.station_inventory"));
        Assert.Equal("completed", await Scalar(db, "select state from sli_jobs.jobs where job_id=@p0", Guid.Parse(job.Text("job_id")!)));
        Assert.Equal(true, await Scalar(db, "select lease_until<clock_timestamp() from sli_plugin_workstations.inventory_publications where job_id=@p0", Guid.Parse(job.Text("job_id")!)));
    }
    sealed class DelayedCommit(ICoreJobSession inner, NpgsqlConnection db, DateTime expires, bool immediate) : ICoreJobSession
    {
        public Task<object?> CallAsync(string function, object?[] args, CancellationToken ct) => inner.CallAsync(function, args, ct);
        public Task BeginAsync(CancellationToken ct) => inner.BeginAsync(ct);
        public Task RollbackAsync(CancellationToken ct) => inner.RollbackAsync(ct);
        public async Task CommitAsync(CancellationToken ct)
        {
            if (immediate) await Exec(db, "set constraints all immediate");
            await Scalar(db, "select pg_sleep_until(@p0)", expires);
            await inner.CommitAsync(ct);
        }
    }
}
