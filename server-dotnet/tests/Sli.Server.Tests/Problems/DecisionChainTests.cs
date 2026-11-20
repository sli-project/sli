using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Problems;

public sealed class DecisionChainTests
{
    const string AcceptanceId = "00000000-0000-0000-0000-000000000001";
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    sealed class Connections(string? dsn = null) : IPostgresConnectionFactory
    {
        internal int Opens;
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            Opens++; if (dsn is null) throw new InvalidOperationException("No database read expected");
            var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db;
        }
    }
    [Theory] [InlineData("")] [InlineData(" ")]
    public void Missing_human_actor_is_rejected(string actor)
    {
        Assert.Equal("actor_required", Assert.Throws<ProblemException>(() => FindingStatusInput.Parse(new() { ["status"] = "review", ["note"] = "manual review" }, actor)).Code);
    }
    [Fact] public async Task Lifecycle_API_does_not_invent_an_actor()
    {
        await using var fixture = await ProblemEndpointTests.Fixture.Start(); fixture.Auth.Username = null;
        var reply = await fixture.Send("POST", "/api/findings/1/status", """{"status":"review","note":"manual review"}""");
        Assert.Equal(400, reply.Status); Assert.Equal("actor_required", reply.Json["error"]!.GetValue<string>()); Assert.Equal(0, fixture.Repo.Calls);
    }
    [Theory] [InlineData("", "manual review", "actor_required")] [InlineData("test-actor", " ", "invalid_revocation_reason")]
    public async Task Risk_revocation_requires_actor_and_reason_before_database(string actor, string reason, string error)
    {
        var connections = new Connections(); var service = new AccountRiskAcceptances(connections, TimeProvider.System);
        Assert.Equal(error, (await Assert.ThrowsAsync<AdInputException>(() => service.RevokeAsync(AcceptanceId, null, actor, reason, Ct))).Message);
        Assert.Equal(0, connections.Opens);
    }
    [Fact] public async Task Risk_acceptance_requires_actor_before_reading_evidence()
    {
        var connections = new Connections(); var service = new AccountRiskAcceptances(connections, TimeProvider.System); int reads = 0;
        Task<JsonObject> Read(long[]? domains, string risk, CancellationToken ct) { reads++; throw new InvalidOperationException("No evidence read expected"); }
        var error = await Assert.ThrowsAsync<AdInputException>(() => service.CreateAsync(1, [1], "account_locked", "Accepted for review", "test-role", "2026-10-08T00:00:00Z", "", Read, Ct));
        Assert.Equal("actor_required", error.Message); Assert.Equal(0, reads); Assert.Equal(0, connections.Opens);
    }
    [Fact] public async Task Human_decisions_and_existing_audit_commit_the_exact_actor_and_reason()
    {
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(Ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(admin, """
            insert into findings(id,fingerprint,rule_code,title,severity,status,status_reason)
            values(1,'test-decision','semantic.test.kind','Test observation','high','new','created from enabled semantic scenario');
            insert into storage_v2_entity_type(value) values('ad_user') on conflict(value) do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select 1,t.id,'test-account','Test account',d.id,sha256('test-account'::bytea)
            from storage_v2_entity_type t cross join domains d where t.value='ad_user' and d.fqdn='example.test';
            """, Ct);
        var connections = new Connections(fixture.Dsn("adlog_user"));
        var repository = new ProblemRepository(connections, TimeProvider.System);
        foreach (var body in new[] { """{"status":"review"}""", """{"status":"review","note":" "}""", """{"status":"confirmed"}""", """{"status":"new","assigned_to":"test-team"}""" })
        {
            var input = FindingStatusInput.Parse(JsonNode.Parse(body)!.AsObject(), "test-actor");
            Assert.Equal("reason_required", (await Assert.ThrowsAsync<ProblemException>(() => repository.StatusAsync(1, input, "test-actor", Ct))).Code);
        }
        await using (var check = new NpgsqlCommand("select status='new' and assigned_to is null and not exists(select 1 from finding_status_history where finding_id=1) from findings where id=1", admin))
            Assert.Equal(true, await check.ExecuteScalarAsync(Ct));
        var decision = FindingStatusInput.Parse(new() { ["status"] = "confirmed", ["status_reason"] = "Exact evidence reviewed" }, "test-actor");
        await repository.StatusAsync(1, decision, "test-actor", Ct);
        await using (var check = new NpgsqlCommand("""
            select f.status='confirmed' and f.status_reason='Exact evidence reviewed' and h.old_status='new' and h.new_status='confirmed'
              and h.changed_by='test-actor' and h.note='Exact evidence reviewed'
            from findings f join finding_status_history h on h.finding_id=f.id where f.id=1
            """, admin)) Assert.Equal(true, await check.ExecuteScalarAsync(Ct));

        var unavailable = new AccountRiskAcceptances(connections, TimeProvider.System);
        var readiness = await Assert.ThrowsAsync<AdInputException>(() => unavailable.RevokeAsync(AcceptanceId, null, "test-actor", "Fresh evidence requires investigation", Ct));
        Assert.Equal("account_risk_acceptance_audit_not_ready", readiness.Message);
        // Exercise the required future schema fix only in this isolated database.
        // adlog_user still cannot insert arbitrary audit rows directly.
        await PostCollectionPostgres.Sql(admin, AuditUpgradeSql, Ct);
        await using (var check = new NpgsqlCommand("select has_table_privilege('adlog_user','public.account_risk_acceptance_audit','INSERT')", admin))
            Assert.Equal(false, await check.ExecuteScalarAsync(Ct));
        var service = new AccountRiskAcceptances(connections, TimeProvider.System);
        long domain;
        await using (var query = new NpgsqlCommand("select domain_id from entities_v2 where id=1", admin)) domain = (long)(await query.ExecuteScalarAsync(Ct))!;
        Task<JsonObject> Report(long[]? domains, string risk, CancellationToken ct)
        {
            Assert.Equal(new[] { domain }, domains); Assert.Equal("account_locked", risk);
            return Task.FromResult(new JsonObject { ["state"] = "available", ["items"] = new JsonArray(new JsonObject { ["entity_id"] = 1, ["domain_id"] = domain }) });
        }
        // Both the unscoped and explicitly scoped vectors use the real audit trigger.
        foreach (long[]? domains in new long[]?[] { null, [domain] })
        {
            var created = await service.CreateAsync(1, [domain], "account_locked", "Accepted for review", "test-role", DateTimeOffset.UtcNow.AddDays(1).ToString("O"), " test-actor ", Report, Ct);
            string id = created["public_id"]!.GetValue<string>(); Assert.Equal("test-actor", created["created_by"]!.GetValue<string>());
            if (domains is not null)
            {
                var denied = await Assert.ThrowsAsync<AdAccessException>(() => service.RevokeAsync(id, [domain + 1000], "test-actor", "Fresh evidence requires investigation", Ct));
                Assert.Equal("risk_acceptance_not_visible_or_not_active", denied.Message);
            }
            var result = await service.RevokeAsync(id, domains, " test-actor ", " Fresh evidence requires investigation ", Ct);
            Assert.Equal("revoked", result["status"]!.GetValue<string>()); Assert.Equal("test-actor", result["revoked_by"]!.GetValue<string>());
            Assert.Equal("Fresh evidence requires investigation", result["revoke_reason"]!.GetValue<string>());
            await using var audit = new NpgsqlCommand("""
                select a.actor='test-actor' and a.snapshot_json->>'revoked_by'='test-actor'
                  and a.snapshot_json->>'revoke_reason'='Fresh evidence requires investigation'
                from account_risk_acceptance_audit a join account_risk_acceptances r on r.id=a.acceptance_id
                where r.public_id=@id and a.action='revoked'
                """, admin);
            audit.Parameters.AddWithValue("id", Guid.Parse(id)); Assert.Equal(true, await audit.ExecuteScalarAsync(Ct));
        }
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }
    internal const string AuditUpgradeSql = """
        create or replace function public.audit_account_risk_acceptance_change()
        returns trigger language plpgsql security definer set search_path=pg_catalog as $$
        begin
            insert into public.account_risk_acceptance_audit(acceptance_id,action,actor,snapshot_json)
            values(new.id,
                case when tg_op='INSERT' then 'created'
                     when new.status='revoked' and old.status is distinct from 'revoked' then 'revoked' else 'updated' end,
                case when tg_op='INSERT' then new.created_by else coalesce(new.revoked_by,new.created_by) end,
                to_jsonb(new));
            return new;
        end;
        $$;
        """;
}
