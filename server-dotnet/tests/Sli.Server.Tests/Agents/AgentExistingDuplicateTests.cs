using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Agents;
using Sli.Server.Infrastructure;
using Sli.Server.InstallationSetup;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentExistingDuplicateTests
{
    private sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { var db=new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }

    [Theory]
    [InlineData("1.0.0", "1.1.0", false, false)]
    [InlineData("1.1.0", "1.1.0", true, false)]
    [InlineData(null, null, true, false)]
    public async Task Startup_reconciles_existing_short_name_and_fqdn_once(string? oldVersion,string? currentVersion,bool currentSeenLater,bool tail)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        await SeedServers(admin,ct);
        var old=Guid.NewGuid(); var current=Guid.NewGuid();
        await SeedAgent(admin,old,Guid.NewGuid(),"DC","dc",oldVersion,currentSeenLater?"2026-11-14T00:00:00Z":"2026-11-15T00:00:00Z",'a',ct);
        // Legacy installations can have only a binding, with no registration hostname or issue metadata.
        await SeedAgent(admin,current,Guid.NewGuid(),null,"dc.example.test",currentVersion,currentSeenLater?"2026-11-15T00:00:00Z":"2026-11-14T00:00:00Z",'b',ct);
        await using(var snapshot=new NpgsqlCommand("insert into sli_agent_snapshot_bindings(agent_id,module_id,config,enabled) values(@id,'sli.ad-snapshot','{\"domain_sid\":\"S-1-5-21-100000001-200000002-300000003\"}',true)",admin))
        { snapshot.Parameters.AddWithValue("id",old); await snapshot.ExecuteNonQueryAsync(ct); }

        var connections=new Connections(fixture.Dsn("adlog_user"));
        await Startup(connections,ct);
        await using(var state=new NpgsqlCommand("""
            select a.status,(select status from sli_agents where id=@current),
                (select revoked_at is not null from sli_agent_certificates where agent_id=@old),
                (select revoked_at is null from sli_agent_certificates where agent_id=@current),
                (select enabled from sli_agent_snapshot_bindings where agent_id=@old),
                (select details->>'replaced_by' from sli_agent_audit where target=@target and action='disable'),
                (select (details->>'tail_import')::boolean from sli_agent_audit where target=@target and action='disable')
            from sli_agents a where a.id=@old
            """,admin))
        {
            state.Parameters.AddWithValue("old",old); state.Parameters.AddWithValue("current",current); state.Parameters.AddWithValue("target",old.ToString());
            await using var row=await state.ExecuteReaderAsync(ct); Assert.True(await row.ReadAsync(ct));
            Assert.Equal("replaced",row.GetString(0)); Assert.Equal("active",row.GetString(1));
            Assert.False(row.GetBoolean(2)); Assert.True(row.GetBoolean(3)); Assert.False(row.GetBoolean(4));
            Assert.Equal(current.ToString(),row.GetString(5)); Assert.Equal(tail,row.GetBoolean(6));
        }
        var health=await SetupCollectionHealth.ReadAsync(new InstallationDatabase(connections),ct);
        Assert.NotEqual("unavailable",(string?)health["state"]); Assert.Null(health["diagnostics"]);
        Assert.Equal(current.ToString(),(string?)Assert.Single(health["items"]!.AsArray())!["id"]);
        var retired=Assert.Single(health["replaced_agents"]!.AsArray());
        Assert.Equal(old.ToString(),(string?)retired!["id"]); Assert.Equal(current.ToString(),(string?)retired["replaced_by"]);
        Assert.Equal("/app/agents?agent_id="+old+"#agent-"+old,(string?)retired["href"]);
        string before=await State(admin,ct);
        await Startup(connections,ct);
        Assert.Equal(before,await State(admin,ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
    [Theory]
    [InlineData("0.2.1", "0.2.2", true)]
    [InlineData("1.0.0", "0.2.2", false)]
    public async Task Newer_contacting_agent_wins_despite_old_agents_accepted_packets(string oldVersion,string newVersion,bool oldDotNet)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        await SeedServers(admin,ct);
        var live=Guid.NewGuid(); var silent=Guid.NewGuid();
        await SeedAgent(admin,live,Guid.NewGuid(),"DC","dc",oldVersion,DateTimeOffset.UtcNow.AddSeconds(-30).ToString("O"),'a',ct,dotNet:oldDotNet);
        await SeedAgent(admin,silent,Guid.NewGuid(),null,"dc.example.test",newVersion,DateTimeOffset.UtcNow.ToString("O"),'b',ct);
        await using(var receipt=new NpgsqlCommand("insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at) values(@id,'sli.windows.ad-dc',1,gen_random_uuid(),@sha,'{}','{\"status\":\"committed\"}',now())",admin))
        { receipt.Parameters.AddWithValue("id",live); receipt.Parameters.AddWithValue("sha",new string('c',64)); await receipt.ExecuteNonQueryAsync(ct); }
        await Startup(new Connections(fixture.Dsn("adlog_user")),ct);
        await using var state=new NpgsqlCommand("select a.status,(select count(*) from sli_agent_certificates c where c.agent_id=a.id and revoked_at is null) from sli_agents a where id=@id",admin);
        state.Parameters.AddWithValue("id",live);
        await using(var row=await state.ExecuteReaderAsync(ct)) { Assert.True(await row.ReadAsync(ct)); Assert.Equal("replaced",row.GetString(0)); Assert.Equal(1L,row.GetInt64(1)); }
        await using var other=new NpgsqlCommand("select status from sli_agents where id=@id",admin);
        other.Parameters.AddWithValue("id",silent);
        Assert.Equal("active",(string?)await other.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }


    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Only_automatic_erroneous_revocation_requires_reissue_without_restoring_certificate(bool administratorRevoked)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        await SeedServers(admin,ct);
        var legacy=Guid.NewGuid(); var current=Guid.NewGuid();
        await SeedAgent(admin,legacy,Guid.NewGuid(),"DC","dc","1.0.0",DateTimeOffset.UtcNow.ToString("O"),'a',ct,dotNet:false);
        await SeedAgent(admin,current,Guid.NewGuid(),null,"dc.example.test","0.2.2",DateTimeOffset.UtcNow.AddMinutes(-2).ToString("O"),'b',ct);
        await using(var previous=new NpgsqlCommand("""
            update sli_agents set created_at=clock_timestamp()-interval '2 days' where id=any(@ids);
            update sli_agents set status='replaced' where id=@id;
            update sli_agent_certificates set revoked_at=clock_timestamp()-interval '1 minute' where agent_id=@id;
            insert into sli_agent_audit(action,actor,target,occurred_at,details) values
                ('revoke',@actor,@target,clock_timestamp()-interval '1 minute',jsonb_build_object('serial',@serial::text)),
                ('disable','system:agent-registration-reconcile',@target,clock_timestamp()-interval '1 minute',
                    jsonb_build_object('reason','registration_replaced','replaced_by',@replacement::text));
            """,admin))
        {
            previous.Parameters.AddWithValue("ids",new[] { legacy,current }); previous.Parameters.AddWithValue("id",current);
            previous.Parameters.AddWithValue("target",current.ToString()); previous.Parameters.AddWithValue("serial",current.ToString("N"));
            previous.Parameters.AddWithValue("replacement",legacy.ToString());
            previous.Parameters.AddWithValue("actor",administratorRevoked?"administrator":"system:agent-registration-reconcile");
            await previous.ExecuteNonQueryAsync(ct);
        }
        var connections=new Connections(fixture.Dsn("adlog_user"));
        await Startup(connections,ct);
        await using(var state=new NpgsqlCommand("select status,(select revoked_at is not null from sli_agent_certificates where agent_id=@id) from sli_agents where id=@id",admin))
        {
            state.Parameters.AddWithValue("id",current); await using var row=await state.ExecuteReaderAsync(ct);
            Assert.True(await row.ReadAsync(ct)); Assert.Equal("replaced",row.GetString(0)); Assert.True(row.GetBoolean(1));
        }
        var health=await SetupCollectionHealth.ReadAsync(new InstallationDatabase(connections),ct);
        var retired=Assert.Single(health["replaced_agents"]!.AsArray());
        Assert.Equal(!administratorRevoked,(bool)retired!["certificate_reissue_required"]!);
        await using(var app=await connections.OpenAsync(ct))
        await using(var tx=await app.BeginTransactionAsync(ct))
        {
            var inventory=await new Sli.Server.Agents.Control.AgentManagementService(new Sli.Server.Agents.Control.AgentControlAudit()).ListAgentsAsync(app,tx,null,"synthetic",ct);
            var agent=Assert.Single(inventory.GetProperty("items").EnumerateArray(),a=>a.GetProperty("id").GetGuid()==current);
            Assert.Equal(!administratorRevoked,agent.GetProperty("certificate_reissue_required").ValueKind==System.Text.Json.JsonValueKind.True);
            await tx.CommitAsync(ct);
        }
        string before=await State(admin,ct); await Startup(connections,ct); Assert.Equal(before,await State(admin,ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory]
    [InlineData(60, -600, "0.2.1")]
    [InlineData(600, -600, "0.2.2")]
    [InlineData(60, 0, "0.2.2")]
    [InlineData(60, 0, "0.2.1", true)]
    public async Task Contact_budget_precedes_version_and_packets_only_break_equal_version_ties(int interval,int newContactOffset,string expectedVersion,bool equalVersions=false)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        await SeedServers(admin,ct);
        var old=Guid.NewGuid(); var current=Guid.NewGuid();
        await SeedAgent(admin,old,Guid.NewGuid(),"DC","dc","0.2.1",DateTimeOffset.UtcNow.ToString("O"),'a',ct);
        await SeedAgent(admin,current,Guid.NewGuid(),null,"dc.example.test",equalVersions?"0.2.1":"0.2.2",DateTimeOffset.UtcNow.AddSeconds(newContactOffset).ToString("O"),'b',ct);
        await using(var policy=new NpgsqlCommand("update sli_agents set collection_policy=jsonb_set(collection_policy,'{interval_seconds}',to_jsonb(@interval::int)) where id=@id",admin))
        { policy.Parameters.AddWithValue("id",current); policy.Parameters.AddWithValue("interval",interval); await policy.ExecuteNonQueryAsync(ct); }
        await using(var receipt=new NpgsqlCommand("insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at) values(@id,'sli.windows.ad-dc',1,gen_random_uuid(),@sha,'{}','{\"status\":\"committed\"}',now())",admin))
        { receipt.Parameters.AddWithValue("id",old); receipt.Parameters.AddWithValue("sha",new string('c',64)); await receipt.ExecuteNonQueryAsync(ct); }
        await Startup(new Connections(fixture.Dsn("adlog_user")),ct);
        await using var state=new NpgsqlCommand("select id from sli_agents where status='active'",admin);
        Assert.Equal(expectedVersion=="0.2.1"?old:current,await state.ExecuteScalarAsync(ct));
        await using var revocations=new NpgsqlCommand("select count(*) from sli_agent_audit where action='revoke'",admin);
        Assert.Equal(0L,await revocations.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Shared_identity_on_different_computers_is_a_security_problem_without_retirement(bool sharedHost)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        await SeedServers(admin,ct);
        var first=Guid.NewGuid(); var second=Guid.NewGuid(); var host=Guid.NewGuid();
        await SeedAgent(admin,first,host,"dc","dc.example.test","1.0.0","2026-11-14T00:00:00Z",'a',ct);
        await SeedAgent(admin,second,sharedHost?host:Guid.NewGuid(),"other-dc","other-dc.example.test","1.1.0","2026-11-15T00:00:00Z",sharedHost?'b':'a',ct,"second");
        var connections=new Connections(fixture.Dsn("adlog_user"));
        await Startup(connections,ct);
        await using(var state=new NpgsqlCommand("select status,rights_probe ? 'identity_conflict',(select revoked_at is null from sli_agent_certificates c where c.agent_id=a.id) from sli_agents a",admin))
        await using(var rows=await state.ExecuteReaderAsync(ct))
        {
            int count=0;
            while(await rows.ReadAsync(ct)) { count++; Assert.Equal("active",rows.GetString(0)); Assert.True(rows.GetBoolean(1)); Assert.True(rows.GetBoolean(2)); }
            Assert.Equal(2,count);
        }
        var health=await SetupCollectionHealth.ReadAsync(new InstallationDatabase(connections),ct);
        Assert.All(health["items"]!.AsArray(),row=>Assert.True((bool)row!["identity_conflict"]!));
        Assert.Empty(health["replaced_agents"]!.AsArray());
        string before=await State(admin,ct); await Startup(connections,ct); Assert.Equal(before,await State(admin,ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Manual_restore_swaps_only_authenticated_agents_on_the_same_computer()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        await SeedServers(admin,ct);
        foreach(var (revoked,otherComputer) in new[] { (false,false),(true,false),(false,true) })
        {
        var old=Guid.NewGuid(); var current=Guid.NewGuid();
        char key=revoked?'c':otherComputer?'e':'a';
        await SeedAgent(admin,old,Guid.NewGuid(),"DC","dc","1.0.0","2026-11-15T00:00:00Z",key,ct,snapshot:!revoked && !otherComputer);
        await SeedAgent(admin,current,Guid.NewGuid(),otherComputer?"other-dc":"DC",otherComputer?"other-dc.example.test":"dc.example.test","1.1.0","2026-11-15T00:00:00Z",(char)(key+1),ct);
        await using(var seed=new NpgsqlCommand("update sli_agents set status='replaced' where id=@id; update sli_agent_certificates set revoked_at=case when @revoked then now() else null end where agent_id=@id",admin))
        { seed.Parameters.AddWithValue("id",old); seed.Parameters.AddWithValue("revoked",revoked); await seed.ExecuteNonQueryAsync(ct); }
        await using(var retired=new NpgsqlCommand("insert into sli_agent_audit(action,actor,target,details) values('disable','synthetic',@target,jsonb_build_object('reason','registration_replaced','replaced_by',@current))",admin))
        { retired.Parameters.AddWithValue("target",old.ToString()); retired.Parameters.AddWithValue("current",current.ToString()); await retired.ExecuteNonQueryAsync(ct); }
        if(!revoked && !otherComputer)
        {
            await using var snapshots=new NpgsqlCommand("""
                insert into sli_agent_snapshot_bindings(agent_id,module_id,config,enabled)
                values(@old,'sli.ad-snapshot','{"domain_sid":"S-1-5-21-100000001-200000002-300000003"}',false),
                      (@current,'sli.ad-snapshot','{"domain_sid":"S-1-5-21-100000001-200000002-300000003"}',true)
                """,admin);
            snapshots.Parameters.AddWithValue("old",old); snapshots.Parameters.AddWithValue("current",current); await snapshots.ExecuteNonQueryAsync(ct);
        }
        var audit=new Sli.Server.Agents.Control.AgentControlAudit();
        var service=new Sli.Server.Agents.Control.AgentLifecycleService(new(audit),audit);
        var body=System.Text.Json.JsonSerializer.SerializeToElement(new { agent_id=old,current_agent_id=current });
        await using var db=new NpgsqlConnection(fixture.Dsn("adlog_user")); await db.OpenAsync(ct);
        await using(var tx=await db.BeginTransactionAsync(ct))
        {
            if(revoked || otherComputer)
            {
                var error=await Assert.ThrowsAsync<Sli.Server.Agents.Control.AgentControlException>(()=>service.RestoreAsync(db,tx,body,"synthetic",ct));
                Assert.Equal(409,error.Status); await tx.RollbackAsync(ct);
            }
            else { await service.RestoreAsync(db,tx,body,"synthetic",ct); await tx.CommitAsync(ct); }
        }
        if(!revoked && !otherComputer)
        {
            await using(var bindings=new NpgsqlCommand("select enabled,(select enabled from sli_agent_snapshot_bindings where agent_id=@current) from sli_agent_snapshot_bindings where agent_id=@old",admin))
            { bindings.Parameters.AddWithValue("old",old); bindings.Parameters.AddWithValue("current",current); await using var r=await bindings.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct)); Assert.True(r.GetBoolean(0)); Assert.False(r.GetBoolean(1)); }
            await using var readTx=await db.BeginTransactionAsync(ct);
            var inventory=await new Sli.Server.Agents.Control.AgentManagementService(audit).ListAgentsAsync(db,readTx,null,"synthetic",ct);
            Assert.Contains(inventory.GetProperty("items").EnumerateArray(),a=>a.GetProperty("id").GetGuid()==old && a.GetProperty("status").GetString()=="active");
            await readTx.RollbackAsync(ct);
        }
        await using var query=new NpgsqlCommand("select status,(select status from sli_agents where id=@current),(select revoked_at is not null from sli_agent_certificates where agent_id=@id) from sli_agents where id=@id",admin);
        query.Parameters.AddWithValue("id",old); query.Parameters.AddWithValue("current",current);
        await using(var rows=await query.ExecuteReaderAsync(ct))
        { Assert.True(await rows.ReadAsync(ct)); Assert.Equal(revoked || otherComputer?"replaced":"active",rows.GetString(0)); Assert.Equal(revoked || otherComputer?"active":"replaced",rows.GetString(1)); Assert.Equal(revoked,rows.GetBoolean(2)); }
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static async Task Startup(IPostgresConnectionFactory connections,CancellationToken ct)
    {
        var services=new ServiceCollection(); services.AddLogging(b=>b.ClearProviders());
        services.AddSingleton(connections); services.AddAgentEnrollment();
        await using var provider=services.BuildServiceProvider();
        var worker=Assert.Single(provider.GetServices<IHostedService>());
        await worker.StartAsync(ct);
        await ((BackgroundService)worker).ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(30),ct);
        await worker.StopAsync(ct);
    }
    private static Task SeedServers(NpgsqlConnection db,CancellationToken ct) => PostCollectionPostgres.Sql(db,"""
        insert into servers(domain_id,hostname,fqdn,role)
        select id,n,n,'domain_controller' from domains cross join unnest(array['dc.example.test','other-dc.example.test']) n where fqdn='example.test';
        """,ct);
    private static async Task SeedAgent(NpgsqlConnection db,Guid id,Guid host,string? name,string source,string? version,string seen,char key,CancellationToken ct,string? instance=null,bool dotNet=true,bool snapshot=false)
    {
        await using var seed=new NpgsqlCommand("""
            insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,instance_name,rights_probe,last_seen,assigned_modules)
            values(@id,@host,@key,@name,@instance,@probe::jsonb,@seen,@modules::jsonb);
            insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
            values(@id,'sli.windows.ad-dc',@sourceid,@source,'ad-dc','1.0.0','1');
            insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after)
            values(@id,@serial,@fingerprint,now()-interval '1 day',now()+interval '1 day');
            """,db);
        seed.Parameters.AddWithValue("id",id); seed.Parameters.AddWithValue("host",host); seed.Parameters.AddWithValue("key",new string(key,64));
        seed.Parameters.AddWithValue("sourceid",id.ToString()); seed.Parameters.AddWithValue("source",source);
        seed.Parameters.Add("name",NpgsqlTypes.NpgsqlDbType.Text).Value=(object?)name??DBNull.Value;
        seed.Parameters.Add("instance",NpgsqlTypes.NpgsqlDbType.Text).Value=(object?)instance??DBNull.Value;
        seed.Parameters.AddWithValue("probe",(dotNet?new JsonObject { ["agent_version"]=version }:new JsonObject()).ToJsonString());
        seed.Parameters.AddWithValue("modules",snapshot ? """[{"module_id":"sli.ad-snapshot","enabled":true,"config":{"domain_sid":"S-1-5-21-100000001-200000002-300000003"}}]""" : "[]");
        seed.Parameters.AddWithValue("seen",DateTimeOffset.Parse(seen));
        seed.Parameters.AddWithValue("serial",id.ToString("N")); seed.Parameters.AddWithValue("fingerprint",id.ToString("N")+id.ToString("N"));
        await seed.ExecuteNonQueryAsync(ct);
        if(!dotNet && version is not null)
        {
            await using var update=new NpgsqlCommand("""
                insert into sli_agent_update_packages(sha256,version,manifest,archive)
                values(@sha,@version,'{"component":"agent","package_id":"sli.agent"}',decode('00','hex')) on conflict do nothing;
                insert into sli_agent_update_results(agent_id,package_sha256,version,status) values(@id,@sha,@version,'updated');
                """,db);
            update.Parameters.AddWithValue("id",id); update.Parameters.AddWithValue("version",version); update.Parameters.AddWithValue("sha",new string(key,64));
            await update.ExecuteNonQueryAsync(ct);
        }
    }
    private static async Task<string> State(NpgsqlConnection db,CancellationToken ct)
    {
        await using var state=new NpgsqlCommand("""
            select jsonb_build_array(
                (select jsonb_agg(to_jsonb(a) order by id) from sli_agents a),
                (select jsonb_agg(to_jsonb(c) order by id) from sli_agent_certificates c),
                (select jsonb_agg(to_jsonb(a) order by id) from sli_agent_audit a),
                (select jsonb_agg(to_jsonb(b) order by agent_id,module_id) from sli_agent_snapshot_bindings b))::text
            """,db);
        return (string)(await state.ExecuteScalarAsync(ct))!;
    }
}
