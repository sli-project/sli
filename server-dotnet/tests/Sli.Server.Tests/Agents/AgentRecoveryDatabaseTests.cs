using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

[Collection("Owned agent recovery")]
public sealed class AgentRecoveryDatabaseTests
{
    private const string Route = "/api/v1/admin/agents/sequence-recovery";
    private static JsonElement Json(object value) => JsonSerializer.SerializeToElement(value);
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string ProofRoot => Environment.GetEnvironmentVariable("SLI_AGENT_MANAGEMENT_EVIDENCE") ?? throw new InvalidOperationException();
    private static async Task<JsonElement> Plan(CancellationToken ct) => JsonDocument.Parse(await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_AGENT_MANAGEMENT_PLAN") ?? throw new InvalidOperationException(),ct)).RootElement.Clone();
    private sealed class Factory(SyntheticDatabase database) : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => database.OpenConnectionAsync(ct); }

    [Fact]
    public async Task OwnerHttpGuardsAndReadOnlyPreviewUseTheActualProductionRoutes()
    {
        var ct = TestContext.Current.CancellationToken; var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal("6a13bcc8-3cba-4ee1-85ce-5808480a9e21",binding.RunId.ToString("D"));
        await using var database = await SyntheticDatabase.BorrowAsync(binding,ct); var plan = await Plan(ct);
        await using (var check = await database.OpenConnectionAsync(ct))
        await using (var query = new NpgsqlCommand("select current_user,is_active,role,exists(select 1 from access_platform_owners where user_id=101),has_table_privilege(current_user,'auth_sessions','DELETE') from auth_users where id=101",check))
        await using (var reader = await query.ExecuteReaderAsync(ct))
        { Assert.True(await reader.ReadAsync(ct)); Assert.Equal("adlog_user",reader.GetString(0)); Assert.True(reader.GetBoolean(1)); Assert.Equal("admin",reader.GetString(2)); Assert.True(reader.GetBoolean(3)); Assert.True(reader.GetBoolean(4)); }
        // GET accepts an absent UUID exactly as source and needs no committed agent.
        // The only committed fixture row is this own source-format session.
        var credentials = new CredentialTokens(); var sessions = new SessionLifecycle(new Factory(database),credentials,TimeProvider.System);
        string token = await sessions.IssueAsync(new Principal("session",101,"admin"),false,ct), digest = credentials.Digest(token);
        try
        {
            var secretPath = Path.Combine(binding.Root,binding.RunId.ToString("D"),binding.Side,"runtime-secret.json");
            using var secret = JsonDocument.Parse(await File.ReadAllBytesAsync(secretPath,ct)); var s = secret.RootElement;
            var builder = new NpgsqlConnectionStringBuilder { Host=binding.ExpectedHost,Port=binding.ExpectedPort,Database="sli_oracle",Username="adlog_user",Password=s.GetProperty("password").GetString(),Pooling=false,CommandTimeout=5,Timeout=3 };
            using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(host => host.ConfigureAppConfiguration((_,cfg) => cfg.AddInMemoryCollection(new Dictionary<string,string?> {
                ["ConnectionStrings:Sli"]=builder.ConnectionString,["Sli:AuthRequired"]="1",["Sli:AllowUnauthenticated"]="0",["Sli:AuthAllowInsecureHttp"]="1",["Sli:TrustedProxies"]="",["Sli:OwnerSetup"]="0"
            })));
            host.UseKestrel(k => k.Listen(IPAddress.Loopback,0)); host.StartServer();
            string url = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses); Assert.True(new Uri(url).IsLoopback);
            using var client = new HttpClient(new HttpClientHandler { UseCookies=false,AllowAutoRedirect=false }) { BaseAddress=new Uri(url) };
            async Task<(HttpStatusCode,JsonElement)> Send(string path,string method="GET",object? body=null,bool authenticated=true,string? origin=null)
            {
                using var request = new HttpRequestMessage(new HttpMethod(method),path);
                if(authenticated) request.Headers.Add("Cookie","adlog_session="+token);
                if(origin is not null) request.Headers.Add("Origin",origin);
                if(body is not null) request.Content = new StringContent(JsonSerializer.Serialize(body),Encoding.UTF8,"application/json");
                using var response = await client.SendAsync(request,ct); Assert.Contains("no-store",response.Headers.CacheControl?.ToString() ?? "");
                using var document = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct)); return(response.StatusCode,document.RootElement.Clone());
            }
            string id=plan.GetProperty("http_agent").GetString()!;
            var absent=await Send(Route+"?agent_id="+id,authenticated:false);Assert.Equal(HttpStatusCode.Unauthorized,absent.Item1);
            var result=await Send(Route+"?agent_id="+id);Assert.Equal(HttpStatusCode.OK,result.Item1);Assert.Empty(result.Item2.GetProperty("gaps").EnumerateArray());Assert.Empty(result.Item2.GetProperty("recovery_preview").GetProperty("observation_ids").EnumerateArray());
            foreach(string suffix in new[]{"","?agent_id="+id+"&agent_id="+id,"?agent_id="+id+"&extra=x"}) {var bad=await Send(Route+suffix);Assert.Equal(HttpStatusCode.BadRequest,bad.Item1);Assert.Equal("agent_sequence_recovery_invalid",bad.Item2.GetProperty("error").GetString());}
            var raw=await Send(Route+"/");Assert.Equal(HttpStatusCode.NotImplemented,raw.Item1);
            var origin=await Send(Route,"POST",new{},origin:"https://invalid.example");Assert.Equal(HttpStatusCode.Forbidden,origin.Item1);
            var invalid=await Send(Route,"POST",new{});Assert.Equal(HttpStatusCode.BadRequest,invalid.Item1);Assert.Equal("agent_sequence_recovery_invalid",invalid.Item2.GetProperty("error").GetString());
            var replace=await Send("/api/v1/admin/agents/replace","POST",new{});Assert.Equal(HttpStatusCode.BadRequest,replace.Item1);Assert.Equal("agent_replacement_invalid",replace.Item2.GetProperty("error").GetString());
            await File.WriteAllTextAsync(Path.Combine(ProofRoot,"http-safe.json"),JsonSerializer.Serialize(new{current_user="adlog_user",owner_id=101,anonymous_status=(int)absent.Item1,empty_preview=result.Item2,checks="query-cardinality/raw-path/origin/invalid-POST",session_digest=digest,agent_seeded=false}),ct);
        }
        finally
        {
            await using var db=await database.OpenConnectionAsync(CancellationToken.None);
            await using var cleanup=new NpgsqlCommand("delete from auth_sessions where user_id=101 and token_hash=@hash",db);cleanup.Parameters.AddWithValue("hash",digest);Assert.Equal(1,await cleanup.ExecuteNonQueryAsync(CancellationToken.None));
            await using var absent=new NpgsqlCommand("select count(*) from auth_sessions where user_id=101 and token_hash=@hash",db);absent.Parameters.AddWithValue("hash",digest);Assert.Equal(0L,await absent.ExecuteScalarAsync(CancellationToken.None));
        }
    }

    [Fact]
    public async Task RecoveryAndRuntimeReplacementExecuteInTheOrdinaryCallerTransactionAndRollback()
    {
        var ct=TestContext.Current.CancellationToken;await using var database=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);var plan=await Plan(ct);
        Guid agent=plan.GetProperty("recovery_agent").GetGuid(),old=plan.GetProperty("old_agent").GetGuid(),next=plan.GetProperty("new_agent").GetGuid();
        await using var db=await database.OpenConnectionAsync(ct);
        await using(var role=new NpgsqlCommand("select current_user,has_function_privilege(current_user,'public.replace_agent_runtime_v296(uuid,uuid,text,text)','EXECUTE')",db))
        await using(var reader=await role.ExecuteReaderAsync(ct)){Assert.True(await reader.ReadAsync(ct));Assert.Equal("adlog_user",reader.GetString(0));Assert.True(reader.GetBoolean(1));}
        await using(var tx=await db.BeginTransactionAsync(ct))
        {
            await using(var seed=new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint,registration_host_name) select id,id,repeat('a',64),'owned-management.example' from unnest(@ids) id",db,tx)) {seed.Parameters.AddWithValue("ids",new[]{agent,old,next});Assert.Equal(3,await seed.ExecuteNonQueryAsync(ct));}
            var audit=new AgentControlAudit();var recovery=new AgentRecoveryService(audit);var observer=new AgentSequenceRecovery(db,tx);var now=DateTimeOffset.UtcNow;var gaps=new List<JsonObject>();
            foreach(string module in new[]{"sli.heartbeat","sli.windows-eventlog"})
            {
                var e=new Envelope(Guid.NewGuid().ToString("D"),agent.ToString("D"),agent.ToString("D"),module,"1.0.0","1","Security",agent.ToString("D"),5,Cursor.Start("record_id"),Cursor.Start("record_id"),"sli.collection-packet.v1",new string('b',64),0,2,Iso8601.Format(now),"not_proven",0,null);
                Assert.Null(await observer.ObserveAsync(new AgentIdentity(agent,agent,new string('a',64),"active"),e,null,now,ct));
            }
            var view=await recovery.ListAsync(db,tx,agent.ToString("D"),ct);var preview=view.GetProperty("recovery_preview");Assert.Equal(2,preview.GetProperty("observation_ids").GetArrayLength());
            var body=Json(new{agent_id=agent,observation_ids=preview.GetProperty("observation_ids"),preview_token=preview.GetProperty("preview_token").GetString(),confirm_loss=true});
            var applied=await recovery.AuthorizeAsync(db,tx,body,"session:101",ct);Assert.Equal("authorized",applied.GetProperty("status").GetString());await recovery.AuthorizeAsync(db,tx,body,"session:101",ct);
            await using(var count=new NpgsqlCommand("select count(*) from sli_agent_audit where target=@id and action='sequence_gap_authorized'",db,tx)){count.Parameters.AddWithValue("id",agent.ToString("D"));Assert.Equal(2L,await count.ExecuteScalarAsync(ct));}
            var changed=(JsonObject)JsonNode.Parse(body.GetRawText())!;changed["observation_ids"]=new JsonArray(preview.GetProperty("observation_ids")[0].GetString());
            Assert.Equal("agent_sequence_recovery_stale",(await Assert.ThrowsAsync<AgentControlException>(()=>recovery.AuthorizeAsync(db,tx,Json(changed),"session:101",ct))).Message);
            await using(var export=new NpgsqlCommand("select coalesce(jsonb_agg(jsonb_build_object('id',id::text,'details',details) order by id),'[]'::jsonb)::text from sli_agent_audit where target=@id and action='sequence_gap_observed'",db,tx)) {export.Parameters.AddWithValue("id",agent.ToString("D"));await File.WriteAllTextAsync(Path.Combine(ProofRoot,"source-preview-input.json"),JsonSerializer.Serialize(new{agent_id=agent,observations=JsonDocument.Parse((string)(await export.ExecuteScalarAsync(ct))!).RootElement,actual_preview=preview}),ct);}
            // Source-authenticated client enrollment/ack are explicit fixture preconditions,
            // not a claim that the still-unported policy-report route was exercised.
            string serial=plan.GetProperty("certificate_serial").GetString()!;
            await using(var seed=new NpgsqlCommand("""
                insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after) values(@new,@serial,@certfp,now()-interval '1 hour',now()+interval '1 day');
                insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at,used_at,replacement_for,enrolled_agent_id)
                values(@token,@tokenhash,@new,repeat('a',64),now(),now()+interval '15 minutes',now(),@old,@new)
                """,db,tx)){seed.Parameters.AddWithValue("new",next);seed.Parameters.AddWithValue("old",old);seed.Parameters.AddWithValue("serial",serial);seed.Parameters.AddWithValue("token",plan.GetProperty("replacement_token").GetGuid());seed.Parameters.AddWithValue("tokenhash",Hash(plan.GetProperty("replacement_token").GetString()!));seed.Parameters.AddWithValue("certfp",Hash(serial));await seed.ExecuteNonQueryAsync(ct);}
            var replacement=new AgentReplacementService();JsonElement Replace(string phase)=>Json(new{old_agent_id=old,new_agent_id=next,phase,confirm=true});
            var prepared=await replacement.ReplaceAsync(db,tx,Replace("prepare"),"session:101",ct);Assert.Equal("draining",prepared.GetProperty("state").GetString());
            await tx.SaveAsync("unready",ct);var unready=await Assert.ThrowsAsync<AgentControlException>(()=>replacement.ReplaceAsync(db,tx,Replace("complete"),"session:101",ct));Assert.Equal(409,unready.Status);Assert.Equal("agent_replacement_not_ready",unready.Message);await tx.RollbackAsync("unready",ct);
            await using(var ack=new NpgsqlCommand("update sli_agents set applied_policy_revision=policy_revision,applied_collection_state='paused',rights_probe=rights_probe||'{\"runtime_handoff_supported\":true}'::jsonb where id=any(@ids)",db,tx)){ack.Parameters.AddWithValue("ids",new[]{old,next});Assert.Equal(2,await ack.ExecuteNonQueryAsync(ct));}
            var completed=await replacement.ReplaceAsync(db,tx,Replace("complete"),"session:101",ct);Assert.Equal("completed",completed.GetProperty("state").GetString());var replay=await replacement.ReplaceAsync(db,tx,Replace("complete"),"session:101",ct);Assert.Equal("completed",replay.GetProperty("state").GetString());
            await using(var check=new NpgsqlCommand("select status from sli_agents where id=@id",db,tx)){check.Parameters.AddWithValue("id",old);Assert.Equal("replaced",await check.ExecuteScalarAsync(ct));}
            await tx.RollbackAsync(ct);
        }
        await using(var absent=new NpgsqlCommand("select (select count(*) from sli_agents where id=any(@ids)),(select count(*) from sli_agent_audit where target=any(@targets)),(select count(*) from sli_agent_runtime_switches where old_agent_id=@old)",db)) {absent.Parameters.AddWithValue("ids",new[]{agent,old,next});absent.Parameters.AddWithValue("targets",new[]{agent.ToString("D"),old.ToString("D"),next.ToString("D")});absent.Parameters.AddWithValue("old",old);await using var reader=await absent.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));for(int i=0;i<3;i++)Assert.Equal(0L,reader.GetInt64(i));}
    }
}
[CollectionDefinition("Owned agent recovery",DisableParallelization=true)]
public sealed class AgentRecoveryCollection { }