using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Tests.Integration;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class GpoPublicationR1DatabaseTests
{
    [Fact]
    public async Task WorkerRollbackTestsPrimitiveDisplayAndEarlyAwareTimestamp()
    {
        var ct=TestContext.Current.CancellationToken;
        var intent=JsonNode.Parse(File.ReadAllText(Environment.GetEnvironmentVariable("SLI_GPO_R1_INTENT")!))!.AsObject();
        var vector=JsonNode.Parse(File.ReadAllText(Environment.GetEnvironmentVariable("SLI_GPO_OWNED_VECTOR")!))!.AsObject();
        var hashes=JsonNode.Parse(File.ReadAllText(Environment.GetEnvironmentVariable("SLI_GPO_R1_HASHES")!))!.AsArray();
        var secret=JsonNode.Parse(File.ReadAllText(Environment.GetEnvironmentVariable("SLI_GPO_WORKER_SECRET")!))!.AsObject();
        await using var owned=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        var cs=new NpgsqlConnectionStringBuilder { Host="127.0.0.1",Port=49248,Database="sli_oracle",Username=secret["username"]!.GetValue<string>(),Password=secret["password"]!.GetValue<string>(),Pooling=false,SslMode=SslMode.Disable };
        await using var db=new NpgsqlConnection(cs.ConnectionString); await db.OpenAsync(ct);
        await using(var role=new NpgsqlCommand("set role adlog_context_worker",db)) await role.ExecuteNonQueryAsync(ct);
        await using(var who=new NpgsqlCommand("select session_user,current_user",db)) { await using var r=await who.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct)); Assert.Equal(secret["username"]!.GetValue<string>(),r.GetString(0)); Assert.Equal("adlog_context_worker",r.GetString(1)); }
        await using var tx=await db.BeginTransactionAsync(ct);
        long domain=intent["domain_id"]!.GetValue<long>(), entity=intent["entity_id"]!.GetValue<long>(); Guid run=Guid.Parse(intent["existing_run"]!.GetValue<string>());
        foreach(var item in hashes)
        {
            var raw=item!["json"]!.GetValue<string>(); var record=(JsonObject)vector["families"]!["ad_gpo_governance"]!["records"]![0]!.DeepClone();
            record["attributes"]!["display_name"]=JsonNode.Parse(raw);
            await GpoIdentityWriter.StoreAsync(db,tx,domain,run,record,entity,ct);
            await using var read=new NpgsqlCommand("select display_name,encode(source_core_sha256,'hex') from entities_v2 where id=@id",db,tx); read.Parameters.AddWithValue("id",entity);
            await using var r=await read.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            Assert.Equal(raw switch { "true"=>"true", "1.0"=>"1", _=>raw },r.GetString(0)); Assert.Equal(item["core_sha256"]!.GetValue<string>(),r.GetString(1));
        }
        var snapshot=(JsonObject)vector["families"]!["gpo_v2"]!.DeepClone(); snapshot["started_at"]="0001-01-01T00:00:00+01:00";
        Guid transient=Guid.Parse(intent["transient_run"]!.GetValue<string>());
        await GpoSnapshotStore.StoreAndVerifyAsync(db,tx,domain,transient,snapshot,true,ct);
        await using(var check=new NpgsqlCommand("select source_started_at_utc < '0001-01-01 00:00:00+00'::timestamptz from gpo_report_v2_source_snapshots where domain_id=@domain and source_run_id=@run",db,tx))
        { check.Parameters.AddWithValue("domain",domain); check.Parameters.AddWithValue("run",transient); Assert.Equal(true,await check.ExecuteScalarAsync(ct)); }
        await tx.RollbackAsync(ct);
        await using var absent=new NpgsqlCommand("select count(*) from gpo_report_v2_source_snapshots where source_run_id=@run",db); absent.Parameters.AddWithValue("run",transient); Assert.Equal(0L,(long)(await absent.ExecuteScalarAsync(ct))!);
    }
}
