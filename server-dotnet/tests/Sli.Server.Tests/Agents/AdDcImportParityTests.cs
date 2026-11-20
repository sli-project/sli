using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AdDcImportParityTests
{
    [Fact]
    public void Every_Python_DC_identity_and_optional_XML_shape_preserves_normalization()
    {
        var vectors=JsonNode.Parse(File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(),
            "server-dotnet/tests/Sli.Server.Tests/Agents/ad-dc-import-source.json")))!.AsArray();
        Assert.True(vectors.Count>100);
        foreach(var vector in vectors.OfType<JsonObject>()) {
            var row=vector["row"]!.AsObject();
            var p=Assert.Single(DirectAdDcPacket.PrepareBatch(new JsonArray(row.DeepClone()))).Projection;
            Assert.Equal((string?)vector["hash"],p.IdentityHash);
            Assert.Equal((string?)vector["noise"]![0],p.Noise);
            Assert.Equal((string?)vector["noise"]![1],p.NoiseVersion);
            var normalized=new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc);
            Assert.Equal((string?)vector["source_hash"],Convert.ToHexStringLower(Direct4624Core.SourceHash(42,2,3,4,null,5,normalized,row,p)));
            Assert.True(JsonNode.DeepEquals(vector["source"],DirectNpsArchiveRows.Event(42,2,3,4,null,5,normalized,row,p)),vector["name"]!.ToString());
            Assert.Equal(vector["entities"]!.AsArray().Count,p.Entities.Count);
            for(int i=0;i<p.Entities.Count;i++) {
                var e=p.Entities[i];var expected=vector["entities"]![i]!;
                Assert.Equal(((string?)expected["entity_type"],(string?)expected["natural_key"],(string?)expected["display_name"],(string?)expected["link_role"]),
                    (e.Type,e.NaturalKey,e.DisplayName,e.Role));
                Assert.Equal((double)expected["confidence"]!,e.Confidence);
                Assert.Equal((bool)expected["domain_scoped"]!,e.DomainScoped);
                Assert.Equal((bool)expected["server_scoped"]!,e.ServerScoped);
                Assert.True(JsonNode.DeepEquals(expected["attributes"],e.Attributes),vector["name"]!.ToString());
                var state=DirectStateProjection.Candidate(row,p,42,i+1,e.Role);
                if(state is not null) {state.Remove("entity_id");state.Remove("source_event_db_id");}
                Assert.True(JsonNode.DeepEquals(vector["states"]![i],state),vector["name"]!.ToString()+":state");
            }
            var facts=Direct4624Facts.Document(42,p);
            if(vector["facts"] is null) Assert.False(Direct4624Facts.HasFacts(facts));
            else {
                foreach(var (key,value) in vector["facts"]!.AsObject())
                    Assert.True(JsonNode.DeepEquals(value,facts[key]),$"{vector["name"]}:{key}");
                Assert.Equal((string?)vector["facts_hash"],Convert.ToHexStringLower(Direct4624Facts.Hash(42,p)));
            }
        }
    }
    [Fact]
    public async Task Source_configuration_requires_one_active_domain_controller()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new PostCollectionPostgres(canonicalSchema:true);await fixture.StartAsync(ct);
        await using var db=new NpgsqlConnection(fixture.ConnectionString);await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db,"""
            create table servers(id bigint,domain_id bigint,site_id bigint,hostname text,role text,is_active boolean,fqdn text);
            create table sli_agent_audit(id bigint,target text,action text,details jsonb);
            """,ct);
        var configurations=JsonNode.Parse(File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(),"server-dotnet/tests/Sli.Server.Tests/Agents/ad-dc-configuration-source.json")))!.AsArray();
        foreach(var config in configurations) {
            await using var tx=await db.BeginTransactionAsync(ct);
            foreach(var source in config!["sources"]!.AsArray()) {
                await using var insert=new NpgsqlCommand("insert into servers(id,domain_id,hostname,role,is_active) values(@id,@domain,'dc-fixture.example.test','domain_controller',true)",db,tx);
                insert.Parameters.AddWithValue("id",(long)source!["server_id"]!);insert.Parameters.AddWithValue("domain",(long)source["domain_id"]!);await insert.ExecuteNonQueryAsync(ct);
            }
            if(config["error"] is not null) {
                var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>DirectAdDcPacket.SourceAsync(db,tx,"dc-fixture.example.test",ct));
                Assert.Equal((string?)config["error"],error.Message);
            } else Assert.Equal(((long)config["expected"]!["server_id"]!,(long)config["expected"]!["domain_id"]!,(long?)null),await DirectAdDcPacket.SourceAsync(db,tx,"dc-fixture.example.test",ct));
            await tx.RollbackAsync(ct);
        }
    }
}
