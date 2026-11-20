using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordStateBoundPostgresTests(ITestOutputHelper output)
{
    [Fact] public async Task Previous_maximum_accepts_386_and_larger_live_state_without_changing_witness_checks_or_acl()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:385);
        await using var db=await fixture.Pg.OpenAsync(ct);
        var sample=PasswordRuleTests.Event(1,1);var scope=sample.Witness.Scope with {SourceInstanceId=new string('s',256),SourceGeneration=new string('g',512)};
        var rows=Enumerable.Range(1,1400).Select(i=> {
            var row=PasswordRuleTests.Event(i,30+i%30,user:$"noise{i}");
            return PasswordNative.Parse(scope,i,row.Witness.Sha256,4625,row.Witness.At,row.SourceXml);
        }).ToArray();
        var proposal=new PasswordRule(scope).Advance(new(),rows,sample.Witness.At.AddSeconds(179));
        Assert.Empty(proposal.Diagnostics);var state=proposal.State.Document;int bytes=PasswordJson.SpacedSize(state);
        Assert.True(bytes>4194304);output.WriteLine($"PostgreSQL checked live state: {bytes} bytes");
        async Task<long> Check(JsonObject document) {
            await using var q=new NpgsqlCommand("select public.password_v2_check_state(@st::jsonb,@s::jsonb,@pin)",db);
            q.Parameters.AddWithValue("st",document.ToJsonString());q.Parameters.AddWithValue("s",scope.Document.ToJsonString());q.Parameters.AddWithValue("pin",proposal.State.Pin!);
            return (long)(await q.ExecuteScalarAsync(ct))!;
        }
        async Task<string> Definition() {
            await using var q=new NpgsqlCommand("select jsonb_build_array(pg_get_functiondef(oid),proowner,proacl)::text from pg_proc where oid='public.password_v2_check_state(jsonb,jsonb,text)'::regprocedure",db);
            return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        var before=await Definition();
        var oldBound=await Assert.ThrowsAsync<PostgresException>(()=>Check(state));Assert.Equal("password_v2_state_bound",oldBound.MessageText);
        var path=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/386_password_live_state_bound.sql");
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        Assert.Equal((long)bytes,await Check(state));
        var corrupt=state.DeepClone().AsObject();corrupt["window"]![0]!["witness"]!["ref"]!["sha256"]="invalid";
        var witness=await Assert.ThrowsAsync<PostgresException>(()=>Check(corrupt));Assert.Equal("password_v2_state_invalid",witness.MessageText);
        var overflow=state.DeepClone().AsObject();
        // Keep counts below their bounds; reject bytes before decoding any witnesses.
        for(int i=0;i<6;i++)foreach(var member in state["window"]!.AsArray())overflow["window"]!.AsArray().Add(member!.DeepClone());
        foreach(var episode in state["episodes"]!.AsArray())overflow["episodes"]!.AsArray().Add(episode!.DeepClone());
        Assert.True(PasswordJson.SpacedSize(overflow)>16777216);
        var denied=await Assert.ThrowsAsync<PostgresException>(()=>Check(overflow));Assert.Equal("password_v2_state_bound",denied.MessageText);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path,".rollback.sql"),null,ct);
        Assert.Equal(before,await Definition());
        var restored=await Assert.ThrowsAsync<PostgresException>(()=>Check(state));Assert.Equal("password_v2_state_bound",restored.MessageText);
        await fixture.Pg.ApplyFileAsync(path,null,ct);Assert.Equal((long)bytes,await Check(state));
    }
}
