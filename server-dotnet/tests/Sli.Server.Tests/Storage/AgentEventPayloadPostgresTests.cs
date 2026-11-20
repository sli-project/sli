using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Storage.Archive;
using Sli.Server.Storage.History;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Parity: tests/storage/test_agent_event_payload_postgres.py, using a private fresh cluster.
public sealed class AgentEventPayloadPostgresTests
{
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    static (JsonObject Summary,JsonObject Row) Source(int kind=4728,int version=2)
    {
        string data = kind==4728 ? $"<Data Name=\"MemberSid\">{Sid}</Data>" : "<Data Name=\"SubcategoryGuid\">{00000000-0000-4000-8000-000000000001}</Data>";
        var row = new JsonObject { ["event_id"]=kind,["record_id"]=11,["channel"]="Security",["computer_name"]="fixture-dc",
            ["time_created"]="2026-10-12T08:04:47Z",["provider_name"]="fixture-provider",
            ["xml"]=$"<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><EventData>{data}</EventData></Event>" };
        // Captured from legacy_event_hash/event_identity_hash in the frozen Python reference;
        // only the fixture SID is replaced with the Q500 synthetic SID.
        string hash = (kind,version) switch {
            (4728,1)=>"c44edb8cf21d51c4403e99f68b197732d0b73bab99b2e80e2f533b3768955e0c",
            (4728,2)=>"9321840c84720d9e7775fcb5a7f40f9a96aa61bb0604d2dfeba2d8188378ee2f",
            (4719,1)=>"24ec22b2bd52bb2519b6cc5380cdad054cc49a8f03d58e73886e35c6d37935eb",
            _=>"f9454242c3f413cf15358096430cdc62c278a27737631e9a3cd18cc5af3a14b4" };
        return (new JsonObject { ["id"]=7,["raw_log_file_id"]=9,["server_id"]=3,["domain_id"]=2,["site_id"]=null,
            ["log_source_id"]=1,["event_id"]=kind,["time_created_utc"]=row["time_created"]!.DeepClone(),["normalized_hash"]=hash },row);
    }

    [Fact]
    public async Task Sql_reader_hydrates_exact_jsonb_for_both_events_and_identity_versions()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=await Fixture.Start(ct);
        foreach (int kind in new[] {4728,4719}) foreach (int version in new[] {1,2}) {
            var (summary,row)=Source(kind,version);
            await fixture.Retain(row,ct);
            var hydrator=new EventArchiveHydrator(new ArchiveReader(Path.Combine(fixture.Pg.Root,"absent-archive"),new UnusedManifest()));
            var payloads=await hydrator.ReadWithAgentPacketsAsync([],new Dictionary<long,JsonObject>{{7,summary}},fixture.Store.AgentPayloadAsync,ct,exact:true);
            var payload=payloads[7];
            Assert.Equal("7",payload["id"]!.ToString()); Assert.False(payload.ContainsKey("source_payload_state"));
            Assert.Equal(summary["normalized_hash"]!.ToString(),payload["normalized_hash"]!.ToString());
            var data=JsonNode.Parse(payload["event_data_json"]!.GetValue<string>())!;
            Assert.Equal(kind==4728 ? Sid : "{00000000-0000-4000-8000-000000000001}",data[kind==4728 ? "MemberSid" : "SubcategoryGuid"]!.ToString());
            Assert.Equal(row["xml"]!.ToString(),payload["record_xml"]!.ToString());
            Assert.Equal("fixture-dc",payload["computer"]!.ToString()); Assert.Equal("fixture-provider",payload["provider_name"]!.ToString());
        }
    }

    [Fact]
    public async Task Sql_reader_rejects_each_unrelated_or_unimported_packet()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=await Fixture.Start(ct);
        foreach (string change in new[] {"raw_file","server","log_source","path","pending","receipt","envelope"}) {
            var (summary,row)=Source(); await fixture.Retain(row,ct);
            if (change is "raw_file" or "server" or "log_source") {
                string field=change=="raw_file" ? "raw_log_file_id" : change=="server" ? "server_id" : "log_source_id";
                summary[field]=int.Parse(summary[field]!.ToString())+1;
            } else await fixture.Sql(change switch {
                "path"=>"update raw_log_files set file_path='agent-packet:00000000-0000-4000-8000-000000000064'",
                "pending"=>"update sli_agent_packet_inbox set imported_at=null",
                "receipt"=>"delete from sli_agent_receipts",
                _=>"update sli_agent_packet_inbox set envelope='{}'::jsonb" },ct);
            Assert.Null(await fixture.Store.AgentPayloadAsync(summary,ct));
        }
    }

    [Fact]
    public async Task Sql_reader_rejects_tampered_jsonb_despite_unchanged_v2_identity()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=await Fixture.Start(ct);
        var (summary,row)=Source(); await fixture.Retain(row,ct);
        row["xml"]="<Event/>";
        Assert.Equal(summary["normalized_hash"]!.ToString(),RetainedEventIdentity.Canonical(row));
        await fixture.Sql("update sli_agent_packet_inbox set event_rows=jsonb_set(event_rows,'{0,xml}','\"<Event/>\"'::jsonb)",ct);
        var error=await Assert.ThrowsAsync<InvalidDataException>(()=>fixture.Store.AgentPayloadAsync(summary,ct));
        Assert.Equal("agent_event_packet_receipt_mismatch",error.Message);
    }

    [Fact]
    public async Task Packet_fallback_preserves_timestamp_identity_and_archive_failure_boundaries()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=await Fixture.Start(ct);
        var (summary,row)=Source(); await fixture.Retain(row,ct);
        summary["time_created_utc"]="2026-10-12T08:04:48Z";
        var error=await Assert.ThrowsAsync<InvalidDataException>(()=>fixture.Store.AgentPayloadAsync(summary,ct));
        Assert.Equal("archive_core_timestamp_mismatch",error.Message);
        summary["time_created_utc"]=row["time_created"]!.DeepClone();
        var summaries=new Dictionary<long,JsonObject>{{7,summary}};
        var hydrator=new EventArchiveHydrator(new ArchiveReader(Path.Combine(fixture.Pg.Root,"archive"),new UnusedManifest()));
        var block=new ArchiveBlock(Guid.NewGuid(),"event",1,0,7,7,1,1,1,"bad","bad","absent","quarantined",DateTime.UtcNow);
        await Assert.ThrowsAsync<InvalidDataException>(()=>hydrator.ReadWithAgentPacketsAsync([block],summaries,(_,_)=>throw new InvalidOperationException("packet fallback forbidden"),ct,exact:true));
        await fixture.Sql("delete from sli_agent_receipts",ct);
        var absent=await hydrator.ReadWithAgentPacketsAsync([],summaries,fixture.Store.AgentPayloadAsync,ct,exact:true);
        Assert.Equal("archive_unavailable",absent[7]["source_payload_state"]!.ToString());
        await Assert.ThrowsAsync<InvalidDataException>(()=>hydrator.ReadWithAgentPacketsAsync([],summaries,fixture.Store.AgentPayloadAsync,ct));
    }

    sealed class Fixture : IAsyncDisposable
    {
        internal readonly PostCollectionPostgres Pg=new(canonicalSchema:true);
        NpgsqlDataSource source=null!;
        internal EventDetailStore Store=null!;
        internal static async Task<Fixture> Start(CancellationToken ct)
        {
            var fixture=new Fixture();
            try {
                await fixture.Pg.StartAsync(ct);
                await fixture.Sql("""
                    create table raw_log_files(id bigint primary key,server_id int,log_source_id int,file_path text,sha256 text);
                    create table sli_agent_packet_inbox(packet_id uuid primary key,event_rows jsonb,imported_at timestamptz,packet jsonb,envelope jsonb);
                    create table sli_agent_receipts(packet_id uuid primary key,envelope jsonb,envelope_sha256 text);
                    create role synthetic_payload_reader;
                    grant select on raw_log_files,sli_agent_packet_inbox,sli_agent_receipts to synthetic_payload_reader;
                    """,ct);
                fixture.source=NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Pg.ConnectionString) { Options="-c role=synthetic_payload_reader",CommandTimeout=0 }.ConnectionString);
                fixture.Store=new EventDetailStore(fixture.source);
                return fixture;
            } catch { await fixture.DisposeAsync(); throw; }
        }
        internal async Task Sql(string sql,CancellationToken ct)
        {
            await using var db=new NpgsqlConnection(Pg.ConnectionString); await db.OpenAsync(ct);
            await PostCollectionPostgres.Sql(db,sql,ct);
        }
        internal async Task Retain(JsonObject row,CancellationToken ct)
        {
            var id=Guid.NewGuid();
            var packet=CollectionPacket.Make("fixture-dc","Security",null,new JsonObject { ["last_record_id"]=11 },
                [new PacketRecord("event_xml",11,row)],"not_proven",null,DateTimeOffset.Parse("2026-10-12T08:04:47Z"));
            var envelope=new JsonObject { ["packet_id"]=id.ToString(),["payload_sha256"]=Packets.Digest(packet) };
            await using var db=new NpgsqlConnection(Pg.ConnectionString); await db.OpenAsync(ct);
            await using var command=new NpgsqlCommand("""
                truncate raw_log_files,sli_agent_packet_inbox,sli_agent_receipts;
                insert into sli_agent_receipts values(@id,@envelope,@hash);
                insert into sli_agent_packet_inbox values(@id,@rows,now(),@packet,@envelope);
                """,db);
            command.Parameters.AddWithValue("id",id); command.Parameters.AddWithValue("hash",Packets.Digest(envelope));
            command.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,envelope.ToJsonString());
            command.Parameters.AddWithValue("packet",NpgsqlDbType.Jsonb,packet.ToJsonString());
            command.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,new JsonArray(row.DeepClone()).ToJsonString());
            await command.ExecuteNonQueryAsync(ct);
            // Match the importer: calculate the raw JSONL digest after JSONB has reordered keys.
            await using var read=new NpgsqlCommand("select event_rows::text from sli_agent_packet_inbox where packet_id=@id",db);
            read.Parameters.AddWithValue("id",id);
            var stored=JsonNode.Parse((string)(await read.ExecuteScalarAsync(ct))!)!.AsArray();
            Assert.NotEqual(row.ToJsonString(),stored[0]!.ToJsonString());
            await using var raw=new NpgsqlCommand("insert into raw_log_files values(9,3,1,'agent-packet:'||@id::text,@hash)",db);
            raw.Parameters.AddWithValue("id",id); raw.Parameters.AddWithValue("hash",Sli.Server.Storage.Direct.DirectPacketJsonl.Create(stored).Sha256);
            await raw.ExecuteNonQueryAsync(ct);
        }
        public async ValueTask DisposeAsync() { if (source is not null) await source.DisposeAsync(); await Pg.DisposeAsync(); }
    }
    sealed class UnusedManifest : IArchiveManifestStore
    {
        public Task EnsureSetAsync(ArchiveSet s,CancellationToken c)=>throw new NotSupportedException();
        public Task<ArchiveBlock?> GetAsync(Guid i,string k,int n,CancellationToken c)=>throw new NotSupportedException();
        public Task<ArchiveBlock> StageAsync(ArchiveBlock b,CancellationToken c)=>throw new NotSupportedException();
        public Task<ArchiveBlock> MarkPublishedAsync(ArchiveBlock b,CancellationToken c)=>throw new NotSupportedException();
        public Task<ArchiveBlock?> FindPublishedAsync(string k,long i,CancellationToken c)=>throw new NotSupportedException();
        public Task<IReadOnlyList<ArchiveBlock>> FindPublishedRangeAsync(string k, long first, long last, CancellationToken c) => throw new NotSupportedException();
        public Task<IReadOnlyList<ArchiveBlock>> FindPublishedRangeAsync(string k, long first, long last, int limit, CancellationToken c) => throw new NotSupportedException();
    }
}
