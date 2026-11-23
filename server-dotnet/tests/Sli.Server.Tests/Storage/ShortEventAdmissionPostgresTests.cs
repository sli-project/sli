using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class ShortEventAdmissionPostgresTests
{
    internal static readonly Guid Agent = new("00000000-0000-4000-8000-000000000349");
    internal static readonly Guid Packet = new("00000000-0000-4000-8000-000000003490");

    internal static async Task RegisterDcAsync(NpgsqlConnection db, Guid agent, Guid host, long server,
        long domain, string hostName, string channel, CancellationToken ct, string? additionalChannel = null,
        bool history = false)
    {
        await using var registry = new NpgsqlCommand("""
            insert into servers(id,domain_id,hostname,role,is_active) values(@server,@domain,@name,'domain_controller',true);
            insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,assigned_modules)
                values(@agent,@host,repeat('c',64),@name,jsonb_build_array(jsonb_build_object('module_id','sli.windows.ad-dc','enabled',true,
                'config',jsonb_build_object('source_name',@name,'connect_address',@name,'policy_revision','1',
                'channels',jsonb_build_object(@channel,true) || jsonb_build_object(@additional,true),
                'channel_generations',jsonb_build_object(@channel,@host::text) ||
                    jsonb_build_object(@additional,@host::text)))) ||
                    case when @history then jsonb_build_array(jsonb_build_object('module_id','sli.windows.ad-dc-history',
                        'enabled',true,'config','{}'::jsonb)) else '[]'::jsonb end);
            insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
                values(@agent,'sli.windows.ad-dc',@host::text,@name,'ad-dc','1.0.0','1');
            """,db);
        registry.Parameters.AddWithValue("agent",agent); registry.Parameters.AddWithValue("host",host);
        registry.Parameters.AddWithValue("server",server); registry.Parameters.AddWithValue("domain",domain);
        registry.Parameters.AddWithValue("name",hostName); registry.Parameters.AddWithValue("channel",channel);
        registry.Parameters.AddWithValue("additional",additionalChannel ?? channel);
        registry.Parameters.AddWithValue("history",history);
        await registry.ExecuteNonQueryAsync(ct);
    }

    // Receipt/inbox are the ingress trust boundary. Only synthetic native events
    // are seeded; none of the three retired tables participates in this fixture.
    internal static async Task<ShortEventRow[]> SeedAsync(NpgsqlConnection db, CancellationToken ct, bool powershell = false,
        DateTimeOffset? occurredAt = null, int[]? eventKinds = null, Guid? hostId = null,
        (Guid Agent, Guid Host, long Server, long Domain)? registered = null, string? nativeTimestamp = null,
        string[]? nativeTimestamps = null, string[]? nativeAccounts = null, string[]? nativeAddresses = null,
        Guid? packetId = null, int sequence = 1, int firstRecordId = 1, string hostName = "dc.example.test",
        IReadOnlyDictionary<string, string>? nativeFields = null, string? eventChannel = null,
        DateTimeOffset[]? allocatedAt = null, string[]? nativeTargetSids = null, bool history = false)
    {
        var agent = registered?.Agent ?? Agent; var host = registered?.Host ?? hostId ?? Agent;
        var packet = packetId ?? Packet;
        long server = registered?.Server ?? 900001, domain = registered?.Domain ?? 1;
        string channel = eventChannel ?? (powershell ? "Microsoft-Windows-PowerShell/Operational" : "Security");
        int[] kinds = eventKinds ?? (powershell ? [4104] : [1102,4624,4625]);
        var natives = new JsonArray();
        string stamp = nativeTimestamp ?? (occurredAt?.UtcDateTime ?? DateTime.UtcNow.AddMinutes(-3)).ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ",System.Globalization.CultureInfo.InvariantCulture);
        foreach (int kind in kinds) {
            if(nativeTimestamps is not null) stamp=nativeTimestamps[natives.Count];
            string provider = powershell ? "Microsoft-Windows-PowerShell" : channel=="System" ? "Service Control Manager"
                : kind is 1102 or 1104 ? "Microsoft-Windows-Eventlog" : "Microsoft-Windows-Security-Auditing";
            string fields = powershell ? "<Data Name='ScriptBlockText'>vssadmin delete shadows /all /quiet</Data>"
                : "<Data Name='TargetUserSid'>S-1-5-21-100000001-200000002-300000003-1001</Data><Data Name='TargetUserName'>synthetic-user</Data><Data Name='TargetDomainName'>example.test</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>192.0.2.1</Data>";
            if(eventKinds is not null) fields += kind switch {
                4625 => "<Data Name='Status'>0xc000006d</Data><Data Name='SubStatus'>0xc000006a</Data>",
                4776 => "<Data Name='Status'>0xc000006a</Data><Data Name='Workstation'>client.example.test</Data>",
                4769 => $"<Data Name='Status'>0x0</Data><Data Name='TicketEncryptionType'>0x17</Data><Data Name='ServiceName'>HTTP/service{natives.Count}.example.test</Data>",
                _ => ""
            };
            if(nativeAccounts is not null) fields=fields.Replace("synthetic-user",nativeAccounts[natives.Count]);
            if(nativeAddresses is not null) fields=fields.Replace("192.0.2.1",nativeAddresses[natives.Count]);
            if(nativeTargetSids is not null) fields=fields.Replace("S-1-5-21-100000001-200000002-300000003-1001",nativeTargetSids[natives.Count]);
            if (nativeFields is not null) {
                foreach (var (key, value) in nativeFields.OrderBy(pair => pair.Key, StringComparer.Ordinal))
                    fields += new XElement("Data", new XAttribute("Name", key), value).ToString(SaveOptions.DisableFormatting);
            }
            string payload = kind == 1104
                ? "<UserData><FileIsFull xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'/></UserData>"
                : $"<EventData>{fields}</EventData>";
            string xml = $"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='{provider}'/><EventID>{kind}</EventID><EventRecordID>{natives.Count+firstRecordId}</EventRecordID><TimeCreated SystemTime='{stamp}'/><Channel>{channel}</Channel><Computer>{hostName}</Computer></System>{payload}</Event>";
            natives.Add(EventXml.Parse(xml,hostName,hostName,channel));
        }
        string module = history ? "sli.windows.ad-dc-history" : "sli.windows.ad-dc";
        var envelope = new JsonObject { ["agent_id"]=agent.ToString(),["module_id"]=module,["source_instance_id"]=host.ToString(),["generation"]=host.ToString() };
        if (registered is null)
            await RegisterDcAsync(db, agent, host, server, domain, hostName, channel, ct, history: history);
        await using (var seed = new NpgsqlCommand("""
            insert into log_sources(name) values(@channel) on conflict do nothing;
            insert into storage_v2_channel(value) values(@channel) on conflict do nothing;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                values(@agent,@module,@sequence,@packet,@hash,@envelope,'{"status":"committed"}');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                values(@packet,@envelope,jsonb_build_object('contract','sli.collection-packet.v1','header',jsonb_build_object('channel',@channel,'source',@name)),@rows,now());
            """,db)) {
            seed.Parameters.AddWithValue("agent",agent); seed.Parameters.AddWithValue("packet",packet); seed.Parameters.AddWithValue("channel",channel);
            seed.Parameters.AddWithValue("name",hostName);
            seed.Parameters.AddWithValue("module",module);
            seed.Parameters.AddWithValue("sequence",sequence);
            seed.Parameters.AddWithValue("hash",Packets.Digest(envelope)); seed.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,envelope.ToJsonString());
            seed.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,natives.ToJsonString()); await seed.ExecuteNonQueryAsync(ct);
        }
        var result = new List<ShortEventRow>();
        foreach (var node in natives) {
            var native = node!.AsObject(); long id = 900000+native["record_id"]!.GetValue<long>();
            byte[] hash = Convert.FromHexString(DirectEventIdentity.Hash(native));
            await using var identity = new NpgsqlCommand("""
                insert into storage_v2_event_identity_allocations(id,server_id,channel_id,event_record_id,time_created_utc,normalized_hash,allocated_at)
                    select @id,@server,id,@record,@time,@hash,coalesce(@allocated,now()) from storage_v2_channel where value=@channel;
                insert into event_source_representations_v2(event_id,normalized_hash,identity_version,canonical_hash,representation,representation_sha256)
                    values(@id,@hash,2,@hash,@row,@digest);
                """,db);
            identity.Parameters.AddWithValue("id",id); identity.Parameters.AddWithValue("record",native["record_id"]!.GetValue<long>());
            identity.Parameters.AddWithValue("server",server);
            identity.Parameters.AddWithValue("time",DirectEventTime.Utc(native["time_created"]!.GetValue<string>()));
            identity.Parameters.AddWithValue("channel",channel); identity.Parameters.AddWithValue("hash",hash);
            identity.Parameters.AddWithValue("allocated",NpgsqlDbType.TimestampTz,(object?)allocatedAt?[result.Count] ?? DBNull.Value);
            identity.Parameters.AddWithValue("row",NpgsqlDbType.Jsonb,native.ToJsonString());
            identity.Parameters.AddWithValue("digest",SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(native))));
            await identity.ExecuteNonQueryAsync(ct);
            result.Add(ShortEventRow.Create(id,domain,native,Direct4624Projection.Create(native),server)! with { PacketId=packet,PacketOrdinal=result.Count });
        }
        return result.ToArray();
    }

    internal static async Task WriteAsync(SqlPostgresFixture fixture, IReadOnlyList<ShortEventRow> rows, CancellationToken ct)
    {
        await using var worker = new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await worker.OpenAsync(ct);
        await using var tx = await worker.BeginTransactionAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set local role adlog_storage_worker",ct);
        await ShortEventWriter.WriteAsync(worker,tx,rows,ct); await tx.CommitAsync(ct);
    }

    [Fact]
    public async Task Accepted_packet_is_attested_without_old_core_and_forged_origin_is_ignored()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        var rows = await SeedAsync(owner,ct);
        var method = JsonNode.Parse(rows[0].Method)!.AsObject(); method["$origin"]=new JsonObject { ["source_instance_id"]="forged" };
        rows[0]=rows[0] with { Method=method.ToJsonString() };
        await WriteAsync(fixture,rows,ct); await WriteAsync(fixture,rows,ct);
        await using (var read = new NpgsqlCommand("""
            select
                count(*),bool_and(source_sha256 is not null and method#>>'{$origin,source_instance_id}'=@source and event_record_id is not null)
                from event_hot
            """,owner)) {
            read.Parameters.AddWithValue("source",Agent.ToString()); await using var r=await read.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            Assert.Equal(rows.Length,r.GetInt64(0)); Assert.True(r.GetBoolean(1));
        }
        // The signed packet still proves admission when hot rows are recreated.
        await PostCollectionPostgres.Sql(owner,"delete from event_hot; delete from event_cold_facts; delete from event_cold_daily",ct);
        await WriteAsync(fixture,rows,ct);
        var forged = rows[0] with { PacketId=null };
        await PostCollectionPostgres.Sql(owner,"delete from event_hot; delete from event_cold_facts; delete from event_cold_daily",ct);
        await WriteAsync(fixture,[forged],ct);
        await using (var read = new NpgsqlCommand("select source_sha256 is null and method->'$origin' is null from event_hot",owner))
            Assert.Equal(true,await read.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Unaccepted_packet_cannot_attest_a_short_event()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        var accepted=await SeedAsync(owner,ct);
        foreach (string condition in new[] { "pending","quarantine","disabled","missing","wrong-event","wrong-envelope" }) {
            string? mutation=condition switch {
                "pending"=>"update sli_agent_packet_inbox set imported_at=null",
                "quarantine"=>"insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal) select packet_id,'source_event_allocation_hash_mismatch',0 from sli_agent_packet_inbox",
                "disabled"=>"update sli_agents set status='disabled'",
                "wrong-envelope"=>"update sli_agent_packet_inbox set envelope=envelope||'{\"generation\":\"forged\"}'",
                _=>null
            };
            if(mutation is not null) await PostCollectionPostgres.Sql(owner,mutation,ct);
            var rows=condition switch {
                "missing"=>accepted.Select(r=>r with { PacketId=Guid.NewGuid() }).ToArray(),
                "wrong-event"=>accepted.Select(r=>r with { PacketOrdinal=99 }).ToArray(),
                _=>accepted
            };
            var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>WriteAsync(fixture,rows,ct));
            Assert.Equal("short_event_attestation_failed",error.Message);
            await using(var read=new NpgsqlCommand("select (select count(*) from event_hot)+(select count(*) from event_cold_facts)+(select count(*) from event_cold_daily)",owner))
                Assert.Equal(0L,await read.ExecuteScalarAsync(ct));
            await PostCollectionPostgres.Sql(owner,"""
                delete from sli_agent_packet_quarantine;
                update sli_agents set status='active';
                update sli_agent_packet_inbox i set imported_at=now(),envelope=r.envelope from sli_agent_receipts r where i.packet_id=r.packet_id;
                """,ct);
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Database_at_previous_maximum_accepts_349_and_can_roll_back()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:348);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(owner,ct,source:1);
        await PostCollectionPostgres.Sql(owner,"""
            insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,source_core_sha256)
                select 41,id,'synthetic-state-user','Synthetic',sha256('synthetic'::bytea) from storage_v2_entity_type where value='ad_user';
            insert into entity_states(entity_id,state_type,severity,status,observed_at_utc,summary,evidence_event_id)
                values(41,'account.access','low','locked','2026-11-01T00:00:00Z','Synthetic',900011);
            insert into entity_state_current(entity_id,state_type,status,observed_at,source_event_db_id,rule_id,rule_version)
                values(41,'account.access','locked','2026-11-01T00:00:00Z',900011,'synthetic','1');
            """,ct);
        string path=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/349_short_event_packet_admission.sql");
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path,".rollback.sql"),null,ct);
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        await using (var retained=new NpgsqlCommand("select s.source_event_db_id=a.id from entity_state_current s join storage_v2_event_identity_allocations a on a.id=s.source_event_db_id where s.entity_id=41",owner))
            Assert.Equal(true,await retained.ExecuteScalarAsync(ct));
        await WriteAsync(fixture,await SeedAsync(owner,ct),ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}

