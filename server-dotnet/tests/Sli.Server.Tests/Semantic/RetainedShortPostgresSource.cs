using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Agents;

namespace Sli.Server.Tests.Semantic;

// Narrow selector/provenance fixtures own their schema. The admission test uses
// SqlPostgresFixture and an accepted packet against the complete installed schema.
internal static class RetainedShortPostgresSource
{
    internal static Task Create(NpgsqlConnection db, CancellationToken ct) => PostCollectionPostgres.Sql(db, """
        create table servers(id bigint primary key,domain_id bigint);
        create table storage_v2_channel(id integer primary key,value text);
        create table storage_v2_provider(id integer primary key,value text);
        create table storage_v2_keywords(id integer primary key,value text);
        create table storage_v2_computer(id integer primary key,value text);
        create table storage_v2_domain_name(id integer primary key,value text);
        create table event_hot(event_id bigint primary key,time_created_utc timestamptz,event_kind integer,domain_id bigint,
          actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb,source_sha256 bytea,event_record_id bigint);
        create table event_cold_facts(like event_hot including all);
        create table finding_event_copies337(like event_hot including defaults);
        insert into servers values(1,1);
        insert into storage_v2_channel values(1,'Security');
        insert into storage_v2_provider values(1,'Microsoft-Windows-Security-Auditing'),(2,'Microsoft-Windows-Eventlog'),(3,'synthetic-wrong-provider');
        insert into storage_v2_keywords values(1,'Audit Success'),(2,'Audit Failure');
        """, ct);

    internal static async Task Insert(NpgsqlConnection db, long id, string hash, CancellationToken ct,
        int kind = 4740, int provider = 1, int keywords = 1, string? sid = null, DateTimeOffset? time = null, NpgsqlTransaction? tx = null)
    {
        var method = new JsonObject { ["$server_id"] = 1, ["$channel"] = "Security",
            ["$provider"] = provider == 1 ? "Microsoft-Windows-Security-Auditing" : provider == 2 ? "Microsoft-Windows-Eventlog" : "synthetic-wrong-provider",
            ["$principals"] = new JsonObject { ["TargetUserSid"] = sid } };
        var outcome = new JsonObject { ["keywords"] = keywords == 1 ? "Audit Success" : "Audit Failure" };
        await using var command = new NpgsqlCommand("""
            insert into event_cold_facts(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields,source_sha256)
            values($1,$2,$3,1,'dc.example.test',$4,$5,'{}',$6)
            """, db, tx);
        Sli.Server.Semantic.SemanticSession.Parameters(command, [id, time ?? DateTimeOffset.UtcNow, kind, method, outcome, Convert.FromHexString(hash)]);
        await command.ExecuteNonQueryAsync(ct);
    }
}
