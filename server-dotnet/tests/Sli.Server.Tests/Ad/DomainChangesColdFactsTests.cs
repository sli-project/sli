using System.Text.Json.Nodes;
using System.Xml.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting.V2;
using Sli.Server.Storage.Direct;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class DomainChangesColdFactsTests
{
    private const string Actor = "S-1-5-21-100000001-200000002-300000003-1001";
    private const string Target = "S-1-5-21-100000001-200000002-300000003-1002";
    private const string Member = "S-1-5-21-100000001-200000002-300000003-1003";
    private static readonly AdPeriod Period = new(DateTimeOffset.Parse("2025-11-16T00:00:00Z"), DateTimeOffset.Parse("2026-11-16T00:00:00Z"));
    private static readonly IConfiguration Legacy = new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string, string?> { ["Sli:Storage:ShortEventReads"] = "false" }).Build();
    private static AdReportRequest Request(string kind = "security", int limit = 200, string? cursor = null, JsonObject? filters = null) =>
        new(kind, false, false, 7, Period, limit, filters ?? new(), cursor);

    private sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }

    private sealed class Details(Dictionary<long,JsonObject> native) : IEventReadService
    {
        internal int Calls;
        public Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<AccessResource>>([new("domain",7)]);
        public async Task<Dictionary<long,JsonObject>> DetailsAsync(long[] ids, bool exact,
            Func<long,CancellationToken,Task<bool>> admitted, CancellationToken ct)
        {
            Calls++;
            var result = new Dictionary<long,JsonObject>();
            foreach(long id in ids) if(await admitted(id,ct)) result[id] = new() { ["event_data"] = native[id].DeepClone() };
            return result;
        }
        public Task<JsonObject> RelationsAsync(long id, Func<long,CancellationToken,Task<bool>> admitted, CancellationToken ct) =>
            throw new NotSupportedException();
    }

    [Fact]
    public void Domain_changes_accept_a_year_in_the_public_request()
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/reports/ad.state/security-events";
        context.Request.QueryString = new QueryString("?domain_id=7&time_from=2025-11-16T00:00:00Z&time_to=2026-11-16T00:00:00Z");
        Assert.Equal(Period, AdReportEndpoints.Parse(context.Request).Period);
        var definition = new ReportDefinitionRegistry().Get("security.events.chains")!;
        var (parameters, _) = ReportParameters.Parse(definition, new QueryCollection(new Dictionary<string,StringValues> {
            ["period"] = "custom", ["from"] = "2025-11-16T00:00:00Z", ["to"] = "2026-11-16T00:00:00Z"
        }));
        Assert.Equal("2025-11-16T00:00:00Z", parameters["period"]!["from_utc"]!.ToString());
        Assert.Equal("2026-11-16T00:00:00Z", parameters["period"]!["to_utc"]!.ToString());
    }

    [Fact]
    public async Task Compact_facts_survive_hot_and_legacy_removal_with_fields_filters_and_cursor()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            create role adlog_storage_owner; create role adlog_storage_worker; create role adlog_user; create role adlog_storage_lifecycle_worker;
            grant adlog_storage_owner to postgres;
            grant create on schema public to adlog_storage_owner;
            create table schema_migrations(version integer primary key,name text);
            insert into schema_migrations values(334,'account_decoy_restore');
            grant select,insert on schema_migrations to adlog_storage_owner;
            create table servers(id bigint primary key,domain_id bigint,hostname text,role text);
            create table storage_v2_channel(id bigint primary key,value text);
            create table storage_v2_provider(id bigint primary key,value text);
            create table storage_v2_keywords(id bigint primary key,value text);
            create table events_v2_core(id bigint primary key,domain_id bigint,server_id bigint,channel_id bigint,provider_id bigint,keywords_id bigint,event_record_id bigint,event_id integer,time_created_utc timestamptz,subject_user_sid text,subject_user_name text,target_user_sid text,target_user_name text,source_core_sha256 bytea,ip_address text,workstation_name text);
            create table event_facts_v2(event_id bigint primary key,account_target_sid text,account_target_name text,membership_member_sid text,membership_member_name text,account_name_before text,account_name_after text,result_code text,source_facts_sha256 bytea);
            create table entities_v2(id bigint primary key,domain_id bigint);
            create table ad_context_entity_aliases(domain_id bigint,entity_id bigint,alias_type text,normalized_value text);
            create function entity_v2_is_active(bigint) returns boolean language sql immutable as $$select true$$;
            create table semantic_processing_outbox(source_event_id bigint,job_kind text,status text);
            create table ad_context_entity_versions(entity_id bigint,source_run_id text,source_section text,valid_to_utc timestamptz,last_observed_at_utc timestamptz,attributes_json jsonb);
            create table ad_context_runs(run_id text,status text,scope_json jsonb);
            create table ad_context_evidence(id bigint,source_run_id text,locator_json jsonb);
            insert into servers values(1,7,'dc01.example.test','domain_controller'),(2,8,'dc01.example.test','domain_controller'),(3,7,'member.example.test','member');
            insert into storage_v2_channel values(1,'Security');
            insert into storage_v2_provider values(1,'Microsoft-Windows-Security-Auditing');
            insert into storage_v2_keywords values(1,'AuditSuccess');
            """, ct);
        await pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/335_event_storage_s2.sql"), null, ct);
        var rows = new List<ShortEventRow>(); var nativeData = new Dictionary<long,JsonObject>();
        foreach (var (id, code) in new[] { (1L,4722),(2L,4781),(3L,4728),(4L,4719) })
        {
            var data = new Dictionary<string,string> { ["SubjectUserSid"] = Actor, ["TargetSid"] = Target,
                ["SubjectUserName"] = "operator", ["TargetUserName"] = "affected" };
            if(code == 4728) { data["MemberSid"] = Member; data["MemberName"] = "CN=Alice,DC=example,DC=test"; }
            if(code == 4781) { data["OldTargetUserName"] = "before"; data["NewTargetUserName"] = "after"; }
            if(code == 4719) { data["CategoryId"] = "synthetic-category"; data["SubcategoryGuid"] = "synthetic-subcategory"; data["AuditPolicyChanges"] = "synthetic-change"; }
            XNamespace ns = EventXml.Namespace;
            string time = AdJson.Iso(Period.Start.AddDays(id * 80));
            var xml = new XElement(ns + "Event", new XElement(ns + "System",
                new XElement(ns + "Provider", new XAttribute("Name", AdReportStore.SecurityProvider)),
                new XElement(ns + "EventID", code), new XElement(ns + "EventRecordID", id), new XElement(ns + "Keywords", "0x8020000000000000"),
                new XElement(ns + "TimeCreated", new XAttribute("SystemTime", time)),
                new XElement(ns + "Channel", "Security"), new XElement(ns + "Computer", "dc01.example.test")),
                new XElement(ns + "EventData", data.Select(p => new XElement(ns + "Data", new XAttribute("Name", p.Key), p.Value))));
            var native = EventXml.Parse(xml.ToString(), "dc01.example.test", "dc01.example.test", "Security");
            nativeData[id] = System.Text.Json.JsonSerializer.SerializeToNode(data)!.AsObject();
            rows.Add(ShortEventRow.Create(id, 7, native, Direct4624Projection.Create(native),1)!);

        }
        await SeedCompact(db,[..rows, rows[0] with { EventId = 10, DomainId = 8 }, rows[0] with { EventId = 11, Method = new JsonObject { ["$server_id"] = 3, ["$channel"] = "Security", ["$provider"] = AdReportStore.SecurityProvider }.ToJsonString() }],ct);
        var connections = new Connections(pg.ConnectionString);
        var details = new Details(nativeData);
        var old = new AdReportStore(connections, details, Legacy);
        var current = new AdReportStore(connections, details);
        foreach (string kind in new[] { "account", "membership","security" }) {
            var expected = await old.ReadAsync(Request(kind), false, ct);
            var actual = await current.ReadAsync(Request(kind), false, ct);
            Assert.True(JsonNode.DeepEquals(expected,actual));
            Assert.NotEmpty(actual["items"]!.AsArray());
            Assert.All(actual["items"]!.AsArray(),item=>Assert.Null(item!["event_record_id"]));
            string name = kind == "account" ? "subject_user_name" : "name";
            Assert.Null(actual["items"]![0]!["actor"]![name]);
        }
        Assert.Equal(0,details.Calls);
        Assert.True(await current.HasSourceAsync("account", 7, ct));
        await PostCollectionPostgres.Sql(db, "delete from event_hot; drop table events_v2_core,event_facts_v2,storage_v2_channel,storage_v2_provider,storage_v2_keywords", ct);
        var page = await current.ReadAsync(Request(limit: 2), false, ct);
        Assert.Equal(new long[] { 4,3 }, page["items"]!.AsArray().Select(r => r!["event_db_id"]!.GetValue<long>()));
        Assert.Equal("synthetic-change", page["items"]![0]!["change"]!["observed_value"]!.ToString());
        string cursor = page["next_cursor"]!.ToString();
        var next = await current.ReadAsync(Request(limit: 2, cursor: cursor), false, ct);
        Assert.Equal(new long[] { 2,1 }, next["items"]!.AsArray().Select(r => r!["event_db_id"]!.GetValue<long>()));
        Assert.Equal("before", next["items"]![0]!["account_change"]!["observed_transition"]!["before"]!["value"]!.ToString());
        var filtered = await current.ReadAsync(Request(filters: new JsonObject { ["group"] = Target, ["q"] = "Alice" }), false, ct);
        Assert.Equal(3, Assert.Single(filtered["items"]!.AsArray())!["event_db_id"]!.GetValue<long>());
        Assert.True(await current.HasSourceAsync("membership", 7, ct));
        Assert.False(await current.HasSourceAsync("account", 99, ct));
        var query = AdSecurityQuery.Create(Request(), useColdFacts:true);
        var daily = await AdJson.ReadAsync(db, query.DailySql, ct, query.DailyArgs.Concat(new object?[] { "Asia/Bangkok" }).ToArray());
        Assert.Equal(4, daily.Sum(r => AdJson.Int(r,"count")));
        Assert.Equal("retained_match_present", (await query.CategoriesAsync(db,ct))["group_membership"]!["state"]!.ToString());
        Assert.Equal("no_retained_match", (await query.CategoriesAsync(db,ct))["authentication"]!["state"]!.ToString());
        Assert.Equal(0,details.Calls);
        // Record the S2 admission boundary without weakening it for this reader.
        // A separately numbered migration is required before API-role rollout.
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(db,"set local role adlog_user",ct);
            var denied = await Assert.ThrowsAsync<PostgresException>(() => AdJson.ReadAsync(db, "select event_id from event_cold_facts limit 1", ct));
            Assert.Equal("42501",denied.SqlState);
            await tx.RollbackAsync(ct);
        }
    }
    static async Task SeedCompact(NpgsqlConnection db,IEnumerable<ShortEventRow> rows,CancellationToken ct)
    {
        foreach(var row in rows) {
            await using(var partition=new NpgsqlCommand("select public.create_event_storage_partitions($1::date,$1::date)",db)) {
                partition.Parameters.AddWithValue(DateOnly.FromDateTime(row.Time));await partition.ExecuteNonQueryAsync(ct);
            }
            await using var insert=new NpgsqlCommand("""
                insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
                values($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb);
                """,db);
            foreach(object? value in new object?[]{row.EventId,row.Time,row.Kind,row.DomainId,row.Actor,row.Target,row.Source,row.Computer,row.Method,row.Outcome,System.Text.Json.JsonSerializer.Serialize(row.Fields)})
                insert.Parameters.Add(new(){Value=value??DBNull.Value});
            await insert.ExecuteNonQueryAsync(ct);
            if(row.Layer=="fact") {
                await using var fact=new NpgsqlCommand("insert into event_cold_facts select * from event_hot where event_id=$1 and time_created_utc=$2",db);
                fact.Parameters.AddWithValue(row.EventId);fact.Parameters.AddWithValue(row.Time);await fact.ExecuteNonQueryAsync(ct);
            }
        }
        await PostCollectionPostgres.Sql(db,"""
            insert into event_cold_daily
            select (time_created_utc at time zone 'UTC')::date,sha256(convert_to(jsonb_build_array(event_kind,domain_id,actor,target,source,computer,method,outcome)::text,'UTF8')),
                event_kind,domain_id,actor,target,source,computer,method,outcome,count(*),min(time_created_utc),max(time_created_utc)
            from event_hot where event_kind in(4624,4625,4771,4776)
            group by 1,event_kind,domain_id,actor,target,source,computer,method,outcome
            """,ct);
    }

}
