using System.Text.Json.Nodes;
using System.Xml.Linq;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Ad;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Direct;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

public sealed class PowerShellShortReadTests
{
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    private sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); await using var role = new NpgsqlCommand("set role adlog_user", db); await role.ExecuteNonQueryAsync(ct); return db; }
    }

    private static ShortEventRow Event(long id, int kind, DateTimeOffset at, string text = "synthetic", long domain = 1,
        long server = 7101, string sid = Sid)
    {
        bool power = kind is 4103 or 4104;
        string channel = power ? AdReportStore.PowerChannel : "Security";
        XNamespace ns = EventXml.Namespace;
        var fields = power ? new Dictionary<string,string> {
            [kind == 4104 ? "ScriptBlockText" : "Payload"] = text, ["CommandName"] = "Get-Synthetic" }
            : new Dictionary<string,string> { ["TargetUserSid"] = sid, ["LogonType"] = "10", ["IpAddress"] = "192.0.2.10" };
        var xml = new XElement(ns+"Event", new XElement(ns+"System",
            new XElement(ns+"Provider", new XAttribute("Name", power ? AdReportStore.PowerProvider : AdReportStore.SecurityProvider)),
            new XElement(ns+"EventID", kind), new XElement(ns+"EventRecordID", id),
            new XElement(ns+"TimeCreated", new XAttribute("SystemTime", at.ToString("O"))),
            new XElement(ns+"Channel", channel), new XElement(ns+"Computer", "dc01.example.test"),
            new XElement(ns+"Security", new XAttribute("UserID", sid))),
            new XElement(ns+"EventData", fields.Select(f => new XElement(ns+"Data", new XAttribute("Name", f.Key), f.Value))));
        var row = EventXml.Parse(xml.ToString(), "dc01.example.test", "dc01.example.test", channel);
        return ShortEventRow.Create(id, domain, row, Direct4624Projection.Create(row), server)!;
    }

    [Fact]
    public async Task Writer_report_and_daily_counts_work_without_legacy_events_sessions_or_ClickHouse()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            insert into forests(id,name) values(700001,'powershell.example.test');
            insert into domains(id,forest_id,fqdn) values(1,700001,'powershell.example.test'),(2,700001,'other.powershell.example.test') on conflict(id) do nothing;
            insert into servers(id,domain_id,hostname,role) values
              (7101,1,'dc01.example.test','domain_controller'),(7102,1,'dc02.example.test','domain_controller'),
              (7201,2,'dc01.example.test','domain_controller');
            """, ct);
        var boundary = EventReadService.ShortBoundary(null); var at = boundary.AddDays(2).AddHours(1);
        string text = "<synthetic>'; --" + new string('x', 1100);
        ShortEventRow[] rows = [Event(1,4104,at,text), Event(2,4103,at.AddMinutes(1),text),
            Event(3,4624,at.AddMinutes(-10)), Event(4,4624,at.AddMinutes(-1)),
            Event(5,4624,at,server:7102), Event(6,4624,at,domain:2,server:7201),
            Event(7,4624,at,sid:"S-1-5-21-100000001-200000002-300000003-1002"),
            Event(8,4104,boundary.AddDays(-2),text), Event(9,4104,boundary.AddDays(-2).AddHours(1),"different"),
            Event(10,4103,boundary.AddDays(-2),text),Event(11,4624,at.AddSeconds(20))];
        Assert.All(rows, r => Assert.NotNull(r));
        await using (var storage = new NpgsqlConnection(fixture.Dsn("sli_storage_login"))) {
            await storage.OpenAsync(ct); await using var tx = await storage.BeginTransactionAsync(ct);
            await PostCollectionPostgres.Sql(storage,"set local role adlog_storage_worker",ct);
            await ShortEventWriter.WriteAsync(storage,tx,rows,ct);
            await ShortEventWriter.WriteAsync(storage,tx,rows,ct); await tx.CommitAsync(ct);
        }
        var stored = await AdJson.ReadAsync(db,"select fields->>'ScriptBlockText' as text from event_hot where event_kind in (4103,4104)",ct);
        Assert.Contains(stored, r => r.Text("text") == text[..1024]);
        // Expired text is inaccessible even before the retention worker drops its partition.
        var connections = new Connections(fixture.Pg.ConnectionString);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["Sli:Storage:ShortEventReads"]="true", ["Sli:Storage:HistoryReadMode"]="primary" }).Build();
        var store = new AdReportStore(connections,null!,config);
        var request = new AdReportRequest("powershell",false,false,1,new(boundary.AddDays(-3),at.AddDays(1)),200,new(),null);
        Assert.True(await store.HasSourceAsync("powershell",1,ct));
        Assert.False(await store.HasSourceAsync("powershell",2,ct));
        var report = await store.ReadAsync(request,true,ct);
        Assert.Equal(2,report["items"]!.AsArray().Count);
        var script = report["items"]![0]!;
        Assert.Equal(text[..1024],script["activity"]!["script_block_text"]!.ToString());
        Assert.Equal(11,script["origin"]!["evidence"]!.Int("session_start_event_db_id"));
        Assert.Equal("nearest_logon",script["origin"]!.Text("basis"));
        Assert.Null(script["origin"]!["evidence"]!["session_end_event_db_id"]);
        Assert.Equal(3,report["daily_summaries"]!.AsArray().Sum(n => n.Int("event_count")));
        Assert.DoesNotContain("ScriptBlockText", report["daily_summaries"]!.ToJsonString());
        var restricted = await store.ReadAsync(request,false,ct);
        Assert.All(restricted["items"]!.AsArray(), item => Assert.Null(item!["activity"]!["script_block_text"]));
        Assert.DoesNotContain(text[..1024], restricted.ToJsonString());
        await using (var remove = new NpgsqlCommand("delete from event_hot where time_created_utc<@boundary",db)) {
            remove.Parameters.AddWithValue("boundary",boundary); await remove.ExecuteNonQueryAsync(ct);
        }
        Assert.True(JsonNode.DeepEquals(report,await store.ReadAsync(request,true,ct)));
        var historical = await store.ReadAsync(request with { Period=new(boundary.AddDays(-3),boundary) },true,ct);
        Assert.Empty(historical["items"]!.AsArray());
        Assert.Equal(3,Assert.Single(historical["daily_summaries"]!.AsArray()).Int("event_count"));
        Assert.Equal("available",historical.Text("state"));
        var legacyConfig = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["Sli:Storage:ShortEventReads"]="false", ["Sli:Storage:HistoryReadMode"]="disabled" }).Build();
        var legacyStore = new AdReportStore(connections,null!,legacyConfig);
        Assert.True(await legacyStore.HasSourceAsync("powershell",1,ct));
        Assert.True(JsonNode.DeepEquals(report,await legacyStore.ReadAsync(request,true,ct)));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
