using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Sli.Server.Ad;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

public sealed class AdComputerLogonActivityTests
{
    [Fact]
    public void Logons_accept_the_computers_domain_and_keep_the_exact_period_and_scope()
    {
        var request = new DefaultHttpContext().Request;
        request.QueryString = new("?domain=2&period=custom&from=2026-11-01T00:00:00Z&to=2026-11-08T00:00:00Z");
        var parsed = AdV2Endpoints.Parse(request, "ad.computer-logons", "view", [2, 3]);
        Assert.Equal(new long[] { 2 }, parsed.Domains);
        Assert.Equal(DateTimeOffset.Parse("2026-11-01T00:00:00Z"), parsed.Params["period"]!.Time("from_utc"));
        Assert.Equal(DateTimeOffset.Parse("2026-11-08T00:00:00Z"), parsed.Params["period"]!.Time("to_utc"));
        Assert.Throws<AdAccessException>(() => AdV2Endpoints.Parse(request, "ad.computer-logons", "view", [3]));
        request.QueryString = new("?domain=2&domain_id=3");
        Assert.Throws<AdInputException>(() => AdV2Endpoints.Parse(request, "ad.computer-logons", "view", [2, 3]));
    }

    [Fact]
    public async Task Stored_logons_count_at_the_destination_and_page_groups_within_the_granted_domain()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            create table servers (id bigint primary key, domain_id bigint, hostname text, fqdn text, role text);
            insert into servers values
                (9, 1, 'DC-TEST', 'dc-test.example.test', 'domain_controller'),
                (10, 2, 'DC-TEST', 'dc-test.example.test', 'domain_controller'),
                (11, 1, 'APP-TEST', 'app-test.example.test', 'member_server');
            create table event_hot (
                event_id bigint, time_created_utc timestamptz, event_kind int, domain_id bigint,
                computer text, method jsonb, fields jsonb, source_sha256 bytea
            ) partition by range(time_created_utc);
            create table event_hot_fixture partition of event_hot default;
            insert into event_hot
            select id, stamp::timestamptz, kind, domain, computer,
                   jsonb_build_object('$server_id', server, '$channel', 'Security', '$provider', 'Microsoft-Windows-Security-Auditing',
                       '$principals', jsonb_build_object('TargetUserName', account, 'TargetDomainName', 'EXAMPLE',
                           'WorkstationName', workstation, 'IpAddress', address)),
                   jsonb_build_object('LogonType', logon_type), decode(repeat('ab', 32), 'hex')
            from (values
                (101, '2026-11-01T10:00:00Z', 4624, 1, 9, 'DC-TEST', 'alice', 'CLIENT-TEST', '192.0.2.22', '10'),
                (102, '2026-11-01T11:00:00.123456Z', 4624, 1, 9, 'dc-test', 'Alice', 'client-test', '192.0.2.22', '10'),
                (103, '2026-11-01T11:00:00.123456Z', 4624, 1, 9, 'dc-test', 'Alice', 'client-test', '192.0.2.22', '10'),
                (104, '2026-11-01T11:00:00.123456Z', 4624, 1, 9, 'DC-TEST', 'alice', 'CLIENT-TEST', '192.0.2.23', '10'),
                (105, '2026-11-01T12:00:00Z', 4624, 1, 9, 'DC-TEST', 'client$', 'CLIENT-TEST', '192.0.2.22', '3'),
                (106, '2026-11-01T13:00:00Z', 4624, 1, 9, 'DC-TEST', 'ANONYMOUS LOGON', '-', '-', '3'),
                (107, '2026-11-01T14:00:00Z', 4624, 1, 9, 'DC-TEST', 'local', '-', '::1', '3'),
                (108, '2026-11-01T15:00:00Z', 4625, 1, 9, 'DC-TEST', 'alice', 'CLIENT-TEST', '192.0.2.22', '3'),
                (109, '2026-11-01T16:00:00Z', 4624, 2, 10, 'DC-TEST', 'other-domain', '-', '-', '2'),
                (110, '2026-11-04T00:00:00Z', 4624, 1, 9, 'DC-TEST', 'outside-window', '-', '-', '2'),
                (111, '2026-11-01T15:00:00Z', 4624, 1, 9, 'DC-TEST', 'alice', '-', '-', '4'),
                (112, '2026-11-01T15:00:00Z', 4624, 1, 9, 'DC-TEST', 'alice', '-', '-', '5'),
                (113, '2026-11-01T15:00:00Z', 4624, 1, 9, 'DC-TEST', 'alice', '-', '-', '9'),
                (114, '2026-11-01T15:00:00Z', 4624, 1, 9, 'DC-TEST', 'NT AUTHORITY\SYSTEM', '-', '-', '2'),
                (115, '2026-11-01T15:00:00Z', 4624, 1, 9, 'DC-TEST', 'Local Service', '-', '-', '7'),
                (116, '2026-11-01T15:00:00Z', 4624, 1, 9, 'DC-TEST', 'Network Service', '-', '-', '11'),
                (117, '2026-11-01T15:00:00Z', 4624, 1, 9, 'DC-TEST', 'VIRTUAL USERS\sshd_test', '-', '-', '2'),
                (118, '2026-11-01T15:00:00Z', 4624, 1, 9, 'DC-TEST', 'Window Manager\DWM-1', '-', '-', '2'),
                (119, '2026-11-01T15:00:00Z', 4624, 1, 9, 'DC-TEST', 'Font Driver Host\UMFD-1', '-', '-', '2'),
                (120, '2026-11-01T15:00:00Z', 4624, 1, 9, 'DC-TEST', 'client$', '-', '-', '2'),
                (121, '2026-11-01T10:00:00Z', 4624, 1, 9, 'app-test.example.test', 'alice', '-', '::1', '2'),
                (122, '2026-11-01T10:00:00Z', 4624, 1, 9, 'app-test.example.test', 'alice', '-', '-', '7'),
                (123, '2026-11-01T10:00:00Z', 4624, 1, 9, 'app-test.example.test', 'alice', '-', '-', '11'),
                (124, '2026-11-01T14:00:00Z', 4624, 1, 9, 'DC-TEST', 'alice', '-', '192.0.2.22', '3'),
                (125, '2026-11-01T14:00:00Z', 4624, 1, 9, 'DC-TEST', 'alice', '-', '-', null)
            ) as fixture(id, stamp, kind, domain, server, computer, account, workstation, address, logon_type);
            update event_hot
            set method=jsonb_set(jsonb_set(method, '{$principals,TargetDomainName}', '"vIrTuAl UsErS"'),
                                 '{$principals,TargetUserName}', '"sshd_test"')
            where event_id=117;
            """, ct);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sli"] = pg.ConnectionString
        }).Build();
        var store = new AdV2Store(new PostgresConnectionFactory(config), config);
        var request = new AdV2Request("ad.computer-logons", "view", null, [1],
            Obj(new { period = new { from_utc = "2026-11-01T00:00:00Z", to_utc = "2026-11-04T00:00:00Z" } }),
            "table", null, false, 25, null, "UTC");
        Task<JsonObject> Read(AdV2Request input) => store.ReadAsync(input, _ => true, ct);
        var result = await Read(request);
        var computers = result["items"]!.AsArray();
        Assert.Equal(2, computers.Count);
        var computer = computers[1];
        Assert.Equal("DC-TEST", computer.Text("display_name"), ignoreCase: true);
        Assert.Equal("domain_controller", computer.Text("computer_type"));
        Assert.Equal("server", computers[0].Text("computer_type"));
        Assert.Equal(3, computers[0].Int("login_count"));
        Assert.Equal(4, computer.Int("login_count"));
        Assert.Equal("2026-11-01T11:00:00.123456Z", computer.Text("last_observed_logon_at_utc"));

        var detail = request with { Action = "detail", Row = computer.Text("computer_key"), Limit = 1 };
        var first = await Read(detail);
        var differentSource = Assert.Single(first["items"]!.AsArray());
        Assert.Equal("192.0.2.23", differentSource.Text("ip_address"));
        var second = await Read(detail with { Cursor = first.Text("next_cursor") });
        var repeated = Assert.Single(second["items"]!.AsArray());
        Assert.Equal("EXAMPLE\\Alice", repeated.Text("user_name"));
        Assert.Equal("10", repeated.Text("logon_type"));
        Assert.Equal("CLIENT-TEST", repeated.Text("workstation_name"), ignoreCase: true);
        Assert.Equal("2026-11-01T11:00:00.123456Z", repeated.Text("observed_at_utc"));
        Assert.Equal(103, repeated.Int("source_event_id"));
        Assert.Equal(3, repeated.Int("repeat_count"));
        Assert.Null(second.Text("next_cursor"));

        var service = (JsonObject)request.Params.DeepClone();
        service["service_logons"] = "yes";
        var included = await Read(request with { Params = service });
        var includedCount = included["items"]!.AsArray()[1].Int("login_count");
        Assert.Equal(19, includedCount);
        var includedDetail = await Read(detail with { Params = service, Limit = 25 });
        Assert.Equal(includedCount, includedDetail["items"]!.AsArray().Sum(item => item.Int("repeat_count")));
        var missing = (JsonObject)request.Params.DeepClone();
        missing["user"] = "missing-fixture-user";
        var empty = await Read(request with { Params = missing });
        Assert.Equal("empty", empty.Text("state"));
        Assert.Empty(empty["items"]!.AsArray());
        await Assert.ThrowsAsync<KeyNotFoundException>(() => Read(detail with { Domains = [2] }));
        await Assert.ThrowsAsync<AdInputException>(() => Read(detail with { Cursor = first.Text("next_cursor"), Params = service }));
    }

    [Fact]
    public async Task Activity_totals_use_all_matching_observations_across_detail_pages_and_local_days()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint, fqdn text);
            insert into domains values (1, 'example.test');
            create table ad_snapshot_manifests(manifest_id uuid, domain_id bigint, coverage_state text, slot_start_utc timestamptz);
            create table ad_snapshot_manifest_sources(manifest_id uuid, source_state text, observed_at_utc timestamptz, family text, source_id text, payload_sha256 bytea);
            create table users_report_v2_snapshots(snapshot_id uuid, domain_id bigint, payload_sha256 bytea, payload_json jsonb, scope_json jsonb);
            create table what_where_when_projection_state(singleton boolean, backfill_completed boolean, last_cycle_at_utc timestamptz);
            insert into what_where_when_projection_state values (true, true, now());
            create table what_where_when_observations(projection_id bigint, source_event_id bigint, computer_object_guid uuid, user_name text, observed_at_utc timestamptz);
            insert into what_where_when_observations values
                (1, 101, '00000000-0000-0000-0000-000000000001', 'synthetic-user', '2026-11-01T16:59:00Z'),
                (2, 102, '00000000-0000-0000-0000-000000000001', 'Synthetic-User', '2026-11-01T17:00:00Z'),
                (3, 104, '00000000-0000-0000-0000-000000000001', 'synthetic-user', '2026-11-01T18:00:00Z'),
                (4, 104, '00000000-0000-0000-0000-000000000001', 'other-user', '2026-11-01T19:00:00Z'),
                (5, 105, '00000000-0000-0000-0000-000000000002', 'synthetic-user', '2026-11-01T20:00:00Z'),
                (6, 106, '00000000-0000-0000-0000-000000000001', 'synthetic-user', '2026-11-04T00:00:00Z');
            """, ct);
        var source = JsonNode.Parse("""
            {
              "domain_id": 1, "fqdn": "example.test", "source_state": "complete", "observed_at_utc": "2026-11-03T00:00:00Z",
              "entity_ids": { "00000000-0000-0000-0000-000000000001": 7, "00000000-0000-0000-0000-000000000002": 8 },
              "snapshot": {
                "metadata": {},
                "objects": [
                  { "objectGuid": "00000000-0000-0000-0000-000000000001", "name": "PC-01", "osName": "Windows 11" },
                  { "objectGuid": "00000000-0000-0000-0000-000000000002", "name": "PC-02", "osName": "Windows 11" }
                ]
              }
            }
            """)!.AsObject();
        var input = new AdV2Request("ad.computer-logons", "detail", "7", [1],
            Obj(new { period = new { from_utc = "2026-11-01T00:00:00Z", to_utc = "2026-11-04T00:00:00Z" } }),
            "table", null, false, 1, null, "Asia/Bangkok");
        var first = await AdLogonReports.ReadAsync(db, input, [source], ct);
        var summary = first["computer_logon_activity"]!;
        var firstObservation = Assert.Single(first["items"]!.AsArray())!.AsObject();
        Assert.Equal("4", firstObservation.Text("row_id"));
        Assert.Equal(104, firstObservation.Int("source_event_id"));
        Assert.False(firstObservation.ContainsKey("projection_id"));
        Assert.Equal(4, summary.Int("total"));
        Assert.Equal(2m, summary["typical"]!.GetValue<decimal>());
        Assert.Equal(3, summary["top"].Int("count"));
        Assert.Equal("synthetic-user", summary["top"].Text("account"), ignoreCase: true);
        Assert.Collection(summary["days"]!.AsArray(),
            day => { Assert.Equal("2026-11-01", day.Text("day")); Assert.Equal(1, day.Int("count")); },
            day => { Assert.Equal("2026-11-02", day.Text("day")); Assert.Equal(3, day.Int("count")); });

        var second = await AdLogonReports.ReadAsync(db, input with { Cursor = first.Text("next_cursor") }, [source], ct);
        var secondObservation = Assert.Single(second["items"]!.AsArray())!.AsObject();
        Assert.Equal("3", secondObservation.Text("row_id"));
        Assert.Equal(firstObservation.Int("source_event_id"), secondObservation.Int("source_event_id"));
        Assert.False(secondObservation.ContainsKey("projection_id"));
        var filtered = (JsonObject)input.Params.DeepClone();
        filtered["user"] = "other-user";
        var onlyOther = await AdLogonReports.ReadAsync(db, input with { Params = filtered }, [source], ct);
        Assert.Equal(1, onlyOther["computer_logon_activity"].Int("total"));
        Assert.Equal("other-user", onlyOther["computer_logon_activity"]?["top"].Text("account"));
    }
}
