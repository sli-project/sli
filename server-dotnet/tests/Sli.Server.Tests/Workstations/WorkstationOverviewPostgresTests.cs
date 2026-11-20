using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

// Port of tests/reporting/test_workstation_overview_postgres.py. The fixture owns
// its temporary cluster and runs the retained reader with real schema and runtime grants.
public sealed class WorkstationOverviewPostgresTests
{
    const string Key = "workstations.overview";
    const string Agent = "00000000-0000-4000-8000-000000000001";
    const string HostId = "00000000-0000-4000-9000-000000000001";
    const string Prefix = "synthetic-ws-overview";
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    const string Xml = "<Event>synthetic-workstation-evidence</Event>";
    static readonly string[] Stations = Enumerable.Range(0, 14)
        .Select(n => n == 0 ? "ws:agent:" + Agent : "ws:ad:" + (1000 + n)).ToArray();
    static readonly string FindingId = new('a', 64);
    static readonly string ObservationId = new('b', 64);

    static AccessFacts CreateFacts(bool domain11Only = false, bool denyAgent = false)
    {
        JsonElement Json(object value) => JsonSerializer.SerializeToElement(value);
        object[] scopes = domain11Only
            ? [new { kind = "domain", ids = new[] { 11 } }]
            : [new { kind = "domain", ids = new[] { 11, 22 } }, new { kind = "agent", ids = new[] { Agent } }];
        var capabilities = WorkstationReportContract.Fields.Select(f => "field." + f).Append("workstations.read")
            .Select(c => Json(new { capability_key = c, effect = "allow", scope_json = new { kind = "all" } })).ToList();
        if (denyAgent) capabilities.Add(Json(new { capability_key = "workstations.read", effect = "deny", scope_json = new { kind = "agent", ids = new[] { Agent } } }));
        return new(false, "viewer", [], [], capabilities, [], [],
            scopes.Select(scope => Json(new { report_key = Key, effect = "allow", scope_json = scope,
                field_categories = WorkstationReportContract.Fields, allowed_actions = new[] { "view" } })).ToArray(),
            [Json(new { report_key = Key, version = 1, dataset_version = 1,
                fields_json = WorkstationReportContract.Fields.Select(f => new { category = f }), actions_json = new[] { "view" },
                definition_json = new { field_categories = WorkstationReportContract.Fields, actions = new[] { "view" } } })]);
    }

    static string Search(string term = Prefix, int domain = 11, int limit = 5) =>
        "?search=" + Uri.EscapeDataString(term) + "&domain=" + domain + "&limit=" + limit;
    static string[] Ids(JsonNode body) => body["items"]!.AsArray().Select(row => row!["station_id"]!.GetValue<string>()).ToArray();
    static void Equal(string expected, JsonNode? actual) => Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected), actual),
        "Expected: " + expected + "\nActual: " + actual);
    [Fact]
    public async Task Runtime_role_preserves_unknown_counts_scoped_pages_cards_search_devices_and_exact_evidence()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        var facts = CreateFacts();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
        }).Build();
        var reportReader = new WorkstationReports(new PostgresConnectionFactory(config), config);
        async Task<JsonObject> Read(string query, string? station = null)
        {
            var readAccess = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
            WorkstationReportContract.Admit(readAccess, Key);
            var readRequest = WorkstationReportContract.Parse(Key, new QueryCollection(QueryHelpers.ParseQuery(query)), station);
            return await reportReader.ReadAsync(readRequest, facts, readAccess, ct);
        }
        async Task<WorkstationException> Denied(string query, string station)
        {
            var error = await Assert.ThrowsAsync<WorkstationException>(() => Read(query, station));
            Assert.Equal(403, error.Status);
            return error;
        }

        // A missing inventory cannot establish even a filtered zero.
        foreach (string check in new[] { "", "&check_id=C05" })
        {
            var pending = await Read("?domain=11&limit=50" + check);
            Assert.Empty(pending["items"]!.AsArray()); Assert.Null(pending["filtered_count"]);
            Assert.Equal("inventory_pending", pending["coverage"]!.Text("population_status"));
            var metrics = pending["metrics"]!.AsArray(); Assert.Equal(2, metrics.Count);
            Assert.All(metrics, metric => { Assert.Null(metric!["value"]); Assert.Equal("unknown", metric.Text("quality")); });
        }

        await Seed(fixture, ct);

        var initialRequest = WorkstationReportContract.Parse(Key,
            new QueryCollection(Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(Search())));
        var first = await Read(Search());
        Assert.Equal(13, first.Number("filtered_count"));
        Assert.Equal(12, first["metrics"]![1].Number("value")); // C04+C05 count once per station.
        Assert.Equal(10, first["collections"]!["checks"]!.AsArray().Count);
        Equal("""{"value":null,"relation":"unknown"}""", first["collections"]!["checks"]![2]!["counts"]!["stations"]);
        Assert.Equal(Stations.Take(13).Order(StringComparer.Ordinal).Take(5), Ids(first));
        Equal("""[{"start":1,"has_previous":false,"previous_cursor":null}]""", first["collections"]!["paging"]);
        Assert.All(first["items"]!.AsArray(), row => Assert.IsType<JsonObject>(row!["devices"]));
        Assert.True(first["has_more"]!.GetValue<bool>());
        Assert.Equal(Ids(first)[^1], first.Text("next_cursor"));

        foreach (string station in new[] { Stations[0], Stations[12] })
        {
            var card = await Read(Search(), station);
            Assert.Equal(station, Assert.Single(Ids(card))); Assert.IsType<JsonArray>(card["collections"]!["findings"]);
        }
        var denied = await Denied(Search(), Stations[13]);
        Assert.Equal("workstation_access_denied", denied.Message);

        // Account and IP are searchable; SID is not. SQL wildcards remain literal.
        string account = Search("EXAMPLE\\" + Prefix + "-user_%", limit: 1);
        var accountPage = await Read(account);
        Assert.Equal(2, accountPage.Number("filtered_count")); Assert.Equal(new[] { Stations[1] }, Ids(accountPage));
        Assert.True(accountPage["has_more"]!.GetValue<bool>());
        Assert.Equal(Stations[1], accountPage.Text("next_cursor"));
        var next = await Read(account + "&cursor=" + Uri.EscapeDataString(accountPage.Text("next_cursor")!));
        Assert.Equal(2, next.Number("filtered_count")); Assert.Equal(new[] { Stations[2] }, Ids(next));
        Assert.Equal(2, next["collections"]!["paging"]![0].Number("start"));
        Assert.False(next["has_more"]!.GetValue<bool>()); Assert.Null(next["next_cursor"]);
        foreach (var (term, expected) in new[] { ("192.0.2.77", new[] { Stations[1] }), (Prefix + "-userX%", Array.Empty<string>()), (Sid, Array.Empty<string>()) })
        {
            var found = await Read(Search(term));
            Assert.Equal(expected.Length, found.Number("filtered_count")); Assert.Equal(expected, Ids(found));
        }
        Assert.Equal(Stations[1], Assert.Single(Ids(await Read(account, Stations[1]))));
        await Denied(account, Stations[13]);
        facts = CreateFacts(domain11Only: true);
        var hidden = await Read(Search("EXAMPLE\\" + Prefix + "-user_%", domain: 22));
        Assert.Equal(0, hidden.Number("filtered_count")); Assert.Empty(Ids(hidden));
        facts = CreateFacts();

        var devices = (await Read(Search(), Stations[1]))["items"]![0]!["devices"]!;
        Equal("""{"value":1,"relation":"at_least"}""", devices["devices_7d"]);
        Assert.Equal("unknown", devices.Text("baseline_status")); Assert.Equal("partial", devices["quality"].Text("status"));
        var noDevices = (await Read(Search(), Stations[2]))["items"]![0]!["devices"]!;
        Equal("""{"value":null,"relation":"unknown"}""", noDevices["devices_7d"]);
        Assert.Contains(accountPage["items"]![0]!["devices"]!["devices_7d"].Text("relation"), new[] { "at_least", "unknown" });

        var finding = (await Read(Search(), Stations[0]))["collections"]!["findings"]!.AsArray().Single(f => f.Text("check_id") == "C04")!;
        Equal("""{"path":"C:\\Windows\\Temp\\synthetic.exe","process_id":"17","signature_status":"not_received","current_state":"unknown"}""", finding["process_details"]);
        Assert.Null(finding["subject_ref"]); Assert.DoesNotContain("PRIVATE-COMMAND", finding.ToJsonString());

        string[] checkIds = Stations.Take(12).Order(StringComparer.Ordinal).ToArray();
        string checkQuery = Search() + "&check_id=C05&cursor=";
        var third = await Read(checkQuery + Uri.EscapeDataString(checkIds[9]));
        Assert.Equal(12, third.Number("filtered_count")); Assert.Equal(checkIds[10..12], Ids(third));
        var paging = third["collections"]!["paging"]![0]!;
        Assert.Equal(11, paging.Number("start")); Assert.True(paging["has_previous"]!.GetValue<bool>());
        Assert.Equal(checkIds[4], paging.Text("previous_cursor"));
        var previous = await Read(checkQuery + Uri.EscapeDataString(paging.Text("previous_cursor")!));
        Assert.Equal(checkIds[5..10], Ids(previous));
        Equal("""[{"start":6,"has_previous":true,"previous_cursor":null}]""", previous["collections"]!["paging"]);

        string source = Search() + "&finding_id=" + FindingId + "&evidence_index=1";
        var evidence = Assert.Single((await Read(source, Stations[0]))["items"]!.AsArray())!;
        Assert.Equal(Xml, evidence.Text("source_xml")); Assert.Equal(Ws.Sha(Xml), evidence.Text("source_sha256"));
        await Denied(source, Stations[1]);
        facts = CreateFacts(denyAgent: true);
        await Denied(source, Stations[0]);

        // The reference's already-composed policy is valid and agent-scoped.
        // Exercise that policy as well as the denies from the composed access decision.
        var access = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        access = access with { Capabilities = access.Capabilities with {
            Policies = access.Capabilities.Policies.Select(p => p.Effect == "deny" ? p with { Valid = true } : p).ToArray() } };
        var request = WorkstationReportContract.Parse(Key, new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues> {
            ["search"] = Prefix, ["domain"] = "11", ["finding_id"] = FindingId, ["evidence_index"] = "1" }), Stations[0]);
        var error = await Assert.ThrowsAsync<WorkstationException>(() => reportReader.ReadAsync(request, facts, access, ct));
        Assert.Equal(403, error.Status); Assert.Equal("workstation_access_denied", error.Message);
        var stillVisible = await reportReader.ReadAsync(initialRequest with { RowId = Stations[1] }, facts, access, ct);
        Assert.Equal(Stations[1], Assert.Single(Ids(stillVisible)));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    static async Task Seed(SqlPostgresFixture fixture, CancellationToken ct)
    {
        await using var db = await fixture.Pg.OpenAsync(ct);
        // Use a genuine resolved device observation and directory association for
        // the mixed station. Inventory's AD ID alone must not prove a binding.
        await using var seed = new NpgsqlCommand("""
            insert into storage_v2_entity_type(value) values('ad_computer'),('device') on conflict(value) do nothing;
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,instance_name)
            values(@agent::uuid,@host::uuid,repeat('a',64),'[{"module_id":"sli.workstations"}]',@prefix);
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select 1000+n,(select id from storage_v2_entity_type where value='ad_computer'),
                @stations[n+1],@stations[n+1],case when n<13 then 11 else 22 end,decode(repeat('00',32),'hex')
            from generate_series(0,13) n;
            insert into sli_plugin_workstations.station_inventory(station_id,ad_computer_id,agent_key,domain_id,metadata)
            select @stations[n+1],1000+n,case when n=0 then @agent end,case when n<13 then 11 else 22 end,
                jsonb_build_object('display_name',@prefix||'-'||lpad(n::text,2,'0'),
                    'ip_addresses',case when n in (1,13) then '["192.0.2.77"]'::jsonb else '[]'::jsonb end)
            from generate_series(0,13) n;
            insert into sli_plugin_workstations.station_summary(station_id,last_interactive_login,as_of_utc)
            select @stations[n+1],jsonb_build_object('observed_at',now(),'logon_type',2,'current_state','unknown',
                'account',jsonb_build_object('name',@prefix||case when n=3 then '-userAX' else '-user_%' end,
                    'domain','EXAMPLE','sid',@sid)),now() from unnest(array[1,2,3,13]) n;
            insert into sli_plugin_workstations.device_seen(station_id,device_key,device_id,identity_quality,storage_evidence,first_seen_at,last_seen_at,first_ref,last_ref)
            select @stations[n+1],repeat('d',64),'USBSTOR\SYNTHETIC','station_instance',true,now()-interval '8 days',now()+interval '1 day','{}','{}'
            from unnest(array[1,13]) n;
            insert into sli_plugin_workstations.device_seen_occurrences(station_id,device_key,observed_at)
            select @stations[n+1],repeat('d',64),now()+offsets.dt from unnest(array[1,13]) n
            cross join (values(interval '-8 days'),(interval '-1 day'),(interval '-1 hour'),(interval '1 day')) offsets(dt);
            insert into sli_plugin_workstations.check_findings(id,station_id,check_id,rule_version,episode_id,revision,condition_sha256,status,severity,
                first_detected_at,last_observed_at,materially_changed_at,reason_code,evidence_refs,subject_ref)
            select case when n=0 and check_id='C05' then @finding else encode(sha256(convert_to(n::text||check_id,'UTF8')),'hex') end,
                @stations[n+1],check_id,1,encode(sha256(convert_to(n::text||check_id||'episode','UTF8')),'hex'),1,repeat('c',64),'active','medium',
                now(),now(),now(),'service_or_task_changed',case when n=0 then @refs::jsonb else '[]'::jsonb end,
                case when check_id='C04' then @subject::jsonb else '{}'::jsonb end
            from generate_series(0,11) n cross join (values('C04'),('C05')) checks(check_id) where n=0 or check_id='C05';
            insert into entities_v2(id,entity_type_id,natural_key,display_name,source_core_sha256)
            values(1100,(select id from storage_v2_entity_type where value='device'),
                'core:'||encode(sha256(convert_to('["device","sli.agent.key","agent-registry","'||@agent||'"]','UTF8')),'hex'),
                'synthetic-device',sha256(convert_to(@agent,'UTF8')));
            insert into core_entity_observations(observation_sha256,plugin_id,source_instance_id,entity_kind,entity_id,observed_at_utc,identifiers_json,evidence_refs,resolution)
            values(sha256(convert_to(@host,'UTF8')),'sli.workstations',@host,'device',1100,now(),'[{}]',array['synthetic'],'resolved');
            insert into core_entity_associations(source_entity_id,target_entity_id,relation,actor_id,evidence_refs)
            select 1100,1000,'directory_computer',id,array['synthetic'] from auth_users where username='platform-owner';
            insert into sli_plugin_workstations.observations(id,agent_key,entity_id,ad_computer_id,family,event_id,observed_at,observation,observation_sha256,source_xml)
            values(@observation,@agent,1000,1000,'processes',4688,@at,@body::jsonb,@hash,@xml);
            """, db);
        var body = new JsonObject { ["agent_key"] = Agent, ["entity_id"] = 1000, ["ad_computer_id"] = 1000,
            ["family"] = "processes", ["event_id"] = 4688, ["observed_at"] = Ws.Stamp(DateTimeOffset.UtcNow), ["source_sha256"] = Ws.Sha(Xml) };
        var reference = new JsonArray(new JsonObject { ["kind"] = "workstation_observation", ["agent_key"] = Agent,
            ["observation_id"] = ObservationId, ["source_sha256"] = Ws.Sha(Xml) });
        var subject = new JsonObject { ["kind"] = "workstation_process_observation", ["station_id"] = Stations[0],
            ["path"] = @"C:\Windows\Temp\synthetic.exe", ["process_id"] = "17", ["signature_status"] = "not_received",
            ["current_state"] = "unknown", ["command_line"] = "PRIVATE-COMMAND" };
        foreach (var (name, value) in new (string, object)[] { ("agent", Agent), ("host", HostId), ("prefix", Prefix), ("stations", Stations),
            ("sid", Sid), ("finding", FindingId), ("refs", reference.ToJsonString()), ("subject", subject.ToJsonString()),
            ("observation", ObservationId), ("at", Ws.Time(body.Text("observed_at"))), ("body", body.ToJsonString()), ("hash", Ws.Hash(body)), ("xml", Xml) })
            seed.Parameters.AddWithValue(name, value);
        await seed.ExecuteNonQueryAsync(ct);
    }
}
