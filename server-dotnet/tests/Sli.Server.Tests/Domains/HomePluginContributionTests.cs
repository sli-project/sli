using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class HomePluginContributionTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static DateTimeOffset At(string value) => DateTimeOffset.Parse(value);
    static readonly HomeSummaryQuery Query = new("v2", 7, "UTC", "current", At("2026-10-03T12:00:00Z"), null,
        new(At("2026-10-02T00:00:00Z"), At("2026-10-03T00:00:00Z")),
        new(At("2026-10-01T00:00:00Z"), At("2026-10-02T00:00:00Z")), true);
    static IConfiguration Config(PostCollectionPostgres pg) => new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = pg.ConnectionString,
            ["Sli:Storage:HistoryReadMode"] = "disabled" }).Build();

    [Fact]
    public void Ad_history_and_membership_accept_the_same_3650_day_period()
    {
        foreach (var tab in new[] { "changes", "privileged_changes" })
        {
            var context = new DefaultHttpContext();
            context.Request.QueryString = new($"?tab={tab}&period=custom&from=2016-10-05T00:00:00Z&to=2026-10-03T00:00:00Z");
            var request = AdV2Endpoints.Parse(context.Request, "ad.infrastructure", "view", [7]);
            Assert.Equal(tab, request.Tab);
            Assert.Equal(At("2016-10-05T00:00:00Z"), At(request.Params["period"]!["from_utc"]!.ToString()));
            context.Request.QueryString = new($"?tab={tab}&period=custom&from=2016-10-04T00:00:00Z&to=2026-10-03T00:00:00Z");
            Assert.Equal("report_period_too_wide", Assert.Throws<AdInputException>(() =>
                AdV2Endpoints.Parse(context.Request, "ad.infrastructure", "view", [7])).Message);
        }
    }

    [Fact]
    public async Task Vpn_closed_aggregates_preserve_zero_and_measure_each_window_coverage()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create function read_plugin_states_v1() returns table(plugin_id text,enabled boolean)
                language sql as $$select 'sli.remote-access'::text,true$$;
            create table radius_vpn_session_coverage_v1(domain_id bigint,total_delivery_count bigint,
                history_available_from_utc timestamptz,history_available_to_utc timestamptz);
            insert into radius_vpn_session_coverage_v1 values(7,10,'2026-09-01Z','2026-10-04Z');
            create table radius_vpn_session_rows_v1(domain_id bigint,entity_id bigint,started_at_utc timestamptz,stopped_at_utc timestamptz);
            insert into radius_vpn_session_rows_v1
                select 7,2,'2026-10-02Z'::timestamptz,'2026-10-02T12:00Z'::timestamptz from generate_series(1,4);
            insert into radius_vpn_session_rows_v1 values
                (8,2,'2026-10-02Z','2026-10-02T12:00Z'),
                (7,null,'2026-10-02Z','2026-10-02T12:00Z'),
                (7,2,'2026-10-02Z',null),(7,2,'2026-10-02Z','2026-10-02Z'),
                (7,2,'2026-10-03Z','2026-10-04Z');
            """, Ct);
        var reads = new HomeSummaryReaders(new HomeSummaryRepository(new PostgresConnectionFactory(Config(pg))));
        var data = await reads.Vpn(7, Query, Ct);
        Assert.Equal("ok", data["state"]!.ToString());
        Assert.Equal(4, (long?)data["metrics"]![0]!["value"]);
        Assert.Equal(0, (long?)data["metrics"]![0]!["previous_value"]);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"domains":[7],"state":"available","complete":true}"""), data["comparison_coverage"]));
        Assert.True(JsonNode.DeepEquals(data["comparison_coverage"], data["previous_coverage"]));
        await PostCollectionPostgres.Sql(db, "update radius_vpn_session_coverage_v1 set history_available_from_utc='2026-10-02Z'", Ct);
        data = await reads.Vpn(7, Query, Ct);
        Assert.Null(data["metrics"]![0]!["previous_value"]);
        Assert.True((bool?)data["comparison_coverage"]!["complete"]);
        Assert.False((bool?)data["previous_coverage"]!["complete"]);
        Assert.False((bool?)data["comparison_complete"]);
        await PostCollectionPostgres.Sql(db, "update radius_vpn_session_coverage_v1 set history_available_from_utc='2026-10-01Z',history_available_to_utc='2026-10-02Z'", Ct);
        data = await reads.Vpn(7, Query, Ct);
        Assert.Equal(0, (long?)data["metrics"]![0]!["previous_value"]);
        Assert.False((bool?)data["comparison_coverage"]!["complete"]);
        Assert.True((bool?)data["previous_coverage"]!["complete"]);
    }

    [Fact]
    public async Task Ad_home_and_drilldown_share_authorized_window_and_exclude_initial_and_adjacent_versions()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create role adlog_user;
            create table ad_context_runs(run_id int,domain_id bigint,status text,observed_at_utc timestamptz);
            create table ad_context_sections(run_id int,section_name text,status text);
            insert into ad_context_runs values(1,7,'completed','2026-09-01Z'),(2,7,'completed','2026-10-02Z'),
                (3,8,'completed','2026-10-02Z');
            insert into ad_context_sections select run_id,'privileged_membership','complete' from ad_context_runs;
            create table ad_context_relation_versions(id bigint,domain_id bigint,source_entity_id bigint,target_entity_id bigint,
                relation_key text,source_section text,relation_kind text,valid_from_utc timestamptz,valid_to_utc timestamptz);
            insert into ad_context_relation_versions
                select id,7,2,3,id::text,'privileged_membership','member_of','2026-09-01Z'::timestamptz,
                    case when id<=4 then '2026-10-02Z'::timestamptz else '2026-10-01Z'::timestamptz end
                from generate_series(1,6) id;
            insert into ad_context_relation_versions values
                (7,7,2,3,'end','privileged_membership','member_of','2026-09-01Z','2026-10-03Z'),
                (8,8,2,3,'initial','privileged_membership','member_of','2026-10-02Z','2026-10-02T12:00Z'),
                (10,7,2,3,'content','privileged_membership','member_of','2026-09-01Z','2026-10-02Z'),
                (11,7,2,3,'content','privileged_membership','member_of','2026-10-02Z',null),
                (12,99,2,3,'foreign','privileged_membership','member_of','2026-09-01Z','2026-10-02Z');
            create table platform_settings(key text,value text);
            """, Ct);
        await PostCollectionPostgres.InstallSnapshotChangeStorageAsync(db, Ct);
        var config = Config(pg); var factory = new PostgresConnectionFactory(config);
        var reads = new HomeSummaryReaders(new HomeSummaryRepository(factory));
        var data = await reads.Changes([7], Query, Ct);
        Assert.Equal("partial", data["state"]!.ToString());
        Assert.Equal(4, (long?)data["metrics"]![0]!["value"]);
        Assert.Equal(2, (long?)data["metrics"]![0]!["previous_value"]);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"complete":false,"domains":[7],"kind":"snapshot_observations"}"""), data["comparison_coverage"]));
        Assert.True(JsonNode.DeepEquals(data["comparison_coverage"], data["previous_coverage"]));
        var request = new AdV2Request("ad.infrastructure", "view", null, [7],
            JsonNode.Parse("""{"period":{"from_utc":"2026-10-02T00:00:00Z","to_utc":"2026-10-03T00:00:00Z"}}""")!.AsObject(),
            "privileged_changes", null, false, 100, null, "UTC");
        var store = new AdV2Store(factory, config);
        var detail = await store.ReadAsync(request, _ => true, Ct);
        Assert.Equal(4, detail["items"]!.AsArray().Count);
        Assert.Equal(new[] { "4:removed", "3:removed", "2:removed", "1:removed" }, detail["items"]!.AsArray().Select(r => r!["row_id"]!.ToString()));
        Assert.True(JsonNode.DeepEquals(detail["items"], detail["collections"]!["privileged_changes"]));
        Assert.False((bool?)detail["has_more"]);
        var page = await store.ReadAsync(request with { Limit = 2 }, _ => true, Ct);
        Assert.True((bool?)page["has_more"]); Assert.Equal("2", page["next_cursor"]!.ToString());
        Assert.Equal(new[] { "4:removed", "3:removed" }, page["items"]!.AsArray().Select(r => r!["row_id"]!.ToString()));
        var columns = AdV2Endpoints.Definitions["ad.infrastructure"]!["declaration"]!["views"]!.AsArray()
            .Single(v => v!["key"]!.ToString() == "privileged_changes")!["columns"]!.AsArray();
        Assert.Contains("Удаление", AdV2Endpoints.Csv(columns, detail["items"]!.AsArray()));
        // This branch needs snapshot history, whereas membership above needs only retained observations.
        var history = await store.ReadAsync(request with { Tab = "changes" }, _ => true, Ct);
        Assert.Equal("not_collected", history["state"]!.ToString());
        Assert.Empty(history["collections"]!["changes"]!.AsArray());
        await PostCollectionPostgres.Sql(db, "alter table ad_snapshot_history_confirmations rename to fixture_unavailable_history", Ct);
        var unavailable = await store.ReadAsync(request with { Tab = "changes" }, _ => true, Ct);
        Assert.Equal("error", unavailable["state"]!.ToString());
        Assert.Contains(unavailable["limitations"]!.AsArray(), row => row!["code"]!.ToString() == "history_unavailable");
        Assert.Equal(4, (await store.ReadAsync(request, _ => true, Ct))["items"]!.AsArray().Count);
        var initial = await reads.Changes([8], Query, Ct);
        Assert.Equal(1, (long?)initial["metrics"]![0]!["value"]);
        Assert.Null(initial["metrics"]![0]!["previous_value"]);
        await PostCollectionPostgres.Sql(db, "update ad_context_runs set observed_at_utc='2026-09-01Z' where run_id=3", Ct);
        Assert.Equal(2, (long?)(await reads.Changes([8, 7], Query, Ct))["metrics"]![0]!["previous_value"]);
        var missing = await reads.Changes([9], Query, Ct);
        Assert.Null(missing["metrics"]![0]!["value"]);
        Assert.Null(missing["metrics"]![0]!["previous_value"]);
        await PostCollectionPostgres.Sql(db, "update ad_context_runs set observed_at_utc='2026-10-01Z' where run_id=1", Ct);
        Assert.Null((await reads.Changes([7], Query, Ct))["metrics"]![0]!["previous_value"]);
    }
}
