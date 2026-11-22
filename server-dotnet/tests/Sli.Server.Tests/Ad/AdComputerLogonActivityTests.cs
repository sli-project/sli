using System.Text.Json.Nodes;
using Sli.Server.Ad;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

public sealed class AdComputerLogonActivityTests
{
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
                (3, 103, '00000000-0000-0000-0000-000000000001', 'synthetic-user', '2026-11-01T18:00:00Z'),
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
        Assert.Equal(104, Assert.Single(first["items"]!.AsArray()).Int("source_event_id"));
        Assert.Equal(4, summary.Int("total"));
        Assert.Equal(2m, summary["typical"]!.GetValue<decimal>());
        Assert.Equal(3, summary["top"].Int("count"));
        Assert.Equal("synthetic-user", summary["top"].Text("account"), ignoreCase: true);
        Assert.Collection(summary["days"]!.AsArray(),
            day => { Assert.Equal("2026-11-01", day.Text("day")); Assert.Equal(1, day.Int("count")); },
            day => { Assert.Equal("2026-11-02", day.Text("day")); Assert.Equal(3, day.Int("count")); });

        var second = await AdLogonReports.ReadAsync(db, input with { Cursor = first.Text("next_cursor") }, [source], ct);
        Assert.Equal(103, Assert.Single(second["items"]!.AsArray()).Int("source_event_id"));
        var filtered = (JsonObject)input.Params.DeepClone();
        filtered["user"] = "other-user";
        var onlyOther = await AdLogonReports.ReadAsync(db, input with { Params = filtered }, [source], ct);
        Assert.Equal(1, onlyOther["computer_logon_activity"].Int("total"));
        Assert.Equal("other-user", onlyOther["computer_logon_activity"]?["top"].Text("account"));
    }
}

