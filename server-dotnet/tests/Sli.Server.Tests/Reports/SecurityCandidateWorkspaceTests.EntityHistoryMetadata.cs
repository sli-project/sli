using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Investigations;
using Sli.Server.Reports.SecurityCandidates;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Reports;

// Behavioral vectors from tests/reporting/test_entity_history_metadata.py.
public sealed partial class SecurityCandidateWorkspaceTests
{
    sealed class MetadataConnections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var db = new NpgsqlConnection(dsn);
            await db.OpenAsync(ct);
            return db;
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RetainedMetadataSqlReadsOnlyExactIdsAndPermittedColumns(bool security)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            insert into servers(id,domain_id,hostname,role,is_active) values(900001,1,'dc.example.test','domain_controller',true);
            insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select 5632,id,'sid:S-1-5-21-100000001-200000002-300000003-1001','operator',1,sha256('operator'::bytea)
                from storage_v2_entity_type where value='ad_user';
            """,ct);
        DateTime date = DateTime.UtcNow.Date.AddDays(-2);
        ShortEventRow Row(long id, int kind)
        {
            var row = EntityShortReadsPostgresTests.Row(id,kind,date.AddSeconds(id));
            var method = JsonNode.Parse(row.Method)!.AsObject();
            if (id == 98) method.Remove("$provider");
            if (id <= 97) method["$principals"]!["SubjectUserSid"] = "S-1-5-21-100000001-200000002-300000003-1009";
            return row with { Method = method.ToJsonString() };
        }
        await EntityShortReadsPostgresTests.Write(fixture,[Row(99,4624),Row(98,4740),Row(97,4624),Row(96,4624)],ct);
        // Observe the real app-role read so a new SQL timeout cannot make
        // otherwise authorized metadata disappear on a slow runner.
        await PostCollectionPostgres.Sql(db,"""
            create function public.fixture_metadata_read() returns boolean language plpgsql stable as $$
            begin
                if current_setting('statement_timeout') <> '0' or current_setting('lock_timeout') <> '0' then
                    raise exception 'history must not impose arbitrary query timeouts';
                end if;
                return true;
            end $$;
            alter table event_hot enable row level security;
            create policy fixture_metadata_read on event_hot for select to adlog_user using(public.fixture_metadata_read());
            """,ct);
        var input = new InvestigationWorkspaceInput(null, 5632, "", null,
            security ? date.ToString("O") : null, security ? date.AddDays(1).ToString("O") : null, "UTC", null);
        var store = new InvestigationEntityHistory(new MetadataConnections(fixture.Dsn("adlog_user")), new SecurityCandidateOwner(new Candidates()));
        // The bounded caller may admit exact IDs from its alias search.
        long[] exactIds = security ? [99, 98, 97] : [99, 98, 97, 96];
        var rows = await store.MetadataAsync(input, exactIds, ct);
        Assert.Equal(security ? new long[] { 99, 98, 97 } : [99, 98], rows.Select(r => r["event_db_id"]!.GetValue<long>()));
        Assert.Equal("Microsoft-Windows-Security-Auditing", rows[0]["provider_name"]!.GetValue<string>());
        Assert.Null(rows[1]["provider_name"]);
        string[] fields = ["event_db_id", "event_id", "time_created_utc", "server", "channel", "provider_name", "subject_user_name", "target_user_name"];
        Assert.All(rows, row => Assert.Equal(fields.Order(), row.Select(p => p.Key).Order()));
        Assert.Empty(await store.MetadataAsync(input, [], ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    static JsonObject RetainedMetadata(long id, int eventId = 4624) => new()
    {
        ["event_db_id"] = id, ["event_id"] = eventId,
        ["time_created_utc"] = $"2026-09-10T00:00:{id % 60:00}Z",
        ["server"] = "dc1.example.test", ["channel"] = "Security",
        ["provider_name"] = "Microsoft-Windows-Security-Auditing",
        ["subject_user_name"] = "operator", ["target_user_name"] = "alice",
        ["ip_address"] = "192.0.2.24", ["workstation_name"] = "ws-01"
    };

    [Theory]
    [InlineData(100, false)]
    [InlineData(101, true)]
    public async Task LegacyHistoryReadsOnlyOnePublicPageOfExactRetainedMetadata(int count, bool hasMore)
    {
        var (ctx, candidates, history, provider) = Setup(query: "?entity_id=5632");
        using (provider)
        {
            // Sparse IDs must remain exact IDs, never become an archive range.
            history.LegacyIds = Enumerable.Range(0, count).Select(i => 9000L - i * 17).ToArray();
            history.MetadataRow = id => RetainedMetadata(id);
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(200, ctx.Response.StatusCode);
            Assert.Equal(0, candidates.Reads);
            Assert.Equal(history.LegacyIds, history.Preflights);
            Assert.Equal(history.LegacyIds.Take(100), history.Hydrated);
            var body = Body(ctx);
            Assert.Equal(100, body.GetProperty("summary").GetProperty("events_returned").GetInt32());
            Assert.Equal(hasMore, body.GetProperty("summary").GetProperty("has_more").GetBoolean());
            Assert.Equal(history.Hydrated.Order(), body.GetProperty("timeline").EnumerateArray().Select(i => i.GetProperty("event_db_id").GetInt64()).Order());
        }
    }

    [Theory]
    [InlineData(999999, "Microsoft-Windows-Security-Auditing", "Security", "неизвестный тип события", "unknown", false)]
    [InlineData(4740, "Microsoft-Windows-Security-Auditing", "Security", "Блокировка учетной записи", "account_management", true)]
    [InlineData(4624, null, "Security", "неизвестный тип события", "unknown", false)]
    [InlineData(4624, "Other-Provider", "Security", "неизвестный тип события", "unknown", false)]
    [InlineData(4624, "Microsoft-Windows-Security-Auditing", "Other-Channel", "неизвестный тип события", "unknown", false)]
    public async Task MetadataUsesOnlyExactCatalogIdentityAndNeverInventsRisk(int eventId, string? providerName, string channel, string title, string category, bool catalogued)
    {
        var (ctx, _, history, provider) = Setup(query: "?entity_id=5632");
        using (provider)
        {
            history.LegacyIds = [99];
            history.MetadataRow = id =>
            {
                var row = RetainedMetadata(id, eventId);
                row["provider_name"] = providerName; row["channel"] = channel;
                return row;
            };
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(200, ctx.Response.StatusCode);
            var item = Assert.Single(Body(ctx).GetProperty("timeline").EnumerateArray());
            Assert.Equal(99, item.GetProperty("event_db_id").GetInt64());
            Assert.Equal(title, item.GetProperty("title").GetString());
            Assert.Equal(category, item.GetProperty("category").GetString());
            Assert.Equal(catalogued, item.GetProperty("catalogued").GetBoolean());
            foreach (string key in new[] { "severity", "base_risk", "confidence", "assessment_confidence" })
                Assert.Equal("unknown", item.GetProperty(key).GetString());
            Assert.Equal(System.Text.Json.JsonValueKind.Null, item.GetProperty("summary").ValueKind);
            Assert.Equal("operator", item.GetProperty("actor").GetString());
            Assert.Equal("alice", item.GetProperty("target").GetString());
            Assert.False(item.TryGetProperty("provider_name", out _));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MetadataCancellationIsUnavailableWithoutArchiveFallback(bool canceled)
    {
        var (ctx, _, history, provider) = Setup(query: "?entity_id=5632");
        using (provider)
        {
            history.MetadataFailure = canceled ? new OperationCanceledException("private-db-value") : new TimeoutException("private-db-value");
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(503, ctx.Response.StatusCode);
            Assert.Equal("unavailable", Body(ctx).GetProperty("error").GetString());
            Assert.DoesNotContain("private-db-value", Body(ctx).GetRawText());
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AbsentAndDeniedAliasEvidenceReturnTheSameEmptyHistory(bool denied)
    {
        var (ctx, candidates, history, provider) = Setup(query: "?entity_id=5632&time_from=2026-09-10T00:00:00.123001Z&time_to=2026-09-11T00:00:00.123999Z");
        using (provider)
        {
            candidates.Ids = denied ? [7] : []; // Domain 2 is denied by the exact event grant.
            history.MetadataFailure = new InvalidOperationException("empty history must not read metadata");
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(200, ctx.Response.StatusCode);
            Assert.Empty(history.Hydrated);
            var body = Body(ctx);
            Assert.Equal("ok", body.GetProperty("state").GetString());
            Assert.Equal(5632, body.GetProperty("context").GetProperty("entity_id").GetInt64());
            Assert.Equal(0, body.GetProperty("timeline").GetArrayLength());
            Assert.Equal(0, body.GetProperty("summary").GetProperty("events_returned").GetInt32());
            Assert.False(body.GetProperty("summary").GetProperty("has_more").GetBoolean());
        }
    }

    [Fact]
    public async Task SecurityOwnerMetadataSortsMixedUtcRepresentationsAfterAuthorization()
    {
        var (ctx, candidates, history, provider) = Setup(query: "?entity_id=5632&time_from=2026-09-10T00:00:00Z&time_to=2026-09-11T00:00:00Z");
        using (provider)
        {
            candidates.Ids = [11, 12, 10];
            history.MetadataRow = id =>
            {
                var row = RetainedMetadata(id);
                row["time_created_utc"] = id switch
                {
                    10 => JsonValue.Create(new DateTimeOffset(2026, 9, 10, 2, 0, 0, TimeSpan.Zero)),
                    12 => JsonValue.Create("2026-09-10T01:00:00Z"),
                    _ => JsonValue.Create(new DateTime(2026, 9, 10, 0, 0, 0, DateTimeKind.Unspecified))
                };
                return row;
            };
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(200, ctx.Response.StatusCode);
            Assert.Equal(new long[] { 11, 12, 10 }, history.Hydrated);
            var timeline = Body(ctx).GetProperty("timeline").EnumerateArray().ToArray();
            Assert.Equal(new long[] { 10, 12, 11 }, timeline.Select(i => i.GetProperty("event_db_id").GetInt64()));
            Assert.All(timeline, item => Assert.Contains("SID", item.GetProperty("inclusion_reason").GetString()));
            Assert.Equal("2026-09-10T00:00:00Z", timeline[2].GetProperty("time_utc").GetString());
        }
    }
}
