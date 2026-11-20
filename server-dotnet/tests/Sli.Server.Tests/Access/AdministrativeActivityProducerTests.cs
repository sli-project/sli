using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access.Administration;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Access;

// Vectors from tests/access/test_administrative_activity_producer.py.
public sealed class AdministrativeActivityProducerTests
{
    private static readonly DateTime Created = new(2026, 8, 3, 0, 0, 0, DateTimeKind.Utc);
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Connections(PostCollectionPostgres postgres) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => postgres.OpenAsync(ct);
    }

    private static async Task Sql(NpgsqlConnection db, string sql)
    {
        await using var command = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
        await command.ExecuteNonQueryAsync(Ct);
    }

    private static async Task<JsonObject> Row(NpgsqlConnection db, string sql)
    {
        await using var command = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
        return JsonNode.Parse((string)(await command.ExecuteScalarAsync(Ct))!)!.AsObject();
    }

    private static async Task Schema(NpgsqlConnection db)
    {
        await Sql(db, """
            create table auth_audit(id bigserial primary key,created_at timestamptz not null default clock_timestamp(),
              actor_type text,actor_id bigint,action text,outcome text,remote_address text);
            create table access_audit_v4(id bigserial primary key,created_at timestamptz not null default clock_timestamp(),
              actor_type text,actor_id bigint,action text,subject_type text,subject_id bigint,target_type text,target_key text,
              reason text,outcome text,details_json jsonb,remote_address text);
            create table captured_activity(activity_id bigserial primary key,record jsonb);
            -- Capture only the final journal boundary, just like the reference test's fake_append.
            create function append_administrative_activity_v1(uid uuid,occurred timestamptz,actor text,actor_key text,
              category text,action text,target text,target_key text,outcome text,reason text,details jsonb,address inet,correlation uuid)
            returns table(activity_id bigint,record_hash bytea) language plpgsql as $$
            begin
              return query insert into captured_activity(record) values(jsonb_build_object(
                'event_uid',uid,'occurred_at_utc',occurred,'actor_kind',actor,'actor_key',actor_key,'category',category,
                'action_key',action,'target_kind',target,'target_key',target_key,'outcome',outcome,'reason_code',reason,
                'details',details,'remote_address',address,'correlation_id',correlation))
                returning captured_activity.activity_id,decode(repeat('a',64),'hex');
            end $$;
            """);
    }

    private static AdministrativeActivity Access(string action = "report_assignment_created", string? subject = "user",
        long? subjectId = 9, string? target = "report", string? key = "privileged.accounts", string outcome = "ok",
        string actor = "session", long? actorId = 3, long id = 31) =>
        AdministrativeActivityProducer.ProjectAccess(id, Created, actor, actorId, action, subject, subjectId, target, key, outcome, "192.0.2.1");

    [Theory]
    [InlineData("action", "report_preference_updated", "access_action_not_allowlisted")]
    [InlineData("target", "package", "access_target_invalid")]
    [InlineData("subject", "computer", "access_subject_invalid")]
    [InlineData("outcome", "maybe", "access_outcome_not_allowlisted")]
    [InlineData("actor", "unknown", "access_actor_not_allowlisted")]
    [InlineData("key", " ", "access_target_invalid")]
    public void UnknownAccessShapesFailClosed(string field, string value, string error)
    {
        var exception = Assert.Throws<AssignmentValidationException>(() => Access(
            action: field == "action" ? value : "report_assignment_created",
            target: field == "target" ? value : "report", subject: field == "subject" ? value : "user",
            outcome: field == "outcome" ? value : "ok", actor: field == "actor" ? value : "session",
            key: field == "key" ? value : "privileged.accounts"));
        Assert.Equal("administrative_activity_" + error, exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0L)]
    [InlineData(-1L)]
    public void SubjectRequiresPositiveId(long? id) => Assert.Equal("administrative_activity_access_subject_invalid",
        Assert.Throws<AssignmentValidationException>(() => Access(subjectId: id)).Message);

    [Fact]
    public async Task AuthAndAccessProjectionEnabledDisabledAndErrorsMatchReference()
    {
        await using var postgres = new PostCollectionPostgres(canonicalSchema: true);
        await postgres.StartAsync(Ct);
        await using var db = await postgres.OpenAsync(Ct);
        await Schema(db);
        await using var transaction = await db.BeginTransactionAsync(Ct);

        // Singleton initial owner slot: session/anonymous, success/failure (all four source vectors).
        foreach (var actor in new[] { "session", "anonymous" })
        foreach (var outcome in new[] { "ok", "failed" })
        {
            var result = await AuthAudit.MirrorAsync(transaction, 7, Created,
                new(actor, actor == "session" ? 7 : null, "initial_owner_claimed", outcome, "192.0.2.1"), Ct, true);
            Assert.True(result["journal_written"]!.GetValue<bool>());
            var activity = await Row(db, "select record::text from captured_activity order by activity_id desc limit 1");
            Assert.Equal("access_management", activity["category"]!.ToString());
            Assert.Equal("auth.initial_owner.claimed", activity["action_key"]!.ToString());
            Assert.Equal("platform_owner", activity["target_kind"]!.ToString());
            Assert.Equal("platform_owner:primary", activity["target_key"]!.ToString());
            Assert.Equal(actor == "session" ? "session:7" : "system:anonymous", activity["actor_key"]!.ToString());
            Assert.Equal(outcome == "ok" ? "succeeded" : "failed", activity["outcome"]!.ToString());
        }

        var disabled = await AuthAudit.MirrorAsync(transaction, 7, Created,
            new("session", 3, "user_updated:9:username-must-not-be-copied", RemoteAddress: "192.0.2.1"), Ct);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"status":"disabled","source":"auth_audit","source_row_id":7,"journal_written":false}"""), disabled));
        Assert.Equal(4, (await Row(db, "select jsonb_build_object('count',count(*))::text from captured_activity"))["count"]!.GetValue<int>());
        // The enabled projection drops the username suffix too.
        await AuthAudit.MirrorAsync(transaction, 7, Created,
            new("session", 3, "user_updated:9:username-must-not-be-copied"), Ct, true);
        var user = await Row(db, "select record::text from captured_activity order by activity_id desc limit 1");
        Assert.Equal("user:9", user["target_key"]!.ToString());
        Assert.DoesNotContain("username-must-not-be-copied", user.ToJsonString());

        await AuthAudit.MirrorAsync(transaction, 11, Created, new("anonymous", null, "login", "throttled", "192.0.2.1"), Ct, true);
        var login = await Row(db, "select record::text from captured_activity order by activity_id desc limit 1");
        Assert.Equal("auth.login", login["action_key"]!.ToString());
        Assert.Equal("denied", login["outcome"]!.ToString());
        Assert.Equal("system:anonymous", login["actor_key"]!.ToString());
        Assert.Equal("authentication_throttled", login["reason_code"]!.ToString());
        Assert.Equal("11676037-267c-52de-93a6-1485287ce73f", login["event_uid"]!.ToString());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"legacy_auth_audit_id":11}"""), login["details"]));
        Assert.Equal(new DateTimeOffset(Created), DateTimeOffset.Parse(login["occurred_at_utc"]!.ToString()));

        foreach (var (entry, error) in new (AuthAuditEvent, string)[]
        {
            (new("session", 3, "unknown"), "auth_action_not_allowlisted"),
            (new("session", 3, "login", "maybe"), "auth_outcome_not_allowlisted"),
            (new("unknown", 3, "login"), "auth_actor_not_allowlisted"),
            (new("session", 3, "user_updated:not-an-id"), "auth_target_invalid"),
            (new("session", 3, "initial_owner_claimed:7"), "auth_target_invalid")
        })
        {
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => AuthAudit.MirrorAsync(transaction, 7, Created, entry, Ct));
            Assert.Equal("administrative_activity_" + error, exception.Message);
        }

        long beforeDisabled = (await Row(db, "select jsonb_build_object('count',count(*))::text from captured_activity"))["count"]!.GetValue<long>();
        var accessDisabled = await AdministrativeActivityProducer.MirrorAsync(transaction, Access(), "access_audit_v4", 31, false, Ct);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"status":"disabled","source":"access_audit_v4","source_row_id":31,"journal_written":false}"""), accessDisabled));
        var vpn = Access("vpn_session_evidence_grant_created", subjectId: 34, target: "capability", key: "vpn.session.evidence.read", actor: "local", actorId: null, id: 35);
        Assert.Equal("local_operator:anonymous", vpn.ActorKey);
        Assert.False((await AdministrativeActivityProducer.MirrorAsync(transaction, vpn, "access_audit_v4", 35, false, Ct))["journal_written"]!.GetValue<bool>());

        Assert.Equal(beforeDisabled, (await Row(db, "select jsonb_build_object('count',count(*))::text from captured_activity"))["count"]!.GetValue<long>());
        var published = Access("report_published", subject: null, subjectId: null, id: 32);
        var written = await AdministrativeActivityProducer.MirrorAsync(transaction, published, "access_audit_v4", 32, true, Ct);
        Assert.True(written["journal_written"]!.GetValue<bool>());
        Assert.Equal("written", written["status"]!.ToString());
        Assert.True(written["activity_id"]!.GetValue<long>() > 0);
        var publication = await Row(db, "select record::text from captured_activity order by activity_id desc limit 1");
        Assert.Equal("report_publication", publication["category"]!.ToString());
        Assert.Equal("report.published", publication["action_key"]!.ToString());
        Assert.Equal("report:privileged.accounts", publication["target_key"]!.ToString());
        Assert.Equal("4b92f3af-e27e-54e3-b05f-edfeec582c19", publication["event_uid"]!.ToString());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"legacy_access_audit_id":32}"""), publication["details"]));

        await AdministrativeActivityProducer.MirrorAsync(transaction, Access(), "access_audit_v4", 31, true, Ct);
        var assignment = await Row(db, "select record::text from captured_activity order by activity_id desc limit 1");
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"legacy_access_audit_id":31,"subject_type":"user","subject_id":9}"""), assignment["details"]));
        await transaction.RollbackAsync(Ct);
        // Captures participate in the caller's transaction; no independent journal connection/commit.
        Assert.Equal(0, (await Row(db, "select jsonb_build_object('count',count(*))::text from captured_activity"))["count"]!.GetValue<int>());
    }

    [Fact]
    public async Task LegacyHooksShareTransactionSkipUnsupportedActionsAndPropagateFailures()
    {
        await using var postgres = new PostCollectionPostgres(canonicalSchema: true);
        await postgres.StartAsync(Ct);
        await using var db = await postgres.OpenAsync(Ct);
        await Schema(db);
        var audit = new AuthAudit(new Connections(postgres));
        await using (var transaction = await db.BeginTransactionAsync(Ct))
        {
            await audit.AppendAsync(transaction, new("session", 3, "login", RemoteAddress: "192.0.2.1"), Ct, true);
            var auth = await Row(db, "select row_to_json(a)::text from auth_audit a");
            Assert.Equal("login", auth["action"]!.ToString());
            var authMirror = await Row(db, "select record::text from captured_activity");
            Assert.Equal(auth["id"]!.GetValue<long>(), authMirror["details"]!["legacy_auth_audit_id"]!.GetValue<long>());
            Assert.Equal(DateTimeOffset.Parse(auth["created_at"]!.ToString()), DateTimeOffset.Parse(authMirror["occurred_at_utc"]!.ToString()));
            await AssignmentAudit.AppendEventAsync(transaction, new("session", 3), "report_published", null, null,
                "report", "privileged.accounts", null, new { }, "192.0.2.1", Ct, writeEnabled: true);
            var access = await Row(db, "select row_to_json(a)::text from access_audit_v4 a");
            var mirror = await Row(db, "select record::text from captured_activity order by activity_id desc limit 1");
            Assert.Equal(access["id"]!.GetValue<long>(), mirror["details"]!["legacy_access_audit_id"]!.GetValue<long>());
            Assert.Equal(DateTimeOffset.Parse(access["created_at"]!.ToString()), DateTimeOffset.Parse(mirror["occurred_at_utc"]!.ToString()));
            await transaction.RollbackAsync(Ct);
        }
        Assert.Equal(0, (await Row(db, "select jsonb_build_object('count',count(*))::text from auth_audit"))["count"]!.GetValue<int>());
        Assert.Equal(0, (await Row(db, "select jsonb_build_object('count',count(*))::text from access_audit_v4"))["count"]!.GetValue<int>());

        foreach (string action in new[] { "notification_channel_update", "notification_schedule_update", "notification_test_enqueue",
            "notification_subscription_update", "decoy_label_update", "watch_entry_update", "semantic_suppression_create",
            "semantic_suppression_revoke", "semantic_policy_admission", "report_preference_updated" })
        {
            await using var transaction = await db.BeginTransactionAsync(Ct);
            await AssignmentAudit.AppendEventAsync(transaction, new("session", 3), action, null, null,
                "notification_channel", "telegram", null, new { kind = "telegram", operation = "token", phase = "requested" }, null, Ct);
            var row = await Row(db, "select row_to_json(a)::text from access_audit_v4 a");
            Assert.Equal(action, row["action"]!.ToString());
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"kind":"telegram","operation":"token","phase":"requested"}"""), row["details_json"]));
            Assert.Equal(0, (await Row(db, "select jsonb_build_object('count',count(*))::text from captured_activity"))["count"]!.GetValue<int>());
            await transaction.RollbackAsync(Ct);
        }

        // A malformed supported shape fails only after the mandatory legacy row has been fetched.
        await using (var transaction = await db.BeginTransactionAsync(Ct))
        {
            var error = await Assert.ThrowsAsync<AssignmentValidationException>(() => AssignmentAudit.AppendEventAsync(transaction,
                new("session", 3), " report_published ", null, null, "wrong", "synthetic-report", null, new { }, null, Ct));
            Assert.Equal("administrative_activity_access_target_invalid", error.Message);
            Assert.Equal(" report_published ", (await Row(db, "select row_to_json(a)::text from access_audit_v4 a"))["action"]!.ToString());
            // Dispose without commit is the caller's rollback.
        }
        await Sql(db, """
            create function reject_mirror() returns trigger language plpgsql as $$begin raise exception 'synthetic mirror failure'; end$$;
            create trigger reject_mirror before insert on captured_activity for each row execute function reject_mirror();
            """);
        await using (var transaction = await db.BeginTransactionAsync(Ct))
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => AssignmentAudit.AppendEventAsync(transaction,
                new("session", 3), " report_published ", null, null, "report", "synthetic-report", null, new { }, null, Ct, writeEnabled: true));
            Assert.Equal("synthetic mirror failure", error.MessageText);
        }
        Assert.Equal(0, (await Row(db, "select jsonb_build_object('count',count(*))::text from access_audit_v4"))["count"]!.GetValue<int>());
    }
}
