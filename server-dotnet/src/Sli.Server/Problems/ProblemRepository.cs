using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;

namespace Sli.Server.Problems;

public interface IProblemRepository
{
    Task<JsonObject> LegacyFindingsAsync(string query, int limit, CancellationToken ct) => throw new NotSupportedException();
    Task<JsonObject> FindingsAsync(FindingQuery query, ProblemAccess access, CancellationToken ct);
    Task<JsonObject?> ReadQueuePasswordCoverageAsync(long[]? domains, CancellationToken ct) => throw new NotSupportedException();
    Task<JsonObject> StatusAsync(long id, FindingStatusInput input, string actor, CancellationToken ct);
    Task<JsonObject> QueueDecisionAsync(QueueDecision input, ProblemAccess access, Principal principal, CancellationToken ct) => throw new NotSupportedException();
    Task<JsonObject> RiskAsync(long id, RiskInput input, CancellationToken ct);
    Task<JsonObject> ResponsiblesAsync(CancellationToken ct);
    Task<JsonObject> RiskAuditAsync(long id, long? before, CancellationToken ct);
    Task<JsonObject> WatchListAsync(RegistryQuery query, ProblemAccess access, Principal principal, CancellationToken ct);
    Task<JsonObject> WatchSaveAsync(string? id, WatchInput input, ProblemAccess access, Principal principal, CancellationToken ct);
    Task<JsonObject> DecoyListAsync(RegistryQuery query, ProblemAccess access, Principal principal, CancellationToken ct);
    Task<JsonObject> DecoySaveAsync(string? id, DecoyInput input, ProblemAccess access, Principal principal, CancellationToken ct);
}

public sealed partial class ProblemRepository(IPostgresConnectionFactory connections, TimeProvider clock, IConfiguration? configuration=null) : IProblemRepository
{
    private static NpgsqlCommand Command(NpgsqlTransaction tx, string sql, Dictionary<string, object?>? parameters = null)
    {
        var command = new NpgsqlCommand(sql, tx.Connection, tx) { CommandTimeout = 0 };
        foreach (var (key, value) in parameters ?? [])
        {
            if (value is null) command.Parameters.AddWithValue(key, NpgsqlDbType.Unknown, DBNull.Value);
            else command.Parameters.AddWithValue(key, value is DateTimeOffset stamp ? stamp.ToUniversalTime() : value);
        }
        return command;
    }
    private static async Task<JsonArray> Rows(NpgsqlTransaction tx, string sql, Dictionary<string, object?>? parameters, CancellationToken ct)
    {
        await using var command = Command(tx, "select to_jsonb(row) from (" + sql + ") row", parameters);
        return await Read(command, ct);
    }
    private static async Task<JsonArray> Read(NpgsqlCommand command, CancellationToken ct)
    {
        var result = new JsonArray();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) result.Add(JsonNode.Parse(reader.GetString(0)));
        return result;
    }
    private static async Task<JsonObject?> One(NpgsqlTransaction tx, string sql, Dictionary<string, object?>? parameters, CancellationToken ct) =>
        (await Rows(tx, sql, parameters, ct)).FirstOrDefault()?.AsObject();
    private static async Task Execute(NpgsqlTransaction tx, string sql, Dictionary<string, object?> parameters, CancellationToken ct)
    { await using var command = Command(tx, sql, parameters); await command.ExecuteNonQueryAsync(ct); }
    private static async Task<JsonObject?> Returning(NpgsqlTransaction tx, string sql, Dictionary<string, object?> parameters, CancellationToken ct)
    { await using var command = Command(tx, sql, parameters); return (await Read(command, ct)).FirstOrDefault()?.DeepClone().AsObject(); }
    private static async Task Audit(NpgsqlTransaction tx, Principal principal, string action, string target, string id, JsonObject details, CancellationToken ct)
    {
        await Execute(tx, """
            insert into access_audit_v4(actor_type,actor_id,action,target_type,target_key,outcome,details_json)
            values(@type,@actor,@action,@target,@id,'ok',@details::jsonb)
            """, new() { ["type"] = principal.Type, ["actor"] = principal.Id, ["action"] = action, ["target"] = target, ["id"] = id, ["details"] = details.ToJsonString() }, ct);
        // These actions are not in the frozen administrative journal bridge's
        // ACCESS_ACTIONS allowlist; only the legacy access audit is written.
    }
    private static JsonObject Page(JsonArray rows, string cursorField, Func<JsonObject, JsonObject?> transform)
    {
        bool more = rows.Count > 100; var items = new JsonArray();
        foreach (var row in rows.Take(100).OfType<JsonObject>()) if (transform(row) is { } item) items.Add(item);
        return new() { ["items"] = items, ["has_more"] = more,
            ["next_cursor"] = more ? rows[99]![cursorField]!.ToString() : null };
    }
    private static async Task<JsonObject> AccountIdentity(NpgsqlTransaction tx, ProblemAccess access, long entityId, CancellationToken ct)
    {
        access.Registry("watch.registry");
        if (entityId <= 0 || entityId >= ProblemJson.SafeInteger) throw new ProblemException("watch_invalid");
        var row = await One(tx, """
            select e.id as entity_id,e.domain_id from entities_v2_active e
            join storage_v2_entity_type t on t.id=e.entity_type_id
            where e.id=@entity and t.value='ad_user' and e.domain_id is not null
            """, new() { ["entity"] = entityId }, ct) ?? throw new ProblemException("watch_invalid");
        access.Registry("watch.registry", row);
        var records = await Accounts(tx, row, ct);
        var exact = records.Count == 1 ? records[0]?["attributes_json"]?["identity"] as JsonObject : null;
        if (exact is null || ProblemJson.Text(exact["kind"]) != "ad_user" || !Regex.IsMatch(ProblemJson.Text(exact["object_sid"]), @"\AS-1-(?:[0-9]+-)*[0-9]+\z")) throw new ProblemException("watch_invalid");
        row["sid"] = exact["object_sid"]!.DeepClone(); row["guid"] = ProblemJson.Uuid(ProblemJson.Text(exact["object_guid"]), "watch_invalid");
        return row;
    }
    private static Task<JsonArray> Accounts(NpgsqlTransaction tx, JsonObject identity, CancellationToken ct) => Rows(tx, """
        select v.attributes_json,v.last_observed_at_utc from ad_context_entity_versions v
        join ad_context_runs r on r.run_id=v.source_run_id
        where v.entity_id=@entity and r.domain_id=@domain and r.status='completed'
          and v.source_section='directory_accounts' and v.valid_to_utc is null limit 2
        """, new() { ["entity"] = ProblemJson.Long(identity["entity_id"]), ["domain"] = ProblemJson.Long(identity["domain_id"]) }, ct);
    private async Task<JsonObject> Readiness(NpgsqlTransaction tx, string kind, JsonObject identity, bool active, DateTimeOffset now, CancellationToken ct)
    {
        if (kind == "account") return DecoyReadiness.Evaluate(kind, identity, active, await Accounts(tx, identity, ct), new(), false, new(), now);
        var args = new Dictionary<string, object?> { ["agent"] = ProblemJson.Text(identity["agent_id"]), ["source"] = ProblemJson.Text(identity["source_instance_id"]),
            ["scope"] = ProblemJson.Text(identity["collection_scope_id"]), ["path"] = ProblemJson.Text(identity["path"]) };
        var agent = await One(tx, """
            select host_id,status,assigned_modules,file_audit,collection_policy,policy_revision,applied_policy_revision,last_seen
            from sli_agents where id=@agent::uuid
            """, args, ct) ?? new();
        args["policy"] = ProblemJson.Text(agent["file_audit"]?["request"]?["config"]?["policy_revision"]);
        var present = await One(tx, "select sli_plugin_file_audit.decoy_file_present(@agent::uuid,@source,@scope,@path,@policy) as present", args, ct);
        var coverage = await One(tx, "select * from public.file_decoy_coverage(@agent::uuid,@source,@scope,@policy)", args, ct) ?? new();
        return DecoyReadiness.Evaluate(kind, identity, active, [], agent, ProblemJson.Bool(present?["present"]), coverage, now);
    }
    public async Task<JsonObject> WatchListAsync(RegistryQuery query, ProblemAccess access, Principal principal, CancellationToken ct)
    {
        var scope = access.Scope("watch.registry");
        var args = new Dictionary<string, object?>(); string predicate = scope.Predicate(args, true);
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var identity = query.EntityId is { } entity ? await AccountIdentity(tx, access, entity, ct) : null;
        string condition = "valid_to is null";
        if (query.Id is { } id) { condition = "id=@id::uuid and (@before::bigint is null or revision<@before::bigint)"; args["id"] = id; args["before"] = query.Cursor; }
        else { condition += " and (@after::uuid is null or id>@after::uuid)"; args["after"] = query.Cursor; }
        if (identity is not null) { condition += " and identity=@identity::jsonb"; args["identity"] = identity.ToJsonString(); }
        var rows = await Rows(tx, $"select * from watch_entry_versions where {predicate} and {condition} order by id,revision desc limit 101", args, ct);
        var now = clock.GetUtcNow();
        var page = Page(rows, query.Id is null ? "id" : "revision", row => {
            var account = row["identity"]!.AsObject();
            try { access.Registry("watch.registry", account); } catch (ProblemException) { return null; }
            var item = ProblemJson.Pick(row, "id", "revision", "identity", "owner", "reason", "active", "active_from", "expires_at", "valid_from", "valid_to", "actor_type", "actor_id");
            item["status"] = !ProblemJson.Bool(row["active"]) ? "disabled" : ProblemJson.Stamp(row["expires_at"], out var expiry) && expiry <= now ? "expired" : "active";
            item["can_manage"] = access.CanManage("watch.registry", account, principal);
            ProblemJson.RawTimes(item, "active_from", "expires_at", "valid_from", "valid_to"); return item;
        });
        page["can_manage"] = identity is not null && access.CanManage("watch.registry", identity, principal);
        await tx.CommitAsync(ct); return page;
    }
    public async Task<JsonObject> WatchSaveAsync(string? id, WatchInput input, ProblemAccess access, Principal principal, CancellationToken ct)
    {
        access.Registry("watch.registry");
        if (principal.Role is not ("operator" or "admin")) throw new ProblemException("watch_access_denied", 403);
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var identity = await AccountIdentity(tx, access, input.EntityId, ct); access.Registry("watch.registry", identity, true, principal);
        await Execute(tx, "select pg_advisory_xact_lock(hashtext(@lock))", new() { ["lock"] = "watch:" + input.EntityId }, ct);
        var args = new Dictionary<string, object?> { ["entity"] = input.EntityId };
        var previous = await One(tx, "select * from watch_entry_versions where entity_id=@entity and valid_to is null for update", args, ct);
        if (previous is not null) access.Registry("watch.registry", previous["identity"]!.AsObject(), true, principal);
        var now = input.DecisionAt; var activeFrom = input.CheckPrevious(previous, id, identity, now);
        id = id is null ? Guid.NewGuid().ToString() : ProblemJson.Uuid(id, "watch_invalid");
        args["id"] = id; args["revision"] = input.Revision; args["now"] = now;
        if (previous is not null) await Execute(tx, "update watch_entry_versions set valid_to=@now where id=@id::uuid and revision=@revision and valid_to is null", args, ct);
        args["identity"] = identity.ToJsonString(); args["scope"] = "ad-domain:" + ProblemJson.Long(identity["domain_id"]);
        args["owner"] = input.Owner; args["reason"] = input.Reason; args["active"] = input.Active; args["from"] = activeFrom;
        args["expires"] = input.Expires; args["type"] = principal.Type; args["actor"] = principal.Id;
        await Execute(tx, """
            insert into watch_entry_versions(id,revision,identity,entity_id,collection_scope_id,owner,reason,active,active_from,expires_at,valid_from,actor_type,actor_id)
            values(@id::uuid,@revision+1,@identity::jsonb,@entity,@scope,@owner,@reason,@active,@from,@expires,@now,@type,@actor)
            """, args, ct);
        await Audit(tx, principal, "watch_entry_update", "watch_entry", id, new() { ["id"] = id, ["revision"] = input.Revision + 1, ["active"] = input.Active }, ct);
        await tx.CommitAsync(ct); return new() { ["item"] = new JsonObject { ["id"] = id, ["revision"] = input.Revision + 1 } };
    }
    public async Task<JsonObject> DecoyListAsync(RegistryQuery query, ProblemAccess access, Principal principal, CancellationToken ct)
    {
        var scope = access.Scope("decoys.registry"); var args = new Dictionary<string, object?>(); string predicate = scope.Predicate(args, false);
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        if (query.Touches)
        {
            args["id"] = query.Id; args["revision"] = query.Revision;
            var label = await One(tx, $"select * from decoy_label_versions where {predicate} and id=@id::uuid and revision=@revision and kind='file'", args, ct)
                ?? throw new ProblemException("decoy_access_denied", 403);
            access.Registry("decoys.registry", label["identity"]!.AsObject(), kind: "file"); args["after"] = query.Cursor;
            var rows = await Rows(tx, "select * from public.read_file_decoy_touches(@id::uuid,@revision,@after)", args, ct);
            return Page(rows, "signal_id", row => {
                var obs = row["observation"]!.AsObject(); var context = row["context"]!.AsObject();
                return new() { ["id"] = row["signal_id"]?.DeepClone(), ["mode"] = row["evaluation_mode"]?.DeepClone(), ["revision"] = context["label_revision"]?.DeepClone(),
                    ["path"] = label["identity"]!["path"]?.DeepClone(), ["observed_at"] = obs["observed_at"]?.DeepClone(), ["event_id"] = obs["event_id"]?.DeepClone(),
                    ["meaning"] = context["meaning"]?.DeepClone(), ["outcome"] = context["outcome"]?.DeepClone(),
                    ["denial_layer"] = ProblemJson.Text(context["outcome"]) == "failure" ? ProblemJson.Long(obs["event_id"]) == 5145 ? "smb" : "ntfs" : null,
                    ["subject_sid"] = obs["facts"]?["subject_user_sid"]?.DeepClone(), ["access_mask"] = obs["facts"]?["access_mask"]?.DeepClone(),
                    ["evidence_key"] = obs["evidence_key"]?.DeepClone(), ["sha256"] = obs["payload_sha256"]?.DeepClone() };
            });
        }
        string condition = "active_to is null";
        if (query.Id is { } id) { condition = "id=@id::uuid and (@before::bigint is null or revision<@before::bigint)"; args["id"] = id; args["before"] = query.Cursor; }
        else { condition += " and (@after::uuid is null or id>@after::uuid)"; args["after"] = query.Cursor; }
        if (query.Revision is { } revision) { condition += " and revision=@revision"; args["revision"] = revision; }
        var labels = await Rows(tx, $"select * from decoy_label_versions where {predicate} and {condition} order by id,revision desc limit 101", args, ct);
        var result = Page(labels, query.Id is null ? "id" : "revision", row => ProblemJson.Pick(row, "id", "revision", "kind", "identity", "owner", "reason", "active", "active_from", "active_to", "actor_type", "actor_id"));
        int index = 0;
        foreach (var item in result["items"]!.AsArray().OfType<JsonObject>())
        {
            var row = labels[index++]!.AsObject(); string kind = ProblemJson.Text(row["kind"]); var identity = row["identity"]!.AsObject();
            item["readiness"] = row["active_to"] is null ? await Readiness(tx, kind, identity, ProblemJson.Bool(row["active"]), clock.GetUtcNow(), ct) : row["readiness"]?.DeepClone();
            item["can_manage"] = access.CanManage("decoys.registry", identity, principal, kind);
            ProblemJson.RawTimes(item, "active_from", "active_to");
        }
        await tx.CommitAsync(ct); return result;
    }
    public async Task<JsonObject> DecoySaveAsync(string? id, DecoyInput input, ProblemAccess access, Principal principal, CancellationToken ct)
    {
        access.Registry("decoys.registry", input.Identity, true, principal, input.Kind); bool updating = id is not null; id ??= Guid.NewGuid().ToString();
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var args = new Dictionary<string, object?> { ["id"] = id, ["lock"] = "decoy:" + id };
        await Execute(tx, "select pg_advisory_xact_lock(hashtext(@lock))", args, ct);
        var previous = await One(tx, "select * from decoy_label_versions where id=@id::uuid and active_to is null for update", args, ct);
        if (previous is not null) access.Registry("decoys.registry", previous["identity"]!.AsObject(), true, principal, ProblemJson.Text(previous["kind"]));
        input.CheckPrevious(previous, updating); var now = clock.GetUtcNow(); var readiness = await Readiness(tx, input.Kind, input.Identity, input.Active, now, ct);
        args["revision"] = input.Revision; args["now"] = now;
        if (previous is not null) await Execute(tx, "update decoy_label_versions set active_to=@now where id=@id::uuid and revision=@revision and active_to is null", args, ct);
        var target = ProblemAccess.Resource(input.Identity, input.Kind);
        args["kind"] = input.Kind; args["identity"] = input.Identity.ToJsonString(); args["owner"] = input.Owner; args["reason"] = input.Reason;
        args["active"] = input.Active; args["type"] = principal.Type; args["actor"] = principal.Id; args["readiness"] = readiness.ToJsonString();
        args["plugin"] = target.PluginId; args["source"] = target.SourceInstanceId; args["device"] = target.DeviceId; args["entity"] = target.EntityId; args["scope"] = target.CollectionScopeId;
        await Execute(tx, """
            insert into decoy_label_versions(id,revision,kind,identity,owner,reason,active,active_from,actor_type,actor_id,readiness,plugin_id,source_instance_id,device_id,entity_id,collection_scope_id)
            values(@id::uuid,@revision+1,@kind,@identity::jsonb,@owner,@reason,@active,@now,@type,@actor,@readiness::jsonb,@plugin,@source,@device,@entity::bigint,@scope)
            """, args, ct);
        await Audit(tx, principal, "decoy_label_update", "decoy_label", id, new() { ["id"] = id, ["revision"] = input.Revision + 1, ["active"] = input.Active, ["readiness"] = readiness["state"]!.DeepClone() }, ct);
        await tx.CommitAsync(ct); return new() { ["item"] = new JsonObject { ["id"] = id, ["revision"] = input.Revision + 1, ["readiness"] = readiness } };
    }
}
