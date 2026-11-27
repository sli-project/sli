using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Access;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Domains;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting.V2;

namespace Sli.Server.Agents.FileAudit;

internal static class FileAuditCatalog
{
    internal const string AdminRoute = "/api/v1/admin/agents/file-audit/catalog";
    internal const string ReportRoute = "/api/v1/agent/file-audit-catalog-report";
    internal const string SupportHeader = "X-SLI-File-Audit-Catalog";
    private const string Source = "coalesce(to_jsonb(a)->>'source_host_id',a.host_id::text)";
    private const string Table = "public.sli_file_audit_smb_catalog";
    private sealed record Share(string Name, string Path);
    private sealed record Item(string share_name, string path, string collection_scope_id);
    private sealed record Selection(Item Item, JsonObject? Command);

    internal static string ScopeId(string source, string share, string path) => AuthAudit.Uuid5("sli:file-audit:smb:v1:" +
        JsonSerializer.Serialize(new[] { source, share.ToUpperInvariant(), path.ToUpperInvariant() })).ToString("D");

    internal static bool IsAdministrativeShare(string name, string path) =>
        name.ToUpperInvariant() is "ADMIN$" or "IPC$" or "PRINT$" or "FAX$"
        || name.Length == 2 && name[1] == '$' && path.Length == 3
            && char.ToUpperInvariant(name[0]) == char.ToUpperInvariant(path[0]);

    private static async Task<bool> CacheAvailable(NpgsqlConnection db, NpgsqlTransaction? tx, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("""
            select exists(select 1 from pg_attribute where attrelid=to_regclass('public.sli_file_audit_smb_catalog')
                and attname='cached_at' and not attisdropped)
            """, db, tx);
        return await query.ExecuteScalarAsync(ct) is true;
    }

    internal static Task Admin(HttpContext context) => AgentControlEndpoints.HandleAsync(
        context, AdminRoute, maxBodyBytes: 1024, noStoreOnly: true,
        authorizedOperation: (db, tx, body, principal, access, ct) =>
        {
            bool request = HttpMethods.IsPost(context.Request.Method);
            var query = context.Request.Query;
            if (request && query.Count == 0 && Exactly(body))
                return RefreshDueAsync(db, tx, principal, access, ct);
            string? id = request
                ? Exactly(body, "agent_id") ? AgentControlJson.String(body.GetProperty("agent_id")) : null
                : query.Count == 1 && query["agent_id"].Count == 1 ? query["agent_id"][0] : null;
            if (request && query.Count > 0 || !Guid.TryParseExact(id, "D", out var agent) || agent == Guid.Empty)
                throw Invalid();
            return ReadOrRequestAsync(db, tx, agent, request, principal, access, ct);
        });

    private static async Task<JsonElement> RefreshDueAsync(NpgsqlConnection db, NpgsqlTransaction tx,
        Principal principal, CapabilityDecisionSet access, CancellationToken ct)
    {
        if (!await CacheAvailable(db, tx, ct)) return JsonSerializer.SerializeToElement(new { });
        var due = new List<Guid>();
        var scopes = FileAuditAccess.DiscoveryScopes(access).ToArray();
        await using (var read = new NpgsqlCommand($"""
            select a.id,c.source_id from {Table} c join public.sli_agents a on a.id=c.agent_id and {Source}=c.source_id
            where a.status='active' and c.supported_until>clock_timestamp()
                and (c.expires_at is null or c.expires_at<=clock_timestamp())
                and (c.cached_at is null or c.cached_at<=clock_timestamp()-interval '10 minutes')
            order by a.id limit 1000
            """, db, tx))
        await using (var rows = await read.ExecuteReaderAsync(ct))
            while (await rows.ReadAsync(ct))
            {
                var agent = rows.GetGuid(0);
                var source = rows.GetString(1);
                if (scopes.Any(scope => FileAuditAccess.Allowed(access, principal.Role, principal.Type, principal.Id, agent.ToString("D"), source, scope)))
                    due.Add(agent);
            }
        if (due.Count > 0)
        {
            await using var refresh = new NpgsqlCommand($"""
                update {Table} c set request_id=gen_random_uuid(), expires_at=clock_timestamp()+interval '5 minutes',
                    result_status=null,native_status=null,shares='[]'::jsonb
                from public.sli_agents a
                where a.id=c.agent_id and a.status='active' and {Source}=c.source_id and a.id=any(@agents)
                    and c.supported_until>clock_timestamp() and (c.expires_at is null or c.expires_at<=clock_timestamp())
                    and (c.cached_at is null or c.cached_at<=clock_timestamp()-interval '10 minutes')
                """, db, tx);
            refresh.Parameters.AddWithValue("agents", due.ToArray());
            await refresh.ExecuteNonQueryAsync(ct);
        }
        return JsonSerializer.SerializeToElement(new { });
    }

    private static async Task<JsonElement> ReadOrRequestAsync(NpgsqlConnection db, NpgsqlTransaction tx,
        Guid agent, bool request, Principal principal, CapabilityDecisionSet access, CancellationToken ct)
    {
        string source;
        await using (var command = new NpgsqlCommand($"""
            select {Source} from public.sli_agents a where a.id=@agent and a.status='active'
            """, db, tx))
        {
            command.Parameters.AddWithValue("agent", agent);
            source = await command.ExecuteScalarAsync(ct) as string ?? throw Denied();
        }
        bool Allowed(string scope) =>
            FileAuditAccess.Allowed(access, principal.Role, principal.Type, principal.Id, agent.ToString("D"), source, scope);
        if (!FileAuditAccess.DiscoveryScopes(access).Any(Allowed)) throw Denied();

        if (request)
        {
            await using var refresh = new NpgsqlCommand($"""
                update {Table} c
                set request_id=@request, expires_at=clock_timestamp()+interval '5 minutes',
                    result_status=null, native_status=null, shares='[]'::jsonb
                from public.sli_agents a
                where a.id=c.agent_id and a.status='active' and {Source}=c.source_id
                  and c.agent_id=@agent and c.source_id=@source and c.supported_until>clock_timestamp()
                  and (c.request_id is null or c.expires_at<=clock_timestamp() or c.result_status is not null)
                """, db, tx);
            refresh.Parameters.AddWithValue("agent", agent);
            refresh.Parameters.AddWithValue("source", source);
            refresh.Parameters.AddWithValue("request", Guid.NewGuid());
            await refresh.ExecuteNonQueryAsync(ct);
        }

        string state;
        Share[] shares;
        long? nativeStatus;
        JsonObject audit;
        JsonArray modules;
        bool cache = await CacheAvailable(db, tx, ct);
        string hasCache = cache ? "c.cached_at is not null" : "false";
        string cachedShares = cache ? "case when c.cached_at is not null then c.cached_shares else c.shares end" : "c.shares";
        await using (var read = new NpgsqlCommand($"""
            select case
                when c.supported_until is null or c.supported_until<=clock_timestamp() then 'unsupported'
                when {hasCache} then 'ready'
                when c.request_id is null then 'idle'
                when c.expires_at<=clock_timestamp() then 'expired'
                else coalesce(c.result_status,'pending') end,
                {cachedShares},
                a.file_audit, a.assigned_modules, c.native_status
            from public.sli_agents a left join {Table} c on c.agent_id=a.id and c.source_id={Source}
            where a.status='active' and a.id=@agent and {Source}=@source
            """, db, tx))
        {
            read.Parameters.AddWithValue("agent", agent);
            read.Parameters.AddWithValue("source", source);
            await using var reader = await read.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) throw Denied();
            state = reader.GetString(0);
            shares = state == "ready" ? JsonSerializer.Deserialize<Share[]>(reader.GetString(1))! : [];
            audit = JsonNode.Parse(reader.GetString(2))!.AsObject();
            modules = JsonNode.Parse(reader.GetString(3))!.AsArray();
            nativeStatus = state is ("unavailable" or "incomplete") && !reader.IsDBNull(4) ? reader.GetInt64(4) : null;
        }

        var requestState = audit["request"] as JsonObject;
        var commandState = requestState?["command"] as JsonObject;
        var assigned = modules.OfType<JsonObject>().FirstOrDefault(x => x["module_id"]?.ToString() == FileAuditPolicy.ModuleId);
        var saved = new List<Selection>();
        foreach (var (config, savedCheck) in new (JsonNode?, JsonObject?)[] { (requestState?["config"], commandState), (assigned?["config"], null) })
        {
            var roots = Roots(config, savedCheck).ToArray();
            if (roots.Length == 0 || !long.TryParse(config?["policy_revision"]?.ToString(), out long revision))
                continue;
            await using var binding = new NpgsqlCommand("""
                select sli_plugin_file_audit.catalog_policy_matches(@agent,@source,@revision,@policy::jsonb)
                """, db, tx);
            binding.Parameters.AddWithValue("agent", agent);
            binding.Parameters.AddWithValue("source", source);
            binding.Parameters.AddWithValue("revision", revision);
            binding.Parameters.AddWithValue("policy", config!.ToJsonString());
            if (await binding.ExecuteScalarAsync(ct) is true) saved.AddRange(roots);
        }
        Item Project(Share share)
        {
            var retained = saved.FirstOrDefault(x =>
                string.Equals(x.Item.share_name, share.Name, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(x.Item.path, share.Path, StringComparison.OrdinalIgnoreCase));
            var scope = retained?.Item.collection_scope_id ?? ScopeId(source, share.Name, share.Path);
            return new(share.Name, share.Path, scope);
        }
        var selected = saved.FirstOrDefault(x => Allowed(x.Item.collection_scope_id));
        var savedCommand = selected?.Command;
        return JsonSerializer.SerializeToElement(new
        {
            state,
            native_status = nativeStatus,
            items = shares.Select(Project).Where(x => Allowed(x.collection_scope_id)).ToArray(),
            saved_selection = selected?.Item,
            saved_report_share_key = selected is null ? null : FileAuditReportReader.ShareKey(new JsonObject
            {
                ["agent_id"] = agent.ToString("D"),
                ["source_instance_id"] = source,
                ["collection_scope_id"] = selected.Item.collection_scope_id
            }),
            saved_command = savedCommand is null ? null : new
            {
                action = savedCommand["action"],
                command_id = savedCommand["command_id"],
                policy_revision = savedCommand["policy_revision"],
                collection_scope_ids = savedCommand["collection_scope_ids"]
            }
        });
    }

    private static IEnumerable<Selection> Roots(JsonNode? config, JsonObject? command)
    {
        if (config is not JsonObject policy || (policy["source_kind"]?.ToString() ?? "server") != "server"
            || policy["roots"] is not JsonArray roots)
            yield break;
        foreach (var root in roots.OfType<JsonObject>())
        {
            if (root["share_name"] is not JsonValue name || !name.TryGetValue<string>(out var share)
                || root["path"] is not JsonValue local || !local.TryGetValue<string>(out var path)
                || root["collection_scope_id"] is not JsonValue scope || !scope.TryGetValue<string>(out var id))
                continue;
            var matching = command is not null && command["action"]?.ToString() is ("check" or "apply")
                && command["collection_scope_ids"] is JsonArray ids && ids.Any(value => value?.ToString() == id);
            yield return new(new(share, FileAuditPolicy.LocalPath(path), id), matching ? command : null);
        }
    }

    internal static async Task<JsonObject?> PollAsync(NpgsqlConnection db, Guid agent, CancellationToken ct)
    {
        bool cache = await CacheAvailable(db, null, ct);
        var resetCache = cache ? """
            , cached_shares=case when catalog.source_id=excluded.source_id then catalog.cached_shares else '[]'::jsonb end
            , cached_at=case when catalog.source_id=excluded.source_id then catalog.cached_at end
            """ : "";
        await using (var advertise = new NpgsqlCommand($"""
            insert into {Table} as catalog (agent_id,source_id,supported_until)
            select a.id,{Source},clock_timestamp()+interval '15 minutes'
            from public.sli_agents a where a.id=@agent and a.status='active'
            on conflict (agent_id) do update set
                source_id=excluded.source_id, supported_until=excluded.supported_until,
                request_id=case when catalog.source_id=excluded.source_id then catalog.request_id end,
                expires_at=case when catalog.source_id=excluded.source_id then catalog.expires_at end,
                result_status=case when catalog.source_id=excluded.source_id then catalog.result_status end,
                native_status=case when catalog.source_id=excluded.source_id then catalog.native_status end,
                shares=case when catalog.source_id=excluded.source_id then catalog.shares else '[]'::jsonb end
                {resetCache}
            where catalog.source_id<>excluded.source_id or catalog.supported_until<clock_timestamp()+interval '14 minutes'
            """, db))
        {
            advertise.Parameters.AddWithValue("agent", agent);
            await advertise.ExecuteNonQueryAsync(ct);
        }
        if (cache)
        {
            await using var refresh = new NpgsqlCommand($"""
                update {Table} c
                set request_id=@request,expires_at=clock_timestamp()+interval '5 minutes',
                    result_status=null,native_status=null,shares='[]'::jsonb
                from public.sli_agents a
                where c.agent_id=@agent and a.id=c.agent_id and a.status='active' and {Source}=c.source_id
                    and (c.expires_at is null or c.expires_at<=clock_timestamp())
                    and (c.cached_at is null or c.cached_at<=clock_timestamp()-interval '10 minutes')
                """, db);
            refresh.Parameters.AddWithValue("agent", agent);
            refresh.Parameters.AddWithValue("request", Guid.NewGuid());
            await refresh.ExecuteNonQueryAsync(ct);
        }
        await using var read = new NpgsqlCommand($"""
            select c.request_id, c.expires_at
            from {Table} c join public.sli_agents a on a.id=c.agent_id
            where a.status='active' and {Source}=c.source_id and c.agent_id=@agent
              and c.result_status is null and c.expires_at>clock_timestamp()
            """, db);
        read.Parameters.AddWithValue("agent", agent);
        await using var reader = await read.ExecuteReaderAsync(ct);
        return !await reader.ReadAsync(ct) ? null : new JsonObject
        {
            ["request_id"] = reader.GetGuid(0).ToString("D"),
            ["expires_at"] = AgentControlJson.Stamp(new DateTimeOffset(reader.GetDateTime(1)), iso: true)
        };
    }

    internal static async Task Report(HttpContext context)
    {
        var ct = context.RequestAborted;
        var raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? context.Request.Path.Value ?? "";
        if (raw.Split('?', 2)[0] != ReportRoute)
        {
            await DomainHttp.WriteAsync(context, new { error = "not_implemented" }, 501, ct);
            return;
        }
        context.Response.Headers.CacheControl = "no-store";
        try
        {
            var services = context.RequestServices;
            var peer = context.Request.IsHttps ? await context.Connection.GetClientCertificateAsync(ct) : null;
            if (peer is null || services.GetService<AgentTlsTrust>() is null)
                throw new AgentCertificateException("agent_mtls_required", 401);
            using var body = await AuthJsonBody.ReadAsync(context, ct);
            var (request, status, shares, nativeStatus) = ParseReport(body.RootElement);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(2));
            var work = deadline.Token;
            await using var db = await services.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(work);
            await using var tx = await db.BeginTransactionAsync(work);
            var identity = await services.GetRequiredService<AgentIdentityService>().AuthenticateAsync(db, tx, peer, false, work);
            var updateCache = await CacheAvailable(db, tx, work) ? """
                , cached_shares=case when @status='ready' then @shares::jsonb else c.cached_shares end
                , cached_at=case when @status='ready' and c.result_status is null then clock_timestamp() else c.cached_at end
                """ : "";
            await using var command = new NpgsqlCommand($"""
                update {Table} c set result_status=@status,shares=@shares::jsonb,native_status=@native
                {updateCache}
                from public.sli_agents a
                where a.id=c.agent_id and a.status='active' and {Source}=c.source_id
                  and c.agent_id=@agent and c.request_id=@request and c.expires_at>clock_timestamp()
                  and (c.result_status is null or (c.result_status=@status and c.shares=@shares::jsonb
                    and c.native_status is not distinct from @native))
                """, db, tx);
            command.Parameters.AddWithValue("agent", identity.Id);
            command.Parameters.AddWithValue("request", request);
            command.Parameters.AddWithValue("status", status);
            command.Parameters.AddWithValue("shares", JsonSerializer.Serialize(shares));
            command.Parameters.Add("native", NpgsqlTypes.NpgsqlDbType.Bigint).Value = (object?)nativeStatus ?? DBNull.Value;
            if (await command.ExecuteNonQueryAsync(work) != 1)
                throw new AgentControlException("file_audit_catalog_request_conflict", 409);
            await tx.CommitAsync(work);
            await DomainHttp.WriteAsync(context, new { status = "accepted" }, 200, ct);
        }
        catch (AuthInputException e) { await DomainHttp.WriteAsync(context, new { error = e.Code }, e.StatusCode, ct); }
        catch (AgentCertificateException e) { await DomainHttp.WriteAsync(context, new { error = e.Code }, e.Status, ct); }
        catch (AgentControlException e) { await DomainHttp.WriteAsync(context, new { error = e.Message }, e.Status, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception e) when (!context.Response.HasStarted && (e is NpgsqlException or OperationCanceledException or TimeoutException))
        { await DomainHttp.WriteAsync(context, new { error = "file_audit_catalog_unavailable" }, 503, ct); }
    }

    private static (Guid Request, string Status, Share[] Shares, long? NativeStatus) ParseReport(JsonElement body)
    {
        bool hasNativeStatus = body.ValueKind == JsonValueKind.Object && body.TryGetProperty("native_status", out _);
        if (!(hasNativeStatus ? Exactly(body, "request_id", "status", "shares", "native_status")
                : Exactly(body, "request_id", "status", "shares")) ||
            !Guid.TryParseExact(AgentControlJson.String(body.GetProperty("request_id")), "D", out var request) || request == Guid.Empty ||
            AgentControlJson.String(body.GetProperty("status")) is not ("ready" or "incomplete" or "unavailable") ||
            body.GetProperty("shares") is not { ValueKind: JsonValueKind.Array } rows || rows.GetArrayLength() > 128)
            throw Invalid();
        string status = body.GetProperty("status").GetString()!;
        if (status != "ready" && rows.GetArrayLength() != 0) throw Invalid();
        long? nativeStatus = null;
        if (hasNativeStatus)
        {
            var native = body.GetProperty("native_status");
            if (status == "ready" || native.ValueKind != JsonValueKind.Number
                || !native.TryGetUInt32(out var code) || code == 0) throw Invalid();
            nativeStatus = code;
        }
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var shares = new List<Share>();
        foreach (var row in rows.EnumerateArray())
        {
            if (!Exactly(row, "share_name", "path") || AgentControlJson.String(row.GetProperty("share_name")) is not { Length: >= 1 and <= 80 } name ||
                name.Trim() != name || name.Any(c => c < 32 || "\\/:*?\"<>|".Contains(c)) || !names.Add(name) ||
                AgentControlJson.String(row.GetProperty("path")) is not string path)
                throw Invalid();
            string local;
            try { local = FileAuditPolicy.LocalPath(path); }
            catch (AgentException) { throw Invalid(); }
            if (IsAdministrativeShare(name, local))
                continue;
            shares.Add(new(name, local));
        }
        return (request, status, shares.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToArray(), nativeStatus);
    }

    private static bool Exactly(JsonElement value, params string[] keys) =>
        value.ValueKind == JsonValueKind.Object && value.EnumerateObject().Count() == keys.Length
        && keys.All(key => value.TryGetProperty(key, out _));

    private static AgentControlException Invalid() => new("file_audit_catalog_invalid");
    private static AgentControlException Denied() => new("file_audit_catalog_denied", 403);
}
