using System.Numerics;
using System.Text;
using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Investigations;

public sealed class InvestigationLinksRepository(IPostgresConnectionFactory connections) : IInvestigationLinksRepository
{
    internal static async Task<JsonObject> Finding(NpgsqlConnection db, NpgsqlTransaction tx, BigInteger finding, CancellationToken ct)
    {
        if (finding <= 0) throw new InvestigationException("invalid_finding_id", "Finding ID must be positive");
        var rows = await Rows(db, tx, "select id,rule_code,title,status from findings where id=@finding", c => Number(c, "finding", finding), ct);
        return rows.FirstOrDefault() ?? throw new InvestigationException("finding_not_found", $"Finding {finding} was not found", 404);
    }
    static async Task<long[]> Events(NpgsqlConnection db, NpgsqlTransaction tx, BigInteger finding, CancellationToken ct) =>
        (await Rows(db, tx, "select distinct fe.event_id from finding_evidence fe join storage_v2_event_identity_allocations core on core.id=fe.event_id where fe.finding_id=@finding order by fe.event_id desc limit 200", c => Number(c, "finding", finding), ct))
        .Select(r => r["event_id"]!.GetValue<long>()).ToArray();
    public async Task<long[]> FindingEventsAsync(BigInteger finding, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        await Finding(db, tx, finding, ct); var events = await Events(db, tx, finding, ct); await tx.CommitAsync(ct); return events;
    }
    public async Task<JsonObject> LinkFindingAsync(InvestigationIdentity? identity, BigInteger finding, string actor, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        // The source uses the two-int namespace 149 advisory lock.
        await Execute(db, tx, "select pg_advisory_xact_lock(149,@finding::integer)", c => Number(c, "finding", finding), ct);
        var problem = await Finding(db, tx, finding, ct);
        JsonObject? current = identity is null ? null : await InvestigationCaseMutationRepository.ReadCase(db, tx, identity, ct);
        if (current?["status"]?.ToString() == "closed") throw new InvestigationException("investigation_case_closed", "A closed investigation cannot receive findings", 409);
        var linked = await Rows(db, tx, "select investigation_id from investigation_finding_links where finding_id=@finding", c => Number(c, "finding", finding), ct);
        if (linked.Count > 0)
        {
            long linkedId = linked[0]["investigation_id"]!.GetValue<long>();
            throw new InvestigationException("finding_already_linked", $"Finding is already linked to investigation {linkedId}", 409) { InvestigationId = linkedId };
        }
        long id;
        if (current is null)
        {
            string label = (problem["title"]?.ToString() ?? "").Trim();
            if (label.Length == 0) label = (problem["rule_code"]?.ToString() ?? "").Trim();
            if (label.Length == 0) label = "Проблема";
            string title = string.Concat($"Проблема #{finding}: {label}".EnumerateRunes().Take(300).Select(r => r.ToString()));
            var rows = await Rows(db, tx, "insert into investigations(public_id,title,owner,created_by) values(@public,@title,@actor,@actor) returning id", c =>
            { c.Parameters.AddWithValue("public", Guid.NewGuid()); c.Parameters.AddWithValue("title", title); c.Parameters.AddWithValue("actor", actor); }, ct);
            id = rows[0]["id"]!.GetValue<long>();
            await Execute(db, tx, "insert into investigation_audit(investigation_id,action,actor) values(@id,'created',@actor)", c => CaseActor(c, id, actor), ct);
        }
        else id = current["id"]!.GetValue<long>();
        await AttachFindingAsync(db, tx, id, finding, actor, ct);
        var result = await InvestigationCaseMutationRepository.ReadCase(db, tx, new(id, null), ct);
        await tx.CommitAsync(ct); return result;
    }
    internal static Task AttachAsync(NpgsqlConnection db, NpgsqlTransaction tx, long id, BigInteger finding, string actor, CancellationToken ct)
        => AttachFindingAsync(db, tx, id, finding, actor, ct);
    internal static async Task AttachFindingAsync(NpgsqlConnection db, NpgsqlTransaction tx, long id, BigInteger finding, string actor, CancellationToken ct)
    {
        await using (var isolation = new NpgsqlCommand("show transaction_isolation", db, tx))
            if ((string?)await isolation.ExecuteScalarAsync(ct) != "read committed")
                throw new InvestigationException("evidence_write_requires_read_committed", "Investigation evidence writes require READ COMMITTED isolation");
        await Execute(db, tx, "lock table investigation_events in row exclusive mode", _ => { }, ct);
        await Execute(db, tx, "insert into investigation_finding_links(investigation_id,finding_id,linked_by) values(@id,@finding,@actor)", c => { CaseActor(c, id, actor); Number(c, "finding", finding); }, ct);
        int copied = 0;
        foreach (long ev in await Events(db, tx, finding, ct))
            copied += (await Rows(db, tx, "insert into investigation_events(investigation_id,event_db_id,relation_status,added_by) values(@id,@event,'confirmed',@actor) on conflict(investigation_id,event_db_id) do nothing returning event_db_id", c =>
            { CaseActor(c, id, actor); c.Parameters.AddWithValue("event", ev); }, ct)).Count;
        await Execute(db, tx, "update investigations set updated_at=now() where id=@id", c => c.Parameters.AddWithValue("id", id), ct);
        await Execute(db, tx, "insert into investigation_audit(investigation_id,action,actor,payload) values(@id,'finding_linked',@actor,jsonb_build_object('finding_id',@finding::bigint,'events_copied',@copied::int))", c =>
        { CaseActor(c, id, actor); Number(c, "finding", finding); c.Parameters.AddWithValue("copied", copied); }, ct);
    }
    public async Task<JsonObject> AddEvidenceAsync(InvestigationIdentity identity, InvestigationEvidenceInput input, string actor, CancellationToken ct)
    {
        input.Validate();
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var current = await InvestigationCaseMutationRepository.ReadCase(db, tx, identity, ct); long id = current["id"]!.GetValue<long>();
        void Parameters(NpgsqlCommand c)
        { c.Parameters.AddWithValue("id", id); c.Parameters.AddWithValue("kind", input.Kind); Number(c, "domain", input.Domain); c.Parameters.AddWithValue("reference", input.Reference); }
        var exists = await Rows(db, tx, "select session_row_id from radius_vpn_session_rows_v1 where domain_id=@domain and session_row_id=@reference limit 1", c => { Number(c, "domain", input.Domain); c.Parameters.AddWithValue("reference", input.Reference); }, ct);
        if (exists.Count == 0) throw new InvestigationException("not_found", "Investigation evidence was not found", 404);
        const string fields = "evidence_kind,source_domain_id,reference_id,relation_status,added_by,added_at";
        var rows = await Rows(db, tx, "insert into investigation_evidence_refs(investigation_id,evidence_kind,source_domain_id,reference_id,relation_status,added_by) values(@id,@kind,@domain,@reference,@relation,@actor) on conflict(investigation_id,evidence_kind,source_domain_id,reference_id) do nothing returning " + fields, c =>
        { Parameters(c); c.Parameters.AddWithValue("relation", input.Relation); c.Parameters.AddWithValue("actor", actor); }, ct);
        if (rows.Count == 0)
        {
            rows = await Rows(db, tx, "select " + fields + " from investigation_evidence_refs where investigation_id=@id and evidence_kind=@kind and source_domain_id=@domain and reference_id=@reference", Parameters, ct);
            if (rows.Count == 0 || rows[0]["relation_status"]?.ToString() != input.Relation)
                throw new InvestigationException("conflict", "Evidence already exists with a different relation status", 409);
            rows[0]["idempotent_replay"] = true;
        }
        else
        {
            await Execute(db, tx, "update investigations set updated_at=now() where id=@id", c => c.Parameters.AddWithValue("id", id), ct);
            await Execute(db, tx, "insert into investigation_audit(investigation_id,action,actor,payload) values(@id,'evidence_ref_linked',@actor,jsonb_build_object('evidence_kind',@kind::text,'source_domain_id',@domain::bigint,'reference_id',@reference::text,'relation_status',@relation::text))", c =>
            { Parameters(c); c.Parameters.AddWithValue("actor", actor); c.Parameters.AddWithValue("relation", input.Relation); }, ct);
        }
        if (rows[0]["added_at"] is { } timestamp)
        {
            var time = DateTimeOffset.Parse(timestamp.ToString(), CultureInfo.InvariantCulture);
            rows[0]["added_at"] = time.ToString(time.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd HH:mm:sszzz" : "yyyy-MM-dd HH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture);
        }
        await tx.CommitAsync(ct); return rows[0];
    }
    internal static void Number(NpgsqlCommand c, string name, BigInteger n) => c.Parameters.AddWithValue(name, NpgsqlDbType.Numeric, n);
    static void CaseActor(NpgsqlCommand c, long id, string actor) { c.Parameters.AddWithValue("id", id); c.Parameters.AddWithValue("actor", actor); }
    internal static async Task<List<JsonObject>> Rows(NpgsqlConnection db, NpgsqlTransaction tx, string sql, Action<NpgsqlCommand> parameters, CancellationToken ct)
    {
        await using var c = new NpgsqlCommand("select row_to_json(r)::text from (" + sql + ") r", db, tx);
        // INSERT ... RETURNING needs a data-modifying CTE, rather than a subquery.
        if (sql.StartsWith("insert ", StringComparison.Ordinal)) c.CommandText = "with r as (" + sql + ") select row_to_json(r)::text from r";
        parameters(c); await using var reader = await c.ExecuteReaderAsync(ct); var rows = new List<JsonObject>();
        while (await reader.ReadAsync(ct)) rows.Add(JsonNode.Parse(reader.GetString(0))!.AsObject()); return rows;
    }
    internal static async Task Execute(NpgsqlConnection db, NpgsqlTransaction tx, string sql, Action<NpgsqlCommand> parameters, CancellationToken ct)
    { await using var c = new NpgsqlCommand(sql, db, tx); parameters(c); await c.ExecuteNonQueryAsync(ct); }
}
