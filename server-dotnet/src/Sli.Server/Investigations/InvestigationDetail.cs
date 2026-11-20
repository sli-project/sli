using System.Data;
using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Infrastructure;

namespace Sli.Server.Investigations;

public sealed record InvestigationEvidenceOptions(string? EventAfter, string? ReferenceAfter, string? AnchorEventId);
public interface IInvestigationDetailRepository
{
    Task<JsonObject> ReadAsync(InvestigationIdentity identity, AccessDecision access, string report, InvestigationEvidenceOptions? page, IInvestigationVpnEvidence vpn, CancellationToken ct);
}

public sealed class InvestigationDetailRepository(IPostgresConnectionFactory connections) : IInvestigationDetailRepository
{
    public async Task<JsonObject> ReadAsync(InvestigationIdentity identity, AccessDecision access, string report, InvestigationEvidenceOptions? page, IInvestigationVpnEvidence vpn, CancellationToken ct)
    {
        var clock=Stopwatch.StartNew();
        try
        {
            await using var connection=await connections.OpenAsync(ct);
            await using var tx=await connection.BeginTransactionAsync(page is null ? IsolationLevel.ReadCommitted : IsolationLevel.RepeatableRead,ct);
            if(page is not null) { await using var cmd=new NpgsqlCommand("set transaction read only",connection,tx); await cmd.ExecuteNonQueryAsync(ct); }
            var sql=new Reader(connection,tx,page is null?null:clock,ct);
            var identityParameter=identity.Id is {} n ? (object)n : identity.PublicId!.Value;
            var identityType=identity.Id.HasValue ? NpgsqlDbType.Numeric : NpgsqlDbType.Uuid;
            var selected=await sql.Scalar($"select id from investigations where {identity.Column}=@identity", c=>c.Parameters.AddWithValue("identity",identityType,identityParameter));
            if(selected is null) throw new InvestigationException("not_found",page is null?$"Investigation {identity.Display} was not found":"Investigation was not found",404);
            long id=Convert.ToInt64(selected);
            if(page is not null) { var groups=await sql.Groups(id); if(!InvestigationList.Allowed(access,report,groups)) throw new InvestigationException("not_found","Investigation was not found",404); }
            var core=await sql.Rows("select id,public_id,title,status,owner,created_by,created_at,updated_at,closed_at from investigations where id=@id",id);
            if(core.Count==0) throw new InvestigationException("not_found",$"Investigation {identity.Display} was not found",404);
            var row=core[0]!.DeepClone().AsObject();


            if(page is null)
            {
                row["events"]=await sql.Rows("select event_db_id,relation_status,added_by,added_at from investigation_events where investigation_id=@id order by added_at desc limit 500",id);
                row["evidence_refs"]=await sql.Rows("select evidence_kind,source_domain_id,reference_id,relation_status,added_by,added_at from investigation_evidence_refs where investigation_id=@id order by added_at desc,evidence_kind,reference_id limit 500",id);
            }
            row["notes"]=await sql.Rows("select id,body,created_by,created_at from investigation_notes where investigation_id=@id order by created_at desc limit 100",id);
            row["audit"]=await sql.Rows("select id,action,actor,payload,created_at from investigation_audit where investigation_id=@id order by created_at desc,id desc limit 200",id);
            if(page is not null) await InvestigationEvidencePage.BuildAsync(sql,row,id,page,domain=>vpn.Allowed(access,domain));
            if(page is not null && clock.Elapsed>=TimeSpan.FromSeconds(8)) throw new InvestigationException("unavailable","Case evidence read budget exceeded",503);
            await tx.CommitAsync(ct); return row;
        }
        catch(NpgsqlException) when(page is not null) { throw new InvestigationException("unavailable","Case evidence is temporarily unavailable",503); }
        catch(TimeoutException) when(page is not null) { throw new InvestigationException("unavailable","Case evidence is temporarily unavailable",503); }
        catch(OperationCanceledException) when(page is not null && !ct.IsCancellationRequested) { throw new InvestigationException("unavailable","Case evidence is temporarily unavailable",503); }
    }

    private sealed class Reader(NpgsqlConnection db,NpgsqlTransaction tx,Stopwatch? clock,CancellationToken ct) : IInvestigationEvidenceSql
    {
        private async Task Budget()
        {
            if(clock is null) return;
            int remaining=(int)(8000-clock.Elapsed.TotalMilliseconds);
            if(remaining<=0) throw new InvestigationException("unavailable","Case evidence read budget exceeded",503);
            await using var command=new NpgsqlCommand("select set_config('statement_timeout',@timeout,true)",db,tx);
            command.Parameters.AddWithValue("timeout",remaining.ToString(System.Globalization.CultureInfo.InvariantCulture));
            await command.ExecuteNonQueryAsync(ct);
        }
        public async Task<object?> Scalar(string statement,Action<NpgsqlCommand> args)
        {
            await Budget(); await using var cmd=new NpgsqlCommand(statement,db,tx); args(cmd); return await cmd.ExecuteScalarAsync(ct);
        }
        public async Task<JsonArray> Rows(string statement,long id,Action<NpgsqlCommand>? args=null)
        {
            await Budget(); await using var cmd=new NpgsqlCommand("select row_to_json(t)::text from ("+statement+") t",db,tx);
            cmd.Parameters.AddWithValue("id",id); args?.Invoke(cmd);
            var result=new JsonArray(); await using var reader=await cmd.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct)) result.Add(JsonNode.Parse(reader.GetString(0))); return result;
        }
        public async Task<IReadOnlyList<IReadOnlyList<AccessResource>>> Groups(long id)
        {
            var rows=await Rows("""
                select linked.event_db_id,source.server_id,source.domain_id,source.channel from investigation_events linked
                left join lateral (select core.server_id,server.domain_id,channel.value as channel from storage_v2_event_identity_allocations core
                  join servers server on server.id=core.server_id join storage_v2_channel channel on channel.id=core.channel_id
                  where core.id=linked.event_db_id) source on true where linked.investigation_id=@id order by linked.event_db_id
                """,id);
            var groups=new List<IReadOnlyList<AccessResource>>(); var events=new HashSet<long>();
            foreach(var node in rows)
            {
                var row=node!.AsObject(); if(!events.Add(row["event_db_id"]!.GetValue<long>())) continue;
                var group=new List<AccessResource>();
                if(row["server_id"] is {} server) group.Add(new("server",server.GetValue<long>()));
                if(row["domain_id"] is {} domain) group.Add(new("domain",domain.GetValue<long>()));
                if(row["channel"] is {} channel && channel.GetValue<string>().Length>0) group.Add(new("channel",Value:channel.GetValue<string>()));
                groups.Add(group);
            }
            rows=await Rows("select distinct source_domain_id from investigation_evidence_refs where investigation_id=@id order by source_domain_id",id);
            foreach(var node in rows) groups.Add([new("domain",node!["source_domain_id"]!.GetValue<long>())]);
            return groups;
        }
    }
}

public interface IInvestigationEvidenceSql
{
    Task<object?> Scalar(string statement,Action<NpgsqlCommand> args);
    Task<JsonArray> Rows(string statement,long id,Action<NpgsqlCommand>? args=null);
}
public static class InvestigationEvidencePage
{
    public static async Task BuildAsync(IInvestigationEvidenceSql sql,JsonObject row,long id,InvestigationEvidenceOptions options,Func<long,bool> allowed)
        {
            var after=InvestigationEvidenceCursor.Event(options.EventAfter); var anchor=InvestigationEvidenceCursor.Event(options.AnchorEventId);
            row["events_total"]=Convert.ToInt64(await sql.Scalar("select count(*) from investigation_events where investigation_id=@id",c=>c.Parameters.AddWithValue("id",id)));
            var events=await sql.Rows("select event_db_id,relation_status,added_by,added_at from investigation_events where investigation_id=@id"+(after is null?"":" and event_db_id<@after")+" order by event_db_id desc limit 101",id,c=>{if(after is {} n)c.Parameters.AddWithValue("after",n);});
            bool more=events.Count>100; if(more) events.RemoveAt(100);
            row["events_next_cursor"]=more?events[^1]!["event_db_id"]!.DeepClone():null;
            row["events"]=events; row["anchor_event"]=null;
            if(anchor is {} anchorId)
            {
                var found=await sql.Rows("select event_db_id,relation_status,added_by,added_at from investigation_events where investigation_id=@id and event_db_id=@anchor",id,c=>c.Parameters.AddWithValue("anchor",anchorId));
                if(found.Count>0) row["anchor_event"]=found[0]!.DeepClone();
            }
            var cursor=InvestigationEvidenceCursor.Reference(options.ReferenceAfter);
            var domains=await sql.Rows("select distinct source_domain_id from investigation_evidence_refs where investigation_id=@id",id);
            var all=domains.Select(n=>n!["source_domain_id"]!.GetValue<long>()).ToArray(); var visible=all.Where(allowed).ToArray();
            row["evidence_refs_state"]=all.Length==visible.Length?"available":"partially_authorized";
            row["evidence_refs"]=new JsonArray(); row["evidence_refs_total"]=0; row["evidence_refs_next_cursor"]=null;
            if(visible.Length>0)
            {
                row["evidence_refs_total"]=Convert.ToInt64(await sql.Scalar("select count(*) from investigation_evidence_refs where investigation_id=@id and source_domain_id=any(@domains)",c=>{c.Parameters.AddWithValue("id",id); c.Parameters.AddWithValue("domains",visible);}));
                var refs=await sql.Rows("select evidence_kind,source_domain_id,reference_id,relation_status,added_by,added_at from investigation_evidence_refs where investigation_id=@id and source_domain_id=any(@domains)"+
                  (cursor is null?"":" and (evidence_kind,source_domain_id,reference_id)>(@kind,@domain,@reference)")+" order by evidence_kind,source_domain_id,reference_id limit 101",id,c=>
                  {
                      c.Parameters.AddWithValue("domains",visible);
                      if(cursor is {} key){c.Parameters.AddWithValue("kind",key.Kind);c.Parameters.AddWithValue("domain",key.Domain);c.Parameters.AddWithValue("reference",key.Reference);}
                  });
                more=refs.Count>100; if(more)refs.RemoveAt(100);
                if(more) {var last=refs[^1]!; row["evidence_refs_next_cursor"]=InvestigationEvidenceCursor.EncodeReference(last["evidence_kind"]!.GetValue<string>(),last["source_domain_id"]!.GetValue<long>(),last["reference_id"]!.GetValue<string>());}
                row["evidence_refs"]=refs;
            }
            row["evidence_page_size"]=100;
    }
}
