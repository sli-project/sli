using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;

namespace Sli.Server.Investigations;

public static class InvestigationList
{
    public static int Limit(string? value)
    {
        if (value is null) return 50;
        string input = AssignmentValidation.Strip(value);
        var text = new StringBuilder(); bool previous = false; int count = 0;
        foreach (var rune in input.EnumerateRunes())
        {
            if (rune.Value is '+' or '-' && text.Length == 0) { text.Append((char)rune.Value); continue; }
            if (rune.Value == '_' && previous) { text.Append('_'); previous = false; continue; }
            if (Rune.GetUnicodeCategory(rune) != UnicodeCategory.DecimalDigitNumber) return 50;
            text.Append((char)('0' + (int)Rune.GetNumericValue(rune))); previous = true; count++;
        }
        if (!previous || count > 4300 || !BigInteger.TryParse(text.ToString().Replace("_", ""), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var number)) return 50;
        return (int)BigInteger.Clamp(number, 1, 100);
    }
    // The database projects local wall time and its actual session-zone offset.
    // Python datetime.__str__ omits an all-zero fraction and retains six digits otherwise.
    public static string FormatSessionTimestamp(string local, int offsetSeconds)
    {
        string stamp = local.EndsWith(".000000", StringComparison.Ordinal) ? local[..^7] : local;
        int absolute = Math.Abs(offsetSeconds);
        string offset = string.Create(CultureInfo.InvariantCulture, $"{(offsetSeconds < 0 ? '-' : '+')}{absolute / 3600:00}:{absolute % 3600 / 60:00}");
        if (absolute % 60 != 0) offset += string.Create(CultureInfo.InvariantCulture, $":{absolute % 60:00}");
        return stamp + offset;
    }
    public static string? ReportKey(AccessDecision access) => new[] { "investigations.workspace", "cases.workspace" }
        .FirstOrDefault(key => access.Reports.Any(r => r.ReportKey == key && r.Allowed && r.Grants.Any(g => g.AllowedActions.Contains("view"))));
    public static bool Allowed(AccessDecision access,string key,IReadOnlyList<IReadOnlyList<AccessResource>> groups) =>
        access.Capabilities.DecideForResourceGroups("investigations.view",groups).Allowed && ResourceAccessDecisions.ReportAction(access,key,"view",groups).Allowed;
}

public sealed record InvestigationListRow(long id, Guid? public_id, string title, string status, string? owner, string created_by, string created_at, string updated_at, string? closed_at)
{
    public string case_number => $"INV-{id:D7}";
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public object? status_message { get; init; }
}
public interface IInvestigationListRepository
{
    Task<IReadOnlyList<InvestigationListRow>> ReadAsync(int limit,CancellationToken ct);
    Task<IReadOnlyDictionary<long,IReadOnlyList<IReadOnlyList<AccessResource>>>> GroupsAsync(long[] ids,CancellationToken ct);
}
public sealed class InvestigationListRepository(IPostgresConnectionFactory connections) : IInvestigationListRepository
{
    public async Task<IReadOnlyList<InvestigationListRow>> ReadAsync(int limit,CancellationToken ct)
    {
        await using var connection=await connections.OpenAsync(ct);
        await using var cmd=new NpgsqlCommand("select id, public_id, title, status, owner, created_by, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS.US'), extract(timezone from created_at)::integer, to_char(updated_at, 'YYYY-MM-DD HH24:MI:SS.US'), extract(timezone from updated_at)::integer, to_char(closed_at, 'YYYY-MM-DD HH24:MI:SS.US'), extract(timezone from closed_at)::integer from investigations order by updated_at desc limit @limit",connection);
        cmd.Parameters.AddWithValue("limit",limit);
        await using var reader=await cmd.ExecuteReaderAsync(ct); var result=new List<InvestigationListRow>();
        while(await reader.ReadAsync(ct)) result.Add(new(reader.GetInt64(0),reader.IsDBNull(1)?null:reader.GetGuid(1),reader.GetString(2),reader.GetString(3),reader.IsDBNull(4)?null:reader.GetString(4),reader.GetString(5),Stamp(reader,6)!,Stamp(reader,8)!,Stamp(reader,10)));
        return result;
    }
    private static string? Stamp(NpgsqlDataReader reader,int index) => reader.IsDBNull(index)?null:InvestigationList.FormatSessionTimestamp(reader.GetString(index),reader.GetInt32(index+1));
    public async Task<IReadOnlyDictionary<long,IReadOnlyList<IReadOnlyList<AccessResource>>>> GroupsAsync(long[] ids,CancellationToken ct)
    {
        var result=ids.Distinct().ToDictionary(id=>id,_=>new List<IReadOnlyList<AccessResource>>());
        await using var connection=await connections.OpenAsync(ct);
        if(ids.Length==0) return result.ToDictionary(p=>p.Key,p=>(IReadOnlyList<IReadOnlyList<AccessResource>>)p.Value);
        await using var transaction=await connection.BeginTransactionAsync(ct);
        await using(var cmd=new NpgsqlCommand("""
            select linked.investigation_id,linked.event_db_id,source.server_id,source.domain_id,source.channel
            from investigation_events linked left join lateral (
                select core.server_id,server.domain_id,channel.value as channel from storage_v2_event_identity_allocations core
                join servers server on server.id=core.server_id join storage_v2_channel channel on channel.id=core.channel_id
                where core.id=linked.event_db_id
            ) source on true where linked.investigation_id=any(@ids) order by linked.investigation_id,linked.event_db_id
            """,connection,transaction))
        {
            cmd.Parameters.AddWithValue("ids",ids); await using var reader=await cmd.ExecuteReaderAsync(ct); var seen=new HashSet<(long,long)>();
            while(await reader.ReadAsync(ct))
            {
                long id=reader.GetInt64(0); if(!seen.Add((id,reader.GetInt64(1)))) continue;
                var group=new List<AccessResource>();
                if(!reader.IsDBNull(2)) group.Add(new("server",reader.GetInt64(2)));
                if(!reader.IsDBNull(3)) group.Add(new("domain",reader.GetInt64(3)));
                if(!reader.IsDBNull(4) && reader.GetString(4).Length>0) group.Add(new("channel",Value:reader.GetString(4)));
                result[id].Add(group);
            }
        }
        await using(var cmd=new NpgsqlCommand("select investigation_id,source_domain_id from investigation_evidence_refs where investigation_id=any(@ids) order by investigation_id,source_domain_id,reference_id",connection,transaction))
        {
            cmd.Parameters.AddWithValue("ids",ids); await using var reader=await cmd.ExecuteReaderAsync(ct); var seen=new HashSet<(long,long)>();
            while(await reader.ReadAsync(ct)) {long id=reader.GetInt64(0), domain=reader.GetInt64(1); if(seen.Add((id,domain))) result[id].Add([new("domain",domain)]);}
        }
        await transaction.CommitAsync(ct);
        return result.ToDictionary(p=>p.Key,p=>(IReadOnlyList<IReadOnlyList<AccessResource>>)p.Value);
    }
}
public static class InvestigationListEndpoints
{
    public static IServiceCollection AddInvestigationList(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository,AccessFactsRepository>();
        services.TryAddScoped<IInvestigationListRepository,InvestigationListRepository>();
        return services;
    }
    public static IEndpointRouteBuilder MapInvestigationList(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/investigation-cases",InvestigationEndpoints.HandleDisabledAsync);
        return endpoints;
    }
    private static Dictionary<string,string> Catalog(string locale)
    {
        using var stream=typeof(InvestigationListEndpoints).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server."+locale+".json") ?? throw new InvalidOperationException("Presentation catalog missing");
        return JsonSerializer.Deserialize<Dictionary<string,string>>(stream) ?? throw new InvalidOperationException("Invalid presentation catalog");
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct=context.RequestAborted;
        try
        {
            var services=context.RequestServices; var failure=services.GetRequiredService<TransportGate>().CheckTransport(context);
            if(failure is not null) {await DomainHttp.WriteFailureAsync(context,failure,ct); return;}
            var policy=services.GetRequiredService<AuthRequestPolicy>(); Principal principal;
            if(policy.AuthRequired)
            {
                var auth=await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context,ct);
                if(!auth.Succeeded) {await DomainHttp.WriteFailureAsync(context,auth.Failure??new(401,"authentication_required"),ct); return;}
                principal=auth.Principal!;
                if(TransportGate.CheckViewerRole(principal) is { } roleFailure) {await DomainHttp.WriteFailureAsync(context,roleFailure,ct);return;}
            }
            else principal=new("",0,"operator");
            var facts=await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal,ct);
            var caps=new CapabilityComposer().Compose(facts); var access=new ReportEligibility().Compose(facts,caps);
            string? report=InvestigationList.ReportKey(access);
            if(report is null) {await DomainHttp.WriteAsync(context,new {error="report_not_assigned",required_report="investigations.workspace",required_action="view"},403,ct);return;}
            if(!caps.Capabilities.Contains("investigations.view") && !caps.ResourceCapabilities.Contains("investigations.view"))
            {await DomainHttp.WriteAsync(context,new {error="insufficient_capability",required_capability="investigations.view"},403,ct);return;}
            string? raw=context.Request.Query.TryGetValue("limit",out var values) ? values.FirstOrDefault(v=>!string.IsNullOrEmpty(v)) : null;
            int limit=InvestigationList.Limit(raw); var repo=services.GetRequiredService<IInvestigationListRepository>();
            var rows=await repo.ReadAsync(limit,ct); var groups=await repo.GroupsAsync(rows.Select(r=>r.id).ToArray(),ct);
            var visible=rows.Where(row=>InvestigationList.Allowed(access,report,groups.TryGetValue(row.id,out var group)?group:[])).ToArray();
            var catalog=Catalog(DomainHttp.SelectEnglish(context.Request.Headers.AcceptLanguage.ToString()) ? "en" : "ru");
            var presented=visible.Select(row=>catalog.TryGetValue("investigations.caseStatus."+row.status,out var label) ? row with {status_message=new {code="investigations.caseStatus."+row.status,@params=new {},text=label}} : row).ToArray();
            await DomainHttp.WriteAsync(context,new {items=presented,limit,scope_filtered=visible.Length!=rows.Count},200,ct);
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { }
        catch(Exception error) {if(context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context,error,ct,login:false);}
    }
}
