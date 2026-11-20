using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Investigations;
using Xunit;

namespace Sli.Server.Tests.Investigations;
public class InvestigationEvidencePageTests
{
    sealed class Sql : IInvestigationEvidenceSql
    {
        public long[]? CountDomains,PageDomains; public int RefReads;
        public Task<object?> Scalar(string statement,Action<NpgsqlCommand> args)
        {
            using var c=new NpgsqlCommand();args(c);
            if(statement.Contains("investigation_evidence_refs")) {CountDomains=(long[])c.Parameters["domains"].Value!;return Task.FromResult<object?>(101L);}
            return Task.FromResult<object?>(101L);
        }
        public Task<JsonArray> Rows(string statement,long id,Action<NpgsqlCommand>? args=null)
        {
            using var c=new NpgsqlCommand();args?.Invoke(c);
            if(statement.Contains("distinct source_domain_id")) return Task.FromResult(new JsonArray(new JsonObject{["source_domain_id"]=1L},new JsonObject{["source_domain_id"]=2L}));
            if(statement.Contains("investigation_evidence_refs"))
            {
                RefReads++;PageDomains=(long[])c.Parameters["domains"].Value!;
                return Task.FromResult(new JsonArray(Enumerable.Range(1,101).Select(i=>(JsonNode?)new JsonObject{["evidence_kind"]="vpn_accounting_session",["source_domain_id"]=1L,["reference_id"]=$"r{i:D3}"}).ToArray()));
            }
            if(statement.Contains("@anchor")) return Task.FromResult(new JsonArray(new JsonObject{["event_db_id"]=50L}));
            return Task.FromResult(new JsonArray(Enumerable.Range(1,101).Select(i=>(JsonNode?)new JsonObject{["event_db_id"]=(long)(102-i)}).ToArray()));
        }
    }
    [Fact]
    public async Task PagesAreCappedAndHiddenDomainsNeverEnterCountsOrRows()
    {
        var sql=new Sql(); var row=new JsonObject();
        await InvestigationEvidencePage.BuildAsync(sql,row,4,new("200",null,"50"),domain=>domain==1);
        Assert.Equal(new long[]{1},sql.CountDomains);Assert.Equal(new long[]{1},sql.PageDomains);
        Assert.Equal("partially_authorized",row["evidence_refs_state"]!.GetValue<string>());
        Assert.Equal(100,row["events"]!.AsArray().Count);Assert.Equal(2L,row["events_next_cursor"]!.GetValue<long>());
        Assert.Equal(50L,row["anchor_event"]!["event_db_id"]!.GetValue<long>());
        Assert.Equal(100,row["evidence_refs"]!.AsArray().Count);Assert.NotNull(row["evidence_refs_next_cursor"]);
    }
    [Fact]
    public async Task NoVisibleDomainsDoNotIssueReferenceCountOrPageSql()
    {
        var sql=new Sql();var row=new JsonObject();await InvestigationEvidencePage.BuildAsync(sql,row,4,new(null,null,null),_=>false);
        Assert.Null(sql.CountDomains);Assert.Equal(0,sql.RefReads);Assert.Equal(0,row["evidence_refs_total"]!.GetValue<int>());Assert.Empty(row["evidence_refs"]!.AsArray());
    }
}
