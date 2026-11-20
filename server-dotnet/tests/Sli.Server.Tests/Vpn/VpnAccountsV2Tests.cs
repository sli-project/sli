using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Sli.Server.Access;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

// Input/output vectors from tests/reporting/test_vpn_accounts_v2.py.
public sealed class VpnAccountsV2Tests
{
    static CancellationToken Ct=>TestContext.Current.CancellationToken;
    static JsonObject Json(object value)=>VpnRouteTests.Json(value);
    static string Text(JsonNode? node)=>node?.ToString()??"";
    static long Number(JsonNode? node)=>long.Parse(Text(node),CultureInfo.InvariantCulture);
    static readonly (string Key,string Category)[] Fields=[("object_id","identity_basic"),("display_name","identity_basic"),
        ("natural_key","technical"),("enabled","security"),("activity_state","security"),
        ("department","hr"),("password_never_expires","security"),("privileged_overlap","privilege")];
    static AccessFacts Facts(string[]? categories=null)
    {
        categories??=["identity_basic","technical","security"];
        var facts=VpnRouteTests.MakeFacts(false);
        return facts with {
            DirectCapabilities=categories.Select(c=>JsonSerializer.SerializeToElement(new {capability_key="field."+c,effect="allow",scope_json=new {kind="all"}}))
                .Append(JsonSerializer.SerializeToElement(new {capability_key="reports.export",effect="allow",scope_json=new {kind="all"}})).ToArray(),
            ReportAssignments=[JsonSerializer.SerializeToElement(new {report_key="vpn.audit",effect="allow",allowed_actions=new[]{"view","export"},field_categories=categories,scope_json=new {kind="domain",ids=new[]{7}}})],
            Definitions=[JsonSerializer.SerializeToElement(new {report_key="vpn.audit",version=1,dataset_version=1,
                definition_json=new {actions=new[]{"view","export"}},actions_json=new[]{"view","export"},fields_json=Fields.Select(f=>new {key=f.Key,category=f.Category})})]
        };
    }
    static QueryCollection Query(params (string Key,string Value)[] values)=>new(values.ToDictionary(x=>x.Key,x=>new StringValues(x.Value)));
    static Task<JsonObject> Read(Inventory store,QueryCollection? query=null,AccessFacts? facts=null,string action="view")=>
        VpnReports.Read(store,new VpnAccess(facts??Facts()),"vpn.accounts",query??Query(),action,Ct);
    static string[] Ids(JsonObject body)=>body["items"]!.AsArray().Select(row=>Text(row!["object_id"])).ToArray();
    static List<JsonObject> Users()=>Enumerable.Range(1,438).Select(i=>Json(new {id=i,object_id=i.ToString(CultureInfo.InvariantCulture),
        display_name="Account",natural_key=$"account-{i:0000}",domain_id=7,enabled=i<=418,
        activity_state=i>418?"disabled":i>391?"inactive":"active"})).ToList();

    // Like the Python FakeDb: execute the population/filter/page contract over synthetic
    // rows, and inspect SQL separately so that ignoring scope, DISTINCT or filters fails.
    sealed class Inventory : IVpnStore,IVpnReadSession
    {
        public List<JsonObject> Users=VpnAccountsV2Tests.Users();
        public string PrivilegeCoverage="complete";
        public readonly List<(string Sql,object?[] Values)> Calls=[];
        public Task<IVpnReadSession> OpenAsync(CancellationToken ct)=>Task.FromResult<IVpnReadSession>(this);
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
        public Task<List<JsonObject>> ReadAsync(string sql,object?[] values,CancellationToken ct)
        {
            Calls.Add((sql,values));
            List<JsonObject> result;
            if(sql.Contains("read_plugin_states_v1",StringComparison.Ordinal)) result=[Json(new {installed=true,enabled=true})];
            else if(sql.StartsWith("select id from domains",StringComparison.Ordinal)) result=[Json(new {id=7}),Json(new {id=8})];
            else if(sql.StartsWith("select value from platform_settings",StringComparison.Ordinal)) result=[];
            else if(sql.Contains("select d.fields_json,r.definition_json",StringComparison.Ordinal))
            {
                Assert.Contains("r.report_key='vpn.audit' and r.status='published'",sql);
                result=[Json(new {fields_json=Fields.Select(f=>new {key=f.Key,category=f.Category,label=f.Key}),
                    definition_json=new {export_policy="controlled",columns=Fields.Select(f=>f.Key),
                        default_sort=new[]{new {field="privileged_overlap",direction="desc"},new {field="activity_state",direction="asc"}}}})];
            }
            else if(sql.Contains("from ad_context_runs run",StringComparison.Ordinal))
                result=new[]{"vpn_membership","directory_accounts","privileged_membership"}.Select(name=>Json(new {section_name=name,domain_count=1,
                    complete_domain_count=name!="privileged_membership"||PrivilegeCoverage=="complete"?1:0,
                    partial_domain_count=name=="privileged_membership"&&PrivilegeCoverage=="partial"?1:0})).ToList();
            else if(sql.StartsWith("with vpn_accounts as (",StringComparison.Ordinal))
            {
                Assert.Contains("select distinct source_entity.id",sql);
                Assert.Contains("source_entity.domain_id=any(",sql);
                Assert.Contains("relation.source_section='vpn_membership'",sql);
                Assert.Contains("relation.valid_to_utc is null and relation.relation_kind='member_of'",sql);
                Assert.Contains("entity_type.value='ad_user' and entity_v2_is_active(source_entity.id)",sql);
                Assert.Contains("current.source_section in ('directory_accounts','vpn_membership')",sql);
                Assert.Contains("order by case current.source_section when 'directory_accounts' then 0 else 1 end",sql);
                Assert.Contains("when account.attributes_json->'attributes'->>'enabled' is null then 'unknown'",sql);
                Assert.Contains("::boolean is false then 'disabled'",sql);
                Assert.Contains("as activity_state",sql);
                var scope=Assert.IsType<JsonObject>(values[0]);
                Assert.Equal("domain",Text(scope["kind"]));
                var domains=scope["ids"]!.AsArray().Select(Number).ToHashSet();
                var population=Users.Where(u=>domains.Contains(Number(u["domain_id"]))).DistinctBy(u=>Text(u["object_id"])).ToList();
                if(sql.Contains("as total_users",StringComparison.Ordinal))
                {
                    Assert.Contains("count(*) filter(where activity_state='active') as active_users",sql);
                    Assert.Equal(2,values.Length);
                    result=[Json(new {total_users=population.Count,active_users=population.Count(u=>Text(u["activity_state"])=="active"),
                        inactive_users=population.Count(u=>Text(u["activity_state"])=="inactive"),disabled_users=population.Count(u=>Text(u["activity_state"])=="disabled"),
                        privileged_overlap_users=population.Count(u=>Text(u["privileged_overlap"])=="true")})];
                }
                else
                {
                    Assert.Contains("strpos(lower(concat_ws(' ',display_name,natural_key)),lower($4))>0",sql);
                    Assert.Contains("($5='' or activity_state=$5)",sql);
                    Assert.Equal(values[2],values[3]);
                    string search=(string)values[2]!,activity=(string)values[4]!;
                    population=population.Where(u=>(Text(u["display_name"])+" "+Text(u["natural_key"])).Contains(search,StringComparison.OrdinalIgnoreCase)
                        && (activity==""||Text(u["activity_state"])==activity)).ToList();
                    if(sql.Contains("as filtered_count from vpn_accounts",StringComparison.Ordinal))
                    {
                        Assert.Equal(5,values.Length);Assert.DoesNotContain("id>$6",sql);
                        Assert.DoesNotContain("limit",sql.Split(") account on true",StringSplitOptions.None)[1]);
                        result=[Json(new {filtered_count=population.Count})];
                    }
                    else
                    {
                        Assert.Contains("and id>$6 order by id limit $7",sql);
                        Assert.Equal(7,values.Length);Assert.Equal(201,values[6]);
                        result=population.Where(u=>Number(u["object_id"])>(long)values[5]!).OrderBy(u=>Number(u["object_id"]))
                            .Take((int)values[6]!).Select(u=>(JsonObject)u.DeepClone()).ToList();
                    }
                }
            }
            else throw new InvalidOperationException("Unexpected VPN accounts SQL: "+sql);
            return Task.FromResult(result);
        }
    }

    [Fact]
    public void Missing_fields_partial_privileges_and_presentation_codes_match_reference()
    {
        var first=Json(new {object_id=1,display_name="A",activity_state="active"});
        VpnAccounts.Present(first,"partial");
        foreach(string field in new[]{"privilege","department","password"})
        {Assert.Equal("Поле недоступно",Text(first[field+"_text"]));Assert.Equal("unavailable",Text(first[field+"_text_code"]));}
        var second=Json(new {object_id=2,display_name="B",activity_state="DISABLED",privileged_overlap=false,department=(string?)null,password_never_expires=true});
        VpnAccounts.Present(second,"partial");
        Assert.Equal("disabled",Text(second["activity"]));
        Assert.Equal("Не обнаружено в неполном срезе",Text(second["privilege_text"]));Assert.Equal("not_detected_partial",Text(second["privilege_text_code"]));
        Assert.Equal("Не указано",Text(second["department_text"]));Assert.Equal("unspecified",Text(second["department_text_code"]));
        Assert.Equal("Без ограничения срока",Text(second["password_text"]));Assert.Equal("never_expires",Text(second["password_text_code"]));
        var row=Json(new {department="Подразделение из источника",password_never_expires=false,privileged_overlap=false});
        VpnAccounts.Present(row,"not_collected");
        Assert.Equal("Подразделение из источника",Text(row["department_text"]));Assert.Null(row["department_text_code"]);
        Assert.Equal("С ограничением срока",Text(row["password_text"]));Assert.Equal("expires",Text(row["password_text_code"]));
        Assert.Equal("Срез не собран",Text(row["privilege_text"]));Assert.Equal("not_collected",Text(row["privilege_text_code"]));
    }

    [Fact]
    public async Task Complete_and_partial_coverage_preserve_field_permissions_and_limitations()
    {
        var store=new Inventory {Users=[Json(new {id=1,object_id="1",domain_id=7,activity_state="active",privileged_overlap=false}),
            Json(new {id=2,object_id="2",domain_id=7,activity_state="inactive",privileged_overlap=true})]};
        var facts=Facts(["identity_basic","technical","security","privilege"]);
        var inactive=await Read(store,Query(("activity","inactive")),facts);
        Assert.Equal(new[]{"2"},Ids(inactive));Assert.Equal("ok",Text(inactive["state"]));
        Assert.Equal("Есть пересечение",Text(inactive["items"]![0]!["privilege_text"]));Assert.Equal("overlap",Text(inactive["items"]![0]!["privilege_text_code"]));
        var active=await Read(store,Query(("activity","active")),facts);
        Assert.Equal("Не обнаружено",Text(active["items"]![0]!["privilege_text"]));Assert.Equal("not_detected",Text(active["items"]![0]!["privilege_text_code"]));
        store.PrivilegeCoverage="partial";
        var partial=await Read(store);
        Assert.Equal("partial",Text(partial["state"]));Assert.Equal("partial",Text(partial["coverage"]!["state"]));
        Assert.Equal(new[]{"privileged_membership"},partial["coverage"]!["missing_sources"]!.AsArray().Select(Text));
        foreach(var item in partial["items"]!.AsArray())
        {Assert.False(item!.AsObject().ContainsKey("privileged_overlap"));Assert.Equal("unavailable",Text(item["privilege_text_code"]));Assert.False(item.AsObject().ContainsKey("department"));}
        var notes=partial["limitations"]!.AsArray();Assert.Equal(7,notes.Count);
        Assert.Equal("vpn_accounts_0",Text(notes[0]!["code"]));Assert.Equal("Состав VPN определяется только членством в явно заданных группах AD.",Text(notes[0]!["text"]));
        Assert.All(notes.Select((note,i)=>(note,i)),pair=>{Assert.Equal($"vpn_accounts_{pair.i}",Text(pair.note!["code"]));Assert.NotEmpty(Text(pair.note["text"]));});
    }

    [Fact]
    public async Task Inventory_keyset_pages_include_all_438_users_once_with_global_count()
    {
        var store=new Inventory();store.Users.Add((JsonObject)store.Users[0].DeepClone());
        var outside=(JsonObject)store.Users[0].DeepClone();outside["object_id"]="999";outside["domain_id"]=8;store.Users.Add(outside);
        var ids=new List<string>();string cursor="";
        foreach(int size in new[]{200,200,38})
        {
            var body=await Read(store,Query(("cursor",cursor)));
            Assert.Equal(438,Number(body["filtered_count"]));Assert.Equal(size,body["items"]!.AsArray().Count);
            Assert.Equal(size==200,body["has_more"]!.GetValue<bool>());
            if(size==38) Assert.Null(body["next_cursor"]);else Assert.NotEmpty(Text(body["next_cursor"]));
            Assert.All(body["items"]!.AsArray(),row=>{Assert.NotNull(row!["activity"]);Assert.False(row.AsObject().ContainsKey("_cursor_id"));Assert.False(row.AsObject().ContainsKey("id"));});
            ids.AddRange(Ids(body));cursor=Text(body["next_cursor"]);
        }
        Assert.Equal(Enumerable.Range(1,438).Select(i=>i.ToString(CultureInfo.InvariantCulture)),ids);
        Assert.Equal(3,store.Calls.Count(c=>c.Sql.Contains("as filtered_count from vpn_accounts",StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("ACCOUNT-0438","",438,438)]
    [InlineData("account-04","inactive",400,418)]
    [InlineData("","disabled",419,438)]
    [InlineData("%_","",0,-1)]
    public async Task Filters_and_literal_search_reach_beyond_first_page(string search,string activity,int first,int last)
    {
        var store=new Inventory();var body=await Read(store,Query(("q",search),("activity",activity)));
        Assert.Equal(Enumerable.Range(first,last-first+1).Select(i=>i.ToString(CultureInfo.InvariantCulture)),Ids(body));
        Assert.Equal(last-first+1,Number(body["filtered_count"]));Assert.Equal(last>=first?"ok":"empty",Text(body["state"]));
        var count=store.Calls.Single(c=>c.Sql.Contains("as filtered_count from vpn_accounts",StringComparison.Ordinal));
        var rows=store.Calls.Single(c=>c.Sql.Contains("select * from vpn_accounts",StringComparison.Ordinal));
        Assert.Equal(count.Values,rows.Values.Take(5));
        Assert.Equal(count.Sql[..count.Sql.IndexOf(" select count(*) as filtered_count",StringComparison.Ordinal)],rows.Sql[..rows.Sql.IndexOf(" select * from vpn_accounts",StringComparison.Ordinal)]);
    }

    [Fact]
    public async Task Activity_cards_count_their_filter_population_and_active_pages_are_200_then_191()
    {
        var store=new Inventory();var initial=await Read(store);
        Assert.Equal(391,Number(initial["metrics"]!.AsArray().Single(m=>Text(m!["key"])=="active_users")!["value"]));
        int filters=0;
        foreach(var metric in initial["metrics"]!.AsArray())
        {
            if(metric!["filter"] is not JsonObject filter) continue;
            filters++;string activity=Text(filter["activity"]);var body=await Read(store,Query(("activity",activity)));
            Assert.Equal(Number(metric["value"]),Number(body["filtered_count"]));Assert.All(body["items"]!.AsArray(),r=>Assert.Equal(activity,Text(r!["activity"])));
        }
        Assert.Equal(3,filters);
        var first=await Read(store,Query(("activity","active")));Assert.Equal(200,Ids(first).Length);Assert.NotEmpty(Text(first["next_cursor"]));
        var last=await Read(store,Query(("activity","active"),("cursor",Text(first["next_cursor"]))));
        Assert.Equal(391,Number(last["filtered_count"]));Assert.Equal(191,Ids(last).Length);Assert.False(last["has_more"]!.GetValue<bool>());Assert.Null(last["next_cursor"]);
    }

    [Fact]
    public async Task Unknown_and_disabled_accounts_are_never_counted_as_active()
    {
        var store=new Inventory {Users=new[]{"active","active","inactive","disabled","unknown"}.Select((state,i)=>Json(new {id=i+1,object_id=(i+1).ToString(CultureInfo.InvariantCulture),
            domain_id=7,enabled=state=="unknown"?(bool?)null:state!="disabled",activity_state=state})).ToList()};
        var body=await Read(store);Assert.Equal(new[]{"active","active","inactive","disabled","unknown"},body["items"]!.AsArray().Select(r=>Text(r!["activity"])));
        Assert.Equal(2,Number(body["metrics"]!.AsArray().Single(m=>Text(m!["key"])=="active_users")!["value"]));
        Assert.Equal(2,Number((await Read(store,Query(("activity","active"))))["filtered_count"]));
    }

    [Theory]
    [InlineData("null")] [InlineData("[]")] [InlineData("{}")] [InlineData("{\"object_id\":true}")]
    [InlineData("{\"object_id\":\"0\"}")] [InlineData("{\"object_id\":\"-1\"}")]
    [InlineData("{\"object_id\":\"9223372036854775808\"}")] [InlineData("{\"object_id\":\"x\"}")]
    public async Task Malformed_cursors_fail_before_inventory_reads(string payload)
    {
        var store=new Inventory();string cursor=Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)).Replace('+','-').Replace('/','_');
        var error=await Assert.ThrowsAsync<VpnInputException>(()=>Read(store,Query(("cursor",cursor))));
        Assert.Equal("invalid_report_cursor",error.Message);Assert.Empty(store.Calls);
    }

    [Fact]
    public async Task Export_uses_published_fields_filters_and_ignores_page_cursor()
    {
        var store=new Inventory();var body=await Read(store,Query(("q","account"),("activity","active"),("cursor","ignored")),action:"export");
        Assert.Equal(200,Ids(body).Length);Assert.Equal("1",Ids(body)[0]);Assert.True(body["has_more"]!.GetValue<bool>());
        var rows=store.Calls.Single(c=>c.Sql.Contains("select * from vpn_accounts",StringComparison.Ordinal));Assert.Equal(0L,rows.Values[5]);
        Assert.Equal("account",rows.Values[2]);Assert.Equal("active",rows.Values[4]);
        string csv=VpnReports.Csv(body,null);Assert.StartsWith("\"object_id\",\"display_name\",\"natural_key\",\"enabled\",\"activity_state\",\"password_never_expires\"\r\n",csv);
        Assert.DoesNotContain("department",csv);Assert.DoesNotContain("privileged_overlap",csv);
    }

    [Fact]
    public async Task Retained_reader_preserves_counts_cursors_and_export_boundary()
    {
        var store = new Inventory();
        var first = await Read(store);
        Assert.Equal("sli.report-result.v2", Text(first["contract_id"]));
        Assert.Equal(438, Number(first["filtered_count"]));
        Assert.Equal(200, first["items"]!.AsArray().Count);
        var cursor = Text(first["next_cursor"]);
        Assert.NotEmpty(cursor);

        var second = await Read(store, Query(("cursor", cursor)));
        Assert.Equal(438, Number(second["filtered_count"]));
        Assert.Equal("201", Text(second["items"]![0]!["object_id"]));
        Assert.NotEmpty(Text(second["next_cursor"]));

        var export = await Read(store, Query(("q", "account"), ("activity", "active"), ("cursor", "ignored")), action: "export");
        Assert.Equal(200, Ids(export).Length);
        Assert.True(export["has_more"]!.GetValue<bool>());
        Assert.Equal("1", Ids(export)[0]);
    }
}
