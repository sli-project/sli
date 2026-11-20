using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Sli.Server.Workspace;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

// Vectors from tests/reporting/test_workstation_access_contract.py exercise
// the retained production reader and scope compiler against a private, disposable PG.
public sealed class WorkstationAccessContractTests : IClassFixture<WorkstationAccessContractTests.Database>
{
    static readonly string[] Keys=["workstations.logons","workstations.processes","workstations.usb","workstations.protection"];
    static readonly string[] Titles=["Входы на станциях","Процессы и службы","Съёмные носители","Локальные администраторы и защита"];
    const string Pilot="00000000-0000-4000-8000-000000000001",Other="00000000-0000-4000-8000-000000000002";
    readonly Database database;
    public WorkstationAccessContractTests(Database database)=>this.database=database;
    static JsonElement J(object value)=>JsonSerializer.SerializeToElement(value);
    static AccessFacts Facts(bool owner)=>new(owner,"viewer",[],[],[],
        new[]{"reports.catalog"}.Concat(WorkstationReportContract.Fields.Select(f=>"field."+f)).Select(k=>J(new{capability_key=k})).ToArray(),[],[],
        Keys.Select(k=>J(new{report_key=k,version=1,dataset_version=1,fields_json=WorkstationReportContract.Fields.Select(f=>new{category=f}),actions_json=new[]{"view"},definition_json=new{field_categories=WorkstationReportContract.Fields,actions=new[]{"view"}}})).ToArray());
    static AccessReadEvaluation Evaluate(AccessFacts facts)
    {
        var caps=new CapabilityComposer().Compose(facts);
        return new(facts,caps,new ReportEligibility().Compose(facts,caps));
    }
    sealed class Connections(Database database):IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)=>database.Pg.OpenAsync(ct);
    }
    sealed class NoConnections:IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)=>throw new InvalidOperationException("Unresolved scope must not read PostgreSQL");
    }
    [Theory][InlineData(true)][InlineData(false)]
    public void Owner_full_grants_execute_all_four_reports_but_enablement_controls_navigation(bool enabled)
    {
        var access=Evaluate(Facts(true));
        Assert.True(access.Capabilities.IsOwner);
        Assert.Equal("platform_owner",access.Capabilities.Decide("reports.catalog").Reason);
        foreach(string key in Keys)
        {
            var report=Assert.Single(access.Reports.Reports,r=>r.ReportKey==key);
            Assert.True(report.Allowed);var grant=Assert.Single(report.Grants);
            Assert.Equal(WorkstationReportContract.Fields.Order(),grant.FieldCategories.Order());
            Assert.Equal("{\"kind\":\"all\"}",grant.Scope.GetRawText());Assert.Contains("view",grant.AllowedActions);
        }
        var catalog=Catalog(access,enabled);
        Assert.All(Keys,key=>Assert.Contains(catalog["items"]!.AsArray(),i=>i!["key"]!.GetValue<string>()==key&&i["executable"]!.GetValue<bool>()));
        var paths=Paths(catalog);
        foreach(string key in Keys)Assert.Equal(enabled,paths.Contains("/report/"+key));
    }
    static JsonNode Catalog(AccessReadEvaluation access,bool enabled)=>JsonSerializer.SerializeToNode(WorkspaceReportCatalog.Compose(access,
        new ReportRuleCatalog(new PluginGenerationReader(null)).Rules,[J(new{plugin_id="sli.workstations",enabled})]))!;
    static HashSet<string> Paths(JsonNode catalog)=>catalog["navigation"]!["sections"]!.AsArray()
        .SelectMany(s=>s!["groups"]!.AsArray()).SelectMany(g=>g!["entries"]!.AsArray()).Select(e=>e!["path"]!.GetValue<string>()).ToHashSet();
    [Fact]
    public void Enablement_does_not_add_unassigned_reports_or_navigation()
    {
        var catalog=Catalog(Evaluate(Facts(false)),true);
        Assert.DoesNotContain(catalog["items"]!.AsArray(),i=>i!["key"]!.GetValue<string>().StartsWith("workstations.",StringComparison.Ordinal));
        Assert.DoesNotContain(catalog["navigation"]!["sections"]!.AsArray(),s=>s!["id"]!.GetValue<string>()=="workstations");
    }
    public static IEnumerable<object[]> DataVectors()=>Keys.SelectMany(k=>new[]{"owner","domain","restricted","unknown"}.Select(scope=>new object[]{k,scope}));
    [Theory][MemberData(nameof(DataVectors))]
    public async Task Four_retained_readers_enforce_production_scope_and_protection_snapshots(string key,string scope)
    {
        var ct=TestContext.Current.CancellationToken;var facts=Facts(true);
        if(scope!="owner")
        {
            var raw=JsonDocument.Parse(scope switch{"domain"=>"{\"kind\":\"domain\",\"ids\":[11]}","restricted"=>"{\"mode\":\"restricted\",\"clauses\":[{\"collection_scope_ids\":[\"ad-domain:11\"]}]}",_=>"{\"kind\":\"unknown\"}"}).RootElement.Clone();
            facts=facts with{IsOwner=false,ReportAssignments=Keys.Select(k=>J(new{report_key=k,effect="allow",scope_json=raw,field_categories=WorkstationReportContract.Fields,allowed_actions=new[]{"view"}})).ToArray(),
                DirectCapabilities=WorkstationReportContract.Fields.Select(f=>J(new{capability_key="field."+f,effect="allow",scope_json=new{kind="all"}})).ToArray()};
        }
        var access = Evaluate(facts);
        WorkstationReportContract.Admit(access.Reports, key);
        Assert.Equal(Titles[Array.IndexOf(Keys, key)], WorkstationReportContract.Declaration(key)["title"]!.GetValue<string>());
        var reader = new WorkstationReports(scope == "unknown" ? new NoConnections() : new Connections(database),
            new ConfigurationBuilder().Build());
        var request = WorkstationReportContract.Parse(key,
            new QueryCollection(QueryHelpers.ParseQuery("period=custom&from=2026-11-08&to=2026-11-08")));
        var body = await reader.ReadAsync(request, facts, access.Reports, ct);
        Assert.Equal("partial",body["state"]!.GetValue<string>());
        var items=body["items"]!.AsArray();var snapshots=items.Where(i=>i!["quality"]?["snapshot"]?.GetValue<bool>()==true).ToArray();
        string[] expected=scope=="unknown"?[]:scope=="owner"?[Pilot,Other]:[Pilot];
        Assert.Equal(expected,items.Where(i=>i!["quality"]?["snapshot"]?.GetValue<bool>()!=true).Select(i=>i!["agent_key"]!.GetValue<string>()));
        Assert.Equal(key=="workstations.protection"?expected:[],snapshots.Select(i=>i!["agent_key"]!.GetValue<string>()));
        Assert.All(snapshots,i=>Assert.False(i!["facts"]!["real_time_protection_enabled"]!.GetValue<bool>()));
        if(scope=="unknown")Assert.Equal("workstation_scope_unresolved",body["limitations"]![0]!["code"]!.GetValue<string>());
    }
    public sealed class Database:IAsyncLifetime
    {
        internal readonly PostCollectionPostgres Pg=new(canonicalSchema:true);
        public async ValueTask InitializeAsync()
        {
            var ct=TestContext.Current.CancellationToken;await Pg.StartAsync(ct);await using var db=await Pg.OpenAsync(ct);
            // Only the columns read by this contract; the fixture is not a runtime schema.
            await PostCollectionPostgres.Sql(db,"""
                create table sli_agents(id uuid primary key,host_id uuid,source_agent_id uuid,source_host_id uuid,status text,assigned_modules jsonb,registration_host_name text);
                create table core_entity_scope_resources(plugin_id text,source_instance_id text,entity_id bigint,device_id text,collection_scope_id text,natural_key text,entity_type text,resolution text);
                create table core_entity_associations(source_entity_id bigint,target_entity_id bigint,relation text);
                create table entities_v2_active(id bigint,natural_key text,domain_id bigint,entity_type_id bigint);
                create table storage_v2_entity_type(id bigint,value text);
                create table ad_context_entity_versions(id bigint,entity_id bigint,source_section text,valid_to_utc timestamptz,attributes_json jsonb);
                create table sli_agent_audit(actor text,target text,action text,id bigint);
                create table sli_agent_group_approval_links(enrollment_token_id uuid,request_id bigint);
                create table sli_agent_group_requests(id bigint,computer_version_id bigint);
                create schema sli_plugin_workstations;
                create table sli_plugin_workstations.observations(id text primary key,agent_key text,entity_id bigint,ad_computer_id bigint,family text,event_id integer,observed_at timestamptz,observation jsonb,observation_sha256 text,source_xml text);
                create table sli_plugin_workstations.protection_state(id text primary key,agent_key text,entity_id bigint,ad_computer_id bigint,observed_at timestamptz,state jsonb,state_sha256 text);
                insert into sli_agents(id,host_id,status,assigned_modules,registration_host_name) values
                  ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000011','active','[{"module_id":"sli.workstations"}]','pilot.example.test'),
                  ('00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000012','active','[{"module_id":"sli.workstations"}]','other.example.test'),
                  ('00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000013','active','[]','unassigned.example.test'),
                  ('00000000-0000-4000-8000-000000000004','00000000-0000-4000-8000-000000000014','replaced','[{"module_id":"sli.workstations"}]','replaced.example.test');
                insert into core_entity_scope_resources select 'sli.workstations',host_id::text,1,'device-pilot','ad-domain:11',
                  'core:'||encode(sha256(convert_to('["device","sli.agent.key","agent-registry","'||id::text||'"]','UTF8')),'hex'),'device','resolved'
                  from sli_agents where id='00000000-0000-4000-8000-000000000001';
                insert into sli_plugin_workstations.observations
                  select lpad(row_number() over(order by a.id,f.family)::text,64,'0'),a.id::text,1,null,f.family,1,'2026-11-08T12:00:00Z',
                    '{"facts":{"storage_evidence":true},"quality":{}}',repeat('a',64),'<Event/>'
                  from sli_agents a cross join (values('logons'),('processes'),('usb'),('protection')) f(family);
                insert into sli_plugin_workstations.protection_state
                  select 'c'||lpad(row_number() over(order by id)::text,63,'0'),id::text,1,null,'2026-11-08T12:00:00Z',
                    '{"state":"available","components":{"real_time_protection_enabled":false}}',repeat('b',64) from sli_agents;
                """,ct);
        }
        public ValueTask DisposeAsync()=>Pg.DisposeAsync();
    }
}
