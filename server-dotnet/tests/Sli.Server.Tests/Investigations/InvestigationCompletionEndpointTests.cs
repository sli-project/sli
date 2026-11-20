using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Investigations;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Investigations;

public sealed class InvestigationCompletionEndpointTests
{
    const string Ref = "radius-session-row:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static JsonElement J(string s) => JsonDocument.Parse(s).RootElement.Clone();
    static JsonObject Row(long id) => JsonNode.Parse($$"""{"event_db_id":{{id}},"event_id":999999,"time_created_utc":"2026-11-02T12:00:00Z","server":"dc1","channel":"Security","provider_name":"unknown","subject":"alice","target":"bob"} """)!.AsObject();
    static JsonObject Case() => JsonNode.Parse("""{"id":4,"public_id":"00000000-0000-4000-8000-000000000001","title":"Проблема #7: Test","status":"new","owner":"alice","created_by":"alice","created_at":"2026-11-02T12:00:00Z","updated_at":"2026-11-02T12:00:00Z","closed_at":null,"events":[],"notes":[],"evidence_refs":[]} """)!.AsObject();
    static AccessFacts Facts(string role, bool report, bool manage, bool view, bool security, string scope, string key)
    {
        string[] capabilities = [..manage ? new[] { "investigations.manage" } : [], ..view ? new[] { "investigations.view", "objects.view", "evidence.exact" } : [], ..security ? new[] { "field.security" } : []];
        return new(false, role, [], [], capabilities.Select(c => J("{\"capability_key\":\"" + c + "\",\"effect\":\"allow\",\"scope_json\":{\"kind\":\"all\"}}")).ToArray(), [], [],
            report ? [J("{\"report_key\":\"" + key + "\",\"effect\":\"allow\",\"allowed_actions\":[\"view\",\"start_case\"],\"field_categories\":[\"security\"],\"scope_json\":" + scope + "}")] : [],
            [J("{\"report_key\":\"" + key + "\",\"version\":1,\"dataset_version\":1,\"definition_json\":{\"actions\":[\"view\",\"start_case\"]},\"actions_json\":[\"view\",\"start_case\"],\"fields_json\":[{\"category\":\"security\"}]}")]);
    }
    sealed class Authentication(string role) : IPrincipalAuthenticator
    { public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken t) => ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, role, "alice"))); }
    sealed class FactsReader(AccessFacts facts) : IAccessFactsRepository
    { public int Reads; public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct) { Reads++; return Task.FromResult(facts); } }
    sealed class Repo : IInvestigationLinksRepository, IInvestigationRepository, IInvestigationEventRepository, IInvestigationEntityHistory, IEventReadService, IInvestigationVpnSessionEvidence, IInvestigationVpnEvidence
    {
        public Func<long, JsonObject> EventRow = Row;
        public long[] RelationIds = [8];
        public int Writes, Preflights, Hydrations, MetadataReads, VpnReads; public bool Available = true, FailMetadata; public long[] Candidates = [7]; public HashSet<long> Hidden = []; public InvestigationException? Failure;
        public string? NextRelation, CursorSeen; public bool FailDetails;
        public Dictionary<long, JsonObject> WorkspaceRows = [];
        public HashSet<long> Missing = [];
        public List<long> ResourceReads = [];
        public List<long> Hydrated = []; public BigInteger? Finding; public InvestigationIdentity? Target; public string? Actor; public InvestigationEvidenceInput? Evidence;
        public Task<long[]> FindingEventsAsync(BigInteger finding, CancellationToken ct) { Preflights++; Finding = finding; if (finding <= 0) throw new InvestigationException("invalid_finding_id", "Finding ID must be positive"); return Task.FromResult(new long[] { 7, 8 }); }
        public Task<JsonObject> LinkFindingAsync(InvestigationIdentity? identity, BigInteger finding, string actor, CancellationToken ct)
        { if (Failure is not null) throw Failure; Writes++; Target = identity; Actor = actor; Finding = finding; return Task.FromResult(Case()); }
        public Task<JsonObject> AddEvidenceAsync(InvestigationIdentity identity, InvestigationEvidenceInput input, string actor, CancellationToken ct)
        { if (Failure is not null) throw Failure; input.Validate(); Writes++; Target = identity; Actor = actor; Evidence = input; return Task.FromResult(JsonNode.Parse("{\"evidence_kind\":\"vpn_accounting_session\",\"source_domain_id\":1,\"reference_id\":\"" + input.Reference + "\",\"relation_status\":\"confirmed\",\"added_by\":\"alice\",\"added_at\":\"2026-11-02T12:00:00Z\"}")!.AsObject()); }
        public Task<IReadOnlyList<IReadOnlyList<AccessResource>>> ResourceGroupsAsync(InvestigationIdentity i, CancellationToken ct) => Task.FromResult<IReadOnlyList<IReadOnlyList<AccessResource>>>([[new("domain", 1)]]);
        public Task<InvestigationNote> AddNoteAsync(InvestigationIdentity i, string b, string a, CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<AccessResource>> EventResourcesAsync(BigInteger i, CancellationToken ct) => ResourcesAsync((long)i, ct);
        public Task<InvestigationEventResult> AddAsync(InvestigationIdentity i, InvestigationEventInput b, string a, CancellationToken ct) => throw new NotSupportedException();
        public Task RemoveAsync(InvestigationIdentity i, BigInteger e, string a, CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id, CancellationToken ct)
        { ResourceReads.Add(id); if (Missing.Contains(id)) throw new InvestigationException("event_not_found", "unavailable", 404); return Task.FromResult<IReadOnlyList<AccessResource>>([new("domain", Hidden.Contains(id) ? 2 : 1)]); }
        public Task<long[]> CandidatesAsync(InvestigationWorkspaceInput i, AccessDecision a, string report, CancellationToken ct) => Task.FromResult(Candidates);
        public Task<IReadOnlyList<JsonObject>> MetadataAsync(InvestigationWorkspaceInput i, long[] ids, CancellationToken ct)
        { MetadataReads++; return Task.FromResult<IReadOnlyList<JsonObject>>(FailMetadata ? [] : ids.Select(id => { var r = Row(id); r["subject_user_name"] = "alice"; return r; }).ToArray()); }
        public readonly List<long[]> DetailBatches = [];
        public JsonArray? RelationRows;
        public Task<Dictionary<long, JsonObject>> DetailsAsync(long[] ids, bool exact, Func<long, CancellationToken, Task<bool>> admitted, CancellationToken ct)
        { if (FailDetails) throw new InvalidOperationException("source_normalizer_bundle_unsupported"); DetailBatches.Add(ids.ToArray()); Hydrations++; Hydrated.AddRange(ids); return Task.FromResult(ids.ToDictionary(id => id, id => {
            var row = WorkspaceRows.TryGetValue(id, out var stored) ? (JsonObject)stored.DeepClone() : EventRow(id); if (!WorkspaceRows.ContainsKey(id) && RelationRows is not null) row["time_created_utc"] = $"2026-07-16T00:0{id - 10}:00Z"; return row;
        })); }
        public Task<JsonObject> RelationsAsync(long id, Func<long, CancellationToken, Task<bool>> admitted, CancellationToken ct) => Task.FromResult(new JsonObject { ["items"] = RelationRows?.DeepClone() ?? new JsonArray(RelationIds.Select(related => (JsonNode?)new JsonObject { ["related_event_db_id"] = related, ["reason"] = "Exact link " + related }).ToArray()), ["truncated"] = false, ["next_cursor"] = null });
        public async Task<JsonObject> RelationsPageAsync(long id, int limit, string? cursor, Func<long,CancellationToken,Task<bool>> admitted, CancellationToken ct)
        { Assert.Equal(40,limit); CursorSeen=cursor; var page=await RelationsAsync(id,admitted,ct);page["next_cursor"]=NextRelation;page["truncated"]=NextRelation is not null;return page; }
        public Task<bool> AvailableAsync(AccessDecision a, BigInteger d, string r, CancellationToken ct) { VpnReads++; return Task.FromResult(Available); }
        public bool Allowed(AccessDecision a, long d) => Available;
    }
    static (DefaultHttpContext C, Repo R, ServiceProvider P) Setup(string path, string body = "{}", string role = "viewer", bool report = true, bool manage = true, bool view = true, bool security = true, string scope = "{\"kind\":\"all\"}", string key = "investigations.workspace", string? deny = null)
    {
        var r = new Repo();
        var facts = Facts(role, report, manage, view, security, scope, key);
        if (deny is not null) facts = facts with { DirectCapabilities = facts.DirectCapabilities.Append(J(deny)).ToArray() };
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        var p = new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config).AddSingleton(new AuthRequestPolicy(config)).AddSingleton(new TransportGate(config))
            .AddSingleton<IPrincipalAuthenticator>(new Authentication(role)).AddSingleton<IAccessFactsRepository>(new FactsReader(facts))
            .AddSingleton<IInvestigationLinksRepository>(r).AddSingleton<IInvestigationRepository>(r).AddSingleton<IInvestigationEventRepository>(r).AddSingleton<IInvestigationEntityHistory>(r).AddSingleton<IEventReadService>(r).AddSingleton<IInvestigationVpnSessionEvidence>(r).AddSingleton<IInvestigationVpnEvidence>(r).BuildServiceProvider();
        var c = new DefaultHttpContext { RequestServices = p }; c.Request.Method = path.Contains('?') ? "GET" : "POST"; c.Request.Scheme = "https";
        var parts = path.Split('?', 2); c.Request.Path = parts[0]; if (parts.Length > 1) c.Request.QueryString = new("?" + parts[1]);
        c.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body)); c.Request.ContentLength = c.Request.Body.Length; c.Request.ContentType = "application/json"; c.Response.Body = new MemoryStream(); c.Request.Headers.AcceptLanguage = "en";
        return (c, r, p);
    }
    static JsonElement Response(DefaultHttpContext c) => J(Encoding.UTF8.GetString(((MemoryStream)c.Response.Body).ToArray()));
    static Task Handle(DefaultHttpContext c) => c.Request.Method == "GET" ? InvestigationWorkspaceEndpoints.HandleAsync(c) : InvestigationLinksEndpoints.HandleAsync(c);
    [Fact]
    public async Task AnchoredCatalogClassificationDoesNotBecomeInvestigationAttention()
    {
        // tests/reporting/test_investigation_event_classification.py: no contextual evidence.
        var (context, repo, provider) = Setup("/api/v1/investigations?event_db_id=517548");
        using (provider)
        {
            repo.EventRow = _ => JsonNode.Parse("""
                {"id":517548,"event_id":4624,"channel":"Security",
                 "provider_name":"Microsoft-Windows-Security-Auditing",
                 "time_created_utc":"2026-09-10T22:35:00Z","server":"DC1","event_data":{}}
                """)!.AsObject();
            repo.RelationIds = [];

            await InvestigationWorkspaceEndpoints.HandleAsync(context);

            Assert.Equal(200, context.Response.StatusCode);
            var response = Response(context);
            var summary = response.GetProperty("summary");
            Assert.Equal("unknown", summary.GetProperty("attention_level").GetString());
            Assert.True(JsonElement.DeepEquals(J("""
                {"risk":"low","classification_origin":"catalog_base","card_completeness":"not_applicable"}
                """), summary.GetProperty("anchor_classification")));
            var item = Assert.Single(response.GetProperty("timeline").EnumerateArray());
            Assert.Equal(517548, item.GetProperty("event_db_id").GetInt64());
            Assert.Equal("catalog_base", item.GetProperty("classification_origin").GetString());
            Assert.Equal("unknown", item.GetProperty("assessment_confidence").GetString());
            const string code = "Security:Microsoft-Windows-Security-Auditing:4624";
            Assert.Equal(code + ".summary", summary.GetProperty("story_code").GetString());
            Assert.Equal("investigations.exact_chain", summary.GetProperty("why_it_matters_code").GetString());
            Assert.Equal(code + ".title", item.GetProperty("title_code").GetString());
            Assert.Equal(code + ".summary", item.GetProperty("summary_code").GetString());
            Assert.Equal(code + ".checks.0", Assert.Single(response.GetProperty("next_check_codes").EnumerateArray()).GetString());
        }
    }
    public static TheoryData<string, string> Routes => new()
    {
        { "/api/v1/investigations?event_db_id=7", "{}" }, { "/api/v1/investigations/from-finding", "{\"finding_id\":7}" },
        { "/api/v1/investigations/4/findings", "{\"finding_id\":7}" },
        { "/api/v1/investigations/4/evidence-refs", "{\"evidence_kind\":\"vpn_accounting_session\",\"source_domain_id\":1,\"reference_id\":\"" + Ref + "\"}" }
    };
    [Theory, MemberData(nameof(Routes))]
    public async Task EveryRouteSucceedsForAnalyst(string path, string body)
    {
        var (c, r, p) = Setup(path, body); using (p)
        {
            await Handle(c); Assert.Equal(c.Request.Method == "GET" ? 200 : 201, c.Response.StatusCode);
            var result = Response(c);
            if (c.Request.Method == "GET") { Assert.Equal(2, result.GetProperty("timeline").GetArrayLength()); Assert.Equal("v1", result.GetProperty("api_version").GetString()); }
            else { Assert.Equal(1, r.Writes); Assert.Equal("alice", r.Actor); if (!path.EndsWith("evidence-refs")) Assert.Equal("INV-0000004", result.GetProperty("case_number").GetString()); }
        }
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task ModuleDenialDoesNotReadBodyOrResources(string path, string body)
    {
        var (c, r, p) = Setup(path, body + "invalid", report: false); using (p)
        { await Handle(c); Assert.Equal(403, c.Response.StatusCode); Assert.Equal("report_not_assigned", Response(c).GetProperty("error").GetString()); Assert.Equal(0, c.Request.Body.Position); Assert.Equal(0, r.Writes + r.Preflights + r.Hydrations + r.VpnReads); }
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task CapabilityDenialHasSourceContract(string path, string body)
    {
        var (c, r, p) = Setup(path, body + "invalid", manage: false, view: false); using (p)
        { await Handle(c); Assert.Equal(403, c.Response.StatusCode); Assert.Equal(c.Request.Method == "GET" ? "insufficient_capability" : "report_not_assigned", Response(c).GetProperty("error").GetString()); Assert.Equal(0, r.Writes); }
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task UnknownRoleCannotUseAnyRoute(string path, string body)
    { var (c, r, p) = Setup(path, body, role: "unknown"); using (p) { await Handle(c); Assert.Equal(403, c.Response.StatusCode); Assert.Equal(0, r.Writes); } }
    [Theory]
    [InlineData("/api/v1/investigations?event_db_id=-1", "{}", "invalid_event_db_id")]
    [InlineData("/api/v1/investigations/from-finding", "{\"finding_id\":true}", "invalid_finding_id")]
    [InlineData("/api/v1/investigations/4/findings", "{\"finding_id\":null}", "invalid_finding_id")]
    [InlineData("/api/v1/investigations/4/evidence-refs", "{\"source_domain_id\":null}", "invalid_evidence_ref")]
    public async Task EveryRouteRejectsInvalidInput(string path, string body, string code)
    { var (c, r, p) = Setup(path, body); using (p) { await Handle(c); Assert.Equal(400, c.Response.StatusCode); Assert.Equal(code, Response(c).GetProperty("error").GetString()); Assert.Equal(0, r.Writes); } }
    [Theory]
    [InlineData("viewer")][InlineData("operator")][InlineData("admin")]
    public async Task ProductRolesCanStartFromFinding(string role)
    { var (c, r, p) = Setup("/api/v1/investigations/from-finding", "{\"finding_id\":7}", role: role); using (p) { await Handle(c); Assert.Equal(201, c.Response.StatusCode); } }
    [Fact] public async Task LegacyReportAssignmentCanGrantInvestigationModule()
    { var (c, r, p) = Setup("/api/v1/investigations/from-finding", "{\"finding_id\":7}", key: "cases.workspace"); using (p) { await Handle(c); Assert.Equal(201, c.Response.StatusCode); } }
    [Theory]
    [InlineData("/api/v1/investigations/from-finding")][InlineData("/api/v1/investigations/4/findings")]
    public async Task AllCopiedFindingEventsMustBeInScope(string path)
    { var (c, r, p) = Setup(path, "{\"finding_id\":7}", scope: "{\"kind\":\"domain\",\"ids\":[1]}"); using (p) { r.Hidden.Add(8); await Handle(c); Assert.Equal(404, c.Response.StatusCode); Assert.Equal(0, r.Writes); } }
    [Fact] public async Task VpnEvidenceNeedsIndependentAdmission()
    { var route = Routes.Last(); var (c, r, p) = Setup(route.Data.Item1, route.Data.Item2); using (p) { r.Available = false; await Handle(c); Assert.Equal(404, c.Response.StatusCode); Assert.Equal(0, r.Writes); } }
    [Theory]
    [InlineData("finding_already_linked",409)][InlineData("finding_not_found",404)][InlineData("investigation_case_closed",409)]
    public async Task FindingServiceErrorsRetainStatusAndDetails(string code,int status)
    { var (c, r, p) = Setup("/api/v1/investigations/4/findings", "{\"finding_id\":7}"); using (p) { r.Failure = new(code,"failure",status) { InvestigationId = code == "finding_already_linked" ? 3 : null }; await Handle(c); Assert.Equal(status,c.Response.StatusCode); if(code=="finding_already_linked") Assert.Equal(3,Response(c).GetProperty("investigation_id").GetInt64()); } }
    [Fact] public async Task RelatedEventDenialPrecedesPayloadHydration()
    { var (c, r, p) = Setup("/api/v1/investigations?event_db_id=7", scope: "{\"kind\":\"domain\",\"ids\":[1]}"); using (p) { r.Hidden.Add(8); await Handle(c); Assert.Equal(200,c.Response.StatusCode); Assert.Equal(new long[]{7},r.Hydrated); Assert.Single(Response(c).GetProperty("timeline").EnumerateArray()); } }
    [Fact] public async Task EntityHistoryDoesNotHydrateArchiveAndNeedsSecurityFields()
    { var (c, r, p) = Setup("/api/v1/investigations?entity_id=10", security:false); using (p) { await Handle(c); Assert.Equal(200,c.Response.StatusCode); Assert.Equal(0,r.MetadataReads+r.Hydrations); Assert.Empty(Response(c).GetProperty("timeline").EnumerateArray()); } }
    [Fact] public async Task EntityHistoryUsesOnlyAuthorizedExactIds()
    { var (c, r, p) = Setup("/api/v1/investigations?entity_id=10", scope:"{\"kind\":\"domain\",\"ids\":[1]}"); using (p) { r.Candidates=[7,8];r.Hidden.Add(8);await Handle(c);Assert.Equal(200,c.Response.StatusCode);Assert.Equal(0,r.Hydrations);var timeline=Response(c).GetProperty("timeline");Assert.Single(timeline.EnumerateArray());Assert.Equal(7,timeline[0].GetProperty("event_db_id").GetInt64());Assert.Equal("unknown",timeline[0].GetProperty("severity").GetString()); } }
    [Fact] public async Task MissingAuthorizedMetadataIsUnavailable()
    { var (c, r, p) = Setup("/api/v1/investigations?entity_id=10"); using(p) {r.FailMetadata=true;await Handle(c);Assert.Equal(503,c.Response.StatusCode);Assert.Equal("unavailable",Response(c).GetProperty("error").GetString());} }
    [Fact] public async Task WorkspaceContinuationPassesBoundRelationCursorAndOmitsRepeatedAnchor()
    {
        var(c,r,p)=Setup("/api/v1/investigations?event_db_id=7");using(p)
        {
            r.NextRelation="next-page";await Handle(c);Assert.Equal(200,c.Response.StatusCode);
            string cursor=Response(c).GetProperty("next_cursor").GetString()!;
            c.Request.QueryString=new("?event_db_id=7&cursor="+Uri.EscapeDataString(cursor));c.Response.Body=new MemoryStream();r.NextRelation=null;
            await Handle(c);Assert.Equal(200,c.Response.StatusCode);Assert.Equal("next-page",r.CursorSeen);
            var timeline=Response(c).GetProperty("timeline");Assert.Single(timeline.EnumerateArray());Assert.Equal(8,timeline[0].GetProperty("event_db_id").GetInt64());
        }
    }
    [Theory] [InlineData("v1")] [InlineData("v2")]
    public async Task WorkspaceRouteInputCannotReplaceServerEvidenceReader(string route)
    {
        var(c,r,p)=Setup("/api/v1/investigations?event_db_id=7&route="+route+"&authorization=invalid");using(p)
        {
            await Handle(c); Assert.Equal(200,c.Response.StatusCode);
            Assert.Equal("ok",Response(c).GetProperty("state").GetString());
            Assert.Equal(new long[]{7,8},r.Hydrated); Assert.Equal(2,r.Hydrations);
        }
    }
    [Fact] public async Task WorkspaceContinuationAuthorizesEachPageAndBindsTimeFilter()
    {
        var(c,r,p)=Setup("/api/v1/investigations?event_db_id=7", scope:"{\"kind\":\"domain\",\"ids\":[1]}"); using(p)
        {
            r.Hidden.Add(8); r.NextRelation="relation-next";
            await Handle(c); Assert.Equal(200,c.Response.StatusCode);
            var first=Response(c); Assert.True(first.GetProperty("summary").GetProperty("has_more").GetBoolean());
            Assert.Equal(new long[]{7},r.Hydrated);
            string cursor=Uri.EscapeDataString(first.GetProperty("next_cursor").GetString()!);
            c.Request.QueryString=new("?event_db_id=7&cursor="+cursor); c.Response.Body=new MemoryStream();
            r.RelationIds=[9]; r.NextRelation=null; r.Hydrated.Clear();
            await Handle(c); Assert.Equal(200,c.Response.StatusCode); Assert.Equal("relation-next",r.CursorSeen);
            var second=Response(c); Assert.Equal(new long[]{7,9},r.Hydrated);
            Assert.Equal(9,Assert.Single(second.GetProperty("timeline").EnumerateArray()).GetProperty("event_db_id").GetInt64());
            Assert.Equal(JsonValueKind.Null,second.GetProperty("next_cursor").ValueKind);
            Assert.False(second.GetProperty("summary").GetProperty("has_more").GetBoolean());
            int reads=r.Hydrations;
            c.Request.QueryString=new("?event_db_id=7&time_from=2026-10-01&cursor="+cursor); c.Response.Body=new MemoryStream();
            await Handle(c); Assert.Equal(400,c.Response.StatusCode); Assert.Equal("invalid_cursor",Response(c).GetProperty("error").GetString());
            Assert.Equal(reads,r.Hydrations);
        }
    }
    [Fact] public async Task WorkspaceWindowCanExcludeAnchorWithoutDiscardingItsContext()
    { var(c,r,p)=Setup("/api/v1/investigations?event_db_id=7&time_from=2026-11-02T13:00:00Z&time_to=2026-11-02T14:00:00Z");using(p){await Handle(c);Assert.Equal(200,c.Response.StatusCode);var result=Response(c);Assert.Equal("empty",result.GetProperty("state").GetString());Assert.False(result.GetProperty("context").GetProperty("anchor_in_window").GetBoolean());Assert.Equal(7,result.GetProperty("anchor_event_db_id").GetInt64());} }
    [Fact] public async Task WorkspaceDependencyFailureIsUnavailableAndNever501()
    { var(c,r,p)=Setup("/api/v1/investigations?event_db_id=7");using(p){r.FailDetails=true;await Handle(c);Assert.Equal(503,c.Response.StatusCode);Assert.Equal("unavailable",Response(c).GetProperty("error").GetString());} }
    // Parity: tests/reporting/test_investigation_time_context.py.
    [Theory]
    [InlineData("2026-09-10", "2026-09-10", "UTC", "2026-09-10T00:00:00Z", "2026-09-11T00:00:00Z", true)]
    [InlineData("2026-09-10T01:00:00Z", "2026-09-10T02:00:00Z", "UTC", "2026-09-10T01:00:00Z", "2026-09-10T02:00:00Z", false)]
    [InlineData("2026-09-10", "2026-09-10", "Asia/Bangkok", "2026-09-09T17:00:00Z", "2026-09-10T17:00:00Z", true)]
    public async Task ExactAnchorKeepsSelectedExclusiveWindowAndCountsUnknownTimes(string from, string to, string zone, string start, string end, bool anchorInWindow)
    {
        var (c, r, p) = Setup("/api/v1/investigations?event_db_id=10&time_from=" + from + "&time_to=" + to + "&timezone=" + zone);
        using (p)
        {
            r.RelationIds = [11, 12, 13];
            foreach (var (id, time) in new (long, string?)[] { (10, "2026-09-10T00:00:00Z"), (11, "2026-09-10T01:00:00Z"), (12, "2026-09-11T00:00:00Z"), (13, null) })
            { var row = Row(id); row["time_created_utc"] = time; r.WorkspaceRows[id] = row; }
            await Handle(c); Assert.Equal(200, c.Response.StatusCode);
            var body = Response(c); var context = body.GetProperty("context");
            Assert.Equal(start, context.GetProperty("time_from_utc").GetString()); Assert.Equal(end, context.GetProperty("time_to_utc_exclusive").GetString());
            Assert.Equal(zone, context.GetProperty("timezone").GetString()); Assert.Equal(anchorInWindow, context.GetProperty("anchor_in_window").GetBoolean());
            Assert.Equal(anchorInWindow ? new long[] { 11, 10 } : [11], body.GetProperty("timeline").EnumerateArray().Select(row => row.GetProperty("event_db_id").GetInt64()));
            Assert.Equal(1, body.GetProperty("limits").GetProperty("events_with_unknown_time").GetInt32());
        }
    }
    [Theory]
    [InlineData("0")][InlineData("-1")][InlineData("")][InlineData("wrong")][InlineData("1.2")][InlineData("True")][InlineData("1e2")][InlineData("9007199254740992")][InlineData(" ")]
    public async Task InvalidExactIdsFailBeforeAccessOrEvidenceAndNeverUseNameQuery(string id)
    {
        foreach (string key in new[] { "event_db_id", "entity_id" })
        {
            var (c, r, p) = Setup("/api/v1/investigations?" + key + "=" + Uri.EscapeDataString(id) + "&q=name-must-not-be-used");
            using (p)
            {
                await Handle(c); Assert.Equal(400, c.Response.StatusCode); Assert.Equal("invalid_" + key, Response(c).GetProperty("error").GetString());
                Assert.Equal(0, ((FactsReader)p.GetRequiredService<IAccessFactsRepository>()).Reads);
                Assert.Empty(r.ResourceReads); Assert.Equal(0, r.MetadataReads + r.Hydrations);
            }
        }
    }
    [Fact] public async Task MissingRelatedResourceIsOmittedBeforePayloadRead()
    {
        var (c, r, p) = Setup("/api/v1/investigations?event_db_id=10"); using (p)
        {
            r.RelationIds = [11, 12, 13]; r.Missing = [12, 13];
            await Handle(c); Assert.Equal(200, c.Response.StatusCode);
            Assert.Equal(new long[] { 10, 11, 12, 13 }, r.ResourceReads); Assert.Equal(new long[] { 10, 11 }, r.Hydrated);
            Assert.Equal(new long[] { 11, 10 }, Response(c).GetProperty("timeline").EnumerateArray().Select(row => row.GetProperty("event_db_id").GetInt64()));
            Assert.DoesNotContain("Exact link 12", Response(c).GetRawText()); Assert.DoesNotContain("Exact link 13", Response(c).GetRawText());
        }
    }
    [Theory]
    [InlineData("report_scope")][InlineData("capability_scope")]
    public async Task RelatedProofNeedsItsOwnReportAndCapabilityScope(string denial)
    {
        var (c, r, p) = Setup("/api/v1/investigations?event_db_id=10",
            scope: denial == "report_scope" ? "{\"kind\":\"domain\",\"ids\":[1]}" : "{\"kind\":\"all\"}",
            deny: denial == "capability_scope" ? "{\"capability_key\":\"investigations.view\",\"effect\":\"deny\",\"scope_json\":{\"kind\":\"domain\",\"ids\":[2]}}" : null);
        using (p)
        {
            r.RelationIds = [11, 12, 13]; r.Hidden = [12, 13];
            await Handle(c); Assert.Equal(200, c.Response.StatusCode);
            Assert.Equal(new long[] { 10, 11, 12, 13 }, r.ResourceReads); Assert.Equal(new long[] { 10, 11 }, r.Hydrated);
            Assert.Equal(new long[] { 11, 10 }, Response(c).GetProperty("timeline").EnumerateArray().Select(row => row.GetProperty("event_db_id").GetInt64()));
            Assert.DoesNotContain("Exact link 12", Response(c).GetRawText()); Assert.DoesNotContain("Exact link 13", Response(c).GetRawText());
        }
    }
    [Theory]
    [InlineData("invalid_evidence_kind",400)][InlineData("invalid_relation_status",400)][InlineData("conflict",409)][InlineData("unavailable",503)][InlineData("not_found",404)]
    public async Task EvidenceMutationErrorsKeepSourceStatus(string error,int status)
    {var route=Routes.Last();var(c,r,p)=Setup(route.Data.Item1,route.Data.Item2);using(p){r.Failure=new(error,error,status);await Handle(c);Assert.Equal(status,c.Response.StatusCode);Assert.Equal(error,Response(c).GetProperty("error").GetString());Assert.Equal(0,r.Writes);} }
    [Theory]
    [InlineData("",409,"storage_v2_investigation_requires_exact_event_id")]
    [InlineData("q=alice",409,"storage_v2_investigation_requires_exact_event_id")]
    [InlineData("q=alice&route=v1&authorization=invalid",409,"storage_v2_investigation_requires_exact_event_id")]
    [InlineData("entity_id=0",400,"invalid_entity_id")]
    [InlineData("entity_id=10&cursor=bad",400,"invalid_cursor")]
    [InlineData("event_db_id=7&cursor=bad",400,"invalid_cursor")]
    [InlineData("event_db_id=7&time_from=2026-11-03&time_to=2026-11-01",400,"empty_or_reversed_time_range")]
    [InlineData("event_db_id=7&timezone=garbage",400,"invalid_timezone")]
    public async Task WorkspaceRejectsInvalidContext(string query,int status,string error)
    { var(c,r,p)=Setup("/api/v1/investigations?"+query);using(p){await Handle(c);Assert.Equal(status,c.Response.StatusCode);Assert.Equal(error,Response(c).GetProperty("error").GetString());Assert.Equal(0,r.Hydrations);} }
    [Fact]
    public async Task AnchoredUiWorkspaceBatchLoadsUniqueEvidenceAndRetainsEachRelationReason()
    {
        var (c, r, p) = Setup("/api/v1/investigations?event_db_id=10&q=alice"); using (p)
        {
            r.RelationRows = JsonNode.Parse("""[{"related_event_db_id":12,"reason":"newer"},{"related_event_db_id":11,"reason":"older"},{"related_event_db_id":12,"reason":"duplicate relation"},{"related_event_db_id":null,"reason":"invalid"}]""")!.AsArray();
            await Handle(c); Assert.Equal(200, c.Response.StatusCode);
            Assert.Equal(2, r.DetailBatches.Count); Assert.Equal(new long[] { 10 }, r.DetailBatches[0]); Assert.Equal(new long[] { 12, 11 }, r.DetailBatches[1]);
            var body = Response(c); var timeline = body.GetProperty("timeline");
            Assert.Equal(new long[] { 12, 12, 11, 10 }, timeline.EnumerateArray().Select(e => e.GetProperty("event_db_id").GetInt64()));
            Assert.Equal("newer", timeline[0].GetProperty("inclusion_reason").GetString()); Assert.Equal("duplicate relation", timeline[1].GetProperty("inclusion_reason").GetString());
            Assert.False(timeline[0].GetProperty("catalogued").GetBoolean()); Assert.Equal("unknown", timeline[0].GetProperty("assessment_confidence").GetString());
            Assert.Equal(40, body.GetProperty("limits").GetProperty("relations").GetInt32());
        }
    }
    [Fact] public async Task RegisteredRoutesCoexistWithExistingCaseRoutes()
    {
        var (_,r,p)=Setup("/api/v1/investigations/from-finding");using(p)
        using(var host=await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(s=>{
            s.AddRouting();s.AddLogging();s.AddSingleton(p.GetRequiredService<IConfiguration>());s.AddSingleton(p.GetRequiredService<AuthRequestPolicy>());s.AddSingleton(p.GetRequiredService<TransportGate>());s.AddSingleton(p.GetRequiredService<IPrincipalAuthenticator>());s.AddSingleton(p.GetRequiredService<IAccessFactsRepository>());
            s.AddSingleton<IInvestigationLinksRepository>(r);s.AddSingleton<IInvestigationRepository>(r);s.AddSingleton<IInvestigationEventRepository>(r);s.AddSingleton<IInvestigationVpnSessionEvidence>(r);s.AddSingleton<IInvestigationVpnEvidence>(r);s.AddSingleton<IEventReadService>(r);s.AddSingleton<IInvestigationEntityHistory>(r);
        }).Configure(app=>{app.UseRouting();app.UseEndpoints(e=>{e.MapInvestigationLinks();e.MapInvestigationWorkspace();e.MapInvestigationCreate();e.MapInvestigationEvents();e.MapInvestigationNoteEndpoints();e.MapInvestigationDetail();e.MapInvestigationList();});})).StartAsync(TestContext.Current.CancellationToken))
        using(var client=host.GetTestClient())
        {
            client.BaseAddress=new("https://localhost");
            foreach(var row in Routes)
            {
                string path=row.Data.Item1,body=row.Data.Item2;
                using var response=path.Contains('?')?await client.GetAsync(path,TestContext.Current.CancellationToken):await client.PostAsync(path,new StringContent(body,Encoding.UTF8,"application/json"),TestContext.Current.CancellationToken);
                Assert.Equal(503,(int)response.StatusCode);
            }
        }
    }
}
