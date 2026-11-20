using System.Text.Json.Nodes;
using System.Xml.Linq;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Domains;
using Sli.Server.Problems;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Semantic;
using Xunit;

namespace Sli.Server.Tests.Problems;

public sealed class AdminGroupLogAuditTests
{
    const string MemberSid = "S-1-5-21-100000001-200000002-300000003-1101";
    const string GroupSid = "S-1-5-21-100000001-200000002-300000003-512";
    const string At = "2026-11-13T10:00:00+00:00";
    static readonly PasswordScope Scope = new("11111111-1111-1111-1111-111111111111", "sli.windows.ad-dc", "synthetic", "1", "");
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static DetectionRow Event(int id, long native = 1) => new(new(Scope, "core_event", native.ToString(), new string('a',64)), DateTimeOffset.Parse(At).AddMinutes(native-1), id, "dc.example.test", new() {
        ["SubjectUserName"] = "admin", ["SubjectDomainName"] = "example.test", ["SubjectUserSid"] = MemberSid,
        ["TargetSid"] = GroupSid, ["TargetUserName"] = "Domain Admins", ["MemberSid"] = MemberSid, ["MemberName"] = "member",
        ["CategoryId"] = "%%8273", ["SubcategoryGuid"] = "{0cce9215-69ae-11d9-bed3-505054503030}", ["AuditPolicyChanges"] = "%%8448 %%8450",
        ["Channel"] = "Security" }) {
            Channel=id==104?"System":"Security", Provider=id is 104 or 1102?"Microsoft-Windows-Eventlog":"Microsoft-Windows-Security-Auditing" };
    static DetectionRow ShortEvent(DetectionRow row)
    {
        bool membership = row.EventId is 4728 or 4732 or 4756;
        var native = DetectionTests.Native(row, membership);
        XNamespace ns = EventXml.Namespace;
        var root = XElement.Parse(native["source_xml"]!.GetValue<string>());
        root.Element(ns + "System")!.Add(new XElement(ns + "Channel", row.Channel),
            new XElement(ns + "Provider", new XAttribute("Name", row.Provider)), new XElement(ns + "EventRecordID", row.Ref.NativeId));
        if (row.EventId is 104 or 1102) {
            XNamespace eventlog = "http://manifests.microsoft.com/win/2004/08/windows/eventlog";
            root.Element(ns + "EventData")!.ReplaceWith(new XElement(ns + "UserData", new XElement(eventlog + "LogFileCleared",
                row.Fields!.Select(field => new XElement(eventlog + field.Key, field.Value!.ToString())))));
        }
        var input = EventXml.Parse(root.ToString(), row.Host, row.Host, row.Channel);
        var compact = Assert.IsType<ShortEventRow>(ShortEventRow.Create(long.Parse(row.Ref.NativeId), 1, input, Direct4624Projection.Create(input), 1));
        var method = JsonNode.Parse(compact.Method)!;
        var fields = method["$principals"]!.DeepClone().AsObject();
        foreach (var (key, value) in compact.Fields) fields[key] = value;
        native["source_xml"] = new JsonObject {
            ["version"] = "sli.short-event.1", ["source_event_id"] = compact.EventId, ["event_id"] = compact.Kind,
            ["occurred_at_utc"] = D.Stamp(new(compact.Time)), ["scope"] = Scope.Document, ["fields"] = fields,
            ["computer"] = method["$machine_name"]?.DeepClone(), ["channel"] = method["$channel"]?.DeepClone(), ["provider"] = method["$provider"]?.DeepClone()
        }.ToJsonString();
        return Assert.Single(DetectionNative.ParseEvents(Scope, [native], membership));
    }
    static IReadOnlyList<JsonObject> Detect(params DetectionRow[] rows) => rows[0].EventId is 4728 or 4732 or 4756
        ? IdentityAttacks.Evaluate(Scope, rows, DateTimeOffset.Parse(At).AddHours(1))
        : AttackPrecursors.DetectEvents(rows, DateTimeOffset.Parse(At).AddHours(1));
    static string Rule(int id) => id is 4728 or 4732 or 4756 ? "qw.privileged-group-addition" : id == 4719 ? "qw.audit-disabled" : "qw.security-log-cleared";
    static JsonObject Observation(DetectionRow e) => new() {
        ["finding_id"] = 1, ["event_id"] = e.EventId, ["time_created_utc"] = e.At.ToString("yyyy-MM-ddTHH:mm:sszzz"), ["hostname"] = e.Host,
        ["subject_user_name"] = e.Get("SubjectUserName"), ["subject_domain_name"] = e.Get("SubjectDomainName"),
        ["target_user_name"] = e.Get("TargetUserName"), ["membership_member_name"] = e.Get("MemberName"), ["membership_member_sid"] = MemberSid,
        ["facts_json"] = new JsonObject { ["audit_category_id"] = e.Get("CategoryId"), ["audit_subcategory_guid"] = e.Get("SubcategoryGuid") } };
    static JsonObject Finding(int id) => new() { ["id"] = 1, ["rule_code"] = "semantic."+Rule(id), ["title"] = "stored English title", ["last_seen_utc"] = At, ["evidence_count"] = 1 };

    [Theory]
    [InlineData(4728)] [InlineData(4732)] [InlineData(4756)] [InlineData(1102)] [InlineData(104)] [InlineData(4719)]
    public async Task Short_events_enqueue_once_and_present_catalog_text_in_both_languages(int id)
    {
        var row = ShortEvent(Event(id));
        var signal = Assert.Single(Detect(row));
        Assert.Equal(Rule(id), signal["rule_id"]!.ToString()); Assert.Equal("high", signal["effective_severity"]!.ToString());
        var sql = new DetectionProducerTests.Sql();
        await DetectionProducer.Admit(sql, id is 4728 or 4732 or 4756 ? IdentityAttacks.PolicyDefinition(Scope,Rule(id)) : AttackPrecursors.PolicyDefinition(signal), Ct);
        await DetectionProducer.Enqueue(sql,signal,Ct); await DetectionProducer.Enqueue(sql,signal,Ct);
        Assert.Single(sql.Signals); Assert.Single(sql.Jobs);
        var finding = Finding(id); ProblemRepository.AttachDetectionPresentation([finding],[Observation(row)]);
        foreach (string language in new[] {"ru","en"}) {
            bool en = language=="en";
            string title = id is 4728 or 4732 or 4756 ? en ? "An account was added to an administrators group" : "Учётную запись добавили в группу администраторов"
                : id==4719 ? en ? "Auditing was turned off on a computer" : "На компьютере отключили аудит" : en ? "Security log cleared" : "Журнал безопасности очищен";
            string what = id is 4728 or 4732 or 4756 ? en ? $"example.test\\admin added member to Domain Admins at {At}." : $"example.test\\admin добавил member в группу Domain Admins в {At}."
                : id==4719 ? en ? $"example.test\\admin turned off auditing of Logon on dc.example.test at {At}." : $"example.test\\admin отключил аудит «Вход» на dc.example.test в {At}."
                : en ? $"example.test\\admin cleared the security log on dc.example.test at {At}." : $"example.test\\admin очистил журнал безопасности на dc.example.test в {At}.";
            var view = ProblemPresentation.Finding(finding,ProblemLifecycleTests.Access("security.queue"),language);
            Assert.Equal(title,view["title"]!.ToString()); Assert.Equal(what,view["what_happened"]!.ToString());
            var home = HomePresentation.Finding(finding,language); Assert.Equal(title,home["title"]!.ToString()); Assert.Equal(what,home["what"]!.ToString());
            string next = id is 4728 or 4732 or 4756 ? en ? "1) Ask example.test\\admin whether this was planned. 2) If not, remove member from the group and reset the password of example.test\\admin." : "1) Уточните у example.test\\admin, было ли это запланировано. 2) Если нет — удалите member из группы и смените пароль example.test\\admin."
                : id==4719 ? en ? "1) Restore the setting: in SLI, “Agents” → computer → “Audit”. 2) Ask example.test\\admin why it was changed." : "1) Верните настройку: в SLI «Агенты» → компьютер → «Аудит». 2) Уточните у example.test\\admin причину."
                : en ? "1) Ask example.test\\admin why this was done. 2) If nobody confirms it, treat the computer as compromised: reset administrator passwords and review “Domain changes” for the day before the log was cleared." : "1) Уточните у example.test\\admin, зачем это сделано. 2) Если никто не подтверждает — считайте компьютер взломанным: смените пароли администраторов и проверьте «Изменения в домене» за сутки до очистки.";
            Assert.Equal(next,view["next_text"]!.ToString()); Assert.Equal(next,home["next_step"]!.ToString());
            var denied=ProblemPresentation.Finding(finding,ProblemLifecycleTests.Access("security.queue",fields:["security"]),language);
            Assert.DoesNotContain("admin",denied["what_happened"]!.ToString());
        }
    }

    [Theory] [InlineData(4728)] [InlineData(1102)] [InlineData(4719)]
    public void Missing_optional_names_leave_a_factual_sentence_without_placeholders(int id)
    {
        var row=Event(id); var observation=Observation(row);
        observation["subject_user_name"]=null; observation["membership_member_name"]=null;
        observation["facts_json"]=new JsonObject();
        var finding=Finding(id); finding["actor"]="previous-admin"; ProblemRepository.AttachDetectionPresentation([finding],[observation]);
        foreach(string language in new[]{"ru","en"}) {
            string text=ProblemPresentation.RuleMessage(finding,"what",language)["text"]!.ToString();
            Assert.Contains(At,text); Assert.DoesNotContain("{",text); Assert.DoesNotContain("S-1-",text);
            Assert.DoesNotContain("Нет данных",text); Assert.DoesNotContain("Unknown",text);
            Assert.DoesNotContain("previous-admin",text);
            Assert.False(string.IsNullOrWhiteSpace(text));
            if (id == 4728) Assert.Contains(language == "en" ? "an account" : "учётную запись", text);
            string next = ProblemPresentation.RuleMessage(finding,"next",language)["text"]!.ToString();
            Assert.False(string.IsNullOrWhiteSpace(next));
            Assert.DoesNotContain("{",next);
            Assert.DoesNotContain("previous-admin",next);
            Assert.False(next.StartsWith("2)", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Audit_enabling_and_ordinary_group_changes_do_not_create_problems()
    {
        var enabled=Event(4719); enabled.Fields!["AuditPolicyChanges"]="%%8449 %%8451"; Assert.Empty(Detect(enabled));
        var ordinary=Event(4728); ordinary.Fields!["TargetSid"]="S-1-5-21-100000001-200000002-300000003-513"; Assert.Empty(Detect(ordinary));
        Assert.Empty(Detect(Event(4729)));
        Assert.Empty(Detect(Event(104) with { Provider="Synthetic-Other-Provider" }));
        Assert.Empty(Detect(Event(104) with { Channel="Application" }));
    }

    [Theory]
    [InlineData("System")]
    [InlineData("Application")]
    [InlineData(null)]
    public void System_event_104_needs_the_cleared_log_to_be_security(string? log)
    {
        var row = Event(104);
        if (log is null) row.Fields!.Remove("Channel");
        else row.Fields!["Channel"] = log;
        Assert.Empty(Detect(ShortEvent(row)));
    }

    [Fact]
    public void Real_1102_userdata_preserves_initiator_and_rejects_ambiguous_payload()
    {
        var row=Event(1102); var native=DetectionTests.Native(row,false);
        native["source_xml"]=$"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1102</EventID><TimeCreated SystemTime='{At}'/><Computer>dc.example.test</Computer></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>admin</SubjectUserName><SubjectDomainName>example.test</SubjectDomainName></LogFileCleared></UserData></Event>";
        Assert.Equal("admin",Assert.Single(DetectionNative.ParseEvents(Scope,[native])).Get("SubjectUserName"));
        native["source_xml"]=native["source_xml"]!.ToString().Replace("</SubjectUserName>","</SubjectUserName><SubjectUserName>other</SubjectUserName>");
        Assert.Throws<DetectionFailure>(()=>DetectionNative.ParseEvents(Scope,[native]));
    }

    [Theory] [InlineData(4728)] [InlineData(1102)] [InlineData(4719)]
    public void Repeated_events_keep_the_same_object_and_all_native_proof(int id)
    {
        var first=Event(id); var second=Event(id,2); var initial=Assert.Single(Detect(first)); var repeated=Detect(first,second);
        Assert.All(repeated,s=>Assert.Equal(initial["entity_key"]!.ToString(),s["entity_key"]!.ToString()));
        Assert.Equal(new[] {"1","2"},repeated.SelectMany(s=>s["evidence_refs"]!.AsArray()).Select(r=>r!["native_id"]!.ToString()).Distinct().Order());
    }
    [Theory] [InlineData(4728)] [InlineData(1102)] [InlineData(104)] [InlineData(4719)]
    public async Task Queue_keeps_one_row_and_increases_count_for_repeated_series(int id)
    {
        await using var pg=new PostCollectionPostgres(); await pg.StartAsync(Ct);
        await using var db=new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db,"""
            create table findings_active(id bigint,rule_code text,fingerprint text,target text,source text,severity text,status text,repeat_count int,first_seen_utc text,last_seen_utc text,evidence_count int default 0);
            create table semantic_security_scenarios(scenario_key bytea,scenario_kind text,partition_key text,strict_keys_json jsonb);
            create table finding_event_copies337(finding_id bigint,event_id bigint,time_created_utc timestamptz,evidence_role text,fields jsonb);
            create table finding_event_details337(finding_id bigint,event_db_id bigint,event_id int,time_created_utc timestamptz,
                hostname text,subject_user_name text,subject_domain_name text,target_user_name text,membership_member_sid text,
                channel text,identity_provider text,evidence_role text);
            """,Ct);
        async Task Add(long finding,DetectionRow ev,JsonObject signal) {
            await using var cmd=new NpgsqlCommand("""
                insert into findings_active(id,rule_code,fingerprint,target,source,severity,status,repeat_count,first_seen_utc,last_seen_utc) values(@finding,@rule,'semantic:'||@hash,null,null,'high','new',0,@at,@at);
                insert into semantic_security_scenarios values(decode(@hash,'hex'),@kind,'synthetic',jsonb_build_object('entity',@entity::text));
                insert into finding_event_details337 values(@finding,@native,@event,@at::timestamptz,'dc.example.test',
                    'admin','example.test','Domain Admins',@sid,@channel,@provider,'primary');
                insert into finding_event_copies337 values(@finding,@native,@at::timestamptz,'primary',
                    '{"MemberName":"member","CategoryId":"%%8273","SubcategoryGuid":"{0cce9215-69ae-11d9-bed3-505054503030}","Channel":"Security"}');
                """,db);
            cmd.Parameters.AddWithValue("finding",finding); cmd.Parameters.AddWithValue("rule","semantic."+Rule(id));
            cmd.Parameters.AddWithValue("hash",new string(finding==1?'a':'b',64)); cmd.Parameters.AddWithValue("kind",Rule(id));
            cmd.Parameters.AddWithValue("entity",signal["entity_key"]!.ToString()); cmd.Parameters.AddWithValue("at",ev.At.ToString("O"));
            cmd.Parameters.AddWithValue("native",long.Parse(ev.Ref.NativeId)); cmd.Parameters.AddWithValue("event",id);
            cmd.Parameters.AddWithValue("channel",ev.Channel); cmd.Parameters.AddWithValue("provider",ev.Provider);
            cmd.Parameters.AddWithValue("sid",MemberSid); await cmd.ExecuteNonQueryAsync(Ct);
        }
        string queue=ProblemCohorts.Queue("from findings_active findings","","findings.status","false")+"select occurrence_count from queue_groups";
        async Task<long[]> Counts() { await using var cmd=new NpgsqlCommand(queue,db); await using var reader=await cmd.ExecuteReaderAsync(Ct); var values=new List<long>(); while(await reader.ReadAsync(Ct))values.Add(Convert.ToInt64(reader.GetValue(0))); return values.ToArray(); }
        var first=Event(id); await Add(1,first,Assert.Single(Detect(first))); Assert.Equal(new long[]{1},await Counts());
        var second=Event(id,2); await Add(2,second,Assert.Single(Detect(second))); Assert.Equal(new long[]{2},await Counts());
        // An event linked twice under different proof roles is still one occurrence.
        await PostCollectionPostgres.Sql(db,"insert into finding_event_details337 select finding_id,event_db_id,event_id,time_created_utc,hostname,subject_user_name,subject_domain_name,target_user_name,membership_member_sid,channel,identity_provider,'secondary' from finding_event_details337 where finding_id=2;",Ct); Assert.Equal(new long[]{2},await Counts());
        if (id == 104) await PostCollectionPostgres.Sql(db,"""
            insert into finding_event_details337 select finding_id,3,event_id,time_created_utc+interval '1 minute',hostname,
                'other-admin',subject_domain_name,target_user_name,membership_member_sid,channel,identity_provider,evidence_role
                from finding_event_details337 where finding_id=1;
            insert into finding_event_copies337 select finding_id,3,time_created_utc+interval '1 minute',evidence_role,
                jsonb_set(fields,'{Channel}','"Application"') from finding_event_copies337 where finding_id=1;
            """,Ct);
        var finding=Finding(id);
        await using var command=new NpgsqlCommand(ProblemRepository.DetectionPresentationSql,db); command.Parameters.AddWithValue("ids",new long[]{1});
        await using var details=await command.ExecuteReaderAsync(Ct); var observations=new List<JsonObject>();
        while(await details.ReadAsync(Ct)) { var observation=new JsonObject(); for(int i=0;i<details.FieldCount;i++) {
            if(details.IsDBNull(i))continue;
            observation[details.GetName(i)]=details.GetDataTypeName(i)=="jsonb"?JsonNode.Parse(details.GetString(i)):details.GetValue(i) switch {
                long number=>JsonValue.Create(number),int number=>JsonValue.Create(number),DateTime time=>JsonValue.Create(new DateTimeOffset(time).ToString("yyyy-MM-ddTHH:mm:sszzz")),var value=>JsonValue.Create(value.ToString()) };
        } observations.Add(observation); }
        ProblemRepository.AttachDetectionPresentation([finding],observations);
        Assert.Equal("example.test\\admin",finding["presentation_facts"]!["actor"]!.ToString());
        Assert.Equal("dc.example.test",finding["presentation_facts"]!["computer"]!.ToString());
        Assert.Equal(At,finding["presentation_facts"]!["time"]!.ToString());
        if(id==4719)Assert.Equal("Вход",ProblemPresentation.RuleParameters(finding)["category"]!.ToString());
        if(id==4728)Assert.Equal("member",ProblemPresentation.RuleParameters(finding)["member"]!.ToString());
    }

}
