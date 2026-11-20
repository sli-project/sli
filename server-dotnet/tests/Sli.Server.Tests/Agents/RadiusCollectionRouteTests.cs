using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Radius;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class RadiusCollectionRouteTests : IDisposable
{
    readonly string configRoot=Path.Combine(Path.GetTempPath(),"radius-collection-"+Guid.NewGuid().ToString("N"));
    readonly Dictionary<string,string?> env=new();
    public RadiusCollectionRouteTests()
    {
        Directory.CreateDirectory(configRoot);
        var root=new DirectoryInfo(AppContext.BaseDirectory);
        while(root is not null && !File.Exists(Path.Combine(root.FullName,"config","stage9_radius_registration_v1.json"))) root=root.Parent;
        Assert.NotNull(root);
        foreach(string file in new[]{"stage9_radius_registration_v1.json","stage9_radius_manual_control_v1.json","stage9_radius_session_consumer_v1.json"})
            File.Copy(Path.Combine(root.FullName,"config",file),Path.Combine(configRoot,file));
        Save(DefaultRoute());
    }
    public void Dispose()=>Directory.Delete(configRoot,true);
    static JsonObject DefaultRoute()
    {
        var value=JsonNode.Parse(Route.Replace("nps.example.test","radius01.example.test"))!.AsObject();
        value["source_instance_id"]="radius01.example.test";value["owner_confirmed_ip"]="198.51.100.23";
        return value;
    }
    void Save(JsonNode? route,string name="stage10_radius_collection_routes_v1.json")=>File.WriteAllText(Path.Combine(configRoot,name),route?.ToJsonString()??"null");
    JsonObject Load()=>RadiusCollectionRoute.Load(configRoot,env);
    JsonObject Describe(JsonObject value)=>RadiusCollectionRoute.Describe(JsonSerializer.SerializeToElement(value),env);
    void OverrideIdentity()
    {
        env["ADLOG_RADIUS_SOURCE_NAME"]="radius02.example.test";
        env["ADLOG_RADIUS_SOURCE_INSTANCE_ID"]="radius-source-02";
        env["ADLOG_RADIUS_OWNER_CONFIRMED_IP"]="198.51.100.24";
        env["ADLOG_RADIUS_ACCOUNTING_SHARE_UNC"]=@"\\radius02.example.test\Accounting$";
    }
    internal const string Route="""
      {"schema_version":1,"contract_id":"sli.radius-collection-routes.v1",
       "source_name":"nps.example.test","connect_address":"nps.example.test","source_instance_id":"radius-instance",
       "runtime_enabled":false,"autostart_enabled":false,
       "event_log_route":{"pack_id":"sli.windows.vpn-radius","channel":"Security","provider_name":"Microsoft-Windows-Security-Auditing",
         "event_ids":[6272,6273],"transport":"windows_event_log_rpc","collection_entrypoint":"scripts/run_dc_log_pilot.py",
         "primary_adapter":"windows-eventlog-pywin32","fallback_adapter":"windows-eventlog-powershell"},
       "accounting_route":{"transport":"dedicated_read_only_smb_share","share_unc":"\\\\nps.example.test\\Accounting",
        "administrative_shares_forbidden":["c$","admin$","ipc$"],"default_windows_logfiles_path_forbidden":true,
        "timezone_descriptor":{"source":"static_accepted_evidence","timezone_id":"N. Central Asia Standard Time","utc_offset_minutes":420,
        "remote_registry_allowed":false,"drift_check_required_before_activation":false,"drift_check_accepted":false,
        "owner_assumption_active":true,"owner_assumption_recorded_on":"2026-08-02"}}}
      """;
    [Fact]
    public void ValidatesSourceRouteAndOverridesBeforeSelectingSource()
    {
        using var doc=JsonDocument.Parse(Route);
        var env=new Dictionary<string,string?> { ["ADLOG_RADIUS_SOURCE_NAME"]="  renamed.example.test  ", ["ADLOG_RADIUS_ACCOUNTING_SHARE_UNC"]="\\\\renamed.example.test\\logs" };
        Assert.Equal("renamed.example.test",RadiusCollectionRoute.Validate(doc.RootElement,env));
        env["ADLOG_RADIUS_ACCOUNTING_SHARE_UNC"]="\\\\wrong.example.test\\logs";
        Assert.Throws<ArgumentException>(()=>RadiusCollectionRoute.Validate(doc.RootElement,env));
    }
    [Fact]
    public void RejectsUnsafeAndMisconfiguredRoutes()
    {
        foreach(string text in new[]{Route.Replace("\"runtime_enabled\":false","\"runtime_enabled\":true"),Route.Replace("nps.example.test\\\\Accounting","nps.example.test\\\\C$"),Route.Replace("6272,6273","6273,6272")})
        { using var doc=JsonDocument.Parse(text);Assert.Throws<ArgumentException>(()=>RadiusCollectionRoute.Validate(doc.RootElement,new Dictionary<string,string?>())); }
    }
    [Fact]
    public void SourceAcceptsNumericStringsAndFloatEventIds()
    {
        string input=Route.Replace("\"schema_version\":1","\"schema_version\":\"1\"")
            .Replace("\"utc_offset_minutes\":420","\"utc_offset_minutes\":\"420\"")
            .Replace("[6272,6273]","[6272.0,6273.0]");
        using var doc=JsonDocument.Parse(input);
        Assert.Equal("nps.example.test",RadiusCollectionRoute.Validate(doc.RootElement,new Dictionary<string,string?>()));
    }
    [Fact]
    public void SourceStringConversionAndLastJsonMemberArePreserved()
    {
        string input=Route.Replace("\"source_name\":\"nps.example.test\",\"connect_address\":\"nps.example.test\"", "\"source_name\":\"ignored\",\"source_name\":123,\"connect_address\":123")
            .Replace("\"share_unc\":","\"ignored_unc\":");
        using var doc=JsonDocument.Parse(input);
        Assert.Equal("123",RadiusCollectionRoute.Validate(doc.RootElement,new Dictionary<string,string?>()));
    }

    // Vectors from tests/sources/test_radius_collection_routes.py.
    [Fact]
    public void EnvironmentSelectsExternalRouteFile()
    {
        var value=DefaultRoute();value["source_name"]="radius02.example.test";value["connect_address"]="radius02.example.test";
        value["source_instance_id"]="radius-source-02";value["accounting_route"]!["share_unc"]=@"\\radius02.example.test\Accounting$";
        Save(value,"routes.json");env["ADLOG_RADIUS_COLLECTION_ROUTES_PATH"]=Path.Combine(configRoot,"routes.json");
        var result=Load();
        Assert.Equal("radius02.example.test",result["source_name"]!.GetValue<string>());
        Assert.Equal("radius-source-02",result["source_instance_id"]!.GetValue<string>());
        Assert.Equal(@"\\radius02.example.test\Accounting$",result["accounting_share_unc"]!.GetValue<string>());
    }

    [Fact]
    public void EnvironmentEndpointsKeepIdentityConsistent()
    {
        OverrideIdentity();var result=Load();
        Assert.Equal("radius02.example.test",result["source_name"]!.GetValue<string>());
        Assert.Equal("radius-source-02",result["source_instance_id"]!.GetValue<string>());
        Assert.True(result["accounting_ready"]!.GetValue<bool>());
        env.Remove("ADLOG_RADIUS_SOURCE_INSTANCE_ID");
        Assert.Equal("radius02.example.test",Load()["source_instance_id"]!.GetValue<string>());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ConfiguredIdentityReachesRegistrationLeaseAndConsumer(bool externalRegistration)
    {
        OverrideIdentity();var registration=RadiusSourceContracts.LoadRegistration(configRoot,env);
        if(externalRegistration)
        {
            registration["subscription"]!["consumer_component_version"]="synthetic-version";
            Save(registration,"registration.json");env["ADLOG_RADIUS_REGISTRATION_CONTRACT_PATH"]=Path.Combine(configRoot,"registration.json");
            Assert.True(JsonNode.DeepEquals(registration,RadiusSourceContracts.LoadRegistration(configRoot,env)));
        }
        Assert.Equal("radius-source-02",registration["source"]!["source_instance_id"]!.GetValue<string>());
        Assert.Equal("example.test",registration["source"]!["organization_scope"]!.GetValue<string>());
        Assert.Equal("fqdn:radius02.example.test|ipv4:198.51.100.24",registration["source"]!["endpoint_identity"]!.GetValue<string>());
        Assert.Equal("disabled",registration["desired_activation"]!.GetValue<string>());
        var lease=RadiusSourceContracts.LoadManualControl(configRoot,env);var consumer=RadiusSourceContracts.LoadConsumer(configRoot,env);
        Assert.Equal("radius-source-02",lease["source_instance_id"]!.GetValue<string>());
        Assert.Equal("vpn-radius-session-observations-radius02-v1",lease["subscription_id"]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(registration["subscription"]!["subscription_id"],consumer["subscription_id"]));
        var pinned=new JsonObject { ["subscription_id"]=consumer["subscription_id"]!.DeepClone() };
        env["ADLOG_RADIUS_SOURCE_NAME"]="changed.example.test";
        Assert.Equal("vpn-radius-session-observations-radius02-v1",RadiusObservationHost.ConsumerSubscription(pinned));
    }

    [Fact]
    public void UnconfiguredSourceHasExplicitError()
    {
        var value=DefaultRoute();foreach(string key in new[]{"source_name","connect_address","source_instance_id"}) value[key]="";
        Save(value);
        Assert.Equal("radius_source_not_configured",Assert.Throws<ArgumentException>(()=>Load()).Message);
    }

    [Fact]
    public void EmptyEnvironmentSourceDoesNotFallBack()
    {
        env["ADLOG_RADIUS_SOURCE_NAME"]=" ";
        Assert.Equal("radius_source_not_configured",Assert.Throws<ArgumentException>(()=>Load()).Message);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("\"invalid\"")]
    public void ExternalRouteMustBeAnObjectBeforeOverrides(string json)
    {
        File.WriteAllText(Path.Combine(configRoot,"routes.json"),json);
        env["ADLOG_RADIUS_COLLECTION_ROUTES_PATH"]=Path.Combine(configRoot,"routes.json");env["ADLOG_RADIUS_SOURCE_NAME"]="radius02.example.test";
        Assert.Equal("route_contract_object_required",Assert.Throws<ArgumentException>(()=>Load()).Message);
    }

    [Fact]
    public void ReadyRoutesKeepRuntimeOffAndExposeAcceptedTimezoneAssumption()
    {
        var result=Load();
        Assert.True(result["event_log_ready"]!.GetValue<bool>());Assert.True(result["accounting_ready"]!.GetValue<bool>());
        Assert.Equal("windows-eventlog-pywin32",result["event_log_adapter"]!.GetValue<string>());
        Assert.Equal("windows-eventlog-powershell",result["event_log_fallback_adapter"]!.GetValue<string>());
        Assert.Empty(result["blockers"]!.AsArray());
        Assert.False(result["timezone_drift_check_accepted"]!.GetValue<bool>());Assert.True(result["timezone_owner_assumption_active"]!.GetValue<bool>());
        var (share,timezone,offset)=RadiusCollectionRoute.RequireAccountingSource(configRoot,env);
        Assert.Equal(result["accounting_share_unc"]!.GetValue<string>().TrimEnd('\\'),share.TrimEnd('\\'));
        Assert.Equal("N. Central Asia Standard Time",timezone);Assert.Equal(420,offset);
        Assert.False(result["runtime_enabled"]!.GetValue<bool>());Assert.False(result["autostart_enabled"]!.GetValue<bool>());
        Assert.True(JsonNode.DeepEquals(result["source_name"],result["source_instance_id"]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingShareBlocksAccountingAndFailsRequirement(bool environmentOverride)
    {
        if(environmentOverride) env["ADLOG_RADIUS_ACCOUNTING_SHARE_UNC"]=" ";
        else { var value=DefaultRoute();value["accounting_route"]!["share_unc"]=null;Save(value); }
        var result=Load();Assert.False(result["accounting_ready"]!.GetValue<bool>());Assert.Null(result["accounting_share_unc"]);
        Assert.Equal("radius_dedicated_read_only_share_not_configured",Assert.Single(result["blockers"]!.AsArray())!.GetValue<string>());
        Assert.Equal("radius_dedicated_read_only_share_not_configured",Assert.Throws<ArgumentException>(()=>RadiusCollectionRoute.RequireAccountingSource(configRoot,env)).Message);
    }

    [Theory]
    [InlineData(@"\\radius01.example.test\c$\Windows\System32\LogFiles","dedicated_share_unc_required")]
    [InlineData(@"\\radius01.example.test\admin$\System32\LogFiles","dedicated_share_unc_required")]
    [InlineData(@"\\other.example.test\RadiusAccounting$","dedicated_share_host_mismatch")]
    [InlineData(@"\\radius01.example.test\ADMIN$","administrative_share_forbidden")]
    [InlineData(@"\\radius01.example.test\ipc$","administrative_share_forbidden")]
    public void AdministrativeOrWrongHostShareFailsClosed(string share,string error)
    {
        var value=DefaultRoute();value["accounting_route"]!["share_unc"]=share;
        Assert.Equal(error,Assert.Throws<ArgumentException>(()=>Describe(value)).Message);
    }

    [Theory]
    [InlineData("radius01.example.test")]
    [InlineData("radius-prototype.example.test")]
    public void ConsistentDedicatedHiddenShareIsAcceptedWithoutStartingRuntime(string host)
    {
        var value=DefaultRoute();value["source_name"]=host;value["connect_address"]=host;value["source_instance_id"]=host;
        value["accounting_route"]!["share_unc"]=$@"\\{host}\SLI-RadiusAccounting$";
        var result=Describe(value);Assert.Equal(host,result["source_name"]!.GetValue<string>());Assert.Equal(host,result["source_instance_id"]!.GetValue<string>());
        Assert.True(result["accounting_ready"]!.GetValue<bool>());Assert.False(result["runtime_enabled"]!.GetValue<bool>());Assert.False(result["autostart_enabled"]!.GetValue<bool>());
    }

    [Theory]
    [InlineData("source_instance_id","","source_instance_id_mismatch")]
    [InlineData("connect_address","other-radius.example.test","source_identity_mismatch")]
    public void InconsistentIdentityHasExplicitError(string key,string replacement,string error)
    {
        var value=DefaultRoute();value[key]=replacement;
        Assert.Equal(error,Assert.Throws<ArgumentException>(()=>Describe(value)).Message);
    }

    [Theory]
    [InlineData("remote_registry_allowed",true)]
    [InlineData("owner_assumption_active",false)]
    public void TimezoneSafetyCannotBeSilentlyChanged(string key,bool replacement)
    {
        var value=DefaultRoute();value["accounting_route"]!["timezone_descriptor"]![key]=replacement;
        Assert.Equal("accounting_route_mismatch",Assert.Throws<ArgumentException>(()=>Describe(value)).Message);
    }

    [Theory]
    [InlineData("runtime_enabled")]
    [InlineData("autostart_enabled")]
    public void RuntimeCannotBeEnabled(string key)
    {
        var value=DefaultRoute();value[key]=true;
        Assert.Equal("runtime_must_remain_disabled",Assert.Throws<ArgumentException>(()=>Describe(value)).Message);
    }

    [Fact]
    public void ExplicitRoutePathIsNotReboundByEnvironment()
    {
        OverrideIdentity();var result=RadiusCollectionRoute.Load(configRoot,env,Path.Combine(configRoot,"stage10_radius_collection_routes_v1.json"));
        Assert.Equal("radius01.example.test",result["source_name"]!.GetValue<string>());
        env["ADLOG_RADIUS_SOURCE_NAME"]="";
        Assert.Equal("radius01.example.test",RadiusCollectionRoute.Load(configRoot,env,Path.Combine(configRoot,"stage10_radius_collection_routes_v1.json"))["source_instance_id"]!.GetValue<string>());
    }

    [Fact]
    public void ExternalRegistrationCannotOverrideConfiguredIdentityOrEnableRuntime()
    {
        OverrideIdentity();var registration=RadiusSourceContracts.LoadRegistration(configRoot,env);
        env["ADLOG_RADIUS_REGISTRATION_CONTRACT_PATH"]=Path.Combine(configRoot,"registration.json");
        registration["source"]!["source_instance_id"]="wrong-source";Save(registration,"registration.json");
        Assert.Equal("registration_source_identity_mismatch",Assert.Throws<ArgumentException>(()=>RadiusSourceContracts.LoadRegistration(configRoot,env)).Message);
        registration["source"]!["source_instance_id"]="radius-source-02";registration["desired_activation"]="manual_enabled";Save(registration,"registration.json");
        Assert.Equal("registration_must_be_disabled",Assert.Throws<ArgumentException>(()=>RadiusSourceContracts.LoadRegistration(configRoot,env)).Message);
    }

    [Fact]
    public void DerivedContractsKeepTheirSafetyChecks()
    {
        OverrideIdentity();
        string manualFile=Path.Combine(configRoot,"stage9_radius_manual_control_v1.json");var manual=JsonNode.Parse(File.ReadAllText(manualFile))!;
        manual["lease"]!["worker_admin_db_access_enabled"]=true;File.WriteAllText(manualFile,manual.ToJsonString());
        Assert.Equal("manual_contract_mismatch",Assert.Throws<ArgumentException>(()=>RadiusSourceContracts.LoadManualControl(configRoot,env)).Message);
        string consumerFile=Path.Combine(configRoot,"stage9_radius_session_consumer_v1.json");var consumer=JsonNode.Parse(File.ReadAllText(consumerFile))!;
        consumer["source_contact_allowed"]=true;File.WriteAllText(consumerFile,consumer.ToJsonString());
        Assert.Equal("consumer_contract_source_contact_allowed_invalid",Assert.Throws<ArgumentException>(()=>RadiusSourceContracts.LoadConsumer(configRoot,env)).Message);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"subscription_id\":null}")]
    [InlineData("{\"subscription_id\":1}")]
    [InlineData("{\"subscription_id\":\"\"}")]
    public void ChildRejectsMissingOrNonStringSubscriptionBeforeDatabaseAccess(string input)
    {
        Assert.Equal("consumer_subscription_invalid",Assert.Throws<InvalidOperationException>(()=>RadiusObservationHost.ConsumerSubscription(JsonNode.Parse(input)!.AsObject())).Message);
    }
}
