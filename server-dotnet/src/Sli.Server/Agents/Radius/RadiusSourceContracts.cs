using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Agents.Radius;

// Configuration only: these loaders never register a source, activate a lease,
// or open a share. Identity follows the same route snapshot as the Python loaders.
public static class RadiusSourceContracts
{
    private static JsonObject Read(string path,string error)
    {
        try { return JsonNode.Parse(File.ReadAllBytes(path)) as JsonObject ?? throw new ArgumentException(error); }
        catch(Exception e) when(e is IOException or UnauthorizedAccessException or JsonException)
        { throw new ArgumentException(error); }
    }
    private static string Text(JsonNode? node)=>node is JsonValue v && v.TryGetValue<string>(out var text)?text:"";
    private static void Check(bool valid,string error) { if(!valid) throw new ArgumentException(error); }
    private static bool Keys(JsonObject value,params string[] keys)=>value.Select(p=>p.Key).ToHashSet(StringComparer.Ordinal).SetEquals(keys);
    private static JsonObject Template(string file)
    {
        using var stream=typeof(RadiusSourceContracts).Assembly.GetManifestResourceStream("Sli.Server.Agents.Radius."+file)
            ?? throw new InvalidOperationException("radius_contract_template_unavailable");
        return JsonNode.Parse(stream)!.AsObject();
    }

    public static JsonObject LoadRegistration(string configRoot,IReadOnlyDictionary<string,string?> env,string? path=null)
    {
        bool template=path is null && (!env.TryGetValue("ADLOG_RADIUS_REGISTRATION_CONTRACT_PATH",out var external) || string.IsNullOrEmpty(external));
        if(path is null) path=env.TryGetValue("ADLOG_RADIUS_REGISTRATION_CONTRACT_PATH",out var configured) && !string.IsNullOrEmpty(configured)
            ? configured : Path.Combine(configRoot,"stage9_radius_registration_v1.json");
        var value=Read(path,"registration_contract_invalid");
        var routes=RadiusCollectionRoute.Load(configRoot,env);
        string host=Text(routes["source_name"]),instance=Text(routes["source_instance_id"]),ip=Text(routes["owner_confirmed_ip"]);
        int dot=host.IndexOf('.');string organization=dot<0?"":host[(dot+1)..],label=dot<0?host:host[..dot];
        string subscriptionId=$"vpn-radius-session-observations-{label}-v1",partition=$"{organization}:{label}:radius-accounting";
        Check(value["source"] is JsonObject,"registration_source_identity_mismatch");
        Check(value["subscription"] is JsonObject,"registration_subscription_contract_mismatch");
        var source=value["source"]!.AsObject();var subscription=value["subscription"]!.AsObject();
        if(template)
        {
            source["source_instance_id"]=instance;source["organization_scope"]=organization;
            source["endpoint_identity"]=$"fqdn:{host}|ipv4:{ip}";source["display_name"]=$"VPN/RADIUS — {host}";
            subscription["subscription_id"]=subscriptionId;subscription["partition_key"]=partition;
        }
        Check(JsonNode.DeepEquals(value["schema_version"],JsonValue.Create(1)),"registration_schema_unsupported");
        Check(Text(value["contract_id"])=="sli.radius-accounting-registration.v1","registration_contract_id_unexpected");
        Check(Text(value["status"])=="prepared_disabled_only","registration_disabled_status_required");
        Check(JsonNode.DeepEquals(value["required_migration"],JsonValue.Create(58)),"registration_migration_invalid");
        Check(Text(value["desired_activation"])=="disabled","registration_must_be_disabled");
        Check(Text(value["observed_health"])=="unknown","registration_health_must_be_unknown");
        Check(Keys(source,"source_instance_id","organization_scope","source_kind","endpoint_identity","adapter_binding","credential_handle","display_name")
            && Regex.IsMatch(host,@"\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z",RegexOptions.CultureInvariant)
            && Regex.IsMatch(ip,@"\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z",RegexOptions.CultureInvariant)
            && IPAddress.TryParse(ip,out var address) && address.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork
            && Text(source["source_instance_id"])==instance && Text(source["organization_scope"])==organization
            && Text(source["source_kind"])=="windows.nps.radius" && Text(source["endpoint_identity"])==$"fqdn:{host}|ipv4:{ip}"
            && Text(source["adapter_binding"])=="radius-accounting-database-compatible-v1" && source["credential_handle"] is null
            && Text(source["display_name"])==$"VPN/RADIUS — {host}","registration_source_identity_mismatch");
        Check(JsonNode.DeepEquals(value["stream"],new JsonObject {
            ["stream_id"]="radius-accounting",["transport_binding"]="windows-rpc-smb-readonly-tail-v1",
            ["initial_cursor_policy"]="requires_bounded_live_bootstrap",["rotation_policy"]="previous_generation_eof_then_new_generation_offset_zero"
        }),"registration_stream_contract_mismatch");
        Check(Keys(subscription,"subscription_id","consumer_id","consumer_component_id","consumer_component_version","routing_contract_id","consumer_contract_version","replay_policy","resource_profile_id","selector","authority_mode","partition_key"),"registration_subscription_contract_mismatch");
        Check(Text(subscription["routing_contract_id"])=="sli.radius-accounting-runtime.v1","registration_routing_contract_mismatch");
        Check(Text(subscription["authority_mode"])=="authoritative","registration_authority_mode_invalid");
        Check(Text(subscription["replay_policy"])=="bounded_replay","registration_replay_policy_invalid");
        Check(Text(subscription["subscription_id"])==subscriptionId,"registration_subscription_scope_invalid");
        Check(Text(subscription["partition_key"])==partition,"registration_partition_scope_invalid");
        Check(Text(value["evidence_root_policy"])=="explicit_absolute_protected_acl_readback_required","registration_evidence_policy_invalid");
        Check(value["prohibited_actions"] is JsonArray actions && actions.All(a=>a is JsonValue v && v.TryGetValue<string>(out _))
            && actions.Select(Text).ToHashSet(StringComparer.Ordinal).SetEquals(["production_apply","source_contact","cursor_bootstrap","worker_activation","autostart"]),"registration_prohibition_mismatch");
        return value;
    }

    public static JsonObject LoadManualControl(string configRoot,IReadOnlyDictionary<string,string?> env)
    {
        var value=Read(Path.Combine(configRoot,"stage9_radius_manual_control_v1.json"),"manual_contract_invalid");
        var registration=LoadRegistration(configRoot,env);
        value["source_instance_id"]=registration["source"]!["source_instance_id"]!.DeepClone();
        value["subscription_id"]=registration["subscription"]!["subscription_id"]!.DeepClone();
        var expected=Template("stage9_radius_manual_control_v1.json");
        expected["source_instance_id"]=value["source_instance_id"]!.DeepClone();expected["subscription_id"]=value["subscription_id"]!.DeepClone();
        Check(JsonNode.DeepEquals(value,expected),"manual_contract_mismatch");
        return value;
    }

    public static JsonObject LoadConsumer(string configRoot,IReadOnlyDictionary<string,string?> env)
    {
        var value=Read(Path.Combine(configRoot,"stage9_radius_session_consumer_v1.json"),"consumer_contract_invalid");
        value["subscription_id"]=LoadRegistration(configRoot,env)["subscription"]!["subscription_id"]!.DeepClone();
        var expected=Template("stage9_radius_session_consumer_v1.json");
        string[] fields=["schema_version","contract_id","status","required_migration","consumer_role","read_model_contract_id","resource_group",
            "maximum_deliveries_per_claim","maximum_observations_per_session_key","lease_seconds","maximum_attempts","runtime_enabled","autostart_enabled","production_migration_applied","source_contact_allowed"];
        foreach(string field in fields) Check(JsonNode.DeepEquals(value[field],expected[field]),$"consumer_contract_{field}_invalid");
        Check(value["outcomes"] is JsonArray outcomes && outcomes.All(a=>a is JsonValue v && v.TryGetValue<string>(out _))
            && outcomes.Select(Text).ToHashSet(StringComparer.Ordinal).SetEquals(["projected","identity_unresolved","timestamp_unresolved"]),"consumer_contract_outcomes_invalid");
        return value;
    }
}
