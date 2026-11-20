using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Agents.Radius;

// Configuration-only counterpart of accounting_registration.py. Neither method
// connects to a source, registers DB state, bootstraps a cursor or starts a worker.
internal static class RadiusRegistrationContract
{
    private static string Text(JsonNode? node)=>node is JsonValue v && v.TryGetValue<string>(out var s)?s:"";
    private static void Require(bool valid,string code) { if(!valid) throw new ArgumentException(code); }
    private static bool Keys(JsonObject value,params string[] keys)=>value.Select(p=>p.Key).ToHashSet(StringComparer.Ordinal).SetEquals(keys);

    internal static JsonObject FromTemplate(JsonObject template,JsonObject routes)
    {
        var value=(JsonObject)template.DeepClone();
        string host=Text(routes["source_name"]),organization=host[(host.IndexOf('.')+1)..],label=host.Split('.')[0];
        var source=value["source"]!.AsObject();
        source["source_instance_id"]=routes["source_instance_id"]?.DeepClone();
        source["organization_scope"]=organization;
        source["endpoint_identity"]=$"fqdn:{host}|ipv4:{Text(routes["owner_confirmed_ip"])}";
        source["display_name"]=$"VPN/RADIUS — {host}";
        value["subscription"]!["subscription_id"]=$"vpn-radius-session-observations-{label}-v1";
        value["subscription"]!["partition_key"]=$"{organization}:{label}:radius-accounting";
        return Validate(value,routes);
    }

    internal static JsonObject Validate(JsonObject value,JsonObject routes)
    {
        Require(JsonNode.DeepEquals(value["schema_version"],JsonValue.Create(1)),"registration_schema_unsupported");
        Require(Text(value["contract_id"])=="sli.radius-accounting-registration.v1","registration_contract_id_unexpected");
        Require(Text(value["status"])=="prepared_disabled_only","registration_disabled_status_required");
        Require(JsonNode.DeepEquals(value["required_migration"],JsonValue.Create(58)),"registration_migration_invalid");
        Require(Text(value["desired_activation"])=="disabled","registration_must_be_disabled");
        Require(Text(value["observed_health"])=="unknown","registration_health_must_be_unknown");
        string host=Text(routes["source_name"]),ip=Text(routes["owner_confirmed_ip"]);
        string organization=host.Contains('.')?host[(host.IndexOf('.')+1)..]:"",label=host.Split('.')[0];
        var source=value["source"] as JsonObject;
        Require(source is not null && Keys(source,"source_instance_id","organization_scope","source_kind","endpoint_identity","adapter_binding","credential_handle","display_name")
            && Regex.IsMatch(host,@"\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z")
            && Text(source["source_instance_id"]).Length>0 && Text(source["source_instance_id"])==Text(routes["source_instance_id"])
            && IPAddress.TryParse(ip,out var address) && address.AddressFamily==AddressFamily.InterNetwork && address.ToString()==ip
            && Text(source["endpoint_identity"])==$"fqdn:{host}|ipv4:{ip}"
            && Text(source["organization_scope"])==organization && Text(source["source_kind"])=="windows.nps.radius"
            && Text(source["adapter_binding"])=="radius-accounting-database-compatible-v1" && source["credential_handle"] is null
            && Text(source["display_name"])==$"VPN/RADIUS — {host}","registration_source_identity_mismatch");
        var expectedStream=new JsonObject {
            ["stream_id"]="radius-accounting",["transport_binding"]="windows-rpc-smb-readonly-tail-v1",
            ["initial_cursor_policy"]="requires_bounded_live_bootstrap",
            ["rotation_policy"]="previous_generation_eof_then_new_generation_offset_zero"
        };
        Require(JsonNode.DeepEquals(value["stream"],expectedStream),"registration_stream_contract_mismatch");
        var subscription=value["subscription"] as JsonObject;
        Require(subscription is not null && Keys(subscription,"subscription_id","consumer_id","consumer_component_id","consumer_component_version","routing_contract_id","consumer_contract_version","replay_policy","resource_profile_id","selector","authority_mode","partition_key"),"registration_subscription_contract_mismatch");
        Require(Text(subscription!["routing_contract_id"])=="sli.radius-accounting-runtime.v1","registration_routing_contract_mismatch");
        Require(Text(subscription["authority_mode"])=="authoritative","registration_authority_mode_invalid");
        Require(Text(subscription["replay_policy"])=="bounded_replay","registration_replay_policy_invalid");
        Require(Text(subscription["subscription_id"])==$"vpn-radius-session-observations-{label}-v1","registration_subscription_scope_invalid");
        Require(Text(subscription["partition_key"])==$"{organization}:{label}:radius-accounting","registration_partition_scope_invalid");
        Require(Text(value["evidence_root_policy"])=="explicit_absolute_protected_acl_readback_required","registration_evidence_policy_invalid");
        Require(value["prohibited_actions"] is JsonArray actions && actions.Select(Text).ToHashSet(StringComparer.Ordinal).SetEquals(["production_apply","source_contact","cursor_bootstrap","worker_activation","autostart"]),"registration_prohibition_mismatch");
        return value;
    }
}
