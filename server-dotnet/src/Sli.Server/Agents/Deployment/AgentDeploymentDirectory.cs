using System.Text.Json.Nodes;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Groups;

namespace Sli.Server.Agents.Deployment;

internal sealed class AgentDeploymentDirectory(IAgentDeploymentDatabase db)
{
    internal const string CurrentDirectory = "from ad_context_entity_versions v join entities_v2 e on e.id=v.entity_id join ad_context_runs r on r.run_id=v.source_run_id and r.domain_id=e.domain_id join ad_context_sections s on s.run_id=r.run_id and s.section_name=v.source_section where e.domain_id=@domain and v.valid_to_utc is null and r.status='completed' and s.status='complete' and v.last_observed_at_utc between clock_timestamp()-interval '24 hours' and clock_timestamp()";
    internal async Task<(long Version, string[] Dn, JsonObject Record)> Resolve(long entity, long domain, bool ou, CancellationToken ct)
    {
        var rows = await db.Rows("select v.id as version_id,v.attributes_json as record " + CurrentDirectory + " and e.id=@id and v.source_section=@section", ct,
            ("domain", domain), ("id", entity), ("section", ou ? "domain_posture" : "directory_accounts"));
        if (rows.Count == 0) throw new AgentControlException("invalid_group_enrollment_scope");
        var row = rows[0];
        return (AdOperationCredentials.Long(row, "version_id"), AgentGroupDirectory.Record(row["record"], ou), row["record"]!.AsObject());
    }
    internal async Task<JsonObject> Read(JsonObject body, CancellationToken ct)
    {
        if (!AgentGroupInput.Allowed(body, "domain_id", "ou_entity_ids")) throw new AgentControlException("invalid_group_enrollment_scope");
        if (!body.ContainsKey("domain_id"))
        {
            var domains = await db.Rows("select distinct d.id,d.fqdn as name from domains d join ad_context_runs r on r.domain_id=d.id join ad_context_sections s on s.run_id=r.run_id where r.status='completed' and s.section_name='directory_accounts' and s.status='complete' order by d.id limit 1000", ct);
            return new() { ["domains"] = new JsonArray(domains.Select(x => (JsonNode)x).ToArray()) };
        }
        long domain = AgentGroupInput.Positive(body["domain_id"]);
        var ous = AgentGroupInput.Ids(body.ContainsKey("ou_entity_ids") ? body["ou_entity_ids"] : new JsonArray(), 128);
        var dns = new List<string[]>();
        foreach (long ou in ous) dns.Add((await Resolve(ou, domain, true, ct)).Dn);
        var rows = await db.Rows("select e.id as entity_id,v.id as version_id,v.attributes_json as record,v.source_section " + CurrentDirectory + " and v.source_section in ('directory_accounts','domain_posture') order by e.id limit 10001", ct, ("domain", domain));
        var computers = new JsonArray(); var units = new JsonArray();
        foreach (var row in rows.Take(10000))
        {
            bool ou = AdOperationCredentials.Text(row, "source_section") == "domain_posture";
            string[] dn;
            try { dn = AgentGroupDirectory.Record(row["record"], ou); }
            catch (AgentControlException) { continue; }
            var item = new JsonObject { ["id"] = row["entity_id"]!.DeepClone(), ["version_id"] = row["version_id"]!.DeepClone(), ["name"] = row["record"]!["attributes"]!["distinguished_name"]!.DeepClone() };
            if (ou) units.Add(item);
            else if (dns.Count == 0 || dns.Any(unit => AgentGroupDirectory.Within(dn, unit))) computers.Add(item);
        }
        return new() { ["computers"] = computers, ["ous"] = units, ["has_more"] = rows.Count > 10000 };
    }
}
