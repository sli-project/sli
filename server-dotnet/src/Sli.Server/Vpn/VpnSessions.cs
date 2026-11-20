using System.Text.Json.Nodes;

namespace Sli.Server.Vpn;

public static class VpnSessions
{
    public const string Contract="sli.vpn-session-report.v1",EvidenceContract="sli.vpn-session-evidence.v1";
    public static string CoverageState(JsonObject coverage)
    {
        long unresolved=coverage.Number("identity_unresolved_count")+coverage.Number("timestamp_unresolved_count")+coverage.Number("quarantined_delivery_count");
        return coverage.Number("total_delivery_count")==0?"not_collected":coverage.Number("queued_delivery_count")+coverage.Number("leased_delivery_count")+coverage.Number("failed_delivery_count")>0?"processing":coverage.Number("projected_session_count")==0 && unresolved>0?"identity_incomplete":unresolved>0?"partial":"available";
    }
    public static async Task<JsonObject> Sources(IVpnReadSession db,VpnAccess access,bool windows,CancellationToken ct)
    {
        int discovered=0,authorized=0;long after=0;var items=new List<JsonObject>();
        while(items.Count<=100)
        {
            var batch=await db.ReadAsync(windows?VpnSql.WindowsDomains:VpnSql.SessionDomains,[after,256],ct);if(batch.Count==0) break;
            discovered+=batch.Count;if(discovered>10000) throw new VpnInputException(windows?"windows_authentication_source_discovery_scan_limit":"vpn_session_source_discovery_scan_limit");
            foreach(var row in batch)
            {
                long domain=row.Number("domain_id");bool allowed=windows?access.Windows(domain):access.Branch("sessions",domain).Allowed;
                if(!allowed) continue;authorized++;
                if(windows && !(await db.ReadAsync(VpnSql.WindowsPresent,[domain,VpnWindows.EventIds,"Security","Microsoft-Windows-Security-Auditing"],ct)).FirstOrDefault().Flag("source_present")) continue;
                items.Add(VpnJson.Obj(new {source_domain_id=domain}));
            }
            after=batch[^1].Number("domain_id");if(batch.Count<256) break;
        }
        bool hasAccess=access.Capabilities.IsOwner || access.Capabilities.Capabilities.Contains("vpn.sessions.view");
        string state=items.Count>0?"available":windows?authorized>0?"not_collected":"not_authorized":discovered==0 && hasAccess?"not_collected":"not_authorized";
        return VpnJson.Obj(new {contract_id=windows?VpnWindows.Contract:Contract,report_key="vpn.audit",state,items=items.Take(100),bounded=true,limit=100,has_more=items.Count>100});
    }
    public static async Task<JsonObject> Report(IVpnReadSession db,VpnAccess access,VpnQuery q,CancellationToken ct)
    {
        var payload=VpnJson.Obj(new {contract_id=Contract,report_key="vpn.audit",source_domain_id=q.Domain,state="not_authorized",branches=access.Branches(q.Domain,q.Action),coverage=(object?)null,items=System.Array.Empty<object>(),page=new {limit=q.Limit,offset=q.Offset,has_more=false}});
        if(!access.Branch("sessions",q.Domain,q.Action).Allowed) return payload;
        var coverage=(await db.ReadAsync(VpnSql.Coverage,[q.Domain],ct)).FirstOrDefault()??throw new VpnInputException("vpn_session_source_domain_not_registered");
        var rows=await db.ReadAsync("""
            select session_row_id,entity_id,domain_id,generation,lifecycle_state,completeness,started_at_utc,
                   last_observed_at_utc,stopped_at_utc,duration_seconds,observation_count,anomalies,updated_at
            from radius_vpn_session_rows_v1 where domain_id=$1
              and ($2::timestamptz is null or last_observed_at_utc>=$2)
              and ($3::timestamptz is null or last_observed_at_utc<$3)
            order by last_observed_at_utc desc,session_row_id limit $4 offset $5
            """,[q.Domain,q.From,q.To,q.Limit+1,q.Offset],ct);
        payload["state"]=CoverageState(coverage);payload["coverage"]=coverage;payload["items"]=VpnJson.Array(rows.Take(q.Limit));payload["page"]!["has_more"]=rows.Count>q.Limit;
        payload["time_range"]=VpnJson.Obj(new {from_utc=VpnJson.Iso(q.From),to_utc_exclusive=VpnJson.Iso(q.To),timezone=q.Timezone});return payload;
    }
    public static async Task<JsonObject> Evidence(IVpnReadSession db,VpnAccess access,VpnQuery q,CancellationToken ct)
    {
        var branch=access.Branch("session_evidence",q.Domain);
        var payload=VpnJson.Obj(new {contract_id=EvidenceContract,report_key="vpn.audit",source_domain_id=q.Domain,session_row_id=q.RowId,state="not_authorized",branch,lifecycle=(object?)null,observations=System.Array.Empty<object>()});
        if(!branch.Allowed) return payload;
        var rows=await db.ReadAsync(VpnSql.Evidence,[q.Domain,q.RowId,10001],ct);
        if(rows.Count>10000) throw new VpnInputException("vpn_session_evidence_observation_bound_exceeded");
        var target=RadiusSessionFold.Fold(rows).FirstOrDefault(r=>r.Text("session_row_id")==q.RowId)??throw new VpnInputException("vpn_session_evidence_session_not_found");
        var byId=rows.ToDictionary(r=>r.Text("observation_id"),StringComparer.Ordinal);
        var observations=new List<JsonObject>();
        foreach(var id in target["observation_ids"]!.AsArray())
        {
            var row=byId[id!.ToString()];var item=VpnJson.Pick(row,"observation_id","lifecycle_event","observed_at_utc");
            item["evidence"]=VpnJson.Pick(row,"evidence_uid","source_instance_id","stream_id","transport_binding","object_reference","canonical_record_sha256","object_sha256","object_size_bytes","verified_at_utc");observations.Add(item);
        }
        var lifecycle=VpnJson.Pick(target,"lifecycle_state","completeness","started_at_utc","last_observed_at_utc","stopped_at_utc","duration_seconds","observation_count","anomalies");
        lifecycle["stop_evidence"]=new JsonArray(observations.Where(r=>r.Text("lifecycle_event")=="stop").Select(r=>r["evidence"]!.DeepClone()).ToArray());
        lifecycle["incomplete_reason"]=target.Text("completeness")=="complete"?null:target["completeness"]!.DeepClone();
        payload["state"]="available";payload["lifecycle"]=lifecycle;payload["observations"]=VpnJson.Array(observations);payload["limits"]=VpnJson.Obj(new {observation_limit=10000,bounded=true});return payload;
    }
}
