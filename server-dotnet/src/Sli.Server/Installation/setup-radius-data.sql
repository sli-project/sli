select lower(source_instance_id) as source_instance_id,max(verified_at_utc)::text as last_data_utc
from radius_vpn_session_evidence_observations_v1 where lower(source_instance_id)=any(@p0)
group by lower(source_instance_id)
