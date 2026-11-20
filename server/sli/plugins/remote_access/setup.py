"""VPN setup observation independent from the core checklist."""

def source_data(pack, instances):
    from server.sli.core import database
    from server.sli.core.setup_status import _safe, _timestamp

    ids = [item["source_instance_id"].casefold() for item in instances]
    # Accounting captures and NPS event imports are independent evidence.
    rows = _safe(lambda: database.query_rows(
        """
        select lower(source_instance_id) as source_instance_id, max(verified_at_utc) as last_data_utc
        from radius_vpn_session_evidence_observations_v1 where lower(source_instance_id) = any(?)
        group by lower(source_instance_id)
        """, (ids,),
    ))
    arrivals = {str(row["source_instance_id"]).casefold(): row["last_data_utc"] for row in rows or []}
    for instance in instances:
        key = instance["source_instance_id"].casefold()
        host = instance.get("collection_target")
        if not host:
            if rows is None:
                arrivals[key] = "unavailable"
            continue
        host = host.casefold()
        event_rows = _safe(lambda host=host: database.query_rows(
            """
            select max(created_at) as last_data_utc from collector_channel_runs
            where lower(server) = any(?) and lower(channel) = any(?) and inserted > 0
            """, ([host], [channel.casefold() for channel in pack.get("channels", [])]),
        ))
        raw_stamps = [arrivals.get(key), event_rows[0].get("last_data_utc") if event_rows else None]
        stamps = [_timestamp(value) for value in raw_stamps]
        arrivals[key] = max((stamp for stamp in stamps if stamp is not None), default=None)
        if arrivals[key] is None and (rows is None or event_rows is None or any(value is not None for value in raw_stamps)):
            arrivals[key] = "unavailable"
    return arrivals
