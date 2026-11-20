-- Dedicated lifecycle capabilities. No login can assume the closed lock/expiry owner.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_storage_lifecycle_roles_v319'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=318 and name='semantic_pending_candidates')
       or exists(select 1 from public.schema_migrations where version>=319) then
        raise exception 'storage_lifecycle_319_preflight' using errcode='55000';
    end if;
end $$;
-- A rollback in another database may retain these cluster-wide roles.
-- Reuse only the same closed capabilities, never repair an unsafe role silently.
do $$ declare role_name text; role_id oid;
begin
    foreach role_name in array array['adlog_storage_lifecycle_worker','adlog_storage_lifecycle_delete','adlog_storage_lifecycle_guard'] loop
        select oid into role_id from pg_roles where rolname=role_name;
        if role_id is null then
            execute format('create role %I nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls',role_name);
        elsif exists(select 1 from pg_roles where oid=role_id
            and (rolcanlogin or rolinherit or rolsuper or rolcreatedb or rolcreaterole or rolreplication or rolbypassrls))
            or exists(select 1 from pg_auth_members m where m.member=role_id
                and not (role_name='adlog_storage_lifecycle_delete'
                    and m.roleid=(select oid from pg_roles where rolname='adlog_storage_lifecycle_worker')
                    and m.inherit_option and not m.set_option and not m.admin_option))
            or (role_name='adlog_storage_lifecycle_guard'
                and exists(select 1 from pg_auth_members where roleid=role_id)) then
            raise exception 'storage_lifecycle_319_role_invalid: %',role_name using errcode='55000';
        end if;
    end loop;
end $$;
grant adlog_storage_lifecycle_worker to adlog_storage_lifecycle_delete with inherit true, set false;
grant usage on schema public,sli_plugin_file_audit to adlog_storage_lifecycle_worker;
grant usage on schema public,sli_plugin_file_audit to adlog_storage_lifecycle_delete;
grant usage on schema public,sli_plugin_file_audit to adlog_storage_lifecycle_guard;
grant select on public.events_v2_core,public.event_facts_v2,public.event_entity_link_blocks_v2,public.storage_v2_provider,public.storage_v2_channel,public.storage_v2_computer,public.storage_v2_keywords,public.storage_v2_domain_name,public.storage_v2_role,public.storage_v2_archive_blocks,public.source_capture_continuity_declarations,public.raw_log_files,public.ad_snapshot_manifests,public.ad_snapshot_manifest_sources,public.ad_snapshot_history_confirmations,public.users_report_v2_snapshots,public.computers_v6_source_snapshots,public.gpo_report_v2_source_snapshots,public.sli_agent_snapshot_cycles,public.domains,public.runtime_worker_heartbeats to adlog_storage_lifecycle_worker;
grant select(version,name) on public.schema_migrations to adlog_storage_lifecycle_worker;
grant insert on public.ad_snapshot_history_confirmations to adlog_storage_lifecycle_worker;
grant insert,update on public.runtime_worker_heartbeats to adlog_storage_lifecycle_worker;
grant select on public.investigation_events,public.finding_evidence,public.detections,public.event_links,public.entity_states,public.entity_state_current,public.semantic_processing_outbox,public.sli_agent_packet_inbox,public.sli_agent_receipts,public.servers,sli_plugin_file_audit.retention_holds,sli_plugin_file_audit.rule_snapshots,sli_plugin_file_audit.rule_actions,sli_plugin_file_audit.access_snapshots,sli_plugin_file_audit.payload_expirations,sli_plugin_file_audit.observations,sli_plugin_file_audit.action_evidence,sli_plugin_file_audit.collection_publications to adlog_storage_lifecycle_delete;
grant delete on public.events_v2_core,public.sli_agent_packet_inbox,sli_plugin_file_audit.access_snapshots to adlog_storage_lifecycle_delete;
grant insert on sli_plugin_file_audit.payload_expirations to adlog_storage_lifecycle_delete;
grant select on public.events_v2_core,public.event_facts_v2,public.semantic_processing_outbox,public.sli_agent_packet_inbox,sli_plugin_file_audit.access_snapshots,public.ad_snapshot_history_confirmations,public.ad_snapshot_manifests,public.sli_agent_snapshot_cycles,sli_plugin_file_audit.retention_holds,sli_plugin_file_audit.rule_snapshots,sli_plugin_file_audit.rule_actions,sli_plugin_file_audit.observations,sli_plugin_file_audit.action_evidence,sli_plugin_file_audit.collection_publications to adlog_storage_lifecycle_guard;
grant update(id) on public.events_v2_core to adlog_storage_lifecycle_guard;
grant update(event_id) on public.event_facts_v2 to adlog_storage_lifecycle_guard;
grant update(source_event_id) on public.semantic_processing_outbox to adlog_storage_lifecycle_guard;
grant update(packet_id) on public.sli_agent_packet_inbox to adlog_storage_lifecycle_guard;
grant update(snapshot_id) on sli_plugin_file_audit.access_snapshots to adlog_storage_lifecycle_guard;
grant delete on public.events_v2_core,public.ad_snapshot_history_confirmations to adlog_storage_lifecycle_guard;
grant update on public.event_entity_link_blocks_v2,public.investigation_events,sli_plugin_file_audit.retention_holds,sli_plugin_file_audit.rule_snapshots,sli_plugin_file_audit.rule_actions to adlog_storage_lifecycle_guard;
set local role adlog_storage_owner;
create view public.storage_lifecycle_setting_v319 with (security_barrier=true) as
    select value from public.platform_settings where key='ad.snapshot_history_days';
reset role;
alter view public.storage_lifecycle_setting_v319 owner to adlog_user;
grant select on public.storage_lifecycle_setting_v319 to adlog_storage_lifecycle_worker,adlog_storage_lifecycle_guard;
set local role adlog_storage_owner;
create function public.lock_storage_lifecycle_tables_v319(p_scope text) returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    case p_scope
    when 'history' then lock table public.events_v2_core in row exclusive mode nowait;
    when 'evidence' then
        lock table public.event_entity_link_blocks_v2 in share mode nowait;
        lock table public.investigation_events in share mode nowait;
    when 'file_actions' then lock table sli_plugin_file_audit.rule_actions in share mode nowait;
    when 'file' then
        lock table sli_plugin_file_audit.retention_holds in share mode nowait;
        lock table public.investigation_events in share mode nowait;
        lock table sli_plugin_file_audit.rule_snapshots in share mode nowait;
        lock table sli_plugin_file_audit.rule_actions in share mode nowait;
    else raise exception 'storage_lifecycle_lock_scope_invalid' using errcode='22023';
    end case;
end $$;
create function public.lock_storage_lifecycle_events_v319(p_ids bigint[]) returns setof public.events_v2_core
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if cardinality(p_ids)>1000 then raise exception 'storage_lifecycle_lock_budget_invalid'; end if;
    return query select t.* from public.events_v2_core t where t.id=any(p_ids) order by t.id for update nowait;
end $$;
create function public.lock_storage_lifecycle_facts_v319(p_ids bigint[]) returns setof public.event_facts_v2
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if cardinality(p_ids)>1000 then raise exception 'storage_lifecycle_lock_budget_invalid'; end if;
    return query select t.* from public.event_facts_v2 t where t.event_id=any(p_ids) order by t.event_id for update nowait;
end $$;
create function public.lock_storage_lifecycle_semantic_v319(p_ids bigint[]) returns setof public.semantic_processing_outbox
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if cardinality(p_ids)>1000 then raise exception 'storage_lifecycle_lock_budget_invalid'; end if;
    return query select t.* from public.semantic_processing_outbox t where t.source_event_id=any(p_ids) order by t.source_event_id for update nowait;
end $$;
create function public.lock_storage_lifecycle_packets_v319(p_cutoff timestamptz,p_limit integer) returns setof public.sli_agent_packet_inbox
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if p_limit not between 1 and 4 then raise exception 'storage_lifecycle_lock_budget_invalid'; end if;
    return query select i.* from public.sli_agent_packet_inbox i where i.envelope->>'module_id'='sli.file-audit' and i.imported_at is not null
          and i.imported_at<p_cutoff and i.received_at<p_cutoff
          and exists(select 1 from sli_plugin_file_audit.collection_publications p where p.packet_id=i.packet_id)
          and not exists(select 1 from sli_plugin_file_audit.observations o
            where o.agent_id=(i.envelope->>'agent_id')::uuid and o.source_instance_id=i.envelope->>'source_instance_id'
              and o.generation=i.envelope->>'generation' and o.core_evidence_ref like 'agent-workstation-event:%'
              and exists(select 1 from jsonb_array_elements(i.event_rows) r where (r->>'record_id')::bigint=o.record_id))
        order by i.received_at,i.packet_id for update of i skip locked limit p_limit;
end $$;
create function public.lock_storage_lifecycle_snapshots_v319(p_cutoff timestamptz) returns setof sli_plugin_file_audit.access_snapshots
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    return query select s.* from sli_plugin_file_audit.access_snapshots s where s.observed_at<p_cutoff
                  and not exists(select 1 from sli_plugin_file_audit.retention_holds h where h.snapshot_id=s.snapshot_id)
                  and not exists(select 1 from sli_plugin_file_audit.rule_snapshots r where r.snapshot_id=s.snapshot_id)
                order by s.observed_at,s.snapshot_id for update of s skip locked limit 100;
end $$;
create function public.expire_storage_lifecycle_confirmations_v319(p_cutoff timestamptz) returns bigint
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    declare configured integer; deleted bigint;
    begin
        select value::integer into configured from public.storage_lifecycle_setting_v319;
        if configured is not null and configured not between 7 and 3650 then raise exception 'invalid AD history policy'; end if;
        if p_cutoff is null or p_cutoff>now()-make_interval(days=>coalesce(configured,7)) then
            raise exception 'AD history expiry cutoff exceeds policy';
        end if;
        perform pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_history_v1'));
        delete from public.ad_snapshot_history_confirmations h where h.observed_at<p_cutoff
          and not exists(select 1 from public.ad_snapshot_manifests m where m.manifest_id=h.manifest_id or m.manifest_id=h.previous_manifest_id)
          and not exists(select 1 from public.sli_agent_snapshot_cycles c where c.cycle_id=h.manifest_id or c.cycle_id=h.previous_manifest_id);
        get diagnostics deleted=row_count;
        return deleted;
    end;
end $$;
reset role;
grant create on schema public to adlog_storage_lifecycle_guard;
alter function public.lock_storage_lifecycle_tables_v319(text) owner to adlog_storage_lifecycle_guard;
revoke all on function public.lock_storage_lifecycle_tables_v319(text) from public;
grant execute on function public.lock_storage_lifecycle_tables_v319(text) to adlog_storage_lifecycle_delete;
alter function public.lock_storage_lifecycle_events_v319(bigint[]) owner to adlog_storage_lifecycle_guard;
revoke all on function public.lock_storage_lifecycle_events_v319(bigint[]) from public;
grant execute on function public.lock_storage_lifecycle_events_v319(bigint[]) to adlog_storage_lifecycle_delete;
alter function public.lock_storage_lifecycle_facts_v319(bigint[]) owner to adlog_storage_lifecycle_guard;
revoke all on function public.lock_storage_lifecycle_facts_v319(bigint[]) from public;
grant execute on function public.lock_storage_lifecycle_facts_v319(bigint[]) to adlog_storage_lifecycle_delete;
alter function public.lock_storage_lifecycle_semantic_v319(bigint[]) owner to adlog_storage_lifecycle_guard;
revoke all on function public.lock_storage_lifecycle_semantic_v319(bigint[]) from public;
grant execute on function public.lock_storage_lifecycle_semantic_v319(bigint[]) to adlog_storage_lifecycle_delete;
alter function public.lock_storage_lifecycle_packets_v319(timestamptz,integer) owner to adlog_storage_lifecycle_guard;
revoke all on function public.lock_storage_lifecycle_packets_v319(timestamptz,integer) from public;
grant execute on function public.lock_storage_lifecycle_packets_v319(timestamptz,integer) to adlog_storage_lifecycle_delete;
alter function public.lock_storage_lifecycle_snapshots_v319(timestamptz) owner to adlog_storage_lifecycle_guard;
revoke all on function public.lock_storage_lifecycle_snapshots_v319(timestamptz) from public;
grant execute on function public.lock_storage_lifecycle_snapshots_v319(timestamptz) to adlog_storage_lifecycle_delete;
alter function public.expire_storage_lifecycle_confirmations_v319(timestamptz) owner to adlog_storage_lifecycle_guard;
revoke all on function public.expire_storage_lifecycle_confirmations_v319(timestamptz) from public;
grant execute on function public.expire_storage_lifecycle_confirmations_v319(timestamptz) to adlog_storage_lifecycle_delete;
revoke create on schema public from adlog_storage_lifecycle_guard;
-- Preserve the entire existing source/predecessor/hash trigger; add only the
-- closed expiry function owner. Direct worker DELETE still fails this guard.
do $patch$ declare definition text;
begin
    definition:=pg_get_functiondef('public.ad_snapshot_history_confirmation_guard_v165()'::regprocedure);
    if strpos(definition,$old$if tg_op='DELETE' and current_user='postgres' and session_user='adlog_user' then$old$)=0 then raise exception 'storage_lifecycle_319_guard_shape'; end if;
    execute replace(definition,$old$if tg_op='DELETE' and current_user='postgres' and session_user='adlog_user' then$old$,$new$if tg_op='DELETE' and ((current_user='postgres' and session_user='adlog_user') or (current_user='adlog_storage_lifecycle_guard' and pg_has_role(session_user,'adlog_storage_lifecycle_delete','MEMBER'))) then$new$);
end $patch$;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(319,'storage_lifecycle_roles');
reset role;
commit;
