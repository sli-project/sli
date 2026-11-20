-- RU: отдельная версия идентичности; старые хеши и карантин не переписываются.
-- EN: additive identity version; no rewrite of retained hashes or quarantine.
begin;
select pg_advisory_xact_lock(hashtext('sli_event_source_identity_v284'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
           where version=283 and name='file_audit_snapshot_hash')
       or exists(select 1 from public.schema_migrations where version>=284) then
        raise exception 'migration 284 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;

-- An allocation can precede core publication, so there is deliberately no core FK.
create table public.event_source_representations_v2 (
    event_id bigint primary key,
    normalized_hash bytea not null check(octet_length(normalized_hash)=32),
    identity_version smallint not null check(identity_version=2),
    canonical_hash bytea not null check(octet_length(canonical_hash)=32),
    representation jsonb not null check(jsonb_typeof(representation)='object'),
    representation_sha256 bytea not null check(octet_length(representation_sha256)=32)
);
revoke all on public.event_source_representations_v2 from public,adlog_user,adlog_storage_worker;
grant select on public.event_source_representations_v2 to adlog_user;
grant select,insert on public.event_source_representations_v2 to adlog_storage_worker;
grant update(representation,representation_sha256) on public.event_source_representations_v2 to adlog_storage_worker;

-- Exact core-addressed packet access, without granting the worker inbox scans.
create function public.event_source_packet_v284(p_event bigint) returns jsonb
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('event_rows',i.event_rows,'raw_sha256',r.sha256,
        'attested_packet',i.packet,'attested_envelope',i.envelope,
        'envelope_sha256',receipt.envelope_sha256,'packet_id',i.packet_id::text)
    from public.events_v2_core e
    join public.raw_log_files r on r.id=e.raw_log_file_id
        and r.server_id=e.server_id and r.log_source_id=e.log_source_id
    join public.sli_agent_packet_inbox i on r.file_path='agent-packet:' || i.packet_id::text
    join public.sli_agent_receipts receipt on receipt.packet_id=i.packet_id and receipt.envelope=i.envelope
    where e.id=p_event and i.imported_at is not null
$$;
revoke all on function public.event_source_packet_v284(bigint) from public;
grant execute on function public.event_source_packet_v284(bigint) to adlog_storage_worker;

-- Preserve the existing exact imported/receipted source gate. The semantic
-- reader also needs the checksummed preferred body: a v2 native hash excludes
-- XML/properties, and a compatible subset may have a richer retained source.
create or replace function public.read_agent_semantic_source_v190(p_event_id bigint)
returns jsonb language sql stable security definer set search_path=pg_catalog,public as $$
    select case when count(*)=1 then jsonb_agg(jsonb_build_object(
        'core',to_jsonb(core),'event_row',event.row,'preferred',to_jsonb(preferred)))->0 end
    from public.events_v2_core core
    join public.raw_log_files raw on raw.id=core.raw_log_file_id
    join public.sli_agent_packet_inbox inbox on inbox.packet_id=case
        when raw.file_path ~ '^agent-packet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        then substr(raw.file_path,14)::uuid end
    join public.sli_agent_receipts receipt on receipt.packet_id=inbox.packet_id
    left join public.event_source_representations_v2 preferred on preferred.event_id=core.id
    cross join lateral jsonb_array_elements(inbox.event_rows) event(row)
    where core.id=p_event_id and p_event_id>0
      and inbox.imported_at is not null and receipt.receipt->>'status'='committed'
      and inbox.envelope=receipt.envelope
      and (receipt.module_id='sli.windows.ad-dc' or (receipt.module_id='sli.file-audit'
        and inbox.packet->'header'->>'channel'='Security'
        and core.event_id in (4608,4624,4625,4634,4719,1102,4656,4658,4659,4660,4663,4664,4670,4907,5140,5142,5143,5144,5145,5168)))
      and event.row->>'record_id'=core.event_record_id::text
      and event.row->>'event_id'=core.event_id::text
      and (event.row->>'time_created')::timestamptz between
          core.time_created_utc-interval '1 microsecond' and core.time_created_utc+interval '1 microsecond'
      and event.row->>'computer_name'=inbox.packet->'header'->>'source'
      and event.row->>'channel'=inbox.packet->'header'->>'channel'
$$;
revoke all on function public.read_agent_semantic_source_v190(bigint) from public;
grant execute on function public.read_agent_semantic_source_v190(bigint) to adlog_semantic_worker;

alter table public.sli_agent_packet_quarantine
    add column recheck_reason_code text,
    add column recheck_reason_ru text,
    add column recheck_reason_en text,
    add column rechecked_at timestamptz;

-- NULL resolves only an individually imported packet. Runtime has no DELETE
-- privilege and cannot release unimported quarantine through this function.
create function public.recheck_agent_quarantine_v284(p_packet uuid,p_reason text) returns boolean
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare ru text; en text;
begin
    perform 1 from public.sli_agent_packet_inbox where packet_id=p_packet for update;
    if p_reason is null then
        delete from public.sli_agent_packet_quarantine q where q.packet_id=p_packet
            and exists(select 1 from public.sli_agent_packet_inbox i
                where i.packet_id=p_packet and i.imported_at is not null);
        return found;
    end if;
    select reason_ru,reason_en into ru,en from (values
        ('event_identity_differs','Различаются данные идентичности события','Event identity data differs'),
        ('event_xml_differs','Различаются общие поля XML','Shared XML fields differ'),
        ('event_properties_differs','Различаются свойства события','Event properties differ'),
        ('event_representation_incomparable','Представления не вложены друг в друга','Neither representation contains the other'),
        ('event_representation_invalid','Некорректное представление события','Invalid event representation'),
        ('event_retained_source_unavailable','Нет проверенного исходного представления','Verified retained source unavailable'),
        ('event_retained_hash_differs','Нарушена связь с сохранённым хешем','Retained hash binding differs'),
        ('agent_projection_failed','Импорт не завершён; проверьте доступность и допуск','Import incomplete; check availability and admission'),
        ('agent_source_not_configured','Источник не настроен однозначно','Source is not uniquely configured')
    ) reasons(code,reason_ru,reason_en) where code=p_reason;
    if ru is null then raise exception 'unsupported quarantine recheck reason'; end if;
    update public.sli_agent_packet_quarantine set recheck_reason_code=p_reason,
        recheck_reason_ru=ru,recheck_reason_en=en,rechecked_at=clock_timestamp()
        where packet_id=p_packet;
    return found;
end $$;
revoke all on function public.recheck_agent_quarantine_v284(uuid,text) from public;
grant execute on function public.recheck_agent_quarantine_v284(uuid,text) to adlog_user;

insert into public.schema_migrations(version,name) values(284,'event_source_identity');
commit;
