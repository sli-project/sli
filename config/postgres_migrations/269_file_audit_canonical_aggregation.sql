-- Bounded ordered canonical aggregation; retained native authority stays unchanged.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_canonical_aggregation_v269'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
           where version=268 and name='agent_packet_path_lookup_index')
       or exists(select 1 from public.schema_migrations where version>=269)
       or not exists(select 1 from pg_catalog.pg_proc
           where oid=to_regprocedure('public.file_audit_snapshot_canonical_v264(jsonb,integer)')
             and proowner=(select oid from pg_catalog.pg_roles where rolname='adlog_storage_owner')) then
        raise exception 'migration 269 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;

-- Each child remains validated once. Before final49152 rejection, constructed
-- text is bounded by98304 input bytes times worst-case6x escaping=589824 bytes.
-- This is a text-construction bound, not a PostgreSQL physical-memory guarantee.
create or replace function public.file_audit_snapshot_canonical_v264(p jsonb,p_depth integer default 0) returns text
language plpgsql immutable set search_path=pg_catalog,pg_temp as $$
declare output text; part record; separator text:=''; kind text:=jsonb_typeof(p);
begin
    if p is null or p_depth is null or p_depth<0 or p_depth>16 or octet_length(p::text)>98304 then
        raise exception 'file_audit_snapshot_content_invalid';
    end if;
    if kind='string' then return public.file_audit_snapshot_quote_v264(p#>>'{}');
    elsif kind='number' then
        if p::text !~ '^-?(0|[1-9][0-9]*)$' or abs((p::text)::numeric)>9007199254740991 then
            raise exception 'file_audit_snapshot_content_invalid';
        end if;
        return p::text;
    elsif kind in ('boolean','null') then return p::text;
    elsif kind='array' then
        select '['||coalesce(string_agg(public.file_audit_snapshot_canonical_v264(child.value,p_depth+1),
            ',' order by child.ordinality),'')||']' into output
            from jsonb_array_elements(p) with ordinality child(value,ordinality);
        if octet_length(output)>49152 then raise exception 'file_audit_snapshot_content_invalid'; end if;
        return output;
    elsif kind='object' then
        select '{'||coalesce(string_agg(public.file_audit_snapshot_quote_v264(child.key)||':'||
            public.file_audit_snapshot_canonical_v264(child.value,p_depth+1),
            ',' order by child.key collate "C"),'')||'}' into output from jsonb_each(p) child;
        if octet_length(output)>49152 then raise exception 'file_audit_snapshot_content_invalid'; end if;
        return output;
    end if;
    raise exception 'file_audit_snapshot_content_invalid';
end $$;

insert into public.schema_migrations(version,name) values(269,'file_audit_canonical_aggregation');
commit;
