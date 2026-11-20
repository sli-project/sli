-- Exact SID predicate for the application reader, without exposing the alias table.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_security_candidate_sid_lookup_v307'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=306 and name='password_policy_reconciliation')
       or exists(select 1 from public.schema_migrations where version>=307)
       or to_regprocedure('public.security_candidate_sid_matches_v307(bigint,integer,text)') is not null then
        raise exception 'security_candidate_307_preflight' using errcode='55000';
    end if;
end $$;

set local role adlog_storage_owner;
create function public.security_candidate_sid_matches_v307(p_domain bigint,p_entity integer,p_sid text)
returns boolean language sql stable strict security definer
set search_path=pg_catalog,pg_temp
as $$
    select p_domain>0 and p_entity>0 and char_length(p_sid) between 1 and 184 and exists (
        select 1 from public.ad_context_entity_aliases alias
        join public.entities_v2 entity on entity.id=alias.entity_id
        where alias.domain_id=p_domain and alias.alias_type='object_sid'
          and alias.normalized_value=lower(nullif(btrim(p_sid),''))
          and alias.entity_id=p_entity and entity.domain_id=p_domain
          and public.entity_v2_is_active(entity.id)
    )
$$;
revoke all on function public.security_candidate_sid_matches_v307(bigint,integer,text) from public,adlog_user;
grant execute on function public.security_candidate_sid_matches_v307(bigint,integer,text) to adlog_user;
insert into public.schema_migrations(version,name) values(307,'security_candidate_sid_lookup');
reset role;
commit;
