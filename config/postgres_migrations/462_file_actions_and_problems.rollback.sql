begin;
select pg_advisory_xact_lock(hashtext('sli_file_actions_and_problems462'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=462 and name='file_actions_and_problems')
       or exists(select 1 from public.schema_migrations where version>462) then
        raise exception 'file_actions_and_problems462_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $$
declare definition text;
    old_join constant text := 'left join public.servers server on server.hostname=inbox.packet#>>''{header,source}''';
    new_join constant text := 'left join public.servers server on (lower(server.hostname)=lower(inbox.packet#>>''{header,source}'') or lower(server.fqdn)=lower(inbox.packet#>>''{header,source}''))';
begin
    definition := pg_get_functiondef('public.semantic_finding_in_domains_v265(bigint,bigint[])'::regprocedure);
    if strpos(definition,new_join)=0 then
        raise exception 'file_actions_and_problems462_domain_reader_shape' using errcode='55000';
    end if;
    execute replace(definition,new_join,old_join);
end $$;

drop function public.file_ransom_problem_facts462(bigint[],bigint[]);
drop function public.file_action_problems462(jsonb);
drop function public.file_action_page462(jsonb,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer);
delete from public.schema_migrations where version=462;
commit;
