begin;
select pg_advisory_xact_lock(hashtext('sli_agent_unicode_host_names442'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=281 and name='agent_registration_hostname')
       or exists(select 1 from public.schema_migrations where version>=442) then
        raise exception 'agent_unicode_host_names442_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

alter table public.sli_agents
    drop constraint sli_agents_registration_host_name_check,
    add constraint sli_agents_registration_host_name_check check (registration_host_name is null or (
        char_length(registration_host_name) between 1 and 253
        and registration_host_name collate pg_catalog."C" ~ '^[^.]{1,63}(\.[^.]{1,63})*$'
        -- ICU alnum covers Unicode letters (L) and decimal digits (Nd). The
        -- Unicode 16.0 ranges add letter numbers (Nl) and other numbers (No)
        -- accepted by AgentEnrollmentService.HostName.
        and registration_host_name collate pg_catalog."unicode" ~ (
            U&'^[[:alnum:]_.\00B2-\00B3\00B9\00BC-\00BE\09F4-\09F9\0B72-\0B77\0BF0-\0BF2\0C78-\0C7E'
            || U&'\0D58-\0D5E\0D70-\0D78\0F2A-\0F33\1369-\137C\16EE-\16F0\17F0-\17F9\19DA\2070'
            || U&'\2074-\2079\2080-\2089\2150-\2182\2185-\2189\2460-\249B\24EA-\24FF\2776-\2793'
            || U&'\2CFD\3007\3021-\3029\3038-\303A\3192-\3195\3220-\3229\3248-\324F\3251-\325F'
            || U&'\3280-\3289\32B1-\32BF\A6E6-\A6EF\A830-\A835\+010107-\+010133\+010140-\+010178'
            || U&'\+01018A-\+01018B\+0102E1-\+0102FB\+010320-\+010323\+010341\+01034A'
            || U&'\+0103D1-\+0103D5\+010858-\+01085F\+010879-\+01087F\+0108A7-\+0108AF'
            || U&'\+0108FB-\+0108FF\+010916-\+01091B\+0109BC-\+0109BD\+0109C0-\+0109CF'
            || U&'\+0109D2-\+0109FF\+010A40-\+010A48\+010A7D-\+010A7E\+010A9D-\+010A9F'
            || U&'\+010AEB-\+010AEF\+010B58-\+010B5F\+010B78-\+010B7F\+010BA9-\+010BAF'
            || U&'\+010CFA-\+010CFF\+010E60-\+010E7E\+010F1D-\+010F26\+010F51-\+010F54'
            || U&'\+010FC5-\+010FCB\+011052-\+011065\+0111E1-\+0111F4\+01173A-\+01173B'
            || U&'\+0118EA-\+0118F2\+011C5A-\+011C6C\+011FC0-\+011FD4\+012400-\+01246E'
            || U&'\+016B5B-\+016B61\+016E80-\+016E96\+01D2C0-\+01D2D3\+01D2E0-\+01D2F3'
            || U&'\+01D360-\+01D378\+01E8C7-\+01E8CF\+01EC71-\+01ECAB\+01ECAD-\+01ECAF'
            || U&'\+01ECB1-\+01ECB4\+01ED01-\+01ED2D\+01ED2F-\+01ED3D\+01F100-\+01F10C-]+$'
        )
    ));

insert into public.schema_migrations(version,name) values(442,'agent_unicode_host_names');
commit;
