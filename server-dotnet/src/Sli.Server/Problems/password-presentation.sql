with native as (
    select distinct e.event_db_id as id,e.event_id,e.time_created_utc,left(e.hostname,256) as computer,
        case when lower(btrim(e.target_user_name)) not in ('','-','n/a') then left(btrim(e.target_user_name),256) end as account,
        case when lower(btrim(e.target_domain_name)) not in ('','-','n/a') then left(btrim(e.target_domain_name),256) end as domain,
        case when lower(btrim(e.ip_address)) not in ('','-','n/a','::','::1','0.0.0.0','127.0.0.1')
            then left(regexp_replace(lower(btrim(e.ip_address)),'^::ffff:([0-9]+\.)','\1'),256) end as address,
        case when lower(ltrim(btrim(e.workstation_name),'\')) not in ('','-','n/a')
            then left(ltrim(btrim(e.workstation_name),'\'),256) end as workstation
    from finding_event_details337 e
    where e.finding_id=__FINDING__ and e.event_id in (4624,4625,4771,4776)
), observed as (
    select *,max(time_created_utc) filter(where event_id=4624) over() as success_at
    from native
), selected as (
    select * from observed where success_at is null
        or time_created_utc between success_at-interval '600 seconds' and success_at
)
select jsonb_strip_nulls(jsonb_build_object(
    'account',case when count(*) filter(where event_id=4624)>0 then
        (array_agg(concat_ws('\',domain,account) order by time_created_utc desc,id desc) filter(where event_id=4624 and nullif(account,'') is not null))[1]
        when count(distinct (lower(domain),lower(account))) filter(where account is not null)=1
            then min(concat_ws('\',domain,account)) filter(where account is not null) end,
    'source',case when count(distinct address)=1 then min(address)
        when count(address)=0 and count(distinct lower(workstation))=1 then min(workstation) end,
    'account_count',count(distinct (lower(domain),lower(account)))
        filter(where account is not null and event_id<>4624 and (success_at is null or time_created_utc<success_at)),
    'count',case when count(*) filter(where event_id=4624)>0 or __RULE__='semantic.qw.password-brute-force'
        then count(*) filter(where event_id<>4624 and (success_at is null or time_created_utc<success_at))
        else count(distinct (lower(domain),lower(account))) filter(where event_id<>4624 and account is not null) end,
    'time',regexp_replace(to_char(coalesce(max(success_at),min(time_created_utc)) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'\.000000$','')||'+00:00',
    'password_success',count(*) filter(where event_id=4624)>0
) __WORKPLACE__) from selected having count(*)>0
