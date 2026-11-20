with native as (
    select distinct e.event_db_id as id,e.event_id,e.time_created_utc,
        nullif(btrim(e.target_user_name),'-') as account,
        nullif(btrim(e.target_domain_name),'-') as domain,
        coalesce(nullif(nullif(btrim(e.ip_address),''),'-'),nullif(nullif(btrim(e.workstation_name),''),'-')) as source
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
        when count(distinct (domain,account))=1 then min(concat_ws('\',domain,account)) filter(where nullif(account,'') is not null) end,
    'source',case when count(distinct source)=1 then min(source) end,
    'count',case when count(*) filter(where event_id=4624)>0 or __RULE__='semantic.qw.password-brute-force'
        then count(*) filter(where event_id<>4624 and (success_at is null or time_created_utc<success_at))
        else count(distinct (domain,account)) filter(where event_id<>4624 and nullif(account,'') is not null) end,
    'time',regexp_replace(to_char(coalesce(max(success_at),min(time_created_utc)) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'\.000000$','')||'+00:00',
    'password_success',count(*) filter(where event_id=4624)>0
)) from selected having count(*)>0
