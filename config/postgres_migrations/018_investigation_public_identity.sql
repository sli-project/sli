begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_investigation_public_identity'));

alter table investigations add column if not exists public_id uuid;

update investigations
set public_id = md5('investigation:' || id::text || ':' || created_at::text)::uuid
where public_id is null;

alter table investigations alter column public_id set not null;
create unique index if not exists investigations_public_id_uidx on investigations(public_id);

insert into schema_migrations(version, name)
values (18, 'investigation_public_identity')
on conflict(version) do update set name=excluded.name;

commit;
