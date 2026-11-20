begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_local_auth1'));

create table if not exists auth_users (
    id bigserial primary key,
    username text not null,
    password_hash text not null,
    role text not null check (role in ('viewer','operator','admin')),
    is_active boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    last_login_at timestamptz null
);
create unique index if not exists auth_users_username_lower_uq on auth_users(lower(username));

create table if not exists auth_sessions (
    id bigserial primary key,
    user_id bigint not null references auth_users(id) on delete cascade,
    token_hash text not null unique,
    expires_at timestamptz not null,
    revoked_at timestamptz null,
    created_at timestamptz not null default now(),
    last_used_at timestamptz null
);
create index if not exists auth_sessions_active_idx on auth_sessions(token_hash, expires_at) where revoked_at is null;

create table if not exists auth_api_keys (
    id bigserial primary key,
    key_prefix text not null unique,
    key_hash text not null unique,
    label text not null,
    role text not null check (role in ('viewer','operator','admin')),
    is_active boolean not null default true,
    expires_at timestamptz null,
    created_at timestamptz not null default now(),
    last_used_at timestamptz null,
    revoked_at timestamptz null
);

create table if not exists auth_audit (
    id bigserial primary key,
    actor_type text not null,
    actor_id bigint null,
    action text not null,
    outcome text not null,
    remote_address text null,
    created_at timestamptz not null default now()
);

insert into schema_migrations(version, name)
values (14, 'local_auth_runtime_guard')
on conflict(version) do update set name=excluded.name;

commit;
