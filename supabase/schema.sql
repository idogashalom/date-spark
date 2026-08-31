-- Date Spark Supabase schema. Run this entire file in the Supabase SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
    id uuid primary key references auth.users(id) on delete cascade,
    username text not null check (char_length(username) between 1 and 50),
    email text not null unique,
    role text not null default 'user' check (role in ('user', 'admin')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists public.activity_logs (
    id bigint generated always as identity primary key,
    user_id uuid not null references public.profiles(id) on delete cascade,
    event_type text not null check (event_type in ('register', 'login', 'logout', 'password_reset', 'admin_password_reset')),
    email text,
    username text,
    created_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb
);

create table if not exists public.anonymous_prompts (
    id uuid primary key default gen_random_uuid(),
    owner_id uuid not null references public.profiles(id) on delete cascade,
    token uuid not null unique default gen_random_uuid(),
    prompt text not null check (char_length(prompt) between 1 and 180),
    is_active boolean not null default true,
    created_at timestamptz not null default now()
);

create table if not exists public.anonymous_messages (
    id bigint generated always as identity primary key,
    prompt_id uuid not null references public.anonymous_prompts(id) on delete cascade,
    body text not null check (char_length(body) between 1 and 1000),
    created_at timestamptz not null default now()
);

create index if not exists activity_logs_created_at_idx on public.activity_logs (created_at desc);
create index if not exists activity_logs_user_id_created_at_idx on public.activity_logs (user_id, created_at desc);
create index if not exists anonymous_prompts_owner_id_idx on public.anonymous_prompts (owner_id, created_at desc);
create index if not exists anonymous_messages_prompt_id_created_at_idx on public.anonymous_messages (prompt_id, created_at desc);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
    insert into public.profiles (id, username, email)
    values (
        new.id,
        coalesce(nullif(trim(new.raw_user_meta_data ->> 'username'), ''), split_part(new.email, '@', 1)),
        lower(new.email)
    );
    insert into public.activity_logs (user_id, event_type, email, username)
    values (
        new.id, 'register', lower(new.email),
        coalesce(nullif(trim(new.raw_user_meta_data ->> 'username'), ''), split_part(new.email, '@', 1))
    );
    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute procedure public.handle_new_user();

create or replace function public.set_activity_identity()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
    select email, username into new.email, new.username from public.profiles where id = new.user_id;
    return new;
end;
$$;

create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

drop trigger if exists profiles_updated_at on public.profiles;
create trigger profiles_updated_at before update on public.profiles
for each row execute procedure public.set_updated_at();

-- Defined before RLS policies so every policy uses one secure role check.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer set search_path = public
as $$
    select exists (
        select 1 from public.profiles
        where id = auth.uid() and role = 'admin'
    );
$$;

drop trigger if exists activity_identity on public.activity_logs;
create trigger activity_identity before insert on public.activity_logs
for each row execute procedure public.set_activity_identity();

alter table public.profiles enable row level security;
alter table public.activity_logs enable row level security;
alter table public.anonymous_prompts enable row level security;
alter table public.anonymous_messages enable row level security;

create policy "profiles_select_own_or_admin" on public.profiles for select
using (id = auth.uid() or public.is_admin());
create policy "profiles_update_own" on public.profiles for update
using (id = auth.uid()) with check (id = auth.uid() and role = 'user');
create policy "profiles_admin_update" on public.profiles for update
using (public.is_admin()) with check (public.is_admin());

create policy "activity_admin_read" on public.activity_logs for select using (public.is_admin());
create policy "activity_insert_own_login_logout" on public.activity_logs for insert
with check (user_id = auth.uid() and event_type in ('login', 'logout'));

create policy "prompt_owner_manage" on public.anonymous_prompts for all
using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy "message_owner_read" on public.anonymous_messages for select
using (exists (select 1 from public.anonymous_prompts p where p.id = prompt_id and p.owner_id = auth.uid()));
create policy "message_public_submit" on public.anonymous_messages for insert
with check (exists (select 1 from public.anonymous_prompts p where p.id = prompt_id and p.is_active));

-- Anonymous senders receive only a safe prompt payload, never owner information
-- or any inbox content.
create or replace function public.get_anonymous_prompt(prompt_token uuid)
returns table (id uuid, prompt text)
language sql
security definer set search_path = public
as $$
    select id, prompt from public.anonymous_prompts
    where token = prompt_token and is_active = true;
$$;
grant execute on function public.get_anonymous_prompt(uuid) to anon, authenticated;

revoke all on public.profiles from anon;
revoke all on public.activity_logs from anon;
revoke all on public.anonymous_messages from anon;
revoke update on public.profiles from authenticated;
grant update (username) on public.profiles to authenticated;

-- Let Them Say It: one private inbox per owner and safe, token-only public writes.
create table if not exists public.anonymous_inboxes (
    id uuid primary key default gen_random_uuid(),
    owner_id uuid not null unique references public.profiles(id) on delete cascade,
    public_token uuid not null unique default gen_random_uuid(),
    created_at timestamptz not null default now()
);
alter table public.anonymous_messages add column if not exists inbox_id uuid references public.anonymous_inboxes(id) on delete cascade;
alter table public.anonymous_messages add column if not exists message_text text;
alter table public.anonymous_messages add column if not exists image_path text;
alter table public.anonymous_messages add column if not exists is_read boolean not null default false;
alter table public.anonymous_messages alter column prompt_id drop not null;
alter table public.anonymous_messages alter column body drop not null;
create index if not exists anonymous_messages_inbox_created_idx on public.anonymous_messages (inbox_id, created_at desc);
alter table public.anonymous_inboxes enable row level security;
drop policy if exists "inbox_owner_manage" on public.anonymous_inboxes;
create policy "inbox_owner_manage" on public.anonymous_inboxes for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
drop policy if exists "message_owner_read" on public.anonymous_messages;
drop policy if exists "message_public_submit" on public.anonymous_messages;
create policy "message_owner_manage" on public.anonymous_messages for all
using (exists (select 1 from public.anonymous_inboxes i where i.id = inbox_id and i.owner_id = auth.uid()))
with check (exists (select 1 from public.anonymous_inboxes i where i.id = inbox_id and i.owner_id = auth.uid()));

create or replace function public.get_public_anonymous_inbox(p_token uuid)
returns table (valid boolean) language sql security definer set search_path = public as $$
    select true from public.anonymous_inboxes where public_token = p_token
$$;
create or replace function public.submit_anonymous_message(p_token uuid, p_message_text text, p_image_path text default null)
returns void language plpgsql security definer set search_path = public as $$
declare v_inbox uuid;
begin
    select id into v_inbox from public.anonymous_inboxes where public_token = p_token;
    if v_inbox is null then raise exception 'invalid anonymous inbox'; end if;
    if coalesce(length(trim(p_message_text)), 0) = 0 and p_image_path is null then raise exception 'message required'; end if;
    if coalesce(length(p_message_text), 0) > 1000 or (p_image_path is not null and p_image_path !~ ('^' || p_token::text || '/')) then raise exception 'invalid message'; end if;
    insert into public.anonymous_messages (inbox_id, message_text, image_path, body) values (v_inbox, nullif(trim(p_message_text), ''), p_image_path, coalesce(nullif(trim(p_message_text), ''), '[image]'));
end; $$;
grant execute on function public.get_public_anonymous_inbox(uuid) to anon, authenticated;
grant execute on function public.submit_anonymous_message(uuid, text, text) to anon, authenticated;
revoke all on public.anonymous_inboxes from anon;
revoke all on public.anonymous_messages from anon;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('anonymous-message-images', 'anonymous-message-images', false, 5242880, array['image/jpeg','image/png','image/webp']) on conflict (id) do update set public = false, file_size_limit = 5242880, allowed_mime_types = excluded.allowed_mime_types;

-- Storage policies run separately from table RLS. This narrow helper lets a
-- public sender upload only into a folder for a real, active public token;
-- it does not reveal any inbox or profile information.
create or replace function public.is_valid_anonymous_upload_token(p_token text)
returns boolean language sql stable security definer set search_path = public as $$
    select exists (
        select 1 from public.anonymous_inboxes
        where public_token::text = p_token
    )
$$;
grant execute on function public.is_valid_anonymous_upload_token(text) to anon, authenticated;

drop policy if exists "anonymous_upload_by_token_path" on storage.objects;
create policy "anonymous_upload_by_token_path" on storage.objects for insert to anon, authenticated
with check (
    bucket_id = 'anonymous-message-images'
    and public.is_valid_anonymous_upload_token((storage.foldername(name))[1])
    and lower(storage.extension(name)) in ('jpg','jpeg','png','webp')
);
drop policy if exists "anonymous_owner_read_images" on storage.objects;
create policy "anonymous_owner_read_images" on storage.objects for select to authenticated
using (bucket_id = 'anonymous-message-images' and exists (select 1 from public.anonymous_messages m join public.anonymous_inboxes i on i.id = m.inbox_id where i.owner_id = auth.uid() and m.image_path = name));
