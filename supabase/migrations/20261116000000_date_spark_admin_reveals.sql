-- Date Spark: names, presence, secure anonymous reveals, and administration.
-- Apply this migration in the Supabase SQL Editor after the existing schema.sql.

alter table public.profiles
    add column if not exists full_name text,
    add column if not exists last_active_at timestamptz,
    add column if not exists is_suspended boolean not null default false,
    add column if not exists suspended_at timestamptz;

alter table public.profiles
    drop constraint if exists profiles_full_name_length_check;
alter table public.profiles
    add constraint profiles_full_name_length_check
    check (full_name is null or char_length(trim(full_name)) between 2 and 100);

alter table public.activity_logs
    drop constraint if exists activity_logs_event_type_check;
alter table public.activity_logs
    add constraint activity_logs_event_type_check check (event_type in (
        'register', 'login', 'logout', 'password_reset', 'admin_password_reset',
        'activity', 'session_timeout', 'anonymous_message_sent', 'anonymous_reveal',
        'account_suspended', 'account_reinstated',
        'admin_free_reveal_granted', 'admin_free_reveal_revoked'
    ));

create index if not exists profiles_last_active_at_idx
    on public.profiles (last_active_at desc)
    where last_active_at is not null;

-- Sender identity is intentionally isolated from the public message row. Owners
-- can keep querying their messages without gaining a column they could inspect
-- before a valid reveal.
create table if not exists public.anonymous_message_senders (
    message_id bigint primary key references public.anonymous_messages(id) on delete cascade,
    sender_id uuid references public.profiles(id) on delete set null,
    collected_at timestamptz not null default now()
);

create table if not exists public.anonymous_reveal_payments (
    id uuid primary key default gen_random_uuid(),
    recipient_id uuid not null references public.profiles(id) on delete cascade,
    message_id bigint not null references public.anonymous_messages(id) on delete cascade,
    amount_ngn integer not null check (amount_ngn = 500),
    provider text not null,
    provider_reference text not null unique,
    status text not null check (status in ('pending', 'verified', 'failed', 'refunded')),
    verified_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (recipient_id, message_id, provider_reference)
);

create table if not exists public.anonymous_message_reveals (
    id uuid primary key default gen_random_uuid(),
    recipient_id uuid not null references public.profiles(id) on delete cascade,
    message_id bigint not null references public.anonymous_messages(id) on delete cascade,
    access_source text not null check (access_source in ('payment', 'free_admin')),
    payment_id uuid references public.anonymous_reveal_payments(id) on delete set null,
    revealed_at timestamptz not null default now(),
    unique (recipient_id, message_id)
);

create table if not exists public.free_anonymous_reveal_permissions (
    user_id uuid primary key references public.profiles(id) on delete cascade,
    is_active boolean not null default true,
    granted_by uuid not null references public.profiles(id),
    granted_at timestamptz not null default now(),
    revoked_by uuid references public.profiles(id),
    revoked_at timestamptz
);

create table if not exists public.administrative_audit_logs (
    id bigint generated always as identity primary key,
    actor_id uuid not null references public.profiles(id) on delete restrict,
    action text not null,
    target_user_id uuid references public.profiles(id) on delete set null,
    message_id bigint references public.anonymous_messages(id) on delete set null,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create index if not exists anonymous_reveal_payments_recipient_message_idx
    on public.anonymous_reveal_payments (recipient_id, message_id, status);
create index if not exists anonymous_reveal_payments_verified_idx
    on public.anonymous_reveal_payments (verified_at desc) where status = 'verified';
create index if not exists anonymous_message_reveals_recipient_idx
    on public.anonymous_message_reveals (recipient_id, revealed_at desc);
create index if not exists administrative_audit_logs_created_idx
    on public.administrative_audit_logs (created_at desc);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
    v_username text := coalesce(nullif(trim(new.raw_user_meta_data ->> 'username'), ''), split_part(new.email, '@', 1));
    v_full_name text := nullif(trim(new.raw_user_meta_data ->> 'full_name'), '');
begin
    insert into public.profiles (id, username, full_name, email)
    values (new.id, v_username, v_full_name, lower(new.email));

    insert into public.activity_logs (user_id, event_type, email, username)
    values (new.id, 'register', lower(new.email), v_username);
    return new;
end;
$$;

-- A presence event is deliberately throttled in the browser. It is an
-- administrative activity signal, not an audit-proof record of every click.
create or replace function public.record_user_activity()
returns void
language plpgsql
security definer set search_path = public
as $$
begin
    if auth.uid() is null then
        raise exception 'Authentication is required';
    end if;

    update public.profiles
    set last_active_at = now()
    where id = auth.uid() and is_suspended = false;

    if not found then
        raise exception 'Account is unavailable';
    end if;

    insert into public.activity_logs (user_id, event_type)
    values (auth.uid(), 'activity');
end;
$$;

-- Store a verified sender only when the public sender was already signed in.
-- Anonymous senders remain anonymous and are reported as identity unavailable.
create or replace function public.submit_anonymous_message(
    p_token uuid,
    p_message_text text,
    p_image_path text default null
)
returns void
language plpgsql
security definer set search_path = public
as $$
declare
    v_inbox uuid;
    v_message_id bigint;
begin
    select id into v_inbox
    from public.anonymous_inboxes
    where public_token = p_token and active;

    if v_inbox is null then
        raise exception 'Invalid anonymous inbox';
    end if;
    if coalesce(length(trim(p_message_text)), 0) = 0 and p_image_path is null then
        raise exception 'A message or image is required';
    end if;
    if coalesce(length(p_message_text), 0) > 1000
       or (p_image_path is not null and p_image_path !~ ('^' || p_token::text || '/')) then
        raise exception 'Invalid message';
    end if;

    insert into public.anonymous_messages (inbox_id, message_text, image_path, body)
    values (v_inbox, nullif(trim(p_message_text), ''), p_image_path,
            coalesce(nullif(trim(p_message_text), ''), '[image]'))
    returning id into v_message_id;

    if auth.uid() is not null and exists (select 1 from public.profiles where id = auth.uid()) then
        insert into public.anonymous_message_senders (message_id, sender_id)
        values (v_message_id, auth.uid());
        insert into public.activity_logs (user_id, event_type, metadata)
        values (auth.uid(), 'anonymous_message_sent', jsonb_build_object('message_id', v_message_id));
    end if;
end;
$$;

-- This RPC deliberately returns message data and entitlement state only. It
-- never returns the private sender relationship.
create or replace function public.get_owner_anonymous_messages(p_inbox_id uuid)
returns table (
    id bigint,
    message_text text,
    image_path text,
    created_at timestamptz,
    is_read boolean,
    reveal_status text,
    sender_identity_available boolean
)
language sql
security definer set search_path = public
as $$
    select
        m.id,
        m.message_text,
        m.image_path,
        m.created_at,
        m.is_read,
        case
            when s.sender_id is null then 'unavailable'
            when exists (
                select 1 from public.anonymous_message_reveals r
                where r.recipient_id = auth.uid() and r.message_id = m.id
            ) then 'revealed'
            when exists (
                select 1 from public.free_anonymous_reveal_permissions f
                where f.user_id = auth.uid() and f.is_active
            ) then 'free_access'
            else 'payment_required'
        end,
        s.sender_id is not null
    from public.anonymous_messages m
    join public.anonymous_inboxes i on i.id = m.inbox_id
    left join public.anonymous_message_senders s on s.message_id = m.id
    where m.inbox_id = p_inbox_id and i.owner_id = auth.uid()
    order by m.created_at desc;
$$;

-- A sender name is released only after an entitlement record exists, or after
-- the caller's active free-access permission has been converted to one.
create or replace function public.reveal_anonymous_message_sender(p_message_id bigint)
returns table (identity_available boolean, sender_name text)
language plpgsql
security definer set search_path = public
as $$
declare
    v_owner_id uuid;
    v_sender_id uuid;
begin
    if auth.uid() is null then
        raise exception 'Authentication is required';
    end if;

    select i.owner_id, s.sender_id into v_owner_id, v_sender_id
    from public.anonymous_messages m
    join public.anonymous_inboxes i on i.id = m.inbox_id
    left join public.anonymous_message_senders s on s.message_id = m.id
    where m.id = p_message_id;

    if v_owner_id is null or v_owner_id <> auth.uid() then
        raise exception 'Message not found';
    end if;

    if v_sender_id is null then
        return query select false, null::text;
        return;
    end if;

    if not exists (
        select 1 from public.anonymous_message_reveals r
        where r.recipient_id = auth.uid() and r.message_id = p_message_id
    ) then
        if exists (
            select 1 from public.free_anonymous_reveal_permissions f
            where f.user_id = auth.uid() and f.is_active
        ) then
            insert into public.anonymous_message_reveals (recipient_id, message_id, access_source)
            values (auth.uid(), p_message_id, 'free_admin')
            on conflict (recipient_id, message_id) do nothing;
            insert into public.activity_logs (user_id, event_type, metadata)
            values (auth.uid(), 'anonymous_reveal', jsonb_build_object('message_id', p_message_id, 'source', 'free_admin'));
        else
            raise exception 'Payment is required before this sender can be revealed';
        end if;
    end if;

    return query
    select true, coalesce(nullif(trim(p.full_name), ''), nullif(trim(p.username), ''), 'Date Spark member')
    from public.profiles p
    where p.id = v_sender_id;
end;
$$;

-- This function is for a future payment webhook or trusted server only. No
-- browser role receives EXECUTE permission, so a client cannot self-verify.
create or replace function public.record_verified_anonymous_reveal(
    p_recipient_id uuid,
    p_message_id bigint,
    p_provider text,
    p_provider_reference text,
    p_amount_ngn integer
)
returns void
language plpgsql
security definer set search_path = public
as $$
declare
    v_payment_id uuid;
    v_owner_id uuid;
begin
    if p_amount_ngn <> 500 or length(trim(p_provider)) = 0 or length(trim(p_provider_reference)) = 0 then
        raise exception 'Invalid verified payment';
    end if;

    select i.owner_id into v_owner_id
    from public.anonymous_messages m
    join public.anonymous_inboxes i on i.id = m.inbox_id
    where m.id = p_message_id;

    if v_owner_id is null or v_owner_id <> p_recipient_id then
        raise exception 'Payment recipient does not own this message';
    end if;

    insert into public.anonymous_reveal_payments (
        recipient_id, message_id, amount_ngn, provider, provider_reference, status, verified_at
    ) values (
        p_recipient_id, p_message_id, p_amount_ngn, trim(p_provider), trim(p_provider_reference), 'verified', now()
    )
    on conflict (provider_reference) do update
        set status = 'verified', verified_at = excluded.verified_at, updated_at = now()
    returning id into v_payment_id;

    insert into public.anonymous_message_reveals (recipient_id, message_id, access_source, payment_id)
    values (p_recipient_id, p_message_id, 'payment', v_payment_id)
    on conflict (recipient_id, message_id) do nothing;

    insert into public.activity_logs (user_id, event_type, metadata)
    values (p_recipient_id, 'anonymous_reveal', jsonb_build_object('message_id', p_message_id, 'source', 'payment'));
end;
$$;

create or replace function public.get_admin_dashboard_metrics()
returns table (
    total_users bigint,
    new_registrations_30_days bigint,
    total_login_activity bigint,
    active_users_30_minutes bigint,
    anonymous_messages_received bigint,
    verified_reveal_purchases bigint,
    verified_reveal_revenue_ngn bigint
)
language plpgsql
security definer set search_path = public
as $$
begin
    if not public.is_admin() then raise exception 'Administrator access is required'; end if;
    return query select
        (select count(*) from public.profiles),
        (select count(*) from public.profiles where created_at >= now() - interval '30 days'),
        (select count(*) from public.activity_logs where event_type = 'login'),
        (select count(*) from public.profiles where last_active_at >= now() - interval '30 minutes' and not is_suspended),
        (select count(*) from public.anonymous_messages where inbox_id is not null),
        (select count(*) from public.anonymous_reveal_payments where status = 'verified'),
        (select coalesce(sum(amount_ngn), 0) from public.anonymous_reveal_payments where status = 'verified');
end;
$$;

create or replace function public.get_admin_daily_analytics(p_days integer default 30)
returns table (
    day date,
    registrations bigint,
    logins bigint,
    anonymous_messages bigint,
    reveal_purchases bigint,
    verified_revenue_ngn bigint
)
language plpgsql
security definer set search_path = public
as $$
begin
    if not public.is_admin() then raise exception 'Administrator access is required'; end if;
    p_days := least(greatest(coalesce(p_days, 30), 1), 90);
    return query
    with days as (
        select generate_series(
            date_trunc('day', now()) - (p_days - 1) * interval '1 day',
            date_trunc('day', now()),
            interval '1 day'
        ) as day_start
    )
    select
        d.day_start::date,
        (select count(*) from public.profiles p where p.created_at >= d.day_start and p.created_at < d.day_start + interval '1 day'),
        (select count(*) from public.activity_logs a where a.event_type = 'login' and a.created_at >= d.day_start and a.created_at < d.day_start + interval '1 day'),
        (select count(*) from public.anonymous_messages m where m.created_at >= d.day_start and m.created_at < d.day_start + interval '1 day'),
        (select count(*) from public.anonymous_reveal_payments r where r.status = 'verified' and r.verified_at >= d.day_start and r.verified_at < d.day_start + interval '1 day'),
        (select coalesce(sum(r.amount_ngn), 0) from public.anonymous_reveal_payments r where r.status = 'verified' and r.verified_at >= d.day_start and r.verified_at < d.day_start + interval '1 day')
    from days d
    order by d.day_start;
end;
$$;

alter table public.anonymous_message_senders enable row level security;
alter table public.anonymous_reveal_payments enable row level security;
alter table public.anonymous_message_reveals enable row level security;
alter table public.free_anonymous_reveal_permissions enable row level security;
alter table public.administrative_audit_logs enable row level security;

revoke all on public.anonymous_message_senders from anon, authenticated;
revoke all on public.anonymous_reveal_payments from anon, authenticated;
revoke all on public.anonymous_message_reveals from anon, authenticated;
revoke all on public.free_anonymous_reveal_permissions from anon, authenticated;
revoke all on public.administrative_audit_logs from anon, authenticated;

drop policy if exists "anonymous_message_admin_read" on public.anonymous_messages;
create policy "anonymous_message_admin_read" on public.anonymous_messages for select
using (public.is_admin());
drop policy if exists "anonymous_inbox_admin_read" on public.anonymous_inboxes;
create policy "anonymous_inbox_admin_read" on public.anonymous_inboxes for select
using (public.is_admin());
create policy "anonymous_reveal_payment_admin_read" on public.anonymous_reveal_payments for select
using (public.is_admin());
create policy "anonymous_reveal_admin_read" on public.anonymous_message_reveals for select
using (public.is_admin());
create policy "free_reveal_permission_admin_read" on public.free_anonymous_reveal_permissions for select
using (public.is_admin());
create policy "administrative_audit_admin_read" on public.administrative_audit_logs for select
using (public.is_admin());

-- An administrator may open a signed URL for an attachment in the review area.
drop policy if exists "anonymous_admin_read_images" on storage.objects;
create policy "anonymous_admin_read_images" on storage.objects for select to authenticated
using (bucket_id = 'anonymous-message-images' and public.is_admin());

revoke all on function public.record_verified_anonymous_reveal(uuid, bigint, text, text, integer) from public;
grant execute on function public.record_verified_anonymous_reveal(uuid, bigint, text, text, integer) to service_role;
revoke all on function public.record_user_activity() from public;
grant execute on function public.record_user_activity() to authenticated;
revoke all on function public.get_owner_anonymous_messages(uuid) from public;
grant execute on function public.get_owner_anonymous_messages(uuid) to authenticated;
revoke all on function public.reveal_anonymous_message_sender(bigint) from public;
grant execute on function public.reveal_anonymous_message_sender(bigint) to authenticated;
revoke all on function public.get_admin_dashboard_metrics() from public;
grant execute on function public.get_admin_dashboard_metrics() to authenticated;
revoke all on function public.get_admin_daily_analytics(integer) from public;
grant execute on function public.get_admin_daily_analytics(integer) to authenticated;
