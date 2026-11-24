-- SCARHUB backend schema for Supabase (Postgres). Run once in the SQL editor, top to bottom.
-- Security model: every table has RLS on. Clients (anon/authenticated) can NOT write profiles,
-- subscriptions or audit data directly. Writes go through SECURITY DEFINER functions or Edge Functions.
-- Replace the owner email in the last line of section 1 before running.

create extension if not exists citext with schema extensions;

-- 1. config ---------------------------------------------------------------
create table public.app_config (key text primary key, value text not null);
alter table public.app_config enable row level security;      -- no policies: nobody but service_role/definer reads it
revoke all on public.app_config from anon, authenticated;
insert into public.app_config(key, value) values ('owner_email', 'mrb9330@gmail.com');

-- 2. helpers --------------------------------------------------------------
create or replace function public.norm_email(e text) returns text
language plpgsql immutable set search_path = '' as $$
declare l text; d text;
begin
  e := lower(btrim(e)); l := split_part(e, '@', 1); d := split_part(e, '@', 2);
  l := split_part(l, '+', 1);
  if d in ('gmail.com', 'googlemail.com') then l := replace(l, '.', ''); d := 'gmail.com'; end if;
  return l || '@' || d;
end $$;

create type public.app_role as enum ('owner', 'admin', 'user');

-- 3. profiles -------------------------------------------------------------
create table public.profiles (
  id          uuid primary key,                     -- = auth.users.id. No FK on purpose: deleted accounts stay listed for admins.
  email       extensions.citext not null,
  email_norm  extensions.citext not null,
  username    extensions.citext not null check (username ~ '^[A-Za-z][A-Za-z0-9_]{2,19}$'),
  alias       extensions.citext check (alias is null or alias ~ '^[A-Za-z][A-Za-z0-9_ ]{2,24}$'),
  avatar      text not null check (avatar ~ '^(b|g)[1-8]$'),
  role        public.app_role not null default 'user',
  status      text not null default 'active' check (status in ('active', 'deleted')),
  created_at  timestamptz not null default now(),
  deleted_at  timestamptz,
  check ((role = 'user') or alias is not null)      -- staff must have an alias
);
create unique index profiles_email_active on public.profiles (email_norm) where status = 'active';     -- one account per (normalized) email
create unique index profiles_username_active on public.profiles (username) where status = 'active';
create unique index profiles_alias_active on public.profiles (alias) where status = 'active' and alias is not null;
alter table public.profiles enable row level security;
create policy profiles_select_own on public.profiles for select to authenticated using (id = auth.uid());
revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;      -- RLS limits it to the caller's own row; no insert/update/delete grants at all

create or replace function public.is_staff(uid uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles p where p.id = uid and p.status = 'active' and p.role in ('owner', 'admin'))
$$;
create or replace function public.is_owner(uid uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles p where p.id = uid and p.status = 'active' and p.role = 'owner')
$$;
create or replace function public.is_active(uid uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles p where p.id = uid and p.status = 'active')
$$;

-- create the profile when an auth user is created (role is NEVER taken from user-controlled metadata)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
declare uname text := new.raw_user_meta_data ->> 'username'; av text := new.raw_user_meta_data ->> 'avatar'; r public.app_role := 'user'; owner_mail text; al text;
begin
  select value into owner_mail from public.app_config where key = 'owner_email';
  if public.norm_email(new.email) = public.norm_email(owner_mail) and not exists (select 1 from public.profiles where role = 'owner' and status = 'active') then
    r := 'owner'; al := 'Owner';
  end if;
  if uname is null or av is null then raise exception 'invalid signup data'; end if;
  insert into public.profiles (id, email, email_norm, username, avatar, role, alias)
  values (new.id, new.email, public.norm_email(new.email), uname, av, r, al);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

-- public view: what other users may see about someone. Staff show their ALIAS only, never the username.
create or replace view public.public_profiles with (security_invoker = false) as
  select id, case when role in ('owner', 'admin') then alias else username end::text as display_name, avatar, (role in ('owner', 'admin')) as is_staff
  from public.profiles where status = 'active';
revoke all on public.public_profiles from anon;
grant select on public.public_profiles to authenticated;

-- 4. subscriptions (written only by the payment webhook running as service_role) ----
create table public.subscriptions (
  user_id uuid primary key, status text not null, current_period_end timestamptz, provider text not null,
  provider_customer_id text, provider_sub_id text unique, updated_at timestamptz not null default now()
);
alter table public.subscriptions enable row level security;
create policy subs_select_own on public.subscriptions for select to authenticated using (user_id = auth.uid() or public.is_staff(auth.uid()));
revoke all on public.subscriptions from anon, authenticated;
grant select on public.subscriptions to authenticated;
create or replace function public.has_active_sub(uid uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.subscriptions s where s.user_id = uid and s.status in ('active', 'trialing') and s.current_period_end > now())
$$;

-- 5. tools ---------------------------------------------------------------
create table public.tools (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
  name text not null check (char_length(name) between 2 and 40),
  class text not null check (class in ('recon','forensics','defense','pentest','crypto','mobile','platform')),
  description_en text not null check (char_length(description_en) between 10 and 600),
  description_ar text check (description_ar is null or char_length(description_ar) <= 600),
  commands text[] not null default '{}' check (cardinality(commands) <= 10),
  visibility text not null default 'public' check (visibility in ('public', 'private')),   -- private = subscription needed for assets
  status text not null default 'draft' check (status in ('draft', 'published')),
  created_by uuid not null, created_at timestamptz not null default now()
);
create table public.tool_assets (        -- video/repo/file; readable only if public tool, active subscriber, or staff
  tool_id uuid primary key references public.tools(id) on delete cascade,
  video_url text check (video_url is null or video_url ~ '^https://[^\s]+$'),
  repo_url text check (repo_url is null or repo_url ~ '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'),
  file_path text check (file_path is null or file_path ~ '^[a-z0-9][a-z0-9/_.-]{1,120}$')
);
alter table public.tools enable row level security; alter table public.tool_assets enable row level security;
create policy tools_read on public.tools for select to anon, authenticated using (status = 'published' or public.is_staff(auth.uid()));
create policy tools_write on public.tools for all to authenticated using (public.is_staff(auth.uid())) with check (public.is_staff(auth.uid()) and created_by = auth.uid());
create policy assets_read on public.tool_assets for select to anon, authenticated using (
  public.is_staff(auth.uid())
  or exists (select 1 from public.tools t where t.id = tool_id and t.status = 'published' and (t.visibility = 'public' or public.has_active_sub(auth.uid()))));
create policy assets_write on public.tool_assets for all to authenticated using (public.is_staff(auth.uid())) with check (public.is_staff(auth.uid()));
revoke all on public.tools, public.tool_assets from anon, authenticated;
grant select on public.tools, public.tool_assets to anon, authenticated;
grant insert, update, delete on public.tools, public.tool_assets to authenticated;   -- still gated by the policies above

-- private storage bucket for tool files (zip etc). Public bucket flag MUST stay false.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('tool-files', 'tool-files', false, 52428800, array['application/zip','application/x-zip-compressed','application/gzip','application/x-tar','text/plain','application/octet-stream'])
on conflict (id) do update set public = false;
create policy tool_files_read on storage.objects for select to authenticated using (bucket_id = 'tool-files' and (
  public.is_staff(auth.uid()) or public.has_active_sub(auth.uid())
  or exists (select 1 from public.tool_assets a join public.tools t on t.id = a.tool_id where a.file_path = storage.objects.name and t.visibility = 'public' and t.status = 'published')));
create policy tool_files_write on storage.objects for insert to authenticated with check (bucket_id = 'tool-files' and public.is_staff(auth.uid()));
create policy tool_files_update on storage.objects for update to authenticated using (bucket_id = 'tool-files' and public.is_staff(auth.uid()));
create policy tool_files_delete on storage.objects for delete to authenticated using (bucket_id = 'tool-files' and public.is_staff(auth.uid()));

-- 6. chat ------------------------------------------------------------------
create table public.chat_messages (
  id bigint generated always as identity primary key,
  channel text not null check (channel in ('general', 'admins')),
  user_id uuid not null, body text not null check (char_length(body) between 1 and 1000),
  created_at timestamptz not null default now()
);
create index chat_channel_time on public.chat_messages (channel, created_at desc);
alter table public.chat_messages enable row level security;
create policy chat_read on public.chat_messages for select to authenticated using (
  (channel = 'general' and public.is_active(auth.uid())) or (channel = 'admins' and public.is_staff(auth.uid())));
create policy chat_insert on public.chat_messages for insert to authenticated with check (
  user_id = auth.uid() and ((channel = 'general' and public.is_active(auth.uid())) or (channel = 'admins' and public.is_staff(auth.uid()))));
create policy chat_delete on public.chat_messages for delete to authenticated using (public.is_staff(auth.uid()));
revoke all on public.chat_messages from anon, authenticated;
grant select, insert, delete on public.chat_messages to authenticated;
create or replace function public.chat_rate_limit() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if (select count(*) from public.chat_messages where user_id = new.user_id and created_at > now() - interval '10 seconds') >= 5 then
    raise exception 'slow down';
  end if;
  new.body := btrim(new.body);
  return new;
end $$;
create trigger chat_rate before insert on public.chat_messages for each row execute function public.chat_rate_limit();

-- 7. audit log (append only) ---------------------------------------------------
create table public.audit_log (id bigint generated always as identity primary key, actor uuid, action text not null, target uuid, meta jsonb, at timestamptz not null default now());
alter table public.audit_log enable row level security;
create policy audit_read on public.audit_log for select to authenticated using (public.is_staff(auth.uid()));
revoke all on public.audit_log from anon, authenticated;
grant select on public.audit_log to authenticated;

-- 8. RPCs (the only way clients change account data) ------------------------------
create or replace function public.update_my_profile(new_username text, new_avatar text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_active(auth.uid()) then raise exception 'forbidden'; end if;
  update public.profiles set username = coalesce(new_username, username), avatar = coalesce(new_avatar, avatar) where id = auth.uid();
end $$;

-- owner only: promote/demote. Admins cannot change roles. Owner cannot change own role.
create or replace function public.set_role(target uuid, new_role public.app_role, new_alias text default null) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_owner(auth.uid()) then raise exception 'forbidden'; end if;
  if target = auth.uid() or new_role = 'owner' then raise exception 'forbidden'; end if;
  if not exists (select 1 from public.profiles where id = target and status = 'active' and role <> 'owner') then raise exception 'not found'; end if;
  if new_role = 'admin' and (new_alias is null or new_alias !~ '^[A-Za-z][A-Za-z0-9_ ]{2,24}$') then raise exception 'alias required'; end if;
  update public.profiles set role = new_role, alias = case when new_role = 'admin' then new_alias else null end where id = target;
  insert into public.audit_log(actor, action, target, meta) values (auth.uid(), 'set_role', target, jsonb_build_object('role', new_role));
end $$;

-- staff list of accounts, including deleted ones. Admins see usernames of normal users only; staff rows show alias.
-- The owner additionally sees staff usernames and all emails.
create or replace function public.admin_list_users() returns table (id uuid, username text, alias text, email text, avatar text, role public.app_role, status text, created_at timestamptz, deleted_at timestamptz, subscribed boolean)
language plpgsql stable security definer set search_path = '' as $$
declare o boolean := public.is_owner(auth.uid());
begin
  if not public.is_staff(auth.uid()) then raise exception 'forbidden'; end if;
  return query select p.id, case when p.role = 'user' or o then p.username::text else null end, p.alias::text, case when o then p.email::text else null end,
    p.avatar, p.role, p.status, p.created_at, p.deleted_at, public.has_active_sub(p.id)
    from public.profiles p order by p.created_at desc;
end $$;

-- called only by the delete-account Edge Function (service_role)
create or replace function public.mark_deleted(uid uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if exists (select 1 from public.profiles where id = uid and role = 'owner' and status = 'active') then raise exception 'owner cannot be deleted'; end if;
  update public.profiles set status = 'deleted', deleted_at = now() where id = uid and status = 'active';
  delete from public.subscriptions where user_id = uid and status not in ('active','trialing');
  insert into public.audit_log(actor, action, target) values (uid, 'delete_account', uid);
end $$;


-- 9. payment settings (owner edits, admins read-only, public reads active plans). Secrets are NOT here: they live in Edge Function secrets.
create table public.payment_providers (provider text primary key check (provider in ('stripe','paymob','fawry','paypal','manual')), enabled boolean not null default false);
insert into public.payment_providers(provider) values ('stripe'),('paymob'),('fawry'),('paypal'),('manual');
create table public.plans (
  id uuid primary key default gen_random_uuid(), name text not null check (char_length(name) between 2 and 40),
  price_minor integer not null check (price_minor >= 0 and price_minor <= 100000000),   -- minor units, e.g. cents/piastres
  currency text not null check (currency ~ '^[A-Z]{3}$'), period text not null check (period in ('month','year')),
  provider text not null references public.payment_providers(provider), provider_ref text,   -- e.g. Stripe price id
  active boolean not null default false, created_at timestamptz not null default now()
);
alter table public.payment_providers enable row level security; alter table public.plans enable row level security;
create policy prov_read on public.payment_providers for select to authenticated using (public.is_staff(auth.uid()));
create policy prov_write on public.payment_providers for update to authenticated using (public.is_owner(auth.uid())) with check (public.is_owner(auth.uid()));
create policy plans_read on public.plans for select to anon, authenticated using (active or public.is_staff(auth.uid()));
create policy plans_write on public.plans for all to authenticated using (public.is_owner(auth.uid())) with check (public.is_owner(auth.uid()));
revoke all on public.payment_providers, public.plans from anon, authenticated;
grant select on public.plans to anon, authenticated; grant select on public.payment_providers to authenticated;
grant update (enabled) on public.payment_providers to authenticated; grant insert, update, delete on public.plans to authenticated;

revoke execute on all functions in schema public from public, anon;
grant execute on function public.update_my_profile(text, text), public.set_role(uuid, public.app_role, text), public.admin_list_users(),
  public.is_staff(uuid), public.is_active(uuid), public.has_active_sub(uuid) to authenticated;
grant execute on function public.has_active_sub(uuid), public.is_staff(uuid), public.is_active(uuid) to anon;   -- needed by RLS policies evaluated for anon
grant execute on function public.mark_deleted(uuid) to service_role;
grant execute on function public.is_owner(uuid) to authenticated;
