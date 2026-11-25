-- SCARHUB backend schema for Supabase (Postgres). Run once in the SQL editor, top to bottom.
-- Security model: every table has RLS on. Clients (anon/authenticated) can NOT write profiles,
-- subscriptions or audit data directly. Writes go through SECURITY DEFINER functions or Edge Functions.
-- Replace the owner email in the last line of section 1 before running.

create extension if not exists citext with schema extensions;

-- 1. owner bootstrap: NO owner email is stored in this file or in any table.
--    After the owner signs up and verifies their email, run `select public.claim_owner('<their auth user id>');`
--    once in the Supabase SQL editor (runs as postgres). It only works while no owner exists.

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
declare
  uname text := coalesce(nullif(new.raw_user_meta_data ->> 'username', ''), 'user_' || substr(replace(new.id::text, '-', ''), 1, 8));
  av text := coalesce(nullif(new.raw_user_meta_data ->> 'avatar', ''), 'b1');
begin
  -- every new account is a plain user. Role and alias are never taken from user-controlled metadata.
  insert into public.profiles (id, email, email_norm, username, avatar, role)
  values (new.id, new.email, public.norm_email(new.email), uname, av, 'user');
  return new;
end $$;

create or replace function public.claim_owner(uid uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if exists (select 1 from public.profiles where role = 'owner' and status = 'active') then raise exception 'owner already exists'; end if;
  if not exists (select 1 from auth.users u where u.id = uid and u.email_confirmed_at is not null) then raise exception 'user not found or email not confirmed'; end if;
  update public.profiles set role = 'owner', alias = 'Owner' where id = uid and status = 'active';
  if not found then raise exception 'profile not found'; end if;
  insert into public.audit_log(actor, action, target) values (uid, 'claim_owner', uid);
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
create policy subs_select_own on public.subscriptions for select to authenticated using (user_id = auth.uid() or public.is_owner(auth.uid()));
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
  file_path text unique check (file_path is null or file_path ~ '^[a-z0-9][a-z0-9/_.-]{1,120}$')
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
  public.is_staff(auth.uid())
  or exists (select 1 from public.tool_assets a join public.tools t on t.id = a.tool_id
             where a.file_path = storage.objects.name and t.status = 'published'            -- drafts are staff-only
               and (t.visibility = 'public' or public.has_active_sub(auth.uid())))));       -- private needs an active subscription
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
    p.avatar, p.role, p.status, p.created_at, p.deleted_at, case when o then public.has_active_sub(p.id) else null end
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


-- 9. payment settings (OWNER ONLY. Admins have no access. Everyone can read ACTIVE plans so they can buy; that is the only exposure). Secrets are NOT here: they live in Edge Function secrets.
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
create policy prov_read on public.payment_providers for select to authenticated using (public.is_owner(auth.uid()));
create policy prov_write on public.payment_providers for update to authenticated using (public.is_owner(auth.uid())) with check (public.is_owner(auth.uid()));
create policy plans_read on public.plans for select to anon, authenticated using (active or public.is_owner(auth.uid()));
create policy plans_write on public.plans for all to authenticated using (public.is_owner(auth.uid())) with check (public.is_owner(auth.uid()));
revoke all on public.payment_providers, public.plans from anon, authenticated;
grant select on public.plans to anon, authenticated; grant select on public.payment_providers to authenticated;
grant update (enabled) on public.payment_providers to authenticated; grant insert, update, delete on public.plans to authenticated;

revoke execute on all functions in schema public from public, anon;
grant execute on function public.update_my_profile(text, text), public.set_role(uuid, public.app_role, text), public.admin_list_users(),
  public.is_staff(uuid), public.is_active(uuid), public.has_active_sub(uuid) to authenticated;
grant execute on function public.has_active_sub(uuid), public.is_staff(uuid), public.is_active(uuid) to anon;   -- needed by RLS policies evaluated for anon
grant execute on function public.mark_deleted(uuid) to service_role;
-- claim_owner has no grant on purpose: only the postgres role (SQL editor) can run it.
grant execute on function public.is_owner(uuid) to authenticated, anon;


-- 10. Payment methods chosen by the customer: manual (Vodafone Cash transfer + proof, owner approves) and Paymob (automatic).
-- Run this whole block once in the SQL Editor. Both methods stay OFF until the owner switches them on in Admin > Payments.
-- Plans are shared: a plan's price applies to every enabled method. (plans.provider is now just a label and is ignored at checkout.)
-- Secrets are NOT stored here. Paymob keys live in Edge Function secrets. The owner's wallet number is entered in Admin by the owner only.

create table public.manual_settings (
  id int primary key default 1 check (id = 1),
  wallet_number text check (wallet_number ~ '^01[0125][0-9]{8}$'),
  holder_name text check (char_length(holder_name) between 2 and 60),
  note text check (char_length(note) <= 300),
  updated_at timestamptz not null default now()
);
insert into public.manual_settings(id) values (1);
alter table public.manual_settings enable row level security;
revoke all on public.manual_settings from anon, authenticated;          -- no policies on purpose: functions below only

create table public.payment_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  plan_id uuid not null references public.plans(id),
  method text not null check (method in ('manual', 'paymob')),
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'paid', 'failed')),
  amount_minor integer not null check (amount_minor >= 0),               -- snapshot of the plan at request time
  currency text not null check (currency ~ '^[A-Z]{3}$'),
  period text not null check (period in ('month', 'year')),
  reference text check (reference is null or reference ~ '^[A-Za-z0-9 -]{4,40}$'),   -- manual: transfer id / sender number
  proof_path text check (proof_path is null or char_length(proof_path) <= 200),      -- manual: object in the private payment-proofs bucket
  provider_ref text,                                                       -- paymob order id
  reject_reason text check (reject_reason is null or char_length(reject_reason) <= 200),
  reviewed_by uuid, reviewed_at timestamptz,
  created_at timestamptz not null default now()
);
create unique index one_pending_manual on public.payment_requests (user_id) where method = 'manual' and status = 'pending';
create unique index paymob_order_once on public.payment_requests (provider_ref) where provider_ref is not null;
alter table public.payment_requests enable row level security;
create policy pr_select on public.payment_requests for select to authenticated using (user_id = auth.uid() or public.is_owner(auth.uid()));
revoke all on public.payment_requests from anon, authenticated;
grant select on public.payment_requests to authenticated;               -- writes only through the functions below or service_role

-- private bucket for transfer screenshots: users upload only inside their own folder, only the owner and that user can read.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
  values ('payment-proofs', 'payment-proofs', false, 5242880, array['image/jpeg', 'image/png', 'image/webp']);
create policy proofs_insert on storage.objects for insert to authenticated with check (bucket_id = 'payment-proofs' and public.is_active(auth.uid()) and (storage.foldername(name))[1] = auth.uid()::text);
create policy proofs_read on storage.objects for select to authenticated using (bucket_id = 'payment-proofs' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_owner(auth.uid())));

-- which methods can the customer pick right now
create or replace function public.payment_methods() returns table (method text)
language sql stable security definer set search_path = '' as $$
  select p.provider::text from public.payment_providers p
  where p.enabled and p.provider in ('manual', 'paymob') and public.is_active(auth.uid())
$$;

-- where to send the money (only shown while manual is enabled)
create or replace function public.manual_instructions() returns table (wallet_number text, holder_name text, note text)
language sql stable security definer set search_path = '' as $$
  select m.wallet_number, m.holder_name, m.note from public.manual_settings m
  where public.is_active(auth.uid()) and m.wallet_number is not null
    and exists (select 1 from public.payment_providers p where p.provider = 'manual' and p.enabled)
$$;

create or replace function public.set_manual_instructions(w text, holder text, n text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_owner(auth.uid()) then raise exception 'forbidden'; end if;
  update public.manual_settings set wallet_number = w, holder_name = holder, note = nullif(n, ''), updated_at = now() where id = 1;
  insert into public.audit_log(actor, action) values (auth.uid(), 'set_manual_instructions');
end $$;

-- the owner's own view of the wallet settings (admins cannot see them)
create or replace function public.get_manual_settings() returns table (wallet_number text, holder_name text, note text)
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.is_owner(auth.uid()) then raise exception 'forbidden'; end if;
  return query select m.wallet_number, m.holder_name, m.note from public.manual_settings m where m.id = 1;
end $$;

-- customer submits proof for a manual payment (price and currency come from the plan, never from the client)
create or replace function public.submit_manual_payment(p_plan uuid, p_reference text, p_proof text) returns uuid
language plpgsql security definer set search_path = '' as $$
declare pl public.plans; rid uuid;
begin
  if not public.is_active(auth.uid()) then raise exception 'forbidden'; end if;
  if not exists (select 1 from public.payment_providers where provider = 'manual' and enabled) then raise exception 'method off'; end if;
  select * into pl from public.plans where id = p_plan and active;
  if not found then raise exception 'plan'; end if;
  if p_proof is null or p_proof not like auth.uid()::text || '/%' then raise exception 'proof'; end if;
  insert into public.payment_requests(user_id, plan_id, method, amount_minor, currency, period, reference, proof_path)
    values (auth.uid(), pl.id, 'manual', pl.price_minor, pl.currency, pl.period, p_reference, p_proof) returning id into rid;
  return rid;
end $$;

-- adds one period to the user's subscription (extends from the current end if still active). Internal only.
create or replace function public.grant_period(uid uuid, per text, prov text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.subscriptions(user_id, status, current_period_end, provider, updated_at)
    values (uid, 'active', now() + case when per = 'year' then interval '1 year' else interval '1 month' end, prov, now())
  on conflict (user_id) do update set status = 'active', provider = excluded.provider, updated_at = now(),
    current_period_end = greatest(coalesce(public.subscriptions.current_period_end, now()), now()) + case when per = 'year' then interval '1 year' else interval '1 month' end;
end $$;

-- OWNER ONLY: approve or reject a manual payment
create or replace function public.review_manual_payment(p_id uuid, p_approve boolean, p_reason text default null) returns void
language plpgsql security definer set search_path = '' as $$
declare r public.payment_requests;
begin
  if not public.is_owner(auth.uid()) then raise exception 'forbidden'; end if;
  select * into r from public.payment_requests where id = p_id and method = 'manual' and status = 'pending' for update;
  if not found then raise exception 'not pending'; end if;
  update public.payment_requests set status = case when p_approve then 'approved' else 'rejected' end,
    reject_reason = case when p_approve then null else left(p_reason, 200) end, reviewed_by = auth.uid(), reviewed_at = now() where id = p_id;
  if p_approve then perform public.grant_period(r.user_id, r.period, 'manual'); end if;
  insert into public.audit_log(actor, action, target, meta) values (auth.uid(), 'review_manual_payment', r.user_id, jsonb_build_object('approved', p_approve, 'request', p_id));
end $$;

-- called only by the Paymob Edge Functions (service_role). Idempotent: a replay of the same callback changes nothing.
create or replace function public.paymob_start(p_user uuid, p_plan uuid) returns table (request_id uuid, amount_minor integer, currency text)
language plpgsql security definer set search_path = '' as $$
declare pl public.plans; rid uuid;
begin
  if not public.is_active(p_user) then raise exception 'forbidden'; end if;
  if not exists (select 1 from public.payment_providers where provider = 'paymob' and enabled) then raise exception 'method off'; end if;
  select * into pl from public.plans where id = p_plan and active;
  if not found or pl.currency <> 'EGP' then raise exception 'plan'; end if;
  insert into public.payment_requests(user_id, plan_id, method, amount_minor, currency, period) values (p_user, pl.id, 'paymob', pl.price_minor, pl.currency, pl.period) returning id into rid;
  return query select rid, pl.price_minor, pl.currency::text;
end $$;

create or replace function public.paymob_confirm(p_request uuid, p_order text, p_amount integer, p_currency text, p_success boolean) returns text
language plpgsql security definer set search_path = '' as $$
declare r public.payment_requests;
begin
  select * into r from public.payment_requests where id = p_request and method = 'paymob' for update;
  if not found then return 'unknown'; end if;
  if r.status <> 'pending' then return 'already ' || r.status; end if;      -- replay: do nothing
  if not p_success then update public.payment_requests set status = 'failed', provider_ref = p_order where id = r.id; return 'failed'; end if;
  if p_amount <> r.amount_minor or p_currency <> r.currency then return 'mismatch'; end if;   -- never grant on a wrong amount
  update public.payment_requests set status = 'paid', provider_ref = p_order, reviewed_at = now() where id = r.id;
  perform public.grant_period(r.user_id, r.period, 'paymob');
  insert into public.audit_log(actor, action, target, meta) values (null, 'paymob_paid', r.user_id, jsonb_build_object('request', r.id));
  return 'paid';
end $$;

-- grants: new functions must be locked down explicitly
revoke execute on function public.payment_methods(), public.manual_instructions(), public.set_manual_instructions(text, text, text), public.get_manual_settings(),
  public.submit_manual_payment(uuid, text, text), public.grant_period(uuid, text, text), public.review_manual_payment(uuid, boolean, text),
  public.paymob_start(uuid, uuid), public.paymob_confirm(uuid, text, integer, text, boolean) from public, anon, authenticated;
grant execute on function public.payment_methods(), public.manual_instructions(), public.set_manual_instructions(text, text, text), public.get_manual_settings(),
  public.submit_manual_payment(uuid, text, text), public.review_manual_payment(uuid, boolean, text) to authenticated;
grant execute on function public.paymob_start(uuid, uuid), public.paymob_confirm(uuid, text, integer, text, boolean), public.grant_period(uuid, text, text) to service_role;


-- 11. Per-tool pricing. Owner: prices and discounts on every tool. Other admins: the price of tools THEY created only. Discounts: owner only.
-- Run once in the SQL Editor (also in backend/migrations/002-tool-pricing.sql). Ownership is the role on the owner profile, never an email string.
alter table public.tools
  add column price_minor integer check (price_minor is null or (price_minor >= 0 and price_minor <= 100000000)),   -- null = no separate price (subscription or free)
  add column currency text not null default 'EGP' check (currency ~ '^[A-Z]{3}$'),
  add column discount_percent smallint not null default 0 check (discount_percent between 0 and 90),
  add column discount_until timestamptz,
  add constraint tools_discount_needs_price check (discount_percent = 0 or price_minor is not null);

-- price after discount, in minor units (null = no price)
create or replace function public.tool_effective_price(price integer, pct smallint, until timestamptz) returns integer
language sql immutable set search_path = '' as $$
  select case when price is null then null
              when pct > 0 and (until is null or until > now()) then (price * (100 - pct)) / 100
              else price end
$$;

-- guard: runs for every signed-in write (auth.uid() is set). SQL Editor and service_role have no auth.uid() and are not restricted.
create or replace function public.tools_price_guard() returns trigger
language plpgsql security definer set search_path = '' as $$
declare o boolean;
begin
  if auth.uid() is null then return new; end if;
  o := public.is_owner(auth.uid());
  if not o then
    if tg_op = 'INSERT' then
      if new.discount_percent <> 0 or new.discount_until is not null then raise exception 'only the owner can set discounts'; end if;
    else
      if new.created_by is distinct from old.created_by then raise exception 'forbidden'; end if;
      if new.discount_percent <> old.discount_percent or new.discount_until is distinct from old.discount_until then raise exception 'only the owner can set discounts'; end if;
      if (new.price_minor is distinct from old.price_minor or new.currency is distinct from old.currency) and old.created_by <> auth.uid() then
        raise exception 'you can only price your own tools'; end if;
    end if;
  end if;
  if tg_op = 'INSERT' or new.price_minor is distinct from old.price_minor or new.currency is distinct from old.currency
     or new.discount_percent <> old.discount_percent or new.discount_until is distinct from old.discount_until then
    insert into public.audit_log(actor, action, target, meta) values (auth.uid(), 'tool_price', null,
      jsonb_build_object('tool', new.id, 'price_minor', new.price_minor, 'currency', new.currency, 'discount', new.discount_percent, 'until', new.discount_until));
  end if;
  return new;
end $$;
create trigger tools_price_guard before insert or update on public.tools for each row execute function public.tools_price_guard();
revoke execute on function public.tools_price_guard() from public, anon, authenticated;

-- write access: admins change only tools they created; the owner changes any tool. (Before this, one policy covered all writes.)
drop policy tools_write on public.tools;
create policy tools_ins on public.tools for insert to authenticated with check (public.is_staff(auth.uid()) and created_by = auth.uid());
create policy tools_upd on public.tools for update to authenticated
  using (public.is_staff(auth.uid()) and (created_by = auth.uid() or public.is_owner(auth.uid())))
  with check (public.is_staff(auth.uid()));          -- created_by cannot be changed by non-owners: see tools_price_guard
create policy tools_del on public.tools for delete to authenticated using (public.is_staff(auth.uid()) and (created_by = auth.uid() or public.is_owner(auth.uid())));


-- 12. PDF usage guides for tools. Private bucket, one file per tool named <slug>.pdf (e.g. scarpass.pdf).
-- Read: active subscribers and staff only. Upload/replace/delete: the owner, or the admin who created that tool (dynamic tools). Nobody else, anon included.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('tool-guides', 'tool-guides', false, 10485760, array['application/pdf'])
on conflict (id) do update set public = false, file_size_limit = 10485760, allowed_mime_types = array['application/pdf'];
create policy guides_read on storage.objects for select to authenticated
  using (bucket_id = 'tool-guides' and (public.has_active_sub(auth.uid()) or public.is_staff(auth.uid())));
create policy guides_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'tool-guides' and name ~ '^[a-z0-9][a-z0-9-]{1,40}\.pdf$' and (public.is_owner(auth.uid())
    or exists (select 1 from public.tools t where t.created_by = auth.uid() and name = t.slug || '.pdf')));
create policy guides_update on storage.objects for update to authenticated
  using (bucket_id = 'tool-guides' and (public.is_owner(auth.uid()) or exists (select 1 from public.tools t where t.created_by = auth.uid() and name = t.slug || '.pdf')));
create policy guides_delete on storage.objects for delete to authenticated
  using (bucket_id = 'tool-guides' and (public.is_owner(auth.uid()) or exists (select 1 from public.tools t where t.created_by = auth.uid() and name = t.slug || '.pdf')));
