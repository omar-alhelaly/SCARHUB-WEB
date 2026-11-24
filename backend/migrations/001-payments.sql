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
