-- 007: scoped subscription plans. A plan covers all tools (scope 'all', today's behaviour) or only the tools listed in plan_tools.
alter table public.plans add column scope text not null default 'all' check (scope in ('all', 'tools')),
  add column description text check (description is null or char_length(description) <= 300);

create table public.plan_tools (
  plan_id uuid not null references public.plans(id) on delete cascade,
  tool_id uuid not null references public.tools(id) on delete cascade,
  primary key (plan_id, tool_id)
);
alter table public.plan_tools enable row level security;
create policy plan_tools_read on public.plan_tools for select to anon, authenticated
  using (public.is_owner(auth.uid()) or exists (select 1 from public.plans p where p.id = plan_id and p.active));
create policy plan_tools_write on public.plan_tools for all to authenticated using (public.is_owner(auth.uid())) with check (public.is_owner(auth.uid()));
revoke all on public.plan_tools from anon, authenticated;
grant select on public.plan_tools to anon, authenticated;
grant insert, update, delete on public.plan_tools to authenticated;

-- one row per user and scoped plan; the global subscriptions row stays for 'all' plans
create table public.user_plan_access (
  user_id uuid not null, plan_id uuid not null references public.plans(id),
  current_period_end timestamptz not null, updated_at timestamptz not null default now(),
  primary key (user_id, plan_id)
);
alter table public.user_plan_access enable row level security;
create policy upa_select_own on public.user_plan_access for select to authenticated using (user_id = auth.uid() or public.is_owner(auth.uid()));
revoke all on public.user_plan_access from anon, authenticated;
grant select on public.user_plan_access to authenticated;

create or replace function public.has_tool_access(uid uuid, tid uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select public.has_active_sub(uid) or exists (
    select 1 from public.user_plan_access a join public.plan_tools pt on pt.plan_id = a.plan_id
    where a.user_id = uid and a.current_period_end > now() and pt.tool_id = tid)
$$;
create or replace function public.has_any_sub(uid uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select public.has_active_sub(uid) or exists (select 1 from public.user_plan_access a where a.user_id = uid and a.current_period_end > now())
$$;
create or replace function public.has_guide_access(uid uuid, obj text) returns boolean
language sql stable security definer set search_path = '' as $$
  select public.has_active_sub(uid) or exists (
    select 1 from public.tools t where obj = t.slug || '.pdf' and public.has_tool_access(uid, t.id))
$$;
revoke execute on function public.has_tool_access(uuid, uuid), public.has_any_sub(uuid), public.has_guide_access(uuid, text) from public, anon, authenticated;
grant execute on function public.has_tool_access(uuid, uuid), public.has_any_sub(uuid), public.has_guide_access(uuid, text) to anon, authenticated;

drop policy assets_read on public.tool_assets;
create policy assets_read on public.tool_assets for select to anon, authenticated using (
  public.is_staff(auth.uid())
  or exists (select 1 from public.tools t where t.id = tool_id and t.status = 'published' and (t.visibility = 'public' or public.has_tool_access(auth.uid(), t.id))));
drop policy tool_files_read on storage.objects;
create policy tool_files_read on storage.objects for select to authenticated using (bucket_id = 'tool-files' and (
  public.is_staff(auth.uid())
  or exists (select 1 from public.tool_assets a join public.tools t on t.id = a.tool_id
             where a.file_path = storage.objects.name and t.status = 'published'
               and (t.visibility = 'public' or public.has_tool_access(auth.uid(), t.id)))));
drop policy guides_read on storage.objects;
create policy guides_read on storage.objects for select to authenticated
  using (bucket_id = 'tool-guides' and (public.is_staff(auth.uid()) or public.has_guide_access(auth.uid(), storage.objects.name)));

create or replace view public.public_profiles with (security_invoker = false) as
  select id, case when role in ('owner', 'admin') then alias else username end::text as display_name,
         case when avatar = 'custom' and role not in ('owner', 'admin') then 'b1' else avatar end as avatar,
         (role in ('owner', 'admin')) as is_staff, public.has_any_sub(id) as subscribed
  from public.profiles where status = 'active';

drop function public.grant_period(uuid, text, text);
create or replace function public.grant_period(uid uuid, per text, prov text, p_plan uuid default null) returns void
language plpgsql security definer set search_path = '' as $$
declare sc text := 'all'; iv interval := case when per = 'year' then interval '1 year' else interval '1 month' end;
begin
  if p_plan is not null then select scope into sc from public.plans where id = p_plan; end if;
  if sc = 'tools' then
    insert into public.user_plan_access(user_id, plan_id, current_period_end) values (uid, p_plan, now() + iv)
    on conflict (user_id, plan_id) do update set updated_at = now(), current_period_end = greatest(public.user_plan_access.current_period_end, now()) + iv;
  else
    insert into public.subscriptions(user_id, status, current_period_end, provider, updated_at) values (uid, 'active', now() + iv, prov, now())
    on conflict (user_id) do update set status = 'active', provider = excluded.provider, updated_at = now(),
      current_period_end = greatest(coalesce(public.subscriptions.current_period_end, now()), now()) + iv;
  end if;
end $$;
revoke execute on function public.grant_period(uuid, text, text, uuid) from public, anon, authenticated;
grant execute on function public.grant_period(uuid, text, text, uuid) to service_role;

create or replace function public.review_manual_payment(p_id uuid, p_approve boolean, p_reason text default null) returns void
language plpgsql security definer set search_path = '' as $$
declare r public.payment_requests;
begin
  if not public.is_owner(auth.uid()) then raise exception 'forbidden'; end if;
  select * into r from public.payment_requests where id = p_id and method = 'manual' and status = 'pending' for update;
  if not found then raise exception 'not pending'; end if;
  update public.payment_requests set status = case when p_approve then 'approved' else 'rejected' end,
    reject_reason = case when p_approve then null else left(p_reason, 200) end, reviewed_by = auth.uid(), reviewed_at = now() where id = p_id;
  if p_approve then perform public.grant_period(r.user_id, r.period, 'manual', r.plan_id); end if;
  insert into public.audit_log(actor, action, target, meta) values (auth.uid(), 'review_manual_payment', r.user_id, jsonb_build_object('approved', p_approve, 'request', p_id));
end $$;

create or replace function public.paymob_confirm(p_request uuid, p_order text, p_amount integer, p_currency text, p_success boolean) returns text
language plpgsql security definer set search_path = '' as $$
declare r public.payment_requests;
begin
  select * into r from public.payment_requests where id = p_request and method = 'paymob' for update;
  if not found then return 'unknown'; end if;
  if r.status <> 'pending' then return 'already ' || r.status; end if;
  if not p_success then update public.payment_requests set status = 'failed', provider_ref = p_order where id = r.id; return 'failed'; end if;
  if p_amount <> r.amount_minor or p_currency <> r.currency then return 'mismatch'; end if;
  update public.payment_requests set status = 'paid', provider_ref = p_order, reviewed_at = now() where id = r.id;
  perform public.grant_period(r.user_id, r.period, 'paymob', r.plan_id);
  insert into public.audit_log(actor, action, target, meta) values (null, 'paymob_paid', r.user_id, jsonb_build_object('request', r.id));
  return 'paid';
end $$;
