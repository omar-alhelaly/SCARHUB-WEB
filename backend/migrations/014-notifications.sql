-- 014: in-site inbox. A user is told when the owner gives or takes back a free plan.
-- Users can read only their own messages. Nobody can insert from the client: rows are made inside the owner-only grant/revoke functions.
create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  kind text not null check (kind in ('free_plan_granted', 'free_plan_revoked')),
  meta jsonb not null default '{}'::jsonb,
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create index notifications_user_idx on public.notifications(user_id, created_at desc);
alter table public.notifications enable row level security;
create policy notifications_read_own on public.notifications for select to authenticated using (user_id = auth.uid());
revoke all on public.notifications from public, anon, authenticated;
grant select on public.notifications to authenticated;

create or replace function public.mark_notifications_read() returns void
language sql security definer set search_path = '' as $$
  update public.notifications set read_at = now() where user_id = auth.uid() and read_at is null;
$$;
revoke execute on function public.mark_notifications_read() from public, anon;
grant execute on function public.mark_notifications_read() to authenticated;

create or replace function public.admin_grant_plan(target uuid, p_plan uuid default null, p_until timestamptz default null) returns void
language plpgsql security definer set search_path = '' as $$
declare sc text := 'all'; e timestamptz := coalesce(p_until, 'infinity'::timestamptz);
begin
  if not public.is_owner(auth.uid()) then raise exception 'forbidden'; end if;
  if not exists (select 1 from public.profiles where id = target and status = 'active') then raise exception 'not found'; end if;
  if p_until is not null and p_until <= now() then raise exception 'expiry must be in the future'; end if;
  if p_plan is not null then
    select scope into sc from public.plans where id = p_plan;
    if not found then raise exception 'plan not found'; end if;
  end if;
  if sc = 'tools' then
    if exists (select 1 from public.user_plan_access where user_id = target and plan_id = p_plan and source = 'payment' and current_period_end > now()) then
      raise exception 'user already paid for this plan'; end if;
    insert into public.user_plan_access(user_id, plan_id, current_period_end, source) values (target, p_plan, e, 'owner_grant')
    on conflict (user_id, plan_id) do update set current_period_end = e, source = 'owner_grant', updated_at = now();
  else
    if exists (select 1 from public.subscriptions where user_id = target and provider <> 'owner_grant' and status in ('active', 'trialing') and current_period_end > now()) then
      raise exception 'user already has a paid subscription'; end if;
    insert into public.subscriptions(user_id, status, current_period_end, provider, updated_at) values (target, 'active', e, 'owner_grant', now())
    on conflict (user_id) do update set status = 'active', current_period_end = e, provider = 'owner_grant', updated_at = now();
  end if;
  insert into public.notifications(user_id, kind, meta) values (target, 'free_plan_granted', jsonb_build_object('plan', (select name from public.plans where id = p_plan), 'until', p_until));
  insert into public.audit_log(actor, action, target, meta) values (auth.uid(), 'grant_plan', target, jsonb_build_object('plan', p_plan, 'until', p_until));
end $$;

create or replace function public.admin_revoke_plan(target uuid, p_plan uuid default null) returns void
language plpgsql security definer set search_path = '' as $$
declare sc text := 'all'; n int;
begin
  if not public.is_owner(auth.uid()) then raise exception 'forbidden'; end if;
  if p_plan is not null then select scope into sc from public.plans where id = p_plan; end if;
  if sc = 'tools' then
    delete from public.user_plan_access where user_id = target and plan_id = p_plan and source = 'owner_grant';
  else
    update public.subscriptions set status = 'canceled', current_period_end = now(), updated_at = now() where user_id = target and provider = 'owner_grant';
  end if;
  get diagnostics n = row_count;
  if n = 0 then raise exception 'no owner grant to revoke'; end if;
  insert into public.notifications(user_id, kind, meta) values (target, 'free_plan_revoked', jsonb_build_object('plan', (select name from public.plans where id = p_plan)));
  insert into public.audit_log(actor, action, target, meta) values (auth.uid(), 'revoke_plan', target, jsonb_build_object('plan', p_plan));
end $$;

revoke execute on function public.admin_grant_plan(uuid, uuid, timestamptz), public.admin_revoke_plan(uuid, uuid) from public, anon;
grant execute on function public.admin_grant_plan(uuid, uuid, timestamptz), public.admin_revoke_plan(uuid, uuid) to authenticated;
