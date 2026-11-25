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
