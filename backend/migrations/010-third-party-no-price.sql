-- 010: only Zenoth's own tools can have a price. Credited open-source tools (third_party) never do.
update public.tools set price_minor = null, discount_percent = 0, discount_until = null
  where third_party and (price_minor is not null or discount_percent <> 0 or discount_until is not null);
alter table public.tools add constraint tools_third_party_no_price
  check (not third_party or (price_minor is null and discount_percent = 0 and discount_until is null));
