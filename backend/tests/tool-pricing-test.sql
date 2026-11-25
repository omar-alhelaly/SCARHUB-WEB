-- Run in the SQL Editor as postgres AFTER the migration. Needs: one owner profile (O), one admin profile (A), both uuids below. Rolls back, changes nothing.
-- Replace the two uuids first. Each block must print "ok".
begin;
set local role authenticated;
do $$ declare O uuid := '00000000-0000-0000-0000-00000000000a'; A uuid := '00000000-0000-0000-0000-00000000000b'; t_o uuid; t_a uuid; failed boolean;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', O, 'role', 'authenticated')::text, true);
  insert into public.tools(slug, name, class, description_en, created_by, price_minor) values ('zz-owner-tool', 'ZZ Owner', 'recon', 'owner tool for test', O, 5000) returning id into t_o;
  update public.tools set discount_percent = 20 where id = t_o;                          -- owner may discount
  perform set_config('request.jwt.claims', json_build_object('sub', A, 'role', 'authenticated')::text, true);
  insert into public.tools(slug, name, class, description_en, created_by, price_minor) values ('zz-admin-tool', 'ZZ Admin', 'recon', 'admin tool for test', A, 3000) returning id into t_a;
  update public.tools set price_minor = 3500 where id = t_a;                             -- admin prices own tool
  failed := false; begin update public.tools set price_minor = 1 where id = t_o; exception when others then failed := true; end; assert failed, 'admin edited owner price';
  failed := false; begin update public.tools set discount_percent = 50 where id = t_a; exception when others then failed := true; end; assert failed, 'admin set discount';
  failed := false; begin insert into public.tools(slug, name, class, description_en, created_by, price_minor, discount_percent) values ('zz-x', 'ZZ X', 'recon', 'discount on insert test', A, 100, 10); exception when others then failed := true; end; assert failed, 'admin insert discount';
  failed := false; begin update public.tools set created_by = A where id = t_o; exception when others then failed := true; end; assert failed, 'admin took over owner tool';
  perform set_config('request.jwt.claims', json_build_object('sub', O, 'role', 'authenticated')::text, true);
  update public.tools set price_minor = 4000, discount_percent = 30 where id = t_a;     -- owner edits any admin tool
  raise notice 'ok';
end $$;
rollback;
