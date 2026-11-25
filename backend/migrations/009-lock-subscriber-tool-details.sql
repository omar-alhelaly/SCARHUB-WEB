-- 009: a visitor without access to a subscriber-only tool knows only its name, class and what it does.
-- These columns are no longer readable straight from public.tools: commands, orig_creator, orig_license, orig_repo,
-- price_minor, currency, discount_percent, discount_until. The app reads them through public.tools_view, which returns them
-- only for public tools, to staff, or to a user whose plan covers the tool (otherwise they come back empty).
-- Writes to public.tools are unchanged. If a column is added to public.tools later, re-run this file.
revoke select on public.tools from anon, authenticated;
do $$
declare hidden text[] := array['commands','orig_creator','orig_license','orig_repo','price_minor','currency','discount_percent','discount_until'];
        cols text; vcols text;
begin
  select string_agg(quote_ident(column_name), ',' order by ordinal_position) into cols
    from information_schema.columns where table_schema = 'public' and table_name = 'tools' and column_name <> all (hidden);
  execute 'grant select (' || cols || ') on public.tools to anon, authenticated';
  select string_agg(case when column_name = any (hidden)
      then 'case when t.visibility = ''public'' or public.is_staff(auth.uid()) or public.has_tool_access(auth.uid(), t.id) then t.' || quote_ident(column_name) || ' end as ' || quote_ident(column_name)
      else 't.' || quote_ident(column_name) end, ',' order by ordinal_position) into vcols
    from information_schema.columns where table_schema = 'public' and table_name = 'tools';
  execute 'drop view if exists public.tools_view';
  execute 'create view public.tools_view with (security_invoker = false) as select ' || vcols
    || ' from public.tools t where t.status = ''published'' or public.is_staff(auth.uid())';
  execute 'revoke all on public.tools_view from public, anon, authenticated';
  execute 'grant select on public.tools_view to anon, authenticated';
end $$;
