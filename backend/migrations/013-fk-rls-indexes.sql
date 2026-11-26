-- 013: indexes on foreign-key and RLS policy columns (supabase-postgres-best-practices:
-- schema-foreign-key-indexes, security-rls-performance). Additive and reversible
-- (drop index ...) -- no data or policy changes.
create index if not exists payment_requests_user_idx on public.payment_requests (user_id);
create index if not exists payment_requests_plan_idx on public.payment_requests (plan_id);
create index if not exists plan_tools_tool_idx on public.plan_tools (tool_id);
create index if not exists tools_created_by_idx on public.tools (created_by);
