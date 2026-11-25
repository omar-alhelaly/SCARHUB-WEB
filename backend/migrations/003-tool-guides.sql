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
