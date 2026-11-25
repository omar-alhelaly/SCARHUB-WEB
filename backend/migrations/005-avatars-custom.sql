-- 005: staff profile pictures + subscriber badge in the chat.
-- Avatar value 'custom' = uploaded picture in public bucket "avatars" at <user id>/avatar. Only owner/admin may set it; for others the view shows b1.
do $$ declare c text; begin
  select conname into c from pg_constraint where conrelid = 'public.profiles'::regclass and contype = 'c' and pg_get_constraintdef(oid) like '%avatar%';
  if c is not null then execute format('alter table public.profiles drop constraint %I', c); end if;
end $$;
alter table public.profiles add constraint profiles_avatar_check check (avatar ~ '^((b|g)[1-8]|custom)$');

create or replace function public.update_my_profile(new_username text, new_avatar text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_active(auth.uid()) then raise exception 'forbidden'; end if;
  if new_avatar = 'custom' and not public.is_staff(auth.uid()) then raise exception 'forbidden'; end if;
  update public.profiles set username = coalesce(new_username, username), avatar = coalesce(new_avatar, avatar) where id = auth.uid();
end $$;

create or replace view public.public_profiles with (security_invoker = false) as
  select id, case when role in ('owner', 'admin') then alias else username end::text as display_name,
         case when avatar = 'custom' and role not in ('owner', 'admin') then 'b1' else avatar end as avatar,
         (role in ('owner', 'admin')) as is_staff, public.has_active_sub(id) as subscribed
  from public.profiles where status = 'active';

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('avatars', 'avatars', true, 1048576, array['image/png', 'image/jpeg', 'image/webp'])
on conflict (id) do update set public = true, file_size_limit = 1048576, allowed_mime_types = array['image/png', 'image/jpeg', 'image/webp'];
create policy avatars_read on storage.objects for select to authenticated using (bucket_id = 'avatars');
create policy avatars_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and public.is_staff(auth.uid()) and name = auth.uid()::text || '/avatar');
create policy avatars_update on storage.objects for update to authenticated
  using (bucket_id = 'avatars' and public.is_staff(auth.uid()) and name = auth.uid()::text || '/avatar');
create policy avatars_delete on storage.objects for delete to authenticated
  using (bucket_id = 'avatars' and public.is_staff(auth.uid()) and name = auth.uid()::text || '/avatar');
