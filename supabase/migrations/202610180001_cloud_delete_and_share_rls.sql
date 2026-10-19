-- Fix account-deletion RLS (allow authenticated users to delete their own
-- shared_links and subscriptions rows) and close permissive shared_links
-- SELECT/UPDATE policies that allowed full-table enumeration and arbitrary
-- column mutation.
begin;

-- 1. subscriptions: allow owners to delete their own subscription row on account deletion
drop policy if exists "Users delete own subscription" on public.subscriptions;
create policy "Users delete own subscription"
  on public.subscriptions
  for delete
  to authenticated
  using ((select auth.uid()) = user_id);

-- 2. shared_links: replace world-readable / world-writable policies with owner-only RLS
drop policy if exists "Anyone can increment use count" on public.shared_links;
drop policy if exists "Anyone can read shared links" on public.shared_links;
drop policy if exists "Authenticated users can create shared links" on public.shared_links;
drop policy if exists "Users read own shared links" on public.shared_links;
drop policy if exists "Users delete own shared links" on public.shared_links;

create policy "Authenticated users can create shared links"
  on public.shared_links
  for insert
  to authenticated
  with check ((select auth.uid()) = created_by);

create policy "Users read own shared links"
  on public.shared_links
  for select
  to authenticated
  using ((select auth.uid()) = created_by);

create policy "Users delete own shared links"
  on public.shared_links
  for delete
  to authenticated
  using ((select auth.uid()) = created_by);

-- Token-scoped share lookup so callers with an exact share token can inspect
-- a link (including expired/exhausted status) without table-wide SELECT.
create or replace function public.memoir_get_shared_link(link_token text)
returns setof public.shared_links
language sql
security definer
set search_path = ''
as $$
  select *
  from public.shared_links
  where token = link_token
  limit 1;
$$;

revoke all on function public.memoir_get_shared_link(text) from public;
grant execute on function public.memoir_get_shared_link(text) to anon, authenticated;

-- Atomic, token-scoped use_count increment so callers with an exact share token
-- can redeem a link without granting table-wide UPDATE.
create or replace function public.memoir_consume_shared_link(link_token text)
returns setof public.shared_links
language plpgsql
security definer
set search_path = ''
as $$
begin
  if link_token is null or length(trim(link_token)) = 0 then
    return;
  end if;

  return query
  update public.shared_links
     set use_count = coalesce(use_count, 0) + 1
   where token = link_token
     and expires_at > now()
     and coalesce(use_count, 0) < coalesce(max_uses, 5)
  returning *;
end;
$$;

revoke all on function public.memoir_consume_shared_link(text) from public;
grant execute on function public.memoir_consume_shared_link(text) to anon, authenticated;

-- Helper for storage.objects SELECT policy on active shared bundles under <uid>/shares/<token>.gz
create or replace function public.memoir_can_read_shared_object(object_name text)
returns boolean
language sql
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.shared_links sl
    where sl.backup_id = object_name
      and sl.expires_at > now()
      and coalesce(sl.use_count, 0) < coalesce(sl.max_uses, 5)
  );
$$;

revoke all on function public.memoir_can_read_shared_object(text) from public;
grant execute on function public.memoir_can_read_shared_object(text) to anon, authenticated;

drop policy if exists "Recipients read active shared bundles" on storage.objects;
create policy "Recipients read active shared bundles"
  on storage.objects
  for select
  to anon, authenticated
  using (
    bucket_id = 'memoir-backups'
    and (storage.foldername(name))[2] = 'shares'
    and public.memoir_can_read_shared_object(name)
  );

commit;
