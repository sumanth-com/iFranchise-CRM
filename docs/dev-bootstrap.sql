-- iFranchise CRM — one-time DEV bootstrap
--
-- Run this ONCE in the Supabase DEV SQL Editor (service role / postgres).
-- Do not run it from the application or with the publishable key.
--
-- This script does NOT:
--   - insert into auth.users
--   - invent a user UUID
--   - create brands
--   - create leads, customers, meetings, or other CRM data
--
-- REPLACE THIS VALUE before running:
--   <AUTH_USER_UUID>  -> the real UUID of the existing Auth user
--                       (Authentication > Users > the initial CEO/Admin)
--
-- Execution order:
--   1. Apply migration 0001 to DEV (already done).
--   2. Create the initial CEO/Admin user in Supabase Auth (email/password or invite).
--   3. Copy that user's UUID from Authentication > Users.
--   4. Replace <AUTH_USER_UUID> below with that UUID.
--   5. Paste this whole script into the DEV SQL Editor and run it once.
--
-- Role note:
--   organization_memberships allows one role per user per organization.
--   The seeded `ceo` role is assigned because is_org_admin() includes ceo
--   and admin. A second Admin membership for the same user is not possible.

do $$
declare
  supplied_user_id_text constant text := '50f4a0f9-f9eb-461e-baa6-494532790531';
  auth_user_id uuid;
  organization_id uuid;
  ceo_role_id uuid;
begin
  perform set_config('search_path', '', true);

  begin
    auth_user_id := supplied_user_id_text::uuid;
  exception
    when invalid_text_representation then
      raise exception 'Replace <AUTH_USER_UUID> with the real Auth user UUID from Authentication > Users.';
  end;

  lock table public.organizations in share row exclusive mode;
  lock table public.organization_memberships in share row exclusive mode;

  select r.id
  into ceo_role_id
  from public.roles as r
  where r.code = 'ceo'
    and r.scope = 'organization'::public.access_scope;

  if ceo_role_id is null then
    raise exception 'Role ceo (organization) was not found. Apply migration 0001 first.';
  end if;

  if not exists (
    select 1
    from auth.users as u
    where u.id = auth_user_id
  ) then
    raise exception 'Auth user % does not exist. Create the user in Supabase Auth first, then rerun this bootstrap.', auth_user_id;
  end if;

  if exists (
    select 1
    from public.organizations as o
    where o.archived_at is null
  ) then
    raise exception 'An active organization already exists. This bootstrap is one-time only.';
  end if;

  if exists (
    select 1
    from public.organization_memberships as om
    where om.user_id = auth_user_id
      and om.archived_at is null
  ) then
    raise exception 'User % already has an active organization membership.', auth_user_id;
  end if;

  insert into public.profiles (id, email, full_name)
  select
    u.id,
    u.email,
    nullif(
      trim(
        coalesce(
          u.raw_user_meta_data ->> 'full_name',
          u.raw_user_meta_data ->> 'name',
          ''
        )
      ),
      ''
    )
  from auth.users as u
  where u.id = auth_user_id
  on conflict (id) do nothing;

  if not exists (
    select 1
    from public.profiles as p
    where p.id = auth_user_id
      and p.archived_at is null
  ) then
    raise exception 'Profile % is missing or archived. The Auth user must have an active public.profiles row.', auth_user_id;
  end if;

  insert into public.organizations (name, slug)
  values ('iFranchise', 'ifranchise')
  returning id into organization_id;

  insert into public.organization_memberships (
    organization_id,
    user_id,
    role_id
  )
  values (
    organization_id,
    auth_user_id,
    ceo_role_id
  );

  raise notice 'Created organization iFranchise (%).', organization_id;
  raise notice 'Assigned CEO membership to Auth user %.', auth_user_id;
end;
$$;
